use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret};

// ── types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "event_type")]
pub enum P2PEvent {
    PeerOnline { peer_id: String, nickname: String },
    PeerOffline { peer_id: String },
    MessageReceived { peer_id: String, content: String, nickname: String },
    PeerDiscovered { peer_id: String, nickname: String },
    ListenAddress { content: String },
    KeyExchanged { peer_id: String, nickname: String },
    BootstrapStatus { status: String },
    ScanResult { success: bool, message: String, target_peer_id: Option<String> },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueuedMsg {
    content: String,
    nickname: String,
    ts: u64,
}

// ── bootstrap server types ───────────────────────────────────────────────────

#[derive(Serialize)]
struct RegisterReq { peer_id: String }
#[derive(Serialize)]
struct QrReq { peer_id: String, validity_secs: u64 }
#[derive(Deserialize)]
struct QrRes { encrypted_token: String }
#[derive(Deserialize)]
struct ScanRes {
    success: bool,
    message: String,
    target_peer_id: Option<String>,
}

#[derive(Serialize)]
struct IpReq { requester_peer_id: String, target_peer_id: String }
#[derive(Deserialize)]
struct IpRes { ip: Option<String> }
#[derive(Serialize)]
struct PingReq { sender_peer_id: String, target_peer_id: String }
#[derive(Deserialize)]
struct StatusRes { unread_from: Vec<String> }

// ── shared state ─────────────────────────────────────────────────────────────

pub struct P2PHandle {
    sender: mpsc::UnboundedSender<OutboundCmd>,
    pub local_peer_id: String,
    pub local_pubkey_b64: String,
    pub peer_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    pub nickname: Arc<Mutex<String>>,
    pub bootstrap_url: Arc<Mutex<String>>,
}

pub enum OutboundCmd {
    SendMsg { to: String, content: String },
    GenerateQr { validity_secs: u64 },
    ScanQr { token: String },
    SetNickname { name: String },
}

struct AppState {
    local_peer_id: String,
    local_pubkey_b64: String,
    local_secret_bytes: [u8; 32],
    peer_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    offline_queue: Arc<Mutex<HashMap<String, Vec<QueuedMsg>>>>,
    nickname: Arc<Mutex<String>>,
    bootstrap_url: Arc<Mutex<String>>,
    emitter: Arc<TauriEmitter>,
}

pub struct TauriEmitter {
    pub handle: tauri::AppHandle,
}

impl TauriEmitter {
    fn emit(&self, event: P2PEvent) {
        let _ = self.handle.emit("p2p-event", event);
    }
}

// ── encryption ───────────────────────────────────────────────────────────────

fn encrypt(key_bytes: &[u8; 32], plaintext: &str) -> (String, String) {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).expect("encryption failed");
    (B64.encode(nonce_bytes), B64.encode(ciphertext))
}

fn decrypt(key_bytes: &[u8; 32], nonce_b64: &str, cipher_b64: &str) -> Option<String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = B64.decode(nonce_b64).ok()?;
    let ciphertext = B64.decode(cipher_b64).ok()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}

fn derive_key(shared: &SharedSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.finalize().into()
}

// ── networking ───────────────────────────────────────────────────────────────

async fn handle_connection(mut socket: TcpStream, state: Arc<AppState>) {
    let mut buf = vec![0u8; 4096];
    match socket.read(&mut buf).await {
        Ok(n) if n > 0 => {
            if let Ok(env) = serde_json::from_slice::<Envelope>(&buf[..n]) {
                process_envelope(env, state).await;
            }
        }
        _ => {}
    }
}

async fn process_envelope(env: Envelope, state: Arc<AppState>) {
    match env {
        Envelope::Hello { from, pubkey, nickname } => {
            if from != state.local_peer_id {
                if let Ok(pk_bytes) = B64.decode(pubkey) {
                    if pk_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&pk_bytes);
                        let static_secret = x25519_dalek::StaticSecret::from(state.local_secret_bytes);
                        let shared = static_secret.diffie_hellman(&X25519PublicKey::from(arr));
                        let derived = derive_key(&shared);
                        state.peer_keys.lock().unwrap().insert(from.clone(), derived);
                        state.emitter.emit(P2PEvent::KeyExchanged { peer_id: from.clone(), nickname: nickname.clone() });
                        
                        // flush offline queue
                        let to_send = state.offline_queue.lock().unwrap().remove(&from);
                        if let Some(msgs) = to_send {
                            for m in msgs {
                                let _ = send_direct_message(&from, &m.content, state.clone()).await;
                            }
                        }
                    }
                }
            }
        }
        Envelope::Msg { from, to, nonce, ciphertext, nickname, ts: _ } => {
            if to == state.local_peer_id {
                let key = state.peer_keys.lock().unwrap().get(&from).copied();
                if let Some(k) = key {
                    if let Some(plaintext) = decrypt(&k, &nonce, &ciphertext) {
                        state.emitter.emit(P2PEvent::MessageReceived { peer_id: from, content: plaintext, nickname });
                    }
                }
            }
        }
    }
}

async fn send_direct_message(to_peer_id: &str, content: &str, state: Arc<AppState>) -> Result<(), Box<dyn Error>> {
    let bootstrap_url = state.bootstrap_url.lock().unwrap().clone();
    let client = reqwest::Client::new();
    let res = client.post(format!("{}/peer/ip", bootstrap_url))
        .json(&IpReq { requester_peer_id: state.local_peer_id.clone(), target_peer_id: to_peer_id.to_string() })
        .send().await?;
    
    let ip_res: IpRes = res.json().await?;
    if let Some(ip) = ip_res.ip {
        let mut stream = TcpStream::connect(format!("{}:3001", ip)).await?;
        
        let key = state.peer_keys.lock().unwrap().get(to_peer_id).copied();
        if let Some(k) = key {
            let (nonce, ciphertext) = encrypt(&k, content);
            let env = Envelope::Msg {
                from: state.local_peer_id.clone(),
                to: to_peer_id.to_string(),
                nonce,
                ciphertext,
                nickname: state.nickname.lock().unwrap().clone(),
                ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            };
            let bytes = serde_json::to_vec(&env)?;
            stream.write_all(&bytes).await?;
            Ok(())
        } else {
            // Need to exchange keys first
            let env = Envelope::Hello {
                from: state.local_peer_id.clone(),
                pubkey: state.local_pubkey_b64.clone(),
                nickname: state.nickname.lock().unwrap().clone(),
            };
            let bytes = serde_json::to_vec(&env)?;
            stream.write_all(&bytes).await?;
            // Queue message and try again after key exchange? 
            // Simplified: just fail here and let the UI handle it or queue it
            state.offline_queue.lock().unwrap().entry(to_peer_id.to_string()).or_default().push(QueuedMsg {
                content: content.to_string(),
                nickname: "".into(), // not used in queue
                ts: 0,
            });
            Err("Key not found, sent Hello instead".into())
        }
    } else {
        // Peer offline, send ping to bootstrap
        let bootstrap_url = state.bootstrap_url.lock().unwrap().clone();
        client.post(format!("{}/peer/ping", bootstrap_url))
            .json(&PingReq { sender_peer_id: state.local_peer_id.clone(), target_peer_id: to_peer_id.to_string() })
            .send().await?;
        state.offline_queue.lock().unwrap().entry(to_peer_id.to_string()).or_default().push(QueuedMsg {
            content: content.to_string(),
            nickname: "".into(),
            ts: 0,
        });
        Err("Peer offline, pinged via bootstrap".into())
    }
}

// ── main loop ────────────────────────────────────────────────────────────────

pub async fn run_p2p(
    app_handle: tauri::AppHandle,
    mut cmd_rx: mpsc::UnboundedReceiver<OutboundCmd>,
    local_peer_id: String,
    local_pubkey_b64: String,
    secret_bytes: [u8; 32],
    nickname: Arc<Mutex<String>>,
    bootstrap_url: Arc<Mutex<String>>,
) -> Result<(), Box<dyn Error>> {
    let state = Arc::new(AppState {
        local_peer_id: local_peer_id.clone(),
        local_pubkey_b64,
        local_secret_bytes: secret_bytes,
        peer_keys: Arc::new(Mutex::new(HashMap::new())),
        offline_queue: Arc::new(Mutex::new(HashMap::new())),
        nickname,
        bootstrap_url: bootstrap_url.clone(),
        emitter: Arc::new(TauriEmitter { handle: app_handle }),
    });

    // Start TCP listener
    let listener = TcpListener::bind("0.0.0.0:3001").await?;
    let state_conn = state.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((socket, _)) = listener.accept().await {
                let s = state_conn.clone();
                tokio::spawn(async move {
                    handle_connection(socket, s).await;
                });
            }
        }
    });

    // Periodic registration with bootstrap
    let state_reg = state.clone();
    let local_peer_id_reg = local_peer_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        let client = reqwest::Client::new();
        loop {
            interval.tick().await;
            let bootstrap_url_str = state_reg.bootstrap_url.lock().unwrap().clone();
            println!("Backend: Registering with bootstrap at {}", bootstrap_url_str);
            let _ = client.post(format!("{}/register", bootstrap_url_str))
                .json(&RegisterReq { peer_id: local_peer_id_reg.clone() })
                .send().await;
        }
    });

    // Registration attempt immediately (optional as interval.tick() fires immediately in some versions, but explicit is better)
    let _ = client.post(format!("{}/register", bootstrap_url.lock().unwrap()))
        .json(&RegisterReq { peer_id: local_peer_id.clone() })
        .send().await;

    // Periodic status check
    let state_check = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let c = reqwest::Client::new();
        loop {
            interval.tick().await;
            let bootstrap_url_str = state_check.bootstrap_url.lock().unwrap().clone();
            if let Ok(res) = c.post(format!("{}/peer/status", bootstrap_url_str))
                .json(&RegisterReq { peer_id: state_check.local_peer_id.clone() })
                .send().await {
                if let Ok(status) = res.json::<StatusRes>().await {
                    for from in status.unread_from {
                        state_check.emitter.emit(P2PEvent::PeerDiscovered { peer_id: from, nickname: "Offline ping".into() });
                    }
                }
            }
        }
    });

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            OutboundCmd::SendMsg { to, content } => {
                let _ = send_direct_message(&to, &content, state.clone()).await;
            }
            OutboundCmd::GenerateQr { validity_secs } => {
                let bootstrap_url_str = bootstrap_url.lock().unwrap().clone();
                if let Ok(res) = client.post(format!("{}/qr/generate", bootstrap_url_str))
                    .json(&QrReq { peer_id: local_peer_id.clone(), validity_secs })
                    .send().await {
                    if let Ok(qr) = res.json::<QrRes>().await {
                        state.emitter.emit(P2PEvent::ListenAddress { content: qr.encrypted_token });
                    }
                }
            }
            OutboundCmd::ScanQr { token } => {
                let bootstrap_url_str = bootstrap_url.lock().unwrap().clone();
                match client.post(format!("{}/qr/scan", bootstrap_url_str))
                    .json(&ScanReq { scanner_peer_id: local_peer_id.clone(), encrypted_token: token })
                    .send().await {
                    Ok(res) => {
                        if let Ok(scan_res) = res.json::<ScanRes>().await {
                            state.emitter.emit(P2PEvent::ScanResult { 
                                success: scan_res.success, 
                                message: scan_res.message,
                                target_peer_id: scan_res.target_peer_id.clone(),
                            });
                            
                            // If successful, try to resolve IP immediately to speed up discovery
                            if scan_res.success {
                                if let Some(target_id) = scan_res.target_peer_id {
                                    let s = state.clone();
                                    tokio::spawn(async move {
                                        // Wait a bit for the server to propagate? 
                                        // Actually the server linked them in the same request, so get_ip should work.
                                        let burl = s.bootstrap_url.lock().unwrap().clone();
                                        if let Ok(ip_res) = reqwest::Client::new().post(format!("{}/peer/ip", burl))
                                            .json(&IpReq { requester_peer_id: s.local_peer_id.clone(), target_peer_id: target_id.clone() })
                                            .send().await {
                                            if let Ok(ip_data) = ip_res.json::<IpRes>().await {
                                                if let Some(_) = ip_data.ip {
                                                    s.emitter.emit(P2PEvent::PeerDiscovered { peer_id: target_id, nickname: "".into() });
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                        } else {
                            state.emitter.emit(P2PEvent::ScanResult { success: false, message: "Decode error".into(), target_peer_id: None });
                        }
                    }
                    Err(e) => {
                        state.emitter.emit(P2PEvent::ScanResult { success: false, message: e.to_string(), target_peer_id: None });
                    }
                }
            }
            OutboundCmd::SetNickname { name } => {
                *state.nickname.lock().unwrap() = name;
            }
        }
    }
    Ok(())
}

// ── tauri commands ────────────────────────────────────────────────────────────

#[tauri::command]
fn get_my_peer_id(state: State<'_, P2PHandle>) -> String {
    state.local_peer_id.clone()
}

#[tauri::command]
fn send_p2p_message(to: String, content: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::SendMsg { to, content });
}

#[tauri::command]
fn get_nickname(state: State<'_, P2PHandle>) -> String {
    state.nickname.lock().unwrap().clone()
}

#[tauri::command]
fn set_nickname(name: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::SetNickname { name });
}

#[tauri::command]
fn generate_qr(validity: u64, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::GenerateQr { validity_secs: validity });
}

#[tauri::command]
fn scan_qr(token: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::ScanQr { token });
}

#[tauri::command]
async fn reset_identity(app: tauri::AppHandle) -> Result<(), String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let id_path = app_dir.join("p2p_id_v3.txt");
    let secret_path = app_dir.join("p2p_secret_v3.bin");
    
    if id_path.exists() {
        let _ = std::fs::remove_file(id_path);
    }
    if secret_path.exists() {
        let _ = std::fs::remove_file(secret_path);
    }
    
    // Also clear the store if possible? JS handles it but safe to do here if needed.
    // However, the JS reload will wipe memory state anyway.
    Ok(())
}
#[tauri::command]
fn set_bootstrap_url(url: String, state: State<'_, P2PHandle>) {
    let mut burl = state.bootstrap_url.lock().unwrap();
    *burl = url;
}

// ── app entrypoint ────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<OutboundCmd>();
    
    let nickname = Arc::new(Mutex::new(String::new()));
    let peer_keys = Arc::new(Mutex::new(HashMap::new()));
    let bootstrap_url = Arc::new(Mutex::new("http://34.41.180.29:3000".to_string()));
    let bootstrap_url_loop = bootstrap_url.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(tauri_plugin_store::Builder::default().build())
        .setup(move |app| {
            println!("Backend: Setup starting");
            let app_handle = app.handle().clone();
            let app_dir = app.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let key_path = app_dir.join("p2p_id_v3.txt");
            let secret_path = app_dir.join("p2p_secret_v3.bin");
            
            println!("Backend: App dir: {:?}", app_dir);
            let _ = std::fs::create_dir_all(&app_dir);

            // 1. Load or generate secret bytes
            let mut secret_bytes = [0u8; 32];
            if secret_path.exists() {
                if let Ok(bytes) = std::fs::read(&secret_path) {
                    if bytes.len() == 32 {
                        secret_bytes.copy_from_slice(&bytes);
                        println!("Backend: Loaded existing secret key");
                    } else {
                        rand::thread_rng().fill_bytes(&mut secret_bytes);
                        let _ = std::fs::write(&secret_path, &secret_bytes);
                        println!("Backend: Corrupt secret key, generated new one");
                    }
                } else {
                    rand::thread_rng().fill_bytes(&mut secret_bytes);
                    let _ = std::fs::write(&secret_path, &secret_bytes);
                    println!("Backend: Failed to read secret key, generated new one");
                }
            } else {
                rand::thread_rng().fill_bytes(&mut secret_bytes);
                let _ = std::fs::write(&secret_path, &secret_bytes);
                println!("Backend: Generated and saved new secret key");
            }

            // 2. Derive public key and peer ID
            let static_secret = x25519_dalek::StaticSecret::from(secret_bytes);
            let local_pubkey_b64 = B64.encode(X25519PublicKey::from(&static_secret).as_bytes());
            let peer_id = format!("peer_{}", &local_pubkey_b64[..12]);
            
            // Save peer_id for reference (legacy compatibility)
            let _ = std::fs::write(&key_path, &peer_id);
            println!("Backend: Peer ID: {}", peer_id);

            app.manage(P2PHandle {
                sender: cmd_tx,
                local_peer_id: peer_id.clone(),
                local_pubkey_b64: local_pubkey_b64.clone(),
                peer_keys,
                nickname: nickname.clone(),
                bootstrap_url: bootstrap_url_loop,
            });

            tauri::async_runtime::spawn(async move {
                println!("Backend: Spawning run_p2p loop");
                let res = run_p2p(app_handle, cmd_rx, peer_id, local_pubkey_b64, secret_bytes, nickname, bootstrap_url).await;
                if let Err(e) = res {
                    eprintln!("Backend: run_p2p failed: {}", e);
                }
            });
            println!("Backend: Setup complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            send_p2p_message,
            get_my_peer_id,
            get_nickname,
            set_nickname,
            generate_qr,
            scan_qr,
            reset_identity,
            set_bootstrap_url,
        ])
        .run(tauri::generate_context!())
        .expect("error running app");
}
