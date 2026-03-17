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
use std::net::{SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret};

// ── types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
    Punch { from: String },
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
    PortStatus { success: bool, message: String, details: Option<String> },
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
#[derive(Serialize)]
struct ScanReq { scanner_peer_id: String, encrypted_token: String }

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
struct StatusRes { unread_from: Vec<String>, punch_from: Vec<String> }

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
    socket: Arc<UdpSocket>,
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

async fn handle_punch(from: String, _state: Arc<AppState>) {
    println!("Backend: Received direct UDP Punch from {}. NAT hole should be open.", from);
}

async fn process_envelope(env: Envelope, state: Arc<AppState>) {
    match env {
        Envelope::Punch { from } => {
            handle_punch(from, state).await;
        }
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

async fn punch_hole(to_peer_id: &str, state: Arc<AppState>) -> Result<(), Box<dyn Error>> {
    let bootstrap_url = state.bootstrap_url.lock().unwrap().clone();
    let client = reqwest::Client::new();
    let res = client.post(format!("{}/peer/ip", bootstrap_url))
        .json(&IpReq { requester_peer_id: state.local_peer_id.clone(), target_peer_id: to_peer_id.to_string() })
        .send().await?;
    
    let ip_res: IpRes = res.json().await?;
    if let Some(ip) = ip_res.ip {
        let env = Envelope::Punch { from: state.local_peer_id.clone() };
        let bytes = serde_json::to_vec(&env)?;
        state.socket.send_to(&bytes, format!("{}:3001", ip)).await?;
        println!("Backend: Sent direct UDP Punch to {}:3001", ip);
    }
    Ok(())
}

async fn send_direct_message(to_peer_id: &str, content: &str, state: Arc<AppState>) -> Result<(), Box<dyn Error>> {
    let bootstrap_url = state.bootstrap_url.lock().unwrap().clone();
    let client = reqwest::Client::new();
    let res = client.post(format!("{}/peer/ip", bootstrap_url))
        .json(&IpReq { requester_peer_id: state.local_peer_id.clone(), target_peer_id: to_peer_id.to_string() })
        .send().await?;
    
    let ip_res: IpRes = res.json().await?;
    if let Some(ip) = ip_res.ip {
        println!("Backend: Resolved IP {} for peer {}. Sending via UDP...", ip, to_peer_id);
        
        // 1. Send Punch Request to Matchmaker (Bootstrap)
        let _ = client.post(format!("{}/peer/punch", bootstrap_url))
            .json(&PingReq { sender_peer_id: state.local_peer_id.clone(), target_peer_id: to_peer_id.to_string() })
            .send().await;

        let key = state.peer_keys.lock().unwrap().get(to_peer_id).copied();
        let env = if let Some(k) = key {
            let (nonce, ciphertext) = encrypt(&k, content);
            Envelope::Msg {
                from: state.local_peer_id.clone(),
                to: to_peer_id.to_string(),
                nonce,
                ciphertext,
                nickname: state.nickname.lock().unwrap().clone(),
                ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
            }
        } else {
            Envelope::Hello {
                from: state.local_peer_id.clone(),
                pubkey: state.local_pubkey_b64.clone(),
                nickname: state.nickname.lock().unwrap().clone(),
            }
        };

        let bytes = serde_json::to_vec(&env)?;
        // Send multiple times for reliability in UDP hole punching
        for _ in 0..3 {
            state.socket.send_to(&bytes, format!("{}:3001", ip)).await?;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        if key.is_none() {
            state.offline_queue.lock().unwrap().entry(to_peer_id.to_string()).or_default().push(QueuedMsg {
                content: content.to_string(),
                nickname: "".into(),
                ts: 0,
            });
            return Err("Key not found, sent UDP Hello instead".into());
        }
        Ok(())
    } else {
        println!("Backend: Peer {} is currently offline according to bootstrap.", to_peer_id);
        state.emitter.emit(P2PEvent::BootstrapStatus { status: format!("Peer {} is offline.", to_peer_id) });
        let _ = client.post(format!("{}/peer/ping", bootstrap_url))
            .json(&PingReq { sender_peer_id: state.local_peer_id.clone(), target_peer_id: to_peer_id.to_string() })
            .send().await;
        state.offline_queue.lock().unwrap().entry(to_peer_id.to_string()).or_default().push(QueuedMsg {
            content: content.to_string(), nickname: "".into(), ts: 0,
        });
        Err("Peer offline, pinged via bootstrap".into())
    }
}

// ── port forwarding ──────────────────────────────────────────────────────────

async fn try_port_forward(state: Arc<AppState>) {
    let local_ip = match local_ip_address::local_ip() {
        Ok(std::net::IpAddr::V4(ip)) => ip,
        _ => {
            println!("Backend: Could not detect local IPv4 for port forwarding.");
            return;
        }
    };
    
    let state_port = state.clone();
    tokio::task::spawn_blocking(move || {
        // 1. Try UPnP (Standard)
        println!("Backend: Attempting UPnP mapping (sync) for port 3001 (UDP) to {}...", local_ip);
        match igd_next::search_gateway(Default::default()) {
            Ok(gateway) => {
                let local_addr = SocketAddrV4::new(local_ip, 3001);
                match gateway.add_port(
                    igd_next::PortMappingProtocol::UDP,
                    3001,
                    SocketAddr::V4(local_addr),
                    0,
                    "P2PTexter",
                ) {
                    Ok(_) => {
                        println!("Backend: UPnP Success! Port 3001 mapped.");
                    state_port.emitter.emit(P2PEvent::PortStatus { 
                        success: true, 
                        message: "UPnP Mapped".into(),
                        details: None
                    });
                    return;
                    }
                    Err(e) => println!("Backend: UPnP AddPort failed: {}", e),
                }
            }
            Err(e) => println!("Backend: UPnP Gateway search failed: {}", e),
        }

        // 2. Try NAT-PMP (Apple/Modern)
        println!("Backend: Trying NAT-PMP fallback...");
        let mut n = match natpmp::Natpmp::new() {
            Ok(n) => n,
            Err(e) => {
                println!("Backend: NAT-PMP init failed: {}", e);
                return;
            }
        };
        
        if let Ok(_) = n.send_port_mapping_request(natpmp::Protocol::UDP, 3001, 3001, 3600) {
            println!("Backend: NAT-PMP request sent.");
            state_port.emitter.emit(P2PEvent::PortStatus { 
                success: true, 
                message: "NAT-PMP Requested".into(),
                details: None
            });
        }
    });
}

// ── connectivity diagnostics ──────────────────────────────────────────────────

async fn perform_connectivity_test(state: Arc<AppState>) {
    let bootstrap_url = state.bootstrap_url.lock().unwrap().clone();
    // Parse IP from bootstrap URL (e.g. http://1.2.3.4:3000 -> 1.2.3.4)
    let host = bootstrap_url.split("://").last().unwrap_or("").split(':').next().unwrap_or("");
    if host.is_empty() { return; }

    println!("Backend: Testing UDP connectivity via {}:3002...", host);
    let test_msg = b"PING";
    let _ = state.socket.send_to(test_msg, format!("{}:3002", host)).await;

    // Listen for echo with timeout
    let mut buf = [0u8; 1024];
    let socket = state.socket.clone();
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv_from(&mut buf)).await;

    match timeout {
        Ok(Ok((n, _addr))) if &buf[..n] == test_msg => {
            println!("Backend: UDP Echo received! Port 3001 is reachable.");
            state.emitter.emit(P2PEvent::PortStatus { 
                success: true, 
                message: "Internet Ready".into(),
                details: Some("UDP Echo Success".into())
            });
        }
        _ => {
            println!("Backend: UDP Echo timeout. Port 3001 might be blocked.");
            let mut details = "No Echo Response".to_string();
            
            #[cfg(target_os = "linux")]
            if let Some(fw_msg) = check_linux_firewall() {
                details = fw_msg;
            }

            state.emitter.emit(P2PEvent::PortStatus { 
                success: false, 
                message: "Port Blocked?".into(),
                details: Some(details)
            });
        }
    }
}

#[cfg(target_os = "linux")]
fn check_linux_firewall() -> Option<String> {
    use std::process::Command;
    // Check for ufw
    if let Ok(output) = Command::new("ufw").arg("status").output() {
        let status = String::from_utf8_lossy(&output.stdout);
        if status.contains("active") && !status.contains("3001/udp") {
            return Some("ufw active, allow 3001/udp".into());
        }
    }
    // Check for firewalld
    if let Ok(output) = Command::new("firewall-cmd").arg("--state").output() {
        if String::from_utf8_lossy(&output.stdout).trim() == "running" {
            return Some("firewalld active, allow 3001/udp".into());
        }
    }
    None
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
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:3001").await?);
    
    let state = Arc::new(AppState {
        local_peer_id: local_peer_id.clone(),
        local_pubkey_b64,
        local_secret_bytes: secret_bytes,
        peer_keys: Arc::new(Mutex::new(HashMap::new())),
        offline_queue: Arc::new(Mutex::new(HashMap::new())),
        nickname,
        bootstrap_url: bootstrap_url.clone(),
        emitter: Arc::new(TauriEmitter { handle: app_handle }),
        socket,
    });

    // Start UDP inbound loop
    let state_inbound = state.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            if let Ok((n, addr)) = state_inbound.socket.recv_from(&mut buf).await {
                if let Ok(env) = serde_json::from_slice::<Envelope>(&buf[..n]) {
                    println!("Backend: Received UDP envelope from {}", addr);
                    process_envelope(env, state_inbound.clone()).await;
                }
            }
        }
    });

    // Try Automated Port Forwarding (UPnP / NAT-PMP)
    let state_diag = state.clone();
    tokio::spawn(async move {
        try_port_forward(state_diag.clone()).await;
        // Wait a bit for mapping to settle, then test connectivity
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        perform_connectivity_test(state_diag).await;
    });

    let client = reqwest::Client::new();

    // Periodic registration with bootstrap
    let state_reg = state.clone();
    let local_peer_id_reg = local_peer_id.clone();
    let client_reg = client.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            let bootstrap_url_str = state_reg.bootstrap_url.lock().unwrap().clone();
            println!("Backend: Registering with bootstrap at {}", bootstrap_url_str);
            let _ = client_reg.post(format!("{}/register", bootstrap_url_str))
                .json(&RegisterReq { peer_id: local_peer_id_reg.clone() })
                .send().await;
        }
    });

    // Registration attempt immediately is handled by the first tick of the interval above

    // Periodic status check (Pings + Punch Signals)
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
                if let Ok(res) = res.json::<StatusRes>().await {
                    // 1. Process offline notifications
                    for from in res.unread_from {
                        state_check.emitter.emit(P2PEvent::PeerDiscovered { peer_id: from, nickname: "Offline ping".into() });
                    }
                    // 2. Process punch requests (Matchmaking)
                    for from_peer in res.punch_from {
                        println!("Backend: Matchmaker says peer {} wants to connect. Punching...", from_peer);
                        let _ = punch_hole(&from_peer, state_check.clone()).await;
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
                    if let Ok(qr_res) = res.json::<QrRes>().await {
                        state.emitter.emit(P2PEvent::ListenAddress { content: qr_res.encrypted_token });
                    }
                }
            }
            OutboundCmd::ScanQr { token } => {
                let bootstrap_url_str = bootstrap_url.lock().unwrap().clone();
                match client.post(format!("{}/qr/scan", bootstrap_url_str))
                    .json(&ScanReq { scanner_peer_id: local_peer_id.clone(), encrypted_token: token })
                    .send().await {
                    Ok(res) => {
                        if let Ok(scan_data) = res.json::<ScanRes>().await {
                            state.emitter.emit(P2PEvent::ScanResult { 
                                success: scan_data.success, 
                                message: scan_data.message,
                                target_peer_id: scan_data.target_peer_id.clone(),
                            });
                            
                            // If successful, try to resolve IP immediately to speed up discovery
                            if scan_data.success {
                                if let Some(target_id) = scan_data.target_peer_id {
                                    let s = state.clone();
                                    let c = client.clone();
                                    tokio::spawn(async move {
                                        let burl = s.bootstrap_url.lock().unwrap().clone();
                                        if let Ok(ip_res) = c.post(format!("{}/peer/ip", burl))
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
    println!("Backend: RESET called. Cleaning dir: {:?}", app_dir);

    let files_to_delete = vec![
        "p2p_id_v3.txt",
        "p2p_secret_v3.bin",
        ".settings.dat", // This is the store file
    ];
    
    for f_name in files_to_delete {
        let path = app_dir.join(f_name);
        if path.exists() {
            println!("Backend: Deleting {:?}", path);
            let _ = std::fs::remove_file(path);
        }
    }
    
    // Give some time for file system and UI to settle
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    
    println!("Backend: Cleanup complete. Exiting app to enforce re-init.");
    std::process::exit(0);
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

            if key_path.exists() {
                println!("Backend: FOUND legacy id file: {:?}", key_path);
            }
            if secret_path.exists() {
                println!("Backend: FOUND secret key file: {:?}", secret_path);
            }

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
