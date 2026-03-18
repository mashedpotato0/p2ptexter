use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
// sha2 removed as it's no longer used
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, State};
use tokio::sync::mpsc;
use x25519_dalek::PublicKey as X25519PublicKey;
use libp2p::{
    core::upgrade,
    dcutr, identify, kad, noise, relay, request_response, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use futures::StreamExt;

// ── types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
    Punch { from: String },
    BootstrapInfo { peer_id: String, multiaddr: String }, // Added missing variant
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

#[derive(Serialize)]
struct IpReq { requester_peer_id: String, target_peer_id: String }
#[derive(Deserialize)]
struct IpRes { ip: Option<String> }

#[derive(Deserialize)]
struct ScanRes {
    success: bool,
    message: String,
    target_peer_id: Option<String>,
}

// StatusRes removed as it's no longer used

#[derive(Deserialize, Serialize, Clone)]
struct BootstrapInfo {
    peer_id: String,
    multiaddr: String,
}

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
    SetActivePeer { peer_id: Option<String> },
    DialAddr { peer_id: PeerId, addr: Multiaddr },
}

struct AppState {
    local_peer_id: String,
    local_pubkey_b64: String,
    local_ed25519_pubkey_b64: String,
    local_secret_bytes: [u8; 32],
    peer_keys: Mutex<HashMap<String, [u8; 32]>>,
    offline_queue: Mutex<HashMap<String, Vec<QueuedMsg>>>,
    active_peer_id: Mutex<Option<String>>,
    nickname: Arc<Mutex<String>>,
    bootstrap_url: Arc<Mutex<String>>,
    emitter: Arc<TauriEmitter>,
    libp2p_peer_id: PeerId,
}

#[derive(NetworkBehaviour)]
struct AppBehaviour {
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    request_response: request_response::cbor::Behaviour<Envelope, Envelope>, // 1:1 messaging
}

pub struct TauriEmitter {
    pub handle: tauri::AppHandle,
}

impl TauriEmitter {
    fn emit(&self, event: P2PEvent) {
        let _ = self.handle.emit("p2p-event", event);
    }
}

// ── networking ───────────────────────────────────────────────────────────────

// ── main loop ────────────────────────────────────────────────────────────────

#[tauri::command]
async fn set_active_peer(peer_id: Option<String>, state: State<'_, P2PHandle>) -> Result<(), String> {
    let _ = state.sender.send(OutboundCmd::SetActivePeer { peer_id });
    Ok(())
}

// ── libp2p helpers ──────────────────────────────────────────────────────────

fn get_libp2p_peer_id(b64_pubkey: &str) -> Option<PeerId> {
    let bytes = B64.decode(b64_pubkey).ok()?;
    let pubkey = libp2p::identity::ed25519::PublicKey::try_from_bytes(&bytes).ok()?;
    Some(PeerId::from_public_key(&libp2p::identity::PublicKey::from(pubkey)))
}

fn encrypt_message_for_libp2p(to_peer_id: &str, content: &str, state: Arc<AppState>) -> Option<Envelope> {
    let keys = state.peer_keys.lock().unwrap();
    let target_pubkey_bytes = keys.get(to_peer_id)?;
    let pubkey = X25519PublicKey::from(*target_pubkey_bytes);
    let secret = x25519_dalek::StaticSecret::from(state.local_secret_bytes);
    let shared = secret.diffie_hellman(&pubkey);
    
    let key = Key::<Aes256Gcm>::from_slice(shared.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, content.as_bytes()).ok()?;
    
    Some(Envelope::Msg {
        from: state.local_peer_id.clone(),
        to: to_peer_id.to_string(),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
        nickname: state.nickname.lock().unwrap().clone(),
        ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs(),
    })
}

async fn process_envelope(env: Envelope, state: Arc<AppState>) {
    match env {
        Envelope::Hello { from, pubkey, nickname } => {
            println!("Backend: Received Hello from {} ({})", nickname, from);
            if let Ok(key_bytes) = B64.decode(pubkey) {
                if key_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&key_bytes);
                    state.peer_keys.lock().unwrap().insert(from.clone(), arr);
                    state.emitter.emit(P2PEvent::KeyExchanged { peer_id: from.clone(), nickname: nickname.clone() });
                    state.emitter.emit(P2PEvent::PeerOnline { peer_id: from, nickname });
                }
            }
        }
        Envelope::Msg { from, nonce, ciphertext, nickname, .. } => {
            println!("Backend: Received encrypted message from {}", nickname);
            let keys = state.peer_keys.lock().unwrap();
            if let Some(target_pubkey) = keys.get(&from) {
                let pubkey = X25519PublicKey::from(*target_pubkey);
                let secret = x25519_dalek::StaticSecret::from(state.local_secret_bytes);
                let shared = secret.diffie_hellman(&pubkey);
                
                let key = Key::<Aes256Gcm>::from_slice(shared.as_bytes());
                let cipher = Aes256Gcm::new(key);
                
                if let Ok(nonce_bytes) = B64.decode(nonce) {
                    if let Ok(cipher_bytes) = B64.decode(ciphertext) {
                        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&nonce_bytes), cipher_bytes.as_ref()) {
                            if let Ok(content) = String::from_utf8(plaintext) {
                                state.emitter.emit(P2PEvent::MessageReceived { peer_id: from, content, nickname });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

pub async fn run_p2p(
    app_handle: tauri::AppHandle,
    mut cmd_rx: mpsc::UnboundedReceiver<OutboundCmd>,
    local_peer_id: String,
    local_pubkey_b64: String,
    secret_bytes: [u8; 32],
    nickname: Arc<Mutex<String>>,
    bootstrap_url: Arc<Mutex<String>>,
) -> Result<(), Box<dyn Error>> {
    let mut secret_bytes_mut = secret_bytes;
    let libp2p_keypair = libp2p::identity::Keypair::ed25519_from_bytes(&mut secret_bytes_mut).unwrap();
    let libp2p_peer_id = libp2p_keypair.public().to_peer_id();
    println!("Backend: libp2p PeerId: {}", libp2p_peer_id);

    let (relay_transport, relay_client) = relay::client::new(libp2p_peer_id);

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_other_transport(|key| relay_transport.upgrade(upgrade::Version::V1).authenticate(noise::Config::new(key).unwrap()).multiplex(yamux::Config::default()))?
        .with_behaviour(|key: &libp2p::identity::Keypair| {
            let mut kad_cfg = kad::Config::default();
            kad_cfg.set_protocol_names(vec![StreamProtocol::new("/p2ptexter/kad/1.0.0")]);
            let store = kad::store::MemoryStore::new(key.public().to_peer_id());
            AppBehaviour {
                relay_client,
                dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
                kad: kad::Behaviour::with_config(key.public().to_peer_id(), store, kad_cfg),
                identify: identify::Behaviour::new(identify::Config::new("/p2ptexter/1.0.0".into(), key.public())),
                request_response: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/p2ptexter/msg/1.0.0"), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                ),
            }
        })?
        .build();

    let ed25519_pubkey_b64 = B64.encode(libp2p_keypair.public().try_into_ed25519().unwrap().to_bytes());

    let state = Arc::new(AppState {
        local_peer_id: local_peer_id.clone(),
        local_pubkey_b64,
        local_ed25519_pubkey_b64: ed25519_pubkey_b64,
        local_secret_bytes: secret_bytes,
        peer_keys: Mutex::new(HashMap::new()),
        offline_queue: Mutex::new(HashMap::new()),
        active_peer_id: Mutex::new(None),
        nickname,
        bootstrap_url: bootstrap_url.clone(),
        emitter: Arc::new(TauriEmitter { handle: app_handle.clone() }),
        libp2p_peer_id,
    });

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

    let client = reqwest::Client::new();
    let mut bootstrap_info: Option<BootstrapInfo> = None;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Backend: Listening on {}", address);
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted { .. })) => {
                    println!("Backend: Relay reservation accepted!");
                    state.emitter.emit(P2PEvent::PortStatus { success: true, message: "Bridged (Relay/DCUtR)".into(), details: Some("Hole punching active".into()) });
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { info, peer_id, .. })) => {
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RequestResponse(request_response::Event::Message { message, .. })) => {
                    if let request_response::Message::Request { request, channel, .. } = message {
                        process_envelope(request, state.clone()).await;
                        let _ = swarm.behaviour_mut().request_response.send_response(channel, Envelope::Punch { from: local_peer_id.clone() });
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(_)) => {
                    // Hole punching is managed internally; UI notification skipped for now due to type ambiguity
                }
                _ => {}
            },
            cmd = cmd_rx.recv() => if let Some(cmd) = cmd {
                match cmd {
                    OutboundCmd::SendMsg { to, content } => {
                        let mut target_pid: Option<PeerId> = None;
                        {
                            let keys = state.peer_keys.lock().unwrap();
                            if let Some(pk) = keys.get(&to) {
                                target_pid = get_libp2p_peer_id(&B64.encode(pk));
                            }
                        }
                        if let Some(pid) = target_pid {
                            if let Some(env) = encrypt_message_for_libp2p(&to, &content, state.clone()) {
                                swarm.behaviour_mut().request_response.send_request(&pid, env);
                            }
                        }
                    }
                    OutboundCmd::GenerateQr { validity_secs } => {
                        let burl = state.bootstrap_url.lock().unwrap().clone();
                        let composite_id = format!("{}:{}", state.local_pubkey_b64, state.local_ed25519_pubkey_b64);
                        if let Ok(res) = client.post(format!("{}/qr/generate", burl)).json(&QrReq { peer_id: composite_id, validity_secs }).send().await {
                            if let Ok(qr) = res.json::<QrRes>().await {
                                state.emitter.emit(P2PEvent::ListenAddress { content: qr.encrypted_token });
                            }
                        }
                    }
                    OutboundCmd::ScanQr { token } => {
                        let burl = state.bootstrap_url.lock().unwrap().clone();
                        if let Ok(res) = client.post(format!("{}/qr/scan", burl)).json(&ScanReq { scanner_peer_id: state.local_peer_id.clone(), encrypted_token: token }).send().await {
                            if let Ok(scan) = res.json::<ScanRes>().await {
                                let mut final_target_id = scan.target_peer_id.clone();
                                if scan.success {
                                    if let Some(composite) = scan.target_peer_id.clone() {
                                        let parts: Vec<&str> = composite.split(':').collect();
                                        if parts.len() == 2 {
                                            let x25519_pub = parts[0];
                                            let ed25519_pub = parts[1];
                                            if let Ok(key_bytes) = B64.decode(x25519_pub) {
                                                if key_bytes.len() == 32 {
                                                    let mut arr = [0u8; 32];
                                                    arr.copy_from_slice(&key_bytes);
                                                    let short_id = format!("peer_{}", &x25519_pub[..12]);
                                                    final_target_id = Some(short_id.clone());
                                                    state.peer_keys.lock().unwrap().insert(short_id.clone(), arr);
                                                    
                                                    if let Some(pid) = get_libp2p_peer_id(ed25519_pub) {
                                                        swarm.behaviour_mut().kad.get_closest_peers(pid);
                                                        
                                                        // Fallback: try to get IP from signaling server
                                                        let ip_req = IpReq { requester_peer_id: state.local_peer_id.clone(), target_peer_id: short_id.clone() };
                                                        let burl_inner = burl.clone();
                                                        let client_inner = client.clone();
                                                        let cmd_tx_inner = state.emitter.handle.state::<P2PHandle>().sender.clone();
                                                        tokio::spawn(async move {
                                                            if let Ok(ip_res) = client_inner.post(format!("{}/peer/ip", burl_inner)).json(&ip_req).send().await {
                                                                if let Ok(ip_data) = ip_res.json::<IpRes>().await {
                                                                    if let Some(ip) = ip_data.ip {
                                                                        println!("Backend: Signaling found IP for {}: {}", short_id, ip);
                                                                        if let Ok(addr) = format!("/ip4/{}/tcp/4001", ip).parse::<Multiaddr>() {
                                                                            let _ = cmd_tx_inner.send(OutboundCmd::DialAddr { peer_id: pid, addr });
                                                                        }
                                                                        if let Ok(addr) = format!("/ip4/{}/udp/4001/quic-v1", ip).parse::<Multiaddr>() {
                                                                            let _ = cmd_tx_inner.send(OutboundCmd::DialAddr { peer_id: pid, addr });
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                state.emitter.emit(P2PEvent::ScanResult { success: scan.success, message: scan.message, target_peer_id: final_target_id });
                            }
                        }
                    }
                    OutboundCmd::SetActivePeer { peer_id } => {
                        *state.active_peer_id.lock().unwrap() = peer_id;
                    }
                    OutboundCmd::DialAddr { peer_id, addr } => {
                        println!("Backend: Manual dial to found IP: {}", addr);
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                        let _ = swarm.dial(addr.with(libp2p::multiaddr::Protocol::P2p(peer_id)));
                    }
                    OutboundCmd::SetNickname { name: _ } => {}
                }
            },
            _ = tick.tick() => {
                let burl = state.bootstrap_url.lock().unwrap().clone();
                if bootstrap_info.is_none() {
                    if let Ok(res) = client.post(format!("{}/bootstrap/info", burl)).send().await {
                        if let Ok(info_opt) = res.json::<Option<BootstrapInfo>>().await {
                            if let Some(info) = info_opt {
                                if let (Ok(pid), Ok(addr)) = (info.peer_id.parse::<PeerId>(), info.multiaddr.parse::<Multiaddr>()) {
                                    swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                                    let _ = swarm.dial(addr.with(libp2p::multiaddr::Protocol::P2p(pid)));
                                    bootstrap_info = Some(info);
                                }
                            }
                        }
                    }
                }
                let _ = client.post(format!("{}/register", burl)).json(&RegisterReq { peer_id: state.local_peer_id.clone() }).send().await;
            }
        }
    }
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
            set_active_peer,
        ])
        .run(tauri::generate_context!())
        .expect("error running app");
}
