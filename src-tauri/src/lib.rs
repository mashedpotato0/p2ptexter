use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures::StreamExt;
use libp2p::{
    core::upgrade, dcutr, identify, noise, ping, relay, request_response, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, State};
use tokio::sync::mpsc;
use x25519_dalek::PublicKey as X25519PublicKey;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String, ed25519_pubkey: String },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
    Punch { from: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "event_type")]
pub enum P2PEvent {
    PeerOnline { peer_id: String, nickname: String },
    MessageReceived { peer_id: String, content: String, nickname: String },
    ListenAddress { content: String },
    KeyExchanged { peer_id: String, nickname: String },
    ScanResult { success: bool, message: String, target_peer_id: Option<String> },
    PortStatus { success: bool, message: String, details: Option<String> },
}

#[derive(Deserialize, Debug, Clone)]
struct BootstrapInfo {
    peer_id: String,
    _multiaddr: String,
}

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
    DialPeer { peer_id: PeerId },
}

struct AppState {
    local_peer_id: String,
    local_pubkey_b64: String,
    local_ed25519_pubkey_b64: String,
    local_secret_bytes: [u8; 32],
    peer_keys: Mutex<HashMap<String, [u8; 32]>>,
    peer_libp2p_ids: Mutex<HashMap<String, PeerId>>,
    active_peer_id: Mutex<Option<String>>,
    nickname: Arc<Mutex<String>>,
    emitter: Arc<TauriEmitter>,
}

#[derive(NetworkBehaviour)]
struct AppBehaviour {
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
    request_response: request_response::cbor::Behaviour<Envelope, Envelope>,
    ping: ping::Behaviour,
}

pub struct TauriEmitter {
    pub handle: tauri::AppHandle,
}

impl TauriEmitter {
    fn emit(&self, event: P2PEvent) {
        let _ = self.handle.emit("p2p-event", event);
    }
}

fn get_libp2p_peer_id(b64_pubkey: &str) -> Option<PeerId> {
    let bytes = B64.decode(b64_pubkey).ok()?;
    let pubkey = libp2p::identity::ed25519::PublicKey::try_from_bytes(&bytes).ok()?;
    Some(PeerId::from_public_key(&libp2p::identity::PublicKey::from(pubkey)))
}

fn encrypt_message(to_peer_id: &str, content: &str, state: Arc<AppState>) -> Option<Envelope> {
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

async fn process_envelope(peer: PeerId, env: Envelope, state: Arc<AppState>) {
    match env {
        Envelope::Hello { from, pubkey, nickname, ed25519_pubkey: _ } => {
            println!("P2P: received hello from {}", nickname);
            if let Ok(key_bytes) = B64.decode(&pubkey) {
                if key_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&key_bytes);
                    state.peer_keys.lock().unwrap().insert(from.clone(), arr);
                    state.peer_libp2p_ids.lock().unwrap().insert(from.clone(), peer);
                    state.emitter.emit(P2PEvent::KeyExchanged { peer_id: from.clone(), nickname: nickname.clone() });
                    state.emitter.emit(P2PEvent::PeerOnline { peer_id: from, nickname });
                }
            }
        }
        Envelope::Msg { from, nonce, ciphertext, nickname, .. } => {
            println!("P2P: received encrypted msg from {}", nickname);
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

fn extract_ip(url: &str) -> String {
    let stripped = url.replace("http://", "").replace("https://", "");
    let ip_part = stripped.split(':').next().unwrap_or("34.41.180.29"); // Default fallback to production relay
    ip_part.to_string()
}

// Main P2P loop managing swarm events and outbound commands.
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
    println!("P2P: libp2p peerid: {}", libp2p_peer_id);

    let (relay_transport, relay_client) = relay::client::new(libp2p_peer_id);

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_other_transport(|key| relay_transport.upgrade(upgrade::Version::V1).authenticate(noise::Config::new(key).unwrap()).multiplex(yamux::Config::default()))?
        .with_behaviour(|key| {
            AppBehaviour {
                relay_client,
                dcutr: dcutr::Behaviour::new(key.public().to_peer_id()),
                identify: identify::Behaviour::new(identify::Config::new("/p2ptexter/1.0.0".into(), key.public())),
                request_response: request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new("/p2ptexter/msg/1.0.0"), request_response::ProtocolSupport::Full)],
                    request_response::Config::default()
                ),
                ping: ping::Behaviour::new(ping::Config::new().with_interval(std::time::Duration::from_secs(1))),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    let ed25519_pubkey_b64 = B64.encode(libp2p_keypair.public().try_into_ed25519().unwrap().to_bytes());

    let state = Arc::new(AppState {
        local_peer_id: local_peer_id.clone(),
        local_pubkey_b64: local_pubkey_b64.clone(),
        local_ed25519_pubkey_b64: ed25519_pubkey_b64.clone(),
        local_secret_bytes: secret_bytes,
        peer_keys: Mutex::new(HashMap::new()),
        peer_libp2p_ids: Mutex::new(HashMap::new()),
        active_peer_id: Mutex::new(None),
        nickname,
        emitter: Arc::new(TauriEmitter { handle: app_handle.clone() }),
    });

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

    // Dynamic Relay Identity
    let mut current_relay_peer_id: Option<PeerId> = None;
    let mut reservation_active = false;
    let mut listen_on_attempted = false; // track so we only call listen_on once per relay connection
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));

    println!("P2P: Starting loop with dynamic relay discovery");

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("P2P: listening on {}", address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    println!("P2P: connection established! peer: {}", peer_id);
                    if Some(peer_id) == current_relay_peer_id && !listen_on_attempted {
                        println!("P2P: MATCHED relay PeerId — registering relay reservation");
                        listen_on_attempted = true;
                        let remote = endpoint.get_remote_address().clone();
                        // Construct circuit address: /ip4/IP/tcp/4001/p2p/RELAY_ID/p2p-circuit
                        let relay_addr = remote.with(libp2p::multiaddr::Protocol::P2pCircuit);
                        println!("P2P: calling listen_on: {}", relay_addr);
                        if let Err(e) = swarm.listen_on(relay_addr) {
                            eprintln!("P2P: listen_on relay circuit FAILED: {:?}", e);
                            listen_on_attempted = false; // allow retry
                        }
                    } else if Some(peer_id) != current_relay_peer_id {
                        // This is a P2P peer connecting, exchange keys
                        let hello = Envelope::Hello {
                            from: state.local_peer_id.clone(),
                            pubkey: state.local_pubkey_b64.clone(),
                            nickname: state.nickname.lock().unwrap().clone(),
                            ed25519_pubkey: state.local_ed25519_pubkey_b64.clone(),
                        };
                        swarm.behaviour_mut().request_response.send_request(&peer_id, hello);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    println!("P2P: connection closed with {}: {:?}", peer_id, cause);
                    if Some(peer_id) == current_relay_peer_id {
                        println!("P2P: relay connection LOST — will reconnect");
                        current_relay_peer_id = None;
                        reservation_active = false;
                        listen_on_attempted = false;
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                    match event {
                        relay::client::Event::ReservationReqAccepted { .. } => {
                            println!("P2P: relay reservation ACCEPTED ✓");
                            reservation_active = true;
                            state.emitter.emit(P2PEvent::PortStatus { success: true, message: "bridged".into(), details: Some("ready for p2p".into()) });
                        }
                        relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                            println!("P2P: relay outbound circuit established via {}", relay_peer_id);
                        }
                        relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                            println!("P2P: relay inbound circuit from {}", src_peer_id);
                        }
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    println!("P2P: Identify received from {} — protocols: {:?}", peer_id, info.protocols.iter().map(|p| p.to_string()).collect::<Vec<_>>());
                    // Log if relay supports hop but don't retry listen_on — already done on ConnectionEstablished
                    if Some(peer_id) == current_relay_peer_id {
                        let supports_relay = info.protocols.iter().any(|p| p.to_string() == "/libp2p/circuit/relay/0.2.0/hop");
                        println!("P2P: relay HOP support = {}, reservation_active = {}", supports_relay, reservation_active);
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RequestResponse(request_response::Event::Message { peer, message, .. })) => {
                    if let request_response::Message::Request { request, channel, .. } = message {
                        process_envelope(peer, request, state.clone()).await;
                        let _ = swarm.behaviour_mut().request_response.send_response(channel, Envelope::Punch { from: local_peer_id.clone() });
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(dcutr::Event { remote_peer_id, result })) => {
                    if result.is_ok() {
                        println!("P2P: direct connection established to {}", remote_peer_id);
                    }
                }
                _ => {}
            },
            cmd = cmd_rx.recv() => if let Some(cmd) = cmd {
                match cmd {
                    OutboundCmd::SendMsg { to, content } => {
                        let pid_opt = state.peer_libp2p_ids.lock().unwrap().get(&to).cloned();
                        if let Some(pid) = pid_opt {
                            if let Some(env) = encrypt_message(&to, &content, state.clone()) {
                                swarm.behaviour_mut().request_response.send_request(&pid, env);
                            }
                        }
                    }
                    OutboundCmd::GenerateQr { validity_secs: _ } => {
                        let composite_id = format!("{}:{}", state.local_pubkey_b64, state.local_ed25519_pubkey_b64);
                        state.emitter.emit(P2PEvent::ListenAddress { content: composite_id });
                    }
                    OutboundCmd::ScanQr { token } => {
                        let parts: Vec<&str> = token.split(':').collect();
                        if parts.len() == 2 {
                            let x25519_pub = parts[0];
                            let ed25519_pub = parts[1];
                            if let Ok(key_bytes) = B64.decode(x25519_pub) {
                                if key_bytes.len() == 32 {
                                    let mut arr = [0u8; 32];
                                    arr.copy_from_slice(&key_bytes);
                                    let short_id = format!("peer_{}", &x25519_pub[..12]);
                                    state.peer_keys.lock().unwrap().insert(short_id.clone(), arr);
                                    
                                    if let Some(pid) = get_libp2p_peer_id(ed25519_pub) {
                                        state.peer_libp2p_ids.lock().unwrap().insert(short_id.clone(), pid);
                                        let cmd_tx_inner = state.emitter.handle.state::<P2PHandle>().sender.clone();
                                        let _ = cmd_tx_inner.send(OutboundCmd::DialPeer { peer_id: pid });
                                    }
                                    state.emitter.emit(P2PEvent::ScanResult { success: true, message: "scan ok".into(), target_peer_id: Some(short_id) });
                                }
                            }
                        }
                    }
                    OutboundCmd::SetActivePeer { peer_id } => {
                        *state.active_peer_id.lock().unwrap() = peer_id;
                    }
                    OutboundCmd::DialPeer { peer_id } => {
                        let ip = extract_ip(&bootstrap_url.lock().unwrap());
                        println!("P2P: dialing peer via relay (IP: {}) -> {}", ip, peer_id);
                        if let Some(rid) = current_relay_peer_id {
                            if let Ok(base_relay) = format!("/ip4/{}/tcp/4001/p2p/{}", ip, rid).parse::<Multiaddr>() {
                                let target_addr = base_relay.with(libp2p::multiaddr::Protocol::P2pCircuit).with(libp2p::multiaddr::Protocol::P2p(peer_id));
                                let _ = swarm.dial(target_addr);
                            }
                        } else {
                            eprintln!("P2P: CANNOT dial peer, relay ID unknown");
                        }
                    }
                    _ => {}
                }
            },
            _ = tick.tick() => {
                let burl = bootstrap_url.lock().unwrap().clone();
                let ip = extract_ip(&burl);
                
                let is_connected = if let Some(rid) = current_relay_peer_id {
                    swarm.connected_peers().any(|p| *p == rid)
                } else {
                    false
                };

                if !is_connected {
                    println!("P2P: relay NOT connected, fetching bootstrap info from {}/bootstrap/info", burl);
                    let client = reqwest::Client::new();
                    if let Ok(res) = client.post(format!("{}/bootstrap/info", burl)).send().await {
                        if let Ok(Some(info)) = res.json::<Option<BootstrapInfo>>().await {
                            println!("P2P: discovered bootstrap PeerId: {}", info.peer_id);
                            if let Ok(pid) = info.peer_id.parse::<PeerId>() {
                                if Some(pid) != current_relay_peer_id {
                                    println!("P2P: relay PeerId changed or newly discovered: {:?}", pid);
                                    current_relay_peer_id = Some(pid);
                                }
                            }
                        }
                    }
                }

                if let Some(rid) = current_relay_peer_id {
                    if !swarm.connected_peers().any(|p| *p == rid) {
                        println!("P2P: attempting relay connection to /ip4/{}/tcp/4001/p2p/{}", ip, rid);
                        if let Ok(addr) = format!("/ip4/{}/tcp/4001/p2p/{}", ip, rid).parse::<Multiaddr>() {
                            let _ = swarm.dial(addr);
                        }
                    } else {
                        // Already connected, maybe check reservation? Identify should handle it
                    }
                }
            }
        }
    }
}

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
    let files_to_delete = vec!["p2p_id_v3.txt", "p2p_secret_v3.bin", ".settings.dat"];
    for f_name in files_to_delete {
        let path = app_dir.join(f_name);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    std::process::exit(0);
}

#[tauri::command]
fn set_bootstrap_url(url: String, state: State<'_, P2PHandle>) {
    let mut burl = state.bootstrap_url.lock().unwrap();
    *burl = url;
}

#[tauri::command]
async fn set_active_peer(peer_id: Option<String>, state: State<'_, P2PHandle>) -> Result<(), String> {
    let _ = state.sender.send(OutboundCmd::SetActivePeer { peer_id });
    Ok(())
}

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
            let app_handle = app.handle().clone();
            let app_dir = app.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let key_path = app_dir.join("p2p_id_v3.txt");
            let secret_path = app_dir.join("p2p_secret_v3.bin");
            
            let _ = std::fs::create_dir_all(&app_dir);

            let mut secret_bytes = [0u8; 32];
            if secret_path.exists() {
                if let Ok(bytes) = std::fs::read(&secret_path) {
                    if bytes.len() == 32 {
                        secret_bytes.copy_from_slice(&bytes);
                    } else {
                        rand::thread_rng().fill_bytes(&mut secret_bytes);
                        let _ = std::fs::write(&secret_path, &secret_bytes);
                    }
                } else {
                    rand::thread_rng().fill_bytes(&mut secret_bytes);
                    let _ = std::fs::write(&secret_path, &secret_bytes);
                }
            } else {
                rand::thread_rng().fill_bytes(&mut secret_bytes);
                let _ = std::fs::write(&secret_path, &secret_bytes);
            }

            let static_secret = x25519_dalek::StaticSecret::from(secret_bytes);
            let local_pubkey_b64 = B64.encode(X25519PublicKey::from(&static_secret).as_bytes());
            let peer_id = format!("peer_{}", &local_pubkey_b64[..12]);
            
            let _ = std::fs::write(&key_path, &peer_id);

            app.manage(P2PHandle {
                sender: cmd_tx,
                local_peer_id: peer_id.clone(),
                local_pubkey_b64: local_pubkey_b64.clone(),
                peer_keys,
                nickname: nickname.clone(),
                bootstrap_url,
            });

            tauri::async_runtime::spawn(async move {
                let res = run_p2p(app_handle, cmd_rx, peer_id, local_pubkey_b64, secret_bytes, nickname, bootstrap_url_loop).await;
                if let Err(e) = res {
                    eprintln!("P2P: run_p2p failed: {}", e);
                }
            });
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
