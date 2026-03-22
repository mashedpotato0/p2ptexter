use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures::StreamExt;
use libp2p::{
    core::upgrade, dcutr, identify, noise, ping, relay, 
    request_response::{self, OutboundRequestId}, 
    tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::fs;
use tauri::{Emitter, Manager, State};
use tokio::sync::mpsc;
use x25519_dalek::PublicKey as X25519PublicKey;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String, ed25519_pubkey: String },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
    Punch { from: String },
    NicknameUpdate { from: String, nickname: String },
    Heartbeat { from: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "event_type")]
pub enum P2PEvent {
    PeerOnline { peer_id: String, nickname: String },
    PeerOffline { peer_id: String },
    PeerDiscovered { peer_id: String, nickname: String },
    PeerExpired { peer_id: String },
    MessageReceived { peer_id: String, content: String, nickname: String },
    SyncComplete { peer_id: String, count: usize },
    ListenAddress { content: String },
    KeyExchanged { peer_id: String, nickname: String },
    ScanResult { success: bool, message: String, target_peer_id: Option<String> },
    PortStatus { success: bool, message: String, details: Option<String> },
    BootstrapStatus { status: String },
    DeliveryStatus { peer_id: String, timestamp: u64, success: bool, message: String },
}

#[derive(Deserialize, Debug, Clone)]
struct BootstrapInfo {
    peer_id: String,
    #[serde(rename = "multiaddr")]
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
    SilentSync,
}

#[derive(Serialize, Deserialize, Clone)]
struct PersistedPeers {
    keys: HashMap<String, String>,
    libp2p_ids: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct QueuedMessage {
    target_peer_id: String, // short ID
    envelope: Envelope,
    timestamp: u64,
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
    pending_outbound: Mutex<HashMap<OutboundRequestId, QueuedMessage>>,
    offline_queue: Mutex<Vec<QueuedMessage>>,
    mailbox_path: std::path::PathBuf,
    peers_path: std::path::PathBuf,
    last_seen: Mutex<HashMap<String, u64>>,
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

fn save_queue(queue: &[QueuedMessage], path: &std::path::Path) {
    if let Ok(json) = serde_json::to_string(queue) {
        let _ = fs::write(path, json);
    }
}

fn load_queue(path: &std::path::Path) -> Vec<QueuedMessage> {
    if let Ok(data) = fs::read_to_string(path) {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        Vec::new()
    }
}

fn save_peers(state: &Arc<AppState>) {
    let keys_map = state.peer_keys.lock().unwrap();
    let pids_map = state.peer_libp2p_ids.lock().unwrap();
    
    let mut keys = HashMap::new();
    for (sid, key) in keys_map.iter() {
        keys.insert(sid.clone(), B64.encode(key));
    }
    
    let mut libp2p_ids = HashMap::new();
    for (sid, pid) in pids_map.iter() {
        libp2p_ids.insert(sid.clone(), pid.to_base58());
    }
    
    let persisted = PersistedPeers { keys, libp2p_ids };
    if let Ok(json) = serde_json::to_string(&persisted) {
        let _ = fs::write(&state.peers_path, json);
    }
}

fn load_peers(path: &std::path::Path) -> PersistedPeers {
    if let Ok(data) = fs::read_to_string(path) {
        serde_json::from_str::<PersistedPeers>(&data).unwrap_or(PersistedPeers {
            keys: HashMap::new(),
            libp2p_ids: HashMap::new(),
        })
    } else {
        PersistedPeers {
            keys: HashMap::new(),
            libp2p_ids: HashMap::new(),
        }
    }
}

fn sync_offline_messages(peer_id: &PeerId, swarm: &mut libp2p::Swarm<AppBehaviour>, state: Arc<AppState>) {
    // Find if we have a short ID for this libp2p peer_id
    let short_id_opt = {
        let pids = state.peer_libp2p_ids.lock().unwrap();
        pids.iter().find(|(_, &v)| v == *peer_id).map(|(k, _)| k.clone())
    };

    if let Some(short_id) = short_id_opt {
        let mut q = state.offline_queue.lock().unwrap();
        let mut to_send = Vec::new();
        let mut remaining = Vec::new();

        for msg in q.drain(..) {
            if msg.target_peer_id == short_id {
                to_send.push(msg);
            } else {
                remaining.push(msg);
            }
        }
        *q = remaining;
        save_queue(&q, &state.mailbox_path);

        for msg in to_send {
            println!("P2P: re-sending queued message to {}", msg.target_peer_id);
            let req_id = swarm.behaviour_mut().request_response.send_request(peer_id, msg.envelope.clone());
            state.pending_outbound.lock().unwrap().insert(req_id, msg);
        }
    }
}

async fn process_envelope(peer: PeerId, env: Envelope, state: Arc<AppState>) -> Option<PeerId> {
    // Update last_seen for any incoming envelope with a 'from' field
    let sender_id = match &env {
        Envelope::Hello { from, .. } => Some(from.clone()),
        Envelope::Msg { from, .. } => Some(from.clone()),
        Envelope::Punch { from } => Some(from.clone()),
        Envelope::NicknameUpdate { from, .. } => Some(from.clone()),
        Envelope::Heartbeat { from } => Some(from.clone()),
    };
    
    if let Some(sid) = sender_id {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        state.last_seen.lock().unwrap().insert(sid, ts);
    }

    match env {
        Envelope::Hello { from, pubkey, nickname, .. } => {
            println!("P2P: received hello from {}", nickname);
            if let Ok(key_bytes) = B64.decode(&pubkey) {
                if key_bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&key_bytes);
                    state.peer_keys.lock().unwrap().insert(from.clone(), arr.clone());
                    state.peer_libp2p_ids.lock().unwrap().insert(from.clone(), peer);
                    save_peers(&state); // Persist immediately on new hello
                    state.emitter.emit(P2PEvent::KeyExchanged { peer_id: from.clone(), nickname: nickname.clone() });
                    state.emitter.emit(P2PEvent::PeerOnline { peer_id: from, nickname });
                    return Some(peer);
                }
            }
        }
        Envelope::NicknameUpdate { from, nickname } => {
            println!("P2P: received nickname update from {}: {}", from, nickname);
            state.emitter.emit(P2PEvent::PeerOnline { peer_id: from, nickname });
            return Some(peer);
        }
        Envelope::Msg { from, to: _, nonce, ciphertext, nickname, ts: _ } => {
            println!("P2P: received encrypted msg from {}", nickname);
            
            let mut decrypted_content = ciphertext.clone();
            
            let keys = state.peer_keys.lock().unwrap();
            if let Some(target_pubkey) = keys.get(&from) {
                let pubkey = X25519PublicKey::from(*target_pubkey);
                let secret = x25519_dalek::StaticSecret::from(state.local_secret_bytes);
                let shared = secret.diffie_hellman(&pubkey);
                
                let key = Key::<Aes256Gcm>::from_slice(shared.as_bytes());
                let cipher = Aes256Gcm::new(key);
                
                if let Ok(nonce_bytes) = B64.decode(&nonce) {
                    if let Ok(cipher_bytes) = B64.decode(&ciphertext) {
                        if let Ok(plaintext) = cipher.decrypt(Nonce::from_slice(&nonce_bytes), cipher_bytes.as_ref()) {
                            if let Ok(content) = String::from_utf8(plaintext) {
                                decrypted_content = content;
                            }
                        }
                    }
                }
            }

            state.emitter.emit(P2PEvent::MessageReceived { 
                peer_id: from.clone(), 
                content: decrypted_content,
                nickname: nickname.clone() 
            });
            return Some(peer);
        }
        Envelope::Punch { from } => {
            println!("P2P: received punch (ack) from {}", from);
            return Some(peer);
        }
        Envelope::Heartbeat { from: _ } => {
            // Updated last_seen above, nothing else to do
            return Some(peer);
        }
    }
    None
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

    let mailbox_path = app_handle.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let _ = fs::create_dir_all(&mailbox_path);
    let mailbox_path_file = mailbox_path.join("mailbox.json");
    let peers_path_file = mailbox_path.join("peers.json");
    let initial_queue = load_queue(&mailbox_path_file);
    let initial_peers = load_peers(&peers_path_file);

    // Inflate maps from persisted peers
    let mut peer_keys = HashMap::new();
    for (sid, b64_key) in initial_peers.keys {
        if let Ok(key_bytes) = B64.decode(b64_key) {
            if key_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                peer_keys.insert(sid, arr);
            }
        }
    }
    
    let mut peer_libp2p_ids = HashMap::new();
    for (sid, b58_pid) in initial_peers.libp2p_ids {
        if let Ok(pid) = b58_pid.parse::<PeerId>() {
            peer_libp2p_ids.insert(sid, pid);
        }
    }

    let state = Arc::new(AppState {
        local_peer_id: local_peer_id.clone(),
        local_pubkey_b64: local_pubkey_b64.clone(),
        local_ed25519_pubkey_b64: ed25519_pubkey_b64.clone(),
        local_secret_bytes: secret_bytes,
        peer_keys: Mutex::new(peer_keys),
        peer_libp2p_ids: Mutex::new(peer_libp2p_ids),
        active_peer_id: Mutex::new(None),
        nickname,
        emitter: Arc::new(TauriEmitter { handle: app_handle.clone() }),
        pending_outbound: Mutex::new(HashMap::new()),
        offline_queue: Mutex::new(initial_queue),
        mailbox_path: mailbox_path_file,
        peers_path: peers_path_file,
        last_seen: Mutex::new(HashMap::new()),
    });

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

    // Dynamic Relay Identity
    let mut current_relay_peer_id: Option<PeerId> = None;
    let mut reservation_active = false;
    let mut listen_on_attempted = false; // track so we only call listen_on once per relay connection
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut expiry_tick = tokio::time::interval(std::time::Duration::from_secs(10));

    println!("P2P: Starting loop with dynamic relay discovery and heartbeats");

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("P2P: listening on {}", address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    println!("P2P: connection established! peer: {}", peer_id);
                    sync_offline_messages(&peer_id, &mut swarm, state.clone());
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
                        state.emitter.emit(P2PEvent::PortStatus { success: false, message: "Relay Lost".into(), details: Some("Connection to bootstrap server closed.".into()) });
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    if let Some(pid) = peer_id {
                        if Some(pid) == current_relay_peer_id {
                            println!("P2P: relay OUTGOING connection error: {:?}", error);
                            listen_on_attempted = false; // allow retry
                            reservation_active = false;
                        }
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(event)) => {
                    match event {
                        relay::client::Event::ReservationReqAccepted { .. } => {
                            println!("P2P: relay reservation ACCEPTED ✓");
                            reservation_active = true;
                            state.emitter.emit(P2PEvent::PortStatus { success: true, message: "bridged".into(), details: Some("ready for p2p".into()) });
                            
                            // PROACTIVE: Try to sync all known peers now that we have a relay
                            let sender = state.emitter.handle.state::<P2PHandle>().sender.clone();
                            let _ = sender.send(OutboundCmd::SilentSync);
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
                    match message {
                        request_response::Message::Request { request, channel, .. } => {
                            if let Some(sync_peer) = process_envelope(peer, request, state.clone()).await {
                                sync_offline_messages(&sync_peer, &mut swarm, state.clone());
                            }
                            let _ = swarm.behaviour_mut().request_response.send_response(channel, Envelope::Punch { from: local_peer_id.clone() });
                        }
                        request_response::Message::Response { request_id, .. } => {
                            if let Some(qm) = state.pending_outbound.lock().unwrap().remove(&request_id) {
                                println!("P2P: message delivered to {}", qm.target_peer_id);
                                state.emitter.emit(P2PEvent::DeliveryStatus { 
                                    peer_id: qm.target_peer_id, 
                                    timestamp: qm.timestamp, 
                                    success: true, 
                                    message: "delivered".into() 
                                });
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(AppBehaviourEvent::RequestResponse(request_response::Event::OutboundFailure { request_id, error, .. })) => {
                    if let Some(qm) = state.pending_outbound.lock().unwrap().remove(&request_id) {
                        println!("P2P: delivery FAILED to {}: {:?}. Queuing...", qm.target_peer_id, error);
                        let mut q = state.offline_queue.lock().unwrap();
                        q.push(qm.clone());
                        save_queue(&q, &state.mailbox_path);
                        state.emitter.emit(P2PEvent::DeliveryStatus { 
                            peer_id: qm.target_peer_id, 
                            timestamp: qm.timestamp, 
                            success: false, 
                            message: format!("queued (retry: {:?})", error) 
                        });
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
                                let req_id = swarm.behaviour_mut().request_response.send_request(&pid, env.clone());
                                let qm = QueuedMessage {
                                    target_peer_id: to.clone(),
                                    envelope: env,
                                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                };
                                state.pending_outbound.lock().unwrap().insert(req_id, qm);
                            }
                        } else {
                            // Peer offline/unknown — add to queue immediately
                            if let Some(env) = encrypt_message(&to, &content, state.clone()) {
                                println!("P2P: peer {} unknown, queuing message", to);
                                let qm = QueuedMessage {
                                    target_peer_id: to.clone(),
                                    envelope: env,
                                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                                };
                                let mut q = state.offline_queue.lock().unwrap();
                                q.push(qm);
                                save_queue(&q, &state.mailbox_path);
                                state.emitter.emit(P2PEvent::DeliveryStatus { 
                                    peer_id: to, 
                                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), 
                                    success: false, 
                                    message: "queued (offline)".into() 
                                });
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
                                        save_peers(&state); // Persist immediately
                                        let cmd_tx_inner = state.emitter.handle.state::<P2PHandle>().sender.clone();
                                        let _ = cmd_tx_inner.send(OutboundCmd::DialPeer { peer_id: pid });
                                    }
                                    state.emitter.emit(P2PEvent::ScanResult { success: true, message: "scan ok".into(), target_peer_id: Some(short_id) });
                                }
                            }
                        }
                    }
                    OutboundCmd::SetActivePeer { peer_id } => {
                        let mut active = state.active_peer_id.lock().unwrap();
                        *active = peer_id;
                    }
                    OutboundCmd::SilentSync => {
                        let pids = state.peer_libp2p_ids.lock().unwrap().clone();
                        for (sid, pid) in pids {
                            // If we have any offline messages for this peer, dial them to trigger sync
                            println!("P2P: proactive silent sync dial to {}", sid);
                            let _ = swarm.dial(pid);
                            // Also send a Hello if we are already connected to trigger sync from their side
                            let hello = Envelope::Hello {
                                from: state.local_peer_id.clone(),
                                pubkey: state.local_pubkey_b64.clone(),
                                nickname: state.nickname.lock().unwrap().clone(),
                                ed25519_pubkey: state.local_ed25519_pubkey_b64.clone(),
                            };
                            swarm.behaviour_mut().request_response.send_request(&pid, hello);
                        }
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
                    OutboundCmd::SetNickname { name } => {
                        println!("P2P: Setting local nickname to: {}", name);
                        *state.nickname.lock().unwrap() = name.clone();
                        
                        // Broadcast update to all connected peers (not the relay)
                        let update = Envelope::NicknameUpdate { 
                            from: local_peer_id.clone(), 
                            nickname: name 
                        };
                        let peers: Vec<_> = swarm.connected_peers().cloned().collect();
                        for peer in peers {
                            if Some(peer) != current_relay_peer_id {
                                println!("P2P: broadcasting nickname update to {}", peer);
                                swarm.behaviour_mut().request_response.send_request(&peer, update.clone());
                            }
                        }
                    }
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
                    state.emitter.emit(P2PEvent::PortStatus { 
                        success: false, 
                        message: "Searching...".into(), 
                        details: Some(format!("Connecting to bootstrap info at {}...", burl)) 
                    });
                    println!("P2P: relay NOT connected, fetching bootstrap info from {}/bootstrap/info", burl);
                    let client = reqwest::Client::new();
                    let url = format!("{}/bootstrap/info", burl);
                    match client.post(&url).send().await {
                        Ok(res) => {
                            let status = res.status();
                            let text = res.text().await.unwrap_or_default();
                            println!("P2P: discovery response from {}: status={}, body={}", url, status, text);
                            
                            if status.is_success() {
                                if let Ok(info) = serde_json::from_str::<Option<BootstrapInfo>>(&text) {
                                    if let Some(info) = info {
                                        println!("P2P: discovered bootstrap PeerId: {}", info.peer_id);
                                        if let Ok(pid) = info.peer_id.parse::<PeerId>() {
                                            if Some(pid) != current_relay_peer_id {
                                                println!("P2P: relay PeerId changed or newly discovered: {:?}", pid);
                                                current_relay_peer_id = Some(pid);
                                            }
                                        }
                                    } else {
                                        println!("P2P: relay info returned 'null' (None)");
                                        state.emitter.emit(P2PEvent::PortStatus { 
                                            success: false, 
                                            message: "Relay Refused".into(), 
                                            details: Some("Server is running but has not established its P2P identity yet.".into()) 
                                        });
                                    }
                                } else {
                                    println!("P2P: FAILED to parse bootstrap info JSON: {}", text);
                                    state.emitter.emit(P2PEvent::PortStatus { 
                                        success: false, 
                                        message: "Relay Error".into(), 
                                        details: Some(format!("Invalid response format from relay: {}", text)) 
                                    });
                                }
                            } else {
                                println!("P2P: discovery HTTP error: {}", status);
                                state.emitter.emit(P2PEvent::PortStatus { 
                                    success: false, 
                                    message: format!("Relay HTTP {}", status).into(), 
                                    details: Some(format!("The server at {} returned an error.", burl)) 
                                });
                            }
                        }
                        Err(e) => {
                            println!("P2P: FAILED to reach bootstrap info at {}: {:?}", url, e);
                            let err_msg = if e.is_timeout() { "Relay Timeout" } else { "Relay Offline" };
                            state.emitter.emit(P2PEvent::PortStatus { 
                                success: false, 
                                message: err_msg.into(), 
                                details: Some(format!("{}. Check URL: {}", e, burl)) 
                            });
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
            },
            _ = heartbeat_tick.tick() => {
                let pids = state.peer_libp2p_ids.lock().unwrap().clone();
                for (_, pid) in pids {
                    let hb = Envelope::Heartbeat { from: state.local_peer_id.clone() };
                    swarm.behaviour_mut().request_response.send_request(&pid, hb);
                }
            },
            _ = expiry_tick.tick() => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let mut last_seen = state.last_seen.lock().unwrap();
                let mut to_offline = Vec::new();
                
                for (sid, ts) in last_seen.iter() {
                    if now - ts > 60 {
                        to_offline.push(sid.clone());
                    }
                }
                
                for sid in to_offline {
                    println!("P2P: peer {} timed out (60s inactivity)", sid);
                    last_seen.remove(&sid);
                    state.emitter.emit(P2PEvent::PeerOffline { peer_id: sid });
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
fn sync_all_peers(state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::SilentSync);
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
            sync_all_peers,
        ])
        .run(tauri::generate_context!())
        .expect("error running app");
}
