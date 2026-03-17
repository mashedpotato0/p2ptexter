use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures::stream::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, identity, kad, multiaddr, noise, ping, relay,
    request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{Emitter, Manager, State};
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret};

// ── network behaviour ────────────────────────────────────────────────────────

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    direct_messaging: request_response::json::Behaviour<Envelope, Envelope>,
}

// ── wire envelope ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String },
    Ping { from: String },
    SyncVerify { from: String, last_ts: u64 },
    SyncRequest { from: String, since_ts: u64 },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
}

// ── tauri events emitted to the frontend ─────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "event_type")]
pub enum P2PEvent {
    PeerOnline { peer_id: String, nickname: String },
    PeerOffline { peer_id: String },
    MessageReceived { peer_id: String, content: String, nickname: String },
    PeerDiscovered { peer_id: String, nickname: String },
    PeerExpired { peer_id: String },
    ListenAddress { content: String },
    KeyExchanged { peer_id: String, nickname: String },
    SyncComplete { peer_id: String, count: usize },
}

// ── emitter trait for decoupling from tauri ──────────────────────────────────

#[async_trait::async_trait]
pub trait P2PEmitter: Send + Sync {
    async fn emit_event(&self, event: P2PEvent);
}

pub struct TauriEmitter {
    pub handle: tauri::AppHandle,
}

#[async_trait::async_trait]
impl P2PEmitter for TauriEmitter {
    async fn emit_event(&self, event: P2PEvent) {
        let _ = self.handle.emit("p2p-event", event);
    }
}

// ── queued offline message ───────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct QueuedMsg {
    content: String,
    nickname: String,
    ts: u64,
}

// ── shared state managed by tauri ────────────────────────────────────────────

pub struct P2PHandle {
    sender: mpsc::UnboundedSender<OutboundCmd>,
    pub local_peer_id: Arc<Mutex<String>>,
    pub local_pubkey_b64: String,
    pub peer_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    pub offline_queue: Arc<Mutex<HashMap<String, Vec<QueuedMsg>>>>,
    pub sent_history: Arc<Mutex<HashMap<String, Vec<QueuedMsg>>>>,
    pub nickname: Arc<Mutex<String>>,
}

pub enum OutboundCmd {
    SendMsg { to: String, content: String },
    BroadcastHello,
    DialPeer { peer_id: String },
    DialAddress { address: String },
    Ping,
    Bootstrap { address: String },
}

pub struct P2PHandleInner {
    pub sender: mpsc::UnboundedSender<OutboundCmd>,
    pub local_pubkey_b64: String,
    pub local_secret_bytes: [u8; 32],
    pub peer_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    pub offline_queue: Arc<Mutex<HashMap<String, Vec<QueuedMsg>>>>,
    pub sent_history: Arc<Mutex<HashMap<String, Vec<QueuedMsg>>>>,
    pub received_history: Arc<Mutex<HashMap<String, u64>>>,
    pub connected_peers: Arc<Mutex<std::collections::HashSet<PeerId>>>,
    pub nickname: Arc<Mutex<String>>,
}

// ── encryption helpers ───────────────────────────────────────────────────────

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

// ── envelope handling ────────────────────────────────────────────────────────

async fn handle_envelope(
    env: Envelope,
    emitter: &Arc<dyn P2PEmitter>,
    handle_state: &Arc<P2PHandleInner>,
    local_peer_id_str: &str,
    _sender: &PeerId,
) {
    match env {
        Envelope::Hello { from, pubkey, nickname } => {
            if from != local_peer_id_str {
                if let Ok(pk_bytes) = B64.decode(pubkey) {
                    if pk_bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&pk_bytes);
                        let static_secret = x25519_dalek::StaticSecret::from(handle_state.local_secret_bytes);
                        let shared = static_secret.diffie_hellman(&X25519PublicKey::from(arr));
                        let derived = derive_key(&shared);
                        handle_state.peer_keys.lock().unwrap().insert(from.clone(), derived);
                        emitter.emit_event(P2PEvent::KeyExchanged { peer_id: from.clone(), nickname: nickname.clone() }).await;
                        
                        // flush queued offline messages
                        if let Some(queued) = handle_state.offline_queue.lock().unwrap().remove(&from) {
                            for qmsg in queued {
                                let _ = handle_state.sender.send(OutboundCmd::SendMsg { to: from.clone(), content: qmsg.content });
                            }
                        }
                    }
                }
            }
        }
        Envelope::Ping { from } => {
            if handle_state.peer_keys.lock().unwrap().contains_key(&from) {
                let last_ts = handle_state.sent_history.lock().unwrap().get(&from).and_then(|h| h.last()).map(|m| m.ts).unwrap_or(0);
                let _reply = Envelope::SyncVerify { from: local_peer_id_str.to_string(), last_ts };
            }
        }
        Envelope::SyncVerify { from, last_ts } => {
            emitter.emit_event(P2PEvent::PeerOnline { peer_id: from.clone(), nickname: "".into() }).await;
            let my_last_received = *handle_state.received_history.lock().unwrap().get(&from).unwrap_or(&0);
            if last_ts > my_last_received {
                let _req = Envelope::SyncRequest { from: local_peer_id_str.to_string(), since_ts: my_last_received };
            }
        }
        Envelope::SyncRequest { .. } => {
        }
        Envelope::Msg { from, to, nonce, ciphertext, nickname, ts } => {
            if to == local_peer_id_str {
                let key_found = handle_state.peer_keys.lock().unwrap().get(&from).copied();
                if let Some(key_bytes) = key_found {
                    if let Some(plaintext) = decrypt(&key_bytes, &nonce, &ciphertext) {
                        {
                            let mut received = handle_state.received_history.lock().unwrap();
                            let cur = received.entry(from.clone()).or_insert(0);
                            if ts > *cur { *cur = ts; }
                        }
                        emitter.emit_event(P2PEvent::MessageReceived { peer_id: from, content: plaintext, nickname }).await;
                    }
                }
            }
        }
    }
}

// ── main p2p event loop ──────────────────────────────────────────────────────

pub async fn run_p2p(
    emitter: Arc<dyn P2PEmitter>,
    mut cmd_rx: mpsc::UnboundedReceiver<OutboundCmd>,
    local_key: identity::Keypair,
    handle_state: Arc<P2PHandleInner>,
) -> Result<(), Box<dyn Error>> {
    let local_peer_id = PeerId::from(local_key.public());
    let peer_id_str = local_peer_id.to_string();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub::ConfigBuilder::default()
                    .validation_mode(gossipsub::ValidationMode::Strict)
                    .build().unwrap(),
            )?;
            Ok(MyBehaviour {
                gossipsub,
                identify: identify::Behaviour::new(identify::Config::new("/p2ptexter/v2".into(), key.public())),
                relay_client,
                dcutr: dcutr::Behaviour::new(local_peer_id),
                autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                ping: ping::Behaviour::new(ping::Config::default()),
                kademlia: kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id)),
                direct_messaging: request_response::json::Behaviour::new(
                    [(
                        libp2p::StreamProtocol::new("/p2ptexter/direct/1.0.0"),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default(),
                ),
            })
        })?
        .build();

    let topic = gossipsub::IdentTopic::new("p2ptexter-v2");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    
    swarm.behaviour_mut().kademlia.set_mode(Some(kad::Mode::Server));

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let cmd_tx = handle_state.sender.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let _ = cmd_tx.send(OutboundCmd::Ping);
        }
    });

    loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    OutboundCmd::BroadcastHello => {
                        let env = Envelope::Hello { from: peer_id_str.clone(), pubkey: handle_state.local_pubkey_b64.clone(), nickname: handle_state.nickname.lock().unwrap().clone() };
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&env)?);
                    }
                    OutboundCmd::DialPeer { peer_id } => {
                        if let Ok(p) = PeerId::from_str(&peer_id) {
                            let _ = swarm.dial(p);
                            swarm.behaviour_mut().kademlia.get_closest_peers(p);
                        }
                    }
                    OutboundCmd::DialAddress { address } => {
                        if let Ok(addr) = address.parse::<Multiaddr>() {
                            let _ = swarm.dial(addr);
                        }
                    }
                    OutboundCmd::Ping => {
                        let env = Envelope::Ping { from: peer_id_str.clone() };
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&env)?);
                    }
                    OutboundCmd::Bootstrap { address } => {
                        if let Ok(addr) = address.parse::<Multiaddr>() {
                            if let Some(peer_id) = addr.iter().find_map(|p| match p {
                                multiaddr::Protocol::P2p(id) => Some(id),
                                _ => None,
                            }) {
                                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                let _ = swarm.behaviour_mut().kademlia.bootstrap();
                            }
                        }
                    }
                    OutboundCmd::SendMsg { to, content } => {
                        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                        let nickname = handle_state.nickname.lock().unwrap().clone();
                        let qmsg = QueuedMsg { content: content.clone(), nickname: nickname.clone(), ts };
                        
                        let pair = {
                            let keys = handle_state.peer_keys.lock().unwrap();
                            keys.get(&to).copied().map(|k| (k, PeerId::from_str(&to).ok()))
                        };

                        if let Some((key_bytes, Some(peer_id))) = pair {
                            let (nonce, ciphertext) = encrypt(&key_bytes, &content);
                            let env = Envelope::Msg { from: peer_id_str.clone(), to: to.clone(), nonce, ciphertext, nickname, ts };
                            swarm.behaviour_mut().direct_messaging.send_request(&peer_id, env);
                            handle_state.sent_history.lock().unwrap().entry(to).or_default().push(qmsg);
                        } else {
                            handle_state.offline_queue.lock().unwrap().entry(to.clone()).or_default().push(qmsg);
                            if let Ok(peer_id) = PeerId::from_str(&to) {
                                let _ = swarm.dial(peer_id); // note: this uses routing since no address provided
                                swarm.behaviour_mut().kademlia.get_closest_peers(peer_id);
                            }
                        }
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        emitter.emit_event(P2PEvent::ListenAddress { content: address.to_string() }).await;
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        handle_state.connected_peers.lock().unwrap().insert(peer_id);
                        let hello = Envelope::Hello { from: peer_id_str.clone(), pubkey: handle_state.local_pubkey_b64.clone(), nickname: handle_state.nickname.lock().unwrap().clone() };
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&hello)?);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        handle_state.connected_peers.lock().unwrap().remove(&peer_id);
                        emitter.emit_event(P2PEvent::PeerOffline { peer_id: peer_id.to_string() }).await;
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        for addr in info.listen_addrs { 
                            let _ = swarm.dial(addr.clone().with(multiaddr::Protocol::P2p(peer_id))); 
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                        match result {
                            kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                                for peer in ok.peers {
                                    emitter.emit_event(P2PEvent::PeerDiscovered { peer_id: peer.peer_id.to_string(), nickname: "".into() }).await;
                                }
                            }
                            kad::QueryResult::Bootstrap(Ok(ok)) => {
                                println!("bootstrap successful: {:?}", ok.peer);
                            }
                            kad::QueryResult::Bootstrap(Err(e)) => {
                                println!("bootstrap failed: {:?}", e);
                            }
                            _ => {}
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::DirectMessaging(request_response::Event::Message { peer, message, .. })) => {
                        if let request_response::Message::Request { request, .. } = message {
                            handle_envelope(request, &emitter, &handle_state, &peer_id_str, &peer).await;
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        if let Ok(env) = serde_json::from_slice::<Envelope>(&message.data) {
                            handle_envelope(env, &emitter, &handle_state, &peer_id_str, &message.source.unwrap_or(PeerId::random())).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// ── tauri commands ────────────────────────────────────────────────────────────

#[tauri::command]
fn get_my_peer_id(state: State<'_, P2PHandle>) -> String {
    state.local_peer_id.lock().unwrap().clone()
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
    let mut nick = state.nickname.lock().unwrap();
    *nick = name;
    let _ = state.sender.send(OutboundCmd::BroadcastHello);
}

#[tauri::command]
fn bootstrap(address: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::Bootstrap { address });
}

#[tauri::command]
fn dial_peer(peer_id: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::DialPeer { peer_id });
}

#[tauri::command]
fn dial_address(address: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(OutboundCmd::DialAddress { address });
}

#[tauri::command]
async fn reset_identity(app: tauri::AppHandle) -> Result<(), String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let key_path = app_dir.join("p2p_identity.key");
    if key_path.exists() {
        std::fs::remove_file(key_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── app entrypoint ────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<OutboundCmd>();
    
    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    
    let static_secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let local_pubkey_b64 = B64.encode(X25519PublicKey::from(&static_secret).as_bytes());

    let peer_keys = Arc::new(Mutex::new(HashMap::new()));
    let offline_queue = Arc::new(Mutex::new(HashMap::new()));
    let sent_history = Arc::new(Mutex::new(HashMap::new()));
    let received_history = Arc::new(Mutex::new(HashMap::new()));
    let connected_peers = Arc::new(Mutex::new(std::collections::HashSet::new()));
    let nickname = Arc::new(Mutex::new(String::new()));
    let local_peer_id = Arc::new(Mutex::new(String::new()));

    tauri::Builder::default()
        .manage(P2PHandle {
            sender: cmd_tx.clone(),
            local_peer_id: Arc::clone(&local_peer_id),
            local_pubkey_b64: local_pubkey_b64.clone(),
            peer_keys: Arc::clone(&peer_keys),
            offline_queue: Arc::clone(&offline_queue),
            sent_history: Arc::clone(&sent_history),
            nickname: Arc::clone(&nickname),
        })
        .plugin(tauri_plugin_log::Builder::default().build())
        .plugin(tauri_plugin_store::Builder::default().build())
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let app_dir = app.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            let key_path = app_dir.join("p2p_identity.key");
            
            let local_key = if key_path.exists() {
                let bytes = std::fs::read(&key_path).expect("failed to read key");
                identity::Keypair::from_protobuf_encoding(&bytes).expect("invalid key")
            } else {
                let key = identity::Keypair::generate_ed25519();
                let bytes = key.to_protobuf_encoding().expect("failed to encode key");
                std::fs::create_dir_all(&app_dir).ok();
                std::fs::write(&key_path, bytes).expect("failed to save key");
                key
            };

            let peer_id_str = PeerId::from(local_key.public()).to_string();
            *local_peer_id.lock().unwrap() = peer_id_str;

            let handle_p2p = Arc::new(P2PHandleInner {
                sender: cmd_tx,
                local_pubkey_b64,
                local_secret_bytes: secret_bytes,
                peer_keys,
                offline_queue,
                sent_history,
                received_history,
                connected_peers,
                nickname,
            });

            let emitter = Arc::new(TauriEmitter { handle: app_handle });
            tauri::async_runtime::spawn(async move {
                let _ = run_p2p(emitter, cmd_rx, local_key, handle_p2p).await;
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            send_p2p_message,
            get_my_peer_id,
            get_nickname,
            set_nickname,
            dial_peer,
            dial_address,
            reset_identity,
            bootstrap,
        ])
        .run(tauri::generate_context!())
        .expect("error running app");
}
