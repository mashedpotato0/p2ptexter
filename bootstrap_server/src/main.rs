use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use axum::{
    extract::State,
    http::StatusCode,
    routing::post,
    Json, Router,
};
// server state holding ephemeral connection data
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use libp2p::{
    core::upgrade,
    identify, kad, noise, relay, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol,
};
use futures::StreamExt;

// server state holding ephemeral connection data
struct ServerState {
    peer_ips: Mutex<HashMap<String, String>>,
    friend_lists: Mutex<HashMap<String, HashSet<String>>>,
    offline_pings: Mutex<HashMap<String, HashSet<String>>>,
    punch_requests: Mutex<HashMap<String, HashSet<String>>>,
    secret_key: [u8; 32],
    libp2p_info: Mutex<Option<(String, String)>>, // (PeerId, Multiaddr)
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    relay: relay::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
}

#[derive(Deserialize)]
struct RegisterReq {
    peer_id: String,
}

#[derive(Deserialize)]
struct QrReq {
    peer_id: String,
    validity_secs: u64,
}

#[derive(Serialize)]
struct QrRes {
    encrypted_token: String,
}

#[derive(Serialize)]
struct ScanRes {
    success: bool,
    message: String,
    target_peer_id: Option<String>,
}

#[derive(Deserialize)]
struct ScanReq {
    scanner_peer_id: String,
    encrypted_token: String,
}

#[derive(Deserialize)]
struct IpReq {
    requester_peer_id: String,
    target_peer_id: String,
}

#[derive(Serialize)]
struct IpRes {
    ip: Option<String>,
}

#[derive(Deserialize)]
struct PingReq {
    sender_peer_id: String,
    target_peer_id: String,
}

#[derive(Serialize)]
struct StatusRes {
    unread_from: Vec<String>,
    punch_from: Vec<String>,
}

// encrypt payload for qr code// simplify: no encryption for now as requested
fn encrypt_token(_key: &[u8; 32], payload: &str) -> String {
    B64.encode(payload)
}

fn decrypt_token(_key: &[u8; 32], token: &str) -> Option<String> {
    let decoded = B64.decode(token).ok()?;
    String::from_utf8(decoded).ok()
}

// get current timestamp
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// register peer ip
async fn register_ip(
    State(state): State<Arc<ServerState>>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterReq>,
) -> StatusCode {
    let ip = addr.ip().to_string();
    println!("DEBUG: Registering peer {} with IP {}", payload.peer_id, ip);
    state.peer_ips.lock().unwrap().insert(payload.peer_id, ip);
    StatusCode::OK
}

// generate expiring qr token (plain base64 for now)
async fn generate_qr(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<QrReq>,
) -> Json<QrRes> {
    let exp = now_secs() + payload.validity_secs;
    let raw_token = format!("{}:{}", payload.peer_id, exp);
    println!("DEBUG: Generating QR token for composite ID: {} (exp: {})", payload.peer_id, exp);
    let encrypted_token = encrypt_token(&state.secret_key, &raw_token);
    Json(QrRes { encrypted_token })
}

// process scanned qr and link friends
async fn scan_qr(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<ScanReq>,
) -> (StatusCode, Json<ScanRes>) {
    println!("DEBUG: Scan attempt by {} with token {}", payload.scanner_peer_id, payload.encrypted_token);
    if let Some(decrypted) = decrypt_token(&state.secret_key, &payload.encrypted_token) {
        println!("DEBUG: Decrypted internal token: {}", decrypted);
        let mut parts: Vec<&str> = decrypted.split(':').collect();
        if parts.len() >= 2 {
            let exp_str = parts.pop().unwrap_or("0");
            let target_id = parts.join(":");
            let exp: u64 = exp_str.parse().unwrap_or(0);
            
            if now_secs() > exp {
                println!("DEBUG: TOKEN EXPIRED for {}. Current: {}, Exp: {}", target_id, now_secs(), exp);
                return (StatusCode::BAD_REQUEST, Json(ScanRes {
                    success: false,
                    message: "qr code expired".into(),
                    target_peer_id: None,
                }));
            }
            
            let target_short_id = if target_id.contains(':') {
                let parts: Vec<&str> = target_id.split(':').collect();
                format!("peer_{}", &parts[0].get(..12).unwrap_or(parts[0]))
            } else {
                target_id.clone()
            };

            println!("DEBUG: LINKING FRIENDS: {} <-> {} (raw: {})", payload.scanner_peer_id, target_short_id, target_id);
            let mut friends = state.friend_lists.lock().unwrap();
            friends.entry(payload.scanner_peer_id.clone()).or_default().insert(target_short_id.clone());
            friends.entry(target_short_id).or_default().insert(payload.scanner_peer_id);
            
            return (StatusCode::OK, Json(ScanRes {
                success: true,
                message: "friends linked successfully".into(),
                target_peer_id: Some(target_id),
            }));
        }
    }
    println!("DEBUG: FAILED scan from {}: Invalid or corrupt token", payload.scanner_peer_id);
    (StatusCode::BAD_REQUEST, Json(ScanRes {
        success: false,
        message: "invalid token".into(),
        target_peer_id: None,
    }))
}

// resolve friend ip
async fn get_ip(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<IpReq>,
) -> (StatusCode, Json<IpRes>) {
    println!("DEBUG: IP lookup request from {} for {}", payload.requester_peer_id, payload.target_peer_id);
    let friends = state.friend_lists.lock().unwrap();
    if let Some(target_friends) = friends.get(&payload.target_peer_id) {
        if target_friends.contains(&payload.requester_peer_id) {
            let ips = state.peer_ips.lock().unwrap();
            let ip = ips.get(&payload.target_peer_id).cloned();
            println!("DEBUG: IP found for {}: {:?}", payload.target_peer_id, ip);
            return (StatusCode::OK, Json(IpRes { ip }));
        }
    }
    println!("DEBUG: IP lookup DENIED (not friends) for {} seeing {}", payload.requester_peer_id, payload.target_peer_id);
    (StatusCode::FORBIDDEN, Json(IpRes { ip: None }))
}

// record offline notification ping
async fn ping_offline(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<PingReq>,
) -> StatusCode {
    let mut pings = state.offline_pings.lock().unwrap();
    pings.entry(payload.target_peer_id).or_default().insert(payload.sender_peer_id);
    StatusCode::OK
}

// record a punch request (matchmaking for UDP)
async fn request_punch(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<PingReq>, // Reuse PingReq (sender->target)
) -> StatusCode {
    let mut punches = state.punch_requests.lock().unwrap();
    punches.entry(payload.target_peer_id).or_default().insert(payload.sender_peer_id);
    StatusCode::OK
}

// check status for pending notifications
async fn check_status(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<RegisterReq>,
) -> Json<StatusRes> {
    let mut pings = state.offline_pings.lock().unwrap();
    let mut punches = state.punch_requests.lock().unwrap();
    let unread = pings.remove(&payload.peer_id).map(|s| s.into_iter().collect()).unwrap_or_default();
    let punch_reqs = punches.remove(&payload.peer_id).map(|s| s.into_iter().collect()).unwrap_or_default();
    Json(StatusRes { unread_from: unread, punch_from: punch_reqs })
}

#[derive(Serialize)]
struct BootstrapInfo {
    peer_id: String,
    multiaddr: String,
}

async fn get_bootstrap_info(
    State(state): State<Arc<ServerState>>,
) -> Json<Option<BootstrapInfo>> {
    let info = state.libp2p_info.lock().unwrap();
    Json(info.as_ref().map(|(id, addr)| BootstrapInfo { 
        peer_id: id.clone(), 
        multiaddr: addr.clone() 
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_path = std::path::Path::new("secret.key");
    let mut secret_key = [0u8; 32];
    
    if key_path.exists() {
        if let Ok(bytes) = std::fs::read(key_path) {
            if bytes.len() == 32 {
                secret_key.copy_from_slice(&bytes);
                println!("Loaded existing secret key from secret.key");
            }
        }
    } else {
        rand::thread_rng().fill_bytes(&mut secret_key);
        let _ = std::fs::write(key_path, &secret_key);
        println!("Generated and saved new secret key to secret.key");
    }

    let state = Arc::new(ServerState {
        peer_ips: Mutex::new(HashMap::new()),
        friend_lists: Mutex::new(HashMap::new()),
        offline_pings: Mutex::new(HashMap::new()),
        punch_requests: Mutex::new(HashMap::new()),
        secret_key,
        libp2p_info: Mutex::new(None),
    });

    // --- libp2p Setup ---
    let libp2p_keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = libp2p_keypair.public().to_peer_id();
    println!("Bootstrap: libp2p PeerId: {}", local_peer_id);

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            let mut kad_cfg = kad::Config::default();
            kad_cfg.set_protocol_names(vec![StreamProtocol::new("/p2ptexter/kad/1.0.0")]);
            let store = kad::store::MemoryStore::new(key.public().to_peer_id());
            
            MyBehaviour {
                relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
                kad: kad::Behaviour::with_config(key.public().to_peer_id(), store, kad_cfg),
                identify: identify::Behaviour::new(identify::Config::new("/p2ptexter/1.0.0".into(), key.public())),
            }
        })?
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/4001/quic-v1".parse()?)?;

    let state_p2p = state.clone();
    tokio::spawn(async move {
        loop {
            match swarm.next().await {
                Some(SwarmEvent::NewListenAddr { address, .. }) => {
                    if address.to_string().contains("127.0.0.1") || address.to_string().contains("::1") { continue; }
                    println!("Bootstrap: libp2p listening on {}", address);
                    let mut info = state_p2p.libp2p_info.lock().unwrap();
                    if info.is_none() {
                        *info = Some((local_peer_id.to_string(), address.to_string()));
                    }
                }
                Some(SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }))) => {
                    println!("Bootstrap: Identified peer {} with addrs {:?}", peer_id, info.listen_addrs);
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                }
                Some(SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. }))) => {
                    println!("Bootstrap: Kademlia routing updated for {}", peer);
                }
                _ => {}
            }
        }
    });

    let app = Router::new()
        .route("/register", post(register_ip))
        .route("/qr/generate", post(generate_qr))
        .route("/qr/scan", post(scan_qr))
        .route("/peer/ip", post(get_ip))
        .route("/peer/ping", post(ping_offline))
        .route("/peer/punch", post(request_punch))
        .route("/peer/status", post(check_status))
        .route("/bootstrap/info", post(get_bootstrap_info))
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Bootstrap: HTTP Signaling listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    
    Ok(())
}
