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
    identify, kad, noise, ping, relay, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent}, StreamProtocol,
};
use futures::StreamExt;

// Server state holding peer IPs, friend relationships, and ephemeral connection info.
struct ServerState {
    peer_ips: Mutex<HashMap<String, String>>,
    friend_lists: Mutex<HashMap<String, HashSet<String>>>,
    offline_pings: Mutex<HashMap<String, HashSet<String>>>,
    punch_requests: Mutex<HashMap<String, HashSet<String>>>,
    secret_key: [u8; 32],
    libp2p_info: Mutex<Option<(String, String)>>, // (PeerId, Multiaddr) for bootstrap discovery
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    relay: relay::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
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

// Generate an expiring token for QR codes. Simple Base64 for now as requested.
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
    println!("Server: Registering peer {} with IP {}", payload.peer_id, ip);
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
    println!("Server: Generating QR token for composite ID: {} (exp: {})", payload.peer_id, exp);
    let encrypted_token = encrypt_token(&state.secret_key, &raw_token);
    Json(QrRes { encrypted_token })
}

// process scanned qr and link friends
async fn scan_qr(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<ScanReq>,
) -> (StatusCode, Json<ScanRes>) {
    println!("Server: Scan attempt by {} with token {}", payload.scanner_peer_id, payload.encrypted_token);
    if let Some(decrypted) = decrypt_token(&state.secret_key, &payload.encrypted_token) {
        println!("Server: Decrypted internal token: {}", decrypted);
        let mut parts: Vec<&str> = decrypted.split(':').collect();
        if parts.len() >= 2 {
            let exp_str = parts.pop().unwrap_or("0");
            let target_id = parts.join(":");
            let exp: u64 = exp_str.parse().unwrap_or(0);
            
            if now_secs() > exp {
                println!("Server: Token expired for {}. Current: {}, Exp: {}", target_id, now_secs(), exp);
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

            println!("Server: Linking friends: {} <-> {} (raw: {})", payload.scanner_peer_id, target_short_id, target_id);
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
    println!("Server: Failed scan from {}: Invalid or corrupt token", payload.scanner_peer_id);
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
    println!("Server: IP lookup request from {} for {}", payload.requester_peer_id, payload.target_peer_id);
    let friends = state.friend_lists.lock().unwrap();
    if let Some(target_friends) = friends.get(&payload.target_peer_id) {
        if target_friends.contains(&payload.requester_peer_id) {
            let ips = state.peer_ips.lock().unwrap();
            let ip = ips.get(&payload.target_peer_id).cloned();
            println!("Server: IP found for {}: {:?}", payload.target_peer_id, ip);
            return (StatusCode::OK, Json(IpRes { ip }));
        }
    }
    println!("Server: IP lookup denied (not friends) for {} seeing {}", payload.requester_peer_id, payload.target_peer_id);
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
    let id_path = std::path::Path::new("p2p_identity.key");
    let local_keypair = if id_path.exists() {
        let bytes = std::fs::read(id_path)?;
        libp2p::identity::Keypair::from_protobuf_encoding(&bytes)?
    } else {
        // Fallback to legacy hardcoded key if no saved identity exists
        let mut secret_bytes: [u8; 32] = [
            142, 45, 12, 98, 233, 11, 4, 203, 77, 65, 122, 199, 10, 56, 88, 201, 34, 111, 67, 89, 21,
            102, 23, 155, 90, 78, 110, 222, 44, 33, 19, 7,
        ];
        let id = libp2p::identity::Keypair::ed25519_from_bytes(&mut secret_bytes).unwrap();
        let _ = std::fs::write(id_path, id.to_protobuf_encoding().unwrap_or_default());
        id
    };
    let local_peer_id = local_keypair.public().to_peer_id();
    println!("=== P2P CONSOLIDATED SERVER ===");
    println!("Bootstrap/Relay PeerId: {}", local_peer_id);

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_keypair)
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
                relay: relay::Behaviour::new(
                    key.public().to_peer_id(), 
                    relay::Config {
                        max_reservations: 1024,
                        max_reservations_per_peer: 8,
                        reservation_duration: std::time::Duration::from_secs(60 * 60),
                        reservation_rate_limiters: vec![],
                        circuit_src_rate_limiters: vec![],
                        max_circuits: 1024,
                        max_circuits_per_peer: 16,
                        max_circuit_duration: std::time::Duration::from_secs(60 * 2), // 2 mins covers hole punching setup flawlessly
                        max_circuit_bytes: 4 * 1024 * 1024,
                    }
                ),
                kad: kad::Behaviour::with_config(key.public().to_peer_id(), store, kad_cfg),
                identify: identify::Behaviour::new(identify::Config::new("/p2ptexter/1.0.0".into(), key.public())),
                ping: ping::Behaviour::new(ping::Config::new().with_interval(std::time::Duration::from_secs(1))),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/4001/quic-v1".parse()?)?;

    let state_p2p = state.clone();
    tokio::spawn(async move {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if address.to_string().contains("127.0.0.1") || address.to_string().contains("::1") { continue; }
                    println!("Bootstrap: libp2p listening on {}", address);
                    swarm.add_external_address(address.clone());
                    let mut info = state_p2p.libp2p_info.lock().unwrap();
                    if info.is_none() {
                        *info = Some((local_peer_id.to_string(), address.to_string()));
                    }
                }
                SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                    println!("Bootstrap: Incoming connection FROM {} (via {})", send_back_addr, local_addr);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    println!("Bootstrap: Outgoing connection error with {:?}: {:?}", peer_id, error);
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    println!("Bootstrap: Connection established WITH {} ({:?})", peer_id, endpoint);
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    println!("Bootstrap: Connection closed WITH {}: {:?}", peer_id, cause);
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Relay(event)) => {
                    match event {
                        relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                            println!("Bootstrap: Relay RESERVATION ACCEPTED from {}", src_peer_id);
                        }
                        relay::Event::ReservationReqDenied { src_peer_id, .. } => {
                            println!("Bootstrap: Relay RESERVATION DENIED from {}", src_peer_id);
                        }
                        _ => println!("Bootstrap: Relay Event: {:?}", event),
                    }
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                    if peer_id == local_peer_id {
                        println!("Bootstrap: Ignoring identify from SELF ({})", peer_id);
                    } else {
                        println!("Bootstrap: Identified peer {} with addrs {:?}", peer_id, info.listen_addrs);
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                        }
                    }
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Kad(kad::Event::RoutingUpdated { peer, .. })) => {
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
