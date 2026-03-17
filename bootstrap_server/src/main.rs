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

// server state holding ephemeral connection data
struct ServerState {
    peer_ips: Mutex<HashMap<String, String>>,
    friend_lists: Mutex<HashMap<String, HashSet<String>>>,
    offline_pings: Mutex<HashMap<String, HashSet<String>>>,
    secret_key: [u8; 32],
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
}

// encrypt payload for qr code
fn encrypt_token(key_bytes: &[u8; 32], payload: &str) -> String {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, payload.as_bytes()).unwrap();
    format!("{}.{}", B64.encode(nonce_bytes), B64.encode(ciphertext))
}

// decrypt qr payload
fn decrypt_token(key_bytes: &[u8; 32], token: &str) -> Option<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 2 {
        return None;
    }
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = B64.decode(parts[0]).ok()?;
    let ciphertext = B64.decode(parts[1]).ok()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
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
    println!("Registering peer {} with IP {}", payload.peer_id, ip);
    state.peer_ips.lock().unwrap().insert(payload.peer_id, ip);
    StatusCode::OK
}

// generate expiring encrypted qr token
async fn generate_qr(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<QrReq>,
) -> Json<QrRes> {
    let exp = now_secs() + payload.validity_secs;
    let raw_token = format!("{}:{}", payload.peer_id, exp);
    let encrypted_token = encrypt_token(&state.secret_key, &raw_token);
    Json(QrRes { encrypted_token })
}

// process scanned qr and link friends
async fn scan_qr(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<ScanReq>,
) -> (StatusCode, &'static str) {
    if let Some(decrypted) = decrypt_token(&state.secret_key, &payload.encrypted_token) {
        let parts: Vec<&str> = decrypted.split(':').collect();
        if parts.len() == 2 {
            let target_id = parts[0].to_string();
            let exp: u64 = parts[1].parse().unwrap_or(0);
            
            if now_secs() > exp {
                return (StatusCode::BAD_REQUEST, "qr code expired");
            }
            
            let mut friends = state.friend_lists.lock().unwrap();
            friends.entry(payload.scanner_peer_id.clone()).or_default().insert(target_id.clone());
            friends.entry(target_id).or_default().insert(payload.scanner_peer_id);
            
            return (StatusCode::OK, "friends linked successfully");
        }
    }
    (StatusCode::BAD_REQUEST, "invalid token")
}

// resolve friend ip
async fn get_ip(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<IpReq>,
) -> (StatusCode, Json<IpRes>) {
    let friends = state.friend_lists.lock().unwrap();
    if let Some(target_friends) = friends.get(&payload.target_peer_id) {
        if target_friends.contains(&payload.requester_peer_id) {
            let ips = state.peer_ips.lock().unwrap();
            let ip = ips.get(&payload.target_peer_id).cloned();
            return (StatusCode::OK, Json(IpRes { ip }));
        }
    }
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

// retrieve and clear pending pings for a peer
async fn check_pings(
    State(state): State<Arc<ServerState>>,
    Json(payload): Json<RegisterReq>,
) -> Json<StatusRes> {
    let mut pings = state.offline_pings.lock().unwrap();
    let unread = if let Some(pending) = pings.remove(&payload.peer_id) {
        pending.into_iter().collect()
    } else {
        vec![]
    };
    Json(StatusRes { unread_from: unread })
}

#[tokio::main]
async fn main() {
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
        secret_key,
    });

    let app = Router::new()
        .route("/register", post(register_ip))
        .route("/qr/generate", post(generate_qr))
        .route("/qr/scan", post(scan_qr))
        .route("/peer/ip", post(get_ip))
        .route("/peer/ping", post(ping_offline))
        .route("/peer/status", post(check_pings))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Bootstrap server running on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}
