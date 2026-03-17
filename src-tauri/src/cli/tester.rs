use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures::stream::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, identity, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
// use std::time::Duration;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as X25519PublicKey, SharedSecret};
use clap::Parser;

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    autonat: autonat::Behaviour,
    ping: ping::Behaviour,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "msg_type")]
enum Envelope {
    Hello { from: String, pubkey: String, nickname: String },
    Ping { from: String },
    SyncVerify { from: String, last_ts: u64 },
    SyncRequest { from: String, since_ts: u64 },
    Msg { from: String, to: String, nonce: String, ciphertext: String, nickname: String, ts: u64 },
}

#[derive(Clone, Serialize, Deserialize)]
struct QueuedMsg {
    content: String,
    nickname: String,
    ts: u64,
}

struct P2PState {
    _local_pubkey_b64: String,
    _local_secret_bytes: [u8; 32],
    peer_keys: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    _nickname: Arc<Mutex<String>>,
    _sent_history: Arc<Mutex<HashMap<String, Vec<QueuedMsg>>>>,
    _received_history: Arc<Mutex<HashMap<String, u64>>>,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "Peer")]
    nick: String,
    #[arg(short, long)]
    dial: Option<String>,
}

fn derive_key(shared: &SharedSecret) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.finalize().into()
}

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let peer_id_str = local_peer_id.to_string();
    println!("[INFO] My Peer ID: {}", peer_id_str);

    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let static_secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let local_pubkey = X25519PublicKey::from(&static_secret);
    let local_pubkey_b64 = B64.encode(local_pubkey.as_bytes());

    let state = Arc::new(P2PState {
        _local_pubkey_b64: local_pubkey_b64.clone(),
        _local_secret_bytes: secret_bytes,
        peer_keys: Arc::new(Mutex::new(HashMap::new())),
        _nickname: Arc::new(Mutex::new(args.nick.clone())),
        _sent_history: Arc::new(Mutex::new(HashMap::new())),
        _received_history: Arc::new(Mutex::new(HashMap::new())),
    });

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_quic()
        .with_relay_client(noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key, relay_client| {
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub::ConfigBuilder::default().build().unwrap(),
            )?;
            Ok(MyBehaviour {
                gossipsub,
                identify: identify::Behaviour::new(identify::Config::new("/p2ptexter/v2".into(), key.public())),
                relay_client,
                dcutr: dcutr::Behaviour::new(local_peer_id),
                autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                ping: ping::Behaviour::new(ping::Config::default()),
            })
        })?
        .build();

    let topic = gossipsub::IdentTopic::new("p2ptexter-v2");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    if let Some(addr) = args.dial {
        println!("[INFO] Dialing {}...", addr);
        swarm.dial(addr.parse::<Multiaddr>()?)?;
    }

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<String>();
    let cmd_tx_clone = cmd_tx.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = stdin.next_line().await {
            let _ = cmd_tx_clone.send(line);
        }
    });

    println!("Commands: /msg <peer_id> <text>, /exit");

    loop {
        tokio::select! {
            Some(line) = cmd_rx.recv() => {
                if line == "/exit" { break; }
                if line == "/hello" {
                    let env = Envelope::Hello {
                        from: peer_id_str.clone(),
                        pubkey: local_pubkey_b64.clone(),
                        nickname: args.nick.clone(),
                    };
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&env)?);
                    println!("[SENT] Hello (broadcast)");
                }
                if line.starts_with("/msg ") {
                    let parts: Vec<&str> = line.splitn(3, ' ').collect();
                    if parts.len() == 3 {
                        let to = parts[1].to_string();
                        let content = parts[2].to_string();
                        let keys = state.peer_keys.lock().unwrap();
                        if let Some(key) = keys.get(&to) {
                            let (nonce, ciphertext) = encrypt(key, &content);
                            let env = Envelope::Msg {
                                from: peer_id_str.clone(), to: to.clone(), nonce, ciphertext,
                                nickname: args.nick.clone(),
                                ts: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
                            };
                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&env)?);
                            println!("[SENT] to {}", to);
                        } else {
                            println!("[ERR] No key for {}. Must wait for Hello.", to);
                        }
                    }
                }
            }
            event = swarm.select_next_some() => {
                println!("[DEBUG] SwarmEvent: {:?}", event);
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => println!("[INFO] Listening on {}", address),
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        println!("[INFO] Connected to {}", peer_id);
                        // broadcast hello on connection
                        let hello = Envelope::Hello {
                            from: peer_id_str.clone(),
                            pubkey: local_pubkey_b64.clone(),
                            nickname: args.nick.clone(),
                        };
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&hello).unwrap());
                        println!("[DEBUG] Broadcasted Hello to mesh");
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        println!("[DEBUG] Gossipsub msg from {:?}", message.source);
                        if let Ok(env) = serde_json::from_slice::<Envelope>(&message.data) {
                            println!("[DEBUG] Envelope: {:?}", env);
                            match env {
                                Envelope::Hello { from, pubkey, nickname } => {
                                    if from != peer_id_str {
                                        println!("[INFO] Hello from {} ({})", nickname, from);
                                        if let Ok(pk_bytes) = B64.decode(pubkey) {
                                            if pk_bytes.len() == 32 {
                                                let mut arr = [0u8; 32];
                                                arr.copy_from_slice(&pk_bytes);
                                                let their_pk = X25519PublicKey::from(arr);
                                                let shared = static_secret.diffie_hellman(&their_pk);
                                                let derived = derive_key(&shared);
                                                state.peer_keys.lock().unwrap().insert(from.clone(), derived);
                                                println!("[DEBUG] Derived shared secret for {}", from);
                                            }
                                        }
                                        // reply with our hello
                                        let reply = Envelope::Hello {
                                            from: peer_id_str.clone(),
                                            pubkey: local_pubkey_b64.clone(),
                                            nickname: args.nick.clone(),
                                        };
                                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), serde_json::to_string(&reply)?);
                                    }
                                }
                                Envelope::Msg { from, to, nonce, ciphertext, nickname, .. } => {
                                    if to == peer_id_str {
                                        let keys = state.peer_keys.lock().unwrap();
                                        if let Some(key) = keys.get(&from) {
                                            if let Some(p) = decrypt(key, &nonce, &ciphertext) {
                                                println!("\n[MSG] {}: {}", nickname, p);
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
