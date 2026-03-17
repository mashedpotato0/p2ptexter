use app_lib::*;
use clap::Parser;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use tokio::sync::mpsc;
use std::time::Duration;
use libp2p::PeerId;
use base64::Engine;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = 0)]
    port: u16,

    #[arg(short, long, default_value = "Peer")]
    nick: String,

    #[arg(short, long)]
    dial: Option<String>,
}

struct ConsoleEmitter;

#[async_trait::async_trait]
impl P2PEmitter for ConsoleEmitter {
    async fn emit_event(&self, event: P2PEvent) {
        match event {
            P2PEvent::MessageReceived { peer_id: _, content, nickname } => {
                println!("\n[MSG] {}: {}", nickname.get(0..5).unwrap_or(&nickname), content);
                print!("> ");
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
            P2PEvent::PeerOnline { peer_id, .. } => {
                println!("\n[INFO] Peer {} is online", peer_id);
                print!("> ");
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
            P2PEvent::ListenAddress { content } => {
                println!("[INFO] Listening on: {}", content);
            }
            e => println!("\n[EVENT] {:?}", e),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<OutboundCmd>();
    
    // session keys (ephemeral for CLI test)
    let secret_bytes = [0u8; 32]; // static for testing consistency
    let static_secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let local_pubkey = x25519_dalek::PublicKey::from(&static_secret);
    let local_pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(local_pubkey.as_bytes());

    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public()).to_string();
    println!("[INFO] My Peer ID: {}", local_peer_id);

    let handle_p2p = Arc::new(P2PHandleInner {
        sender: cmd_tx.clone(),
        local_pubkey_b64: local_pubkey_b64.clone(),
        local_secret_bytes: secret_bytes,
        peer_keys: Arc::new(Mutex::new(HashMap::new())),
        offline_queue: Arc::new(Mutex::new(HashMap::new())),
        sent_history: Arc::new(Mutex::new(HashMap::new())),
        received_history: Arc::new(Mutex::new(HashMap::new())),
        connected_peers: Arc::new(Mutex::new(std::collections::HashSet::new())),
        nickname: Arc::new(Mutex::new(args.nick.clone())),
    });

    let emitter = Arc::new(ConsoleEmitter);
    
    let p2p_handle_state = handle_p2p.clone();
    tokio::spawn(async move {
        if let Err(e) = run_p2p(emitter, cmd_rx, local_key, p2p_handle_state).await {
            eprintln!("[ERROR] P2P loop died: {:?}", e);
        }
    });

    // small delay to let listen happen
    tokio::time::sleep(Duration::from_millis(500)).await;

    if let Some(addr) = args.dial {
        println!("[INFO] Dialing {}...", addr);
        let _ = cmd_tx.send(OutboundCmd::DialAddress { address: addr });
    }

    println!("\nCommands: /msg <peer_id> <text>, /exit");
    
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();

    print!("> ");
    use std::io::Write;
    std::io::stdout().flush().ok();

    while let Ok(Some(line)) = stdin.next_line().await {
        let line = line.trim();
        if line.is_empty() { continue; }
        
        if line == "/exit" { break; }
        
        if line.starts_with("/msg ") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() == 3 {
                let to = parts[1].to_string();
                let content = parts[2].to_string();
                let _ = cmd_tx.send(OutboundCmd::SendMsg { to, content });
            } else {
                println!("[ERR] Use /msg <peer_id> <text>");
            }
        } else {
            println!("[ERR] Unknown command. Use /msg or /exit");
        }
        print!("> ");
        std::io::stdout().flush().ok();
    }

    Ok(())
}
