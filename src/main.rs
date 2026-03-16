use futures::stream::StreamExt;
use libp2p::{
    gossipsub,
    identity, mdns,
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt};
use tokio::sync::mpsc;

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub sender: String,
    pub content: String,
}

pub enum P2PEvent {
    MessageReceived(Message),
    PeerDiscovered(String),
    PeerExpired(String),
    NewListenAddr(String),
}

pub struct P2PHandle {
    sender: mpsc::UnboundedSender<String>,
}

impl P2PHandle {
    pub fn send_message(&self, content: String) {
        let _ = self.sender.send(content);
    }
}

pub async fn run_p2p(event_tx: mpsc::UnboundedSender<P2PEvent>) -> Result<P2PHandle, Box<dyn Error>> {
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<String>();

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let peer_id_str = local_peer_id.to_string();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&message.data, &mut s);
                gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|msg| std::io::Error::new(std::io::Error::Other, msg))?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

            Ok(MyBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let topic = gossipsub::IdentTopic::new("chat");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(content) = msg_rx.recv() => {
                    let msg = Message {
                        sender: peer_id_str.clone(),
                        content,
                    };
                    let json = serde_json::to_string(&msg).expect("Failed to serialize");
                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), json.as_bytes()) {
                        eprintln!("Publish error: {:?}", e);
                    }
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let _ = event_tx.send(P2PEvent::NewListenAddr(address.to_string()));
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, _multiaddr) in list {
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            let _ = event_tx.send(P2PEvent::PeerDiscovered(peer_id.to_string()));
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            let _ = event_tx.send(P2PEvent::PeerExpired(peer_id.to_string()));
                        }
                    }
                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        message,
                        ..
                    })) => {
                        if let Ok(msg) = serde_json::from_slice::<Message>(&message.data) {
                            let _ = event_tx.send(P2PEvent::MessageReceived(msg));
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    Ok(P2PHandle { sender: msg_tx })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handle = run_p2p(event_tx).await?;

    println!("P2P Node started. Type messages and press Enter:");

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let line = line?.expect("stdin error");
                handle.send_message(line);
            }
            Some(event) = event_rx.recv() => match event {
                P2PEvent::MessageReceived(msg) => println!("\n[{}]: {}", msg.sender, msg.content),
                P2PEvent::PeerDiscovered(id) => println!("Discovered: {}", id),
                P2PEvent::PeerExpired(id) => println!("Expired: {}", id),
                P2PEvent::NewListenAddr(addr) => println!("Listening on: {}", addr),
            }
        }
    }
}

