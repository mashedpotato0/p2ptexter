use futures::stream::StreamExt;
use libp2p::{
    gossipsub, identity, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use tauri::{Emitter, State};
use tokio::sync::mpsc;

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Message {
    pub peer_id: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "event_type")]
pub enum P2PEvent {
    MessageReceived { peer_id: String, content: String },
    PeerDiscovered { peer_id: String },
    PeerExpired { peer_id: String },
    ListenAddress { content: String },
}

pub struct P2PHandle {
    sender: mpsc::UnboundedSender<String>,
    local_peer_id: String,
}

pub async fn run_p2p(
    app_handle: tauri::AppHandle,
    mut msg_rx: mpsc::UnboundedReceiver<String>,
    local_key: identity::Keypair,
) -> Result<(), Box<dyn Error>> {
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
                .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

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

    loop {
        tokio::select! {
            Some(content) = msg_rx.recv() => {
                let msg = Message {
                    peer_id: peer_id_str.clone(),
                    content,
                };
                let json = serde_json::to_string(&msg).expect("Failed to serialize");
                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), json.as_bytes()) {
                    let _ = app_handle.emit("p2p-event", P2PEvent::ListenAddress { content: format!("Publish error: {:?}", e) });
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let _ = app_handle.emit("p2p-event", P2PEvent::ListenAddress { content: address.to_string() });
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        let _ = app_handle.emit("p2p-event", P2PEvent::PeerDiscovered { peer_id: peer_id.to_string() });
                    }
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        let _ = app_handle.emit("p2p-event", P2PEvent::PeerExpired { peer_id: peer_id.to_string() });
                    }
                }
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    message,
                    ..
                })) => {
                    if let Ok(msg) = serde_json::from_slice::<Message>(&message.data) {
                        let _ = app_handle.emit("p2p-event", P2PEvent::MessageReceived { 
                            peer_id: msg.peer_id, 
                            content: msg.content 
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

#[tauri::command]
fn get_my_peer_id(state: State<'_, P2PHandle>) -> String {
    state.local_peer_id.clone()
}

#[tauri::command]
fn send_p2p_message(content: String, state: State<'_, P2PHandle>) {
    let _ = state.sender.send(content);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public()).to_string();

    tauri::Builder::default()
        .manage(P2PHandle { 
            sender: msg_tx,
            local_peer_id: local_peer_id.clone(),
        })
        .plugin(tauri_plugin_log::Builder::default().build())
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = run_p2p(handle, msg_rx, local_key).await {
                    eprintln!("P2P run error: {:?}", e);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![send_p2p_message, get_my_peer_id])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

