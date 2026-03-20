use libp2p::{
    identify, noise, relay, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use std::error::Error;
use futures::StreamExt;

#[derive(NetworkBehaviour)]
struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut secret_bytes: [u8; 32] = [
        142, 45, 12, 98, 233, 11, 4, 203, 77, 65, 122, 199, 10, 56, 88, 201, 34, 111, 67, 89, 21,
        102, 23, 155, 90, 78, 110, 222, 44, 33, 19, 7,
    ];
    let local_key = libp2p::identity::Keypair::ed25519_from_bytes(&mut secret_bytes).unwrap();
    let local_peer_id = local_key.public().to_peer_id();
    println!("=== P2P RELAY SERVER ===");
    println!("Relay PeerId: {}", local_peer_id);
    println!("Compile with: cargo build --release --bin relay");
    println!("Run with: cargo run --release --bin relay");

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            RelayBehaviour {
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
                    },
                ),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/p2ptexter/relay/1.0.0".into(),
                    key.public().clone(),
                )),
            }
        })?
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;

    println!("Relay server started locally and bound to port 4001.");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on: {}", address);
            }
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => {
                println!("Relay Event: {:?}", event);
            }
            _ => {}
        }
    }
}
