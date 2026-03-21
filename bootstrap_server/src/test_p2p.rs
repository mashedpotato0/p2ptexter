//! test_p2p — Integration test for relay-mediated P2P messaging.
//!
//! Tests two libp2p nodes communicating through the bootstrap/relay server:
//!   1. Alice connects to the relay and gets a reservation
//!   2. Bob dials Alice through the relay circuit
//!   3. Bob sends a test message; Alice receives and responds
//!   4. The test passes when bob receives the response

use futures::StreamExt;
use libp2p::{
    core::upgrade, identify, noise, ping, relay, request_response, tcp, yamux,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Transport,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestMsg {
    text: String,
}

#[derive(NetworkBehaviour)]
struct PeerBehaviour {
    relay_client: relay::client::Behaviour,
    identify: identify::Behaviour,
    rr: request_response::cbor::Behaviour<TestMsg, TestMsg>,
    ping: ping::Behaviour,
}

async fn build_peer(label: &str) -> (libp2p::swarm::Swarm<PeerBehaviour>, PeerId) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    println!("[{}] PeerId = {}", label, peer_id);

    let (relay_transport, relay_client) = relay::client::new(peer_id);

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
        .unwrap()
        .with_other_transport(|key| {
            relay_transport
                .upgrade(upgrade::Version::V1)
                .authenticate(noise::Config::new(key).unwrap())
                .multiplex(yamux::Config::default())
        })
        .unwrap()
        .with_behaviour(|key| PeerBehaviour {
            relay_client,
            identify: identify::Behaviour::new(
                identify::Config::new("/p2ptexter/1.0.0".into(), key.public()),
            ),
            rr: request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::new("/p2ptexter/msg/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ),
            ping: ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(2))),
        })
        .expect("PeerBehaviour build failed")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    (swarm, peer_id)
}

fn check(label: &str, ok: bool, desc: &str) {
    if ok {
        println!("  \x1b[32m✓ PASS\x1b[0m [{}] {}", label, desc);
    } else {
        eprintln!("  \x1b[31m✗ FAIL\x1b[0m [{}] {}", label, desc);
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let server_url = args
        .windows(2)
        .find(|w| w[0] == "--url")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());

    println!("=== P2P Relay Messaging Integration Test ===");
    println!("Bootstrap server: {}", server_url);

    // ── 1. Fetch relay identity from bootstrap server ─────────────────────────
    let http = reqwest::Client::new();
    let relay_info: serde_json::Value = http
        .post(format!("{}/bootstrap/info", server_url))
        .send()
        .await
        .expect("Cannot reach bootstrap server — is it running?")
        .json()
        .await
        .expect("Bad JSON from /bootstrap/info");

    let relay_peer_id: PeerId = relay_info["peer_id"]
        .as_str()
        .expect("missing peer_id")
        .parse()
        .expect("invalid PeerId");
    let relay_multiaddr: Multiaddr = relay_info["multiaddr"]
        .as_str()
        .expect("missing multiaddr")
        .parse()
        .expect("invalid Multiaddr");
    // full: /ip4/.../tcp/4001/p2p/<relay-id>
    let relay_full_addr = relay_multiaddr
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(relay_peer_id));

    println!("[test] Relay addr: {}", relay_full_addr);

    // ── 2. Build Alice and Bob ────────────────────────────────────────────────
    let (mut alice, alice_id) = build_peer("alice").await;
    let (mut bob, _bob_id) = build_peer("bob").await;

    alice.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();
    bob.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap()).unwrap();

    // ── 3. Alice connects to relay and gets a reservation ─────────────────────
    println!("[alice] Dialing relay...");
    alice.dial(relay_full_addr.clone()).expect("alice dial failed");

    let alice_reserved = timeout(Duration::from_secs(30), async {
        loop {
            let ev = alice.select_next_some().await;
            match ev {
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                    if peer_id == relay_peer_id =>
                {
                    let circuit = endpoint
                        .get_remote_address()
                        .clone()
                        .with(libp2p::multiaddr::Protocol::P2pCircuit);
                    println!("[alice] Connected to relay, listen_on: {}", circuit);
                    alice.listen_on(circuit).expect("alice: listen_on relay error");
                }
                SwarmEvent::Behaviour(PeerBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { .. },
                )) => {
                    println!("[alice] GOT ReservationReqAccepted!");
                    return true;
                }
                SwarmEvent::NewListenAddr { address, .. }
                    if address.to_string().contains("p2p-circuit") =>
                {
                    println!("[alice] Listening via relay: {}", address);
                }
                other => {
                    println!("[alice swarm event] {:?}", other);
                }
            }
        }
    })
    .await;

    check(
        "alice",
        alice_reserved.unwrap_or(false),
        "Relay reservation accepted",
    );

    // ── 4. Bob connects to relay, then dials Alice via relay circuit ───────────
    // We launch into the concurrent loop so Alice is continuously polled
    // while Bob connects to the relay and dials Alice. If Alice isn't polled,
    // her idle connection to the relay will drop.
    println!("[bob] Dialing relay...");
    bob.dial(relay_full_addr.clone()).expect("bob dial relay failed");

    // ── 5. Message exchange ───────────────────────────────────────────────────
    const TEST_MSG: &str = "relay-test-payload-42";
    let mut alice_received = false;
    let mut bob_got_pong = false;
    let mut sent = false;
    let mut bob_send_delay: Option<Box<dyn std::future::Future<Output = ()> + Unpin + Send>> = None;

    let msg_result = timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                ev = alice.select_next_some() => {
                    match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            println!("[alice] Incoming connection from {}", peer_id);
                        }
                        SwarmEvent::Behaviour(PeerBehaviourEvent::Rr(
                            request_response::Event::Message { peer, message, .. }
                        )) => {
                            if let request_response::Message::Request { request, channel, .. } = message {
                                println!("[alice] Received: {:?} from {}", request.text, peer);
                                alice_received = request.text == TEST_MSG;
                                let _ = alice.behaviour_mut().rr
                                    .send_response(channel, TestMsg { text: "pong".into() });
                            }
                        }
                        other => {
                            if let SwarmEvent::Behaviour(ev) = &other {
                                println!("[alice swarm event] {:?}", ev);
                            }
                        }
                    }
                }
                ev = bob.select_next_some() => {
                    match ev {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay_peer_id => {
                            println!("[bob] Connected to relay! Now dialing Alice...");
                            let alice_via_relay = relay_full_addr
                                .clone()
                                .with(libp2p::multiaddr::Protocol::P2pCircuit)
                                .with(libp2p::multiaddr::Protocol::P2p(alice_id));
                            println!("[bob] Dialing alice via relay: {}", alice_via_relay);
                            bob.dial(alice_via_relay).expect("bob: dial alice via relay failed");
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == alice_id => {
                            println!("[bob] Connected to alice via relay!");
                            if !sent {
                                sent = true;
                                bob_send_delay = Some(Box::new(Box::pin(tokio::time::sleep(Duration::from_millis(100)))));
                            }
                        }
                        SwarmEvent::Behaviour(PeerBehaviourEvent::Rr(
                            request_response::Event::Message { message, .. }
                        )) => {
                            if let request_response::Message::Response { response, .. } = message {
                                println!("[bob] Got response: {:?}", response.text);
                                bob_got_pong = response.text == "pong";
                            }
                        }
                        SwarmEvent::Behaviour(PeerBehaviourEvent::RelayClient(
                            relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. }
                        )) => {
                            println!("[bob] Outbound relay circuit via {}", relay_peer_id);
                        }
                        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                            println!("[bob swarm event] ConnectionClosed with {}: {:?}", peer_id, cause);
                        }
                        other => {
                            if let SwarmEvent::Behaviour(ev) = &other {
                                println!("[bob swarm event] {:?}", ev);
                            }
                        }
                    }
                }
                _ = async {
                    if let Some(delay) = bob_send_delay.as_mut() {
                        delay.await;
                    } else {
                        futures::future::pending::<()>().await;
                    }
                }, if bob_send_delay.is_some() => {
                    bob_send_delay = None;
                    bob.behaviour_mut().rr.send_request(
                        &alice_id, TestMsg { text: TEST_MSG.into() }
                    );
                    println!("[bob] Sent: {:?}", TEST_MSG);
                }
            }
            if alice_received && bob_got_pong {
                return true;
            }
        }
    }).await;

    println!();
    println!("════════════════════════════════════════════════");
    let passed = msg_result.unwrap_or(false);
    check("alice", alice_received, "Received relayed message from bob");
    check("bob", bob_got_pong, "Got pong response through relay");
    if passed {
        println!("  \x1b[32m✓ RELAY MESSAGING TEST PASSED\x1b[0m");
        println!("    Full round-trip: bob → relay → alice → relay → bob");
    } else {
        eprintln!("  \x1b[31m✗ RELAY MESSAGING TEST FAILED (timeout)\x1b[0m");
    }
    println!("════════════════════════════════════════════════");
    std::process::exit(if passed { 0 } else { 1 });
}
