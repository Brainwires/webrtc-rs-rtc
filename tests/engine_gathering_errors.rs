//! `icecandidateerror` for the STUN and TURN servers the engine gathers from itself (W3C
//! webrtc-pc 4.8.3: the event "is fired when an error occurs while gathering candidates",
//! with the server's URL, "the numeric STUN error code returned by the STUN or TURN server",
//! or 701 when "no host candidate can reach the server", once per server URL while
//! gathering). The engine raised nothing for its own gathering: a refused Allocate or an
//! unreachable server was only logged.
//!
//! The TURN server is the in-memory one of `common/turn_server.rs`; an unreachable server is
//! one whose datagrams are dropped. Time is virtual.

use anyhow::Result;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;
#[path = "common/turn_server.rs"]
mod turn_server;
use turn_server::{Auth, TurnServer};

const HOST: &str = "10.0.0.1:4000";
const SERVER: &str = "192.0.2.20:3478";
const STUN: &str = "192.0.2.30:3478";

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn peer(now: Instant, server: RTCIceServer) -> Result<RTCPeerConnection> {
    common::install_crypto_provider();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(vec![server])
                .build(),
        )
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_tcp_candidate_gathering(false)
                .build(),
        )
        .build(now)?;
    pc.create_data_channel("errors", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer.clone())?;
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    pc.set_remote_description(now, answer)?;
    let host = a(HOST);
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: host.ip().to_string(),
            port: host.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let init: RTCIceCandidateInit = RTCIceCandidate::from(&candidate).to_json()?;
    pc.add_local_candidate(init)?;
    Ok(pc)
}

/// Runs `pc` with the server (`None`: every datagram is dropped) until `until`; returns the
/// events.
fn run(
    pc: &mut RTCPeerConnection,
    mut server: Option<&mut TurnServer>,
    mut now: Instant,
    until: Instant,
) -> Result<Vec<RTCPeerConnectionEvent>> {
    let mut events = vec![];
    loop {
        let mut moved = false;
        while let Some(w) = pc.poll_write() {
            moved = true;
            if let Some(s) = server.as_deref_mut()
                && s.addresses.contains(&w.transport.peer_addr)
            {
                s.client_sent(
                    now,
                    w.transport.local_addr,
                    w.transport.peer_addr,
                    &w.message,
                )?;
            }
        }
        if let Some(s) = server.as_deref_mut() {
            for (from, to, data) in std::mem::take(&mut s.out) {
                moved = true;
                let _ = pc.handle_read(TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: to,
                        peer_addr: from,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: data[..].into(),
                });
            }
        }
        while let Some(e) = pc.poll_event() {
            moved = true;
            events.push(e);
        }
        if moved {
            continue;
        }
        match pc.poll_timeout() {
            Some(t) if t <= until => {
                now = t.max(now + Duration::from_micros(1));
                pc.handle_timeout(now)?;
            }
            _ => return Ok(events),
        }
    }
}

fn errors(events: &[RTCPeerConnectionEvent]) -> Vec<(String, u16)> {
    events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidateErrorEvent(err) => {
                Some((err.url.clone(), err.error_code))
            }
            _ => None,
        })
        .collect()
}

/// A TURN server that refuses the credentials (401 to the Allocate that carries them): an
/// `icecandidateerror` with the server's URL and 401, and `OnTurnRequestRejected` for the
/// Allocate.
#[test]
fn a_turn_server_refusing_the_credentials_raises_icecandidateerror_with_its_code() -> Result<()> {
    let now = Instant::now();
    let mut server = TurnServer::new(
        Auth::Static(vec![("someone-else".to_owned(), "p".to_owned())]),
        vec![a(SERVER)],
        a(SERVER).ip(),
        now,
    );
    let mut pc = peer(
        now,
        RTCIceServer {
            urls: vec![format!("turn:{SERVER}")],
            username: "u1".to_owned(),
            credential: "p1".to_owned(),
        },
    )?;
    let events = run(
        &mut pc,
        Some(&mut server),
        now,
        now + Duration::from_secs(10),
    )?;
    assert_eq!(
        errors(&events),
        vec![("turn:192.0.2.20:3478?transport=udp".to_owned(), 401)],
        "{events:?}"
    );
    assert!(events.iter().any(|e| matches!(
        e,
        RTCPeerConnectionEvent::OnTurnRequestRejected {
            method: "Allocate",
            error_code: 401,
            ..
        }
    )));
    Ok(())
}

/// A TURN server that never answers: 701, once.
#[test]
fn an_unreachable_turn_server_raises_icecandidateerror_701_once() -> Result<()> {
    let now = Instant::now();
    let mut pc = peer(
        now,
        RTCIceServer {
            urls: vec![format!("turn:{SERVER}")],
            username: "u1".to_owned(),
            credential: "p1".to_owned(),
        },
    )?;
    let events = run(&mut pc, None, now, now + Duration::from_secs(120))?;
    assert_eq!(
        errors(&events),
        vec![("turn:192.0.2.20:3478?transport=udp".to_owned(), 701)],
        "{events:?}"
    );
    Ok(())
}

/// A STUN server that never answers: 701, once, with its URL.
#[test]
fn an_unreachable_stun_server_raises_icecandidateerror_701_once() -> Result<()> {
    let now = Instant::now();
    let mut pc = peer(
        now,
        RTCIceServer {
            urls: vec![format!("stun:{STUN}")],
            ..Default::default()
        },
    )?;
    let events = run(&mut pc, None, now, now + Duration::from_secs(120))?;
    assert_eq!(
        errors(&events),
        vec![("stun:192.0.2.30:3478".to_owned(), 701)],
        "{events:?}"
    );
    Ok(())
}
