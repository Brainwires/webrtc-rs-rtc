//! Re-allocating on the same socket after a release (RFC 8656).
//!
//! An allocation is its 5-tuple's (section 2.2): an Allocate on a 5-tuple that still has one is
//! refused with 437 (section 7.2, step 2). On a 437 the client "SHOULD pick another client
//! transport address and retry", "SHOULD try three different client transport addresses
//! before giving up on this server", and "Once the client gives up on the server, it SHOULD NOT
//! try to create another allocation on the server for 2 minutes" (section 7.4). So the engine
//! never retries an Allocate on the 5-tuple that was refused; it avoids the 437 instead:
//!
//! - It allocates again on a 5-tuple it released only once the server has answered the release
//!   (the Refresh of LIFETIME 0, section 8): before that the allocation still exists, and a lost
//!   or late release would turn the new Allocate into a 437 and two minutes without that server.
//! - Section 8.2 has the server delete the allocation at once. coturn does not: it answers the
//!   release and keeps the allocation for one second more (`refresh_relay_connection`). For
//!   such a server `SettingEngineBuilder::with_turn_reallocation_delay` waits longer.
//! - A new peer connection on the socket a closed one released knows nothing of that release:
//!   with coturn it meets the 437 if it allocates within that second. The remedies are the
//!   application's: wait (after `OnTurnAllocationReleased`) or use another socket.
//!
//! The server is the in-memory one of `common/turn_server.rs` (`release_linger` is coturn's
//! one-second hold); time is virtual.

use anyhow::Result;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::configuration::{
    RTCConfiguration, RTCConfigurationBuilder, RTCIceServer,
};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit,
};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::message::{METHOD_ALLOCATE, METHOD_REFRESH};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

mod common;
#[path = "common/turn_server.rs"]
mod turn_server;
use turn_server::{Auth, TurnServer};

const HOST: &str = "10.0.0.1:4000";
const HOST_2: &str = "10.0.0.1:4001";
const SERVER: &str = "192.0.2.20:3478";
/// coturn keeps a released allocation for one second (its timers fire on the second).
const COTURN_LINGER: Duration = Duration::from_secs(1);

fn a(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn server(now: Instant, linger: Option<Duration>) -> TurnServer {
    let mut s = TurnServer::new(
        Auth::Static(vec![
            ("u1".to_owned(), "p1".to_owned()),
            ("u2".to_owned(), "p2".to_owned()),
        ]),
        vec![a(SERVER)],
        a(SERVER).ip(),
        now,
    );
    s.release_linger = linger;
    s
}

fn config(user: &str, pass: &str) -> RTCConfiguration {
    RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec![format!("turn:{SERVER}")],
            username: user.to_owned(),
            credential: pass.to_owned(),
        }])
        .build()
}

/// A peer connection with the `turn:` server and the host candidates `hosts`, and the peer
/// connection that answered its offer (nothing reaches the answerer).
struct Peer {
    pc: RTCPeerConnection,
    answerer: RTCPeerConnection,
}

impl Peer {
    fn new(now: Instant, hosts: &[&str], reallocation_delay: Option<Duration>) -> Result<Self> {
        common::install_crypto_provider();
        let mut settings = SettingEngineBuilder::new().with_tcp_candidate_gathering(false);
        if let Some(delay) = reallocation_delay {
            settings = settings.with_turn_reallocation_delay(delay);
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(config("u1", "p1"))
            .with_setting_engine(settings.build())
            .build(now)?;
        pc.create_data_channel("reallocate", None)?;
        let answerer = RTCPeerConnectionBuilder::new().build(now)?;
        let mut peer = Self { pc, answerer };
        peer.negotiate(now)?;
        for host in hosts {
            let host = a(host);
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
            peer.pc.add_local_candidate(init)?;
        }
        Ok(peer)
    }

    /// One offer / answer round started by `pc`.
    fn negotiate(&mut self, now: Instant) -> Result<()> {
        let offer = self.pc.create_offer(None)?;
        self.pc.set_local_description(now, offer.clone())?;
        self.answerer.set_remote_description(now, offer)?;
        let answer = self.answerer.create_answer(None)?;
        self.answerer.set_local_description(now, answer.clone())?;
        self.pc.set_remote_description(now, answer)?;
        Ok(())
    }

    /// An ICE restart with the configuration `config` (RFC 8445 section 9).
    fn restart(&mut self, now: Instant, config: Option<RTCConfiguration>) -> Result<()> {
        if let Some(config) = config {
            self.pc.set_configuration(config)?;
        }
        self.pc.restart_ice();
        self.negotiate(now)
    }
}

struct Run {
    now: Instant,
    events: Vec<RTCPeerConnectionEvent>,
}

impl Run {
    fn new(now: Instant) -> Self {
        Self {
            now,
            events: vec![],
        }
    }

    /// Moves datagrams between `pc` and the server, and the timers on, until nothing moves
    /// or `until`. Datagrams to anyone else are dropped.
    fn run(
        &mut self,
        pc: &mut RTCPeerConnection,
        s: &mut TurnServer,
        until: Instant,
    ) -> Result<()> {
        loop {
            let mut moved = false;
            while let Some(w) = pc.poll_write() {
                moved = true;
                if s.addresses.contains(&w.transport.peer_addr) {
                    s.client_sent(
                        self.now,
                        w.transport.local_addr,
                        w.transport.peer_addr,
                        &w.message,
                    )?;
                }
            }
            for (from, to, data) in std::mem::take(&mut s.out) {
                moved = true;
                let _ = pc.handle_read(TaggedBytesMut {
                    now: self.now,
                    transport: TransportContext {
                        local_addr: to,
                        peer_addr: from,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: data[..].into(),
                });
            }
            while let Some(e) = pc.poll_event() {
                moved = true;
                self.events.push(e);
            }
            if moved {
                continue;
            }
            match pc.poll_timeout() {
                Some(t) if t <= until => {
                    self.now = t.max(self.now + Duration::from_micros(1));
                    pc.handle_timeout(self.now)?;
                }
                _ => {
                    self.now = self.now.max(until);
                    return Ok(());
                }
            }
        }
    }

    fn for_(&mut self, pc: &mut RTCPeerConnection, s: &mut TurnServer, d: Duration) -> Result<()> {
        let until = self.now + d;
        self.run(pc, s, until)
    }

    fn released(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, RTCPeerConnectionEvent::OnTurnAllocationReleased { .. }))
            .count()
    }

    fn rejected_437(&self) -> bool {
        self.events.iter().any(|e| {
            matches!(
                e,
                RTCPeerConnectionEvent::OnTurnRequestRejected {
                    method: "Allocate",
                    error_code: 437,
                    ..
                }
            )
        })
    }

    fn relayed(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| match e {
                RTCPeerConnectionEvent::OnIceCandidateEvent(ev) => {
                    let init = ev.candidate.as_ref()?.to_json().ok()?;
                    init.candidate
                        .contains("typ relay")
                        .then_some(init.candidate)
                }
                _ => None,
            })
            .collect()
    }
}

fn mismatches(s: &TurnServer) -> usize {
    s.rejections
        .iter()
        .filter(|r| r.0 == METHOD_ALLOCATE && r.1 == 437)
        .count()
}

fn allocation_of(s: &TurnServer, host: &str) -> Option<String> {
    s.allocations
        .get(&(a(host), a(SERVER)))
        .map(|al| al.username.clone())
}

/// The requests from `from` (index in `s.requests`) on: the index of the first Refresh of
/// LIFETIME 0 the server answered and of the first Allocate.
fn release_then_allocate(s: &TurnServer, from: usize) -> (Option<usize>, Option<usize>) {
    let release = s.requests[from..]
        .iter()
        .position(|r| r.2 == METHOD_REFRESH && r.4 == Some(Duration::ZERO))
        .map(|i| i + from);
    let allocate = s.requests[from..]
        .iter()
        .position(|r| r.2 == METHOD_ALLOCATE)
        .map(|i| i + from);
    (release, allocate)
}

/// RFC 8656 sections 7.2 and 8: an ICE restart with new TURN credentials and one UDP socket
/// releases the old allocation and allocates on the same 5-tuple. The release is lost once
/// (it is retransmitted, RFC 8489 section 6.2.1); the new Allocate waits for its answer, so the
/// server never sees an Allocate on a 5-tuple with an allocation: no 437, and the new
/// generation has its relayed candidate from the same socket.
#[test]
fn a_restart_on_one_socket_allocates_once_the_release_is_answered() -> Result<()> {
    let mut run = Run::new(Instant::now());
    let mut s = server(run.now, None);
    let mut p = Peer::new(run.now, &[HOST], None)?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(5))?;
    assert_eq!(allocation_of(&s, HOST).as_deref(), Some("u1"), "allocated");
    let mark = s.requests.len();

    s.lose_releases = 1;
    p.restart(run.now, Some(config("u2", "p2")))?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(10))?;

    assert_eq!(
        mismatches(&s),
        0,
        "no Allocate on the 5-tuple before its release was answered: requests {:?}",
        &s.requests[mark..]
    );
    let (release, allocate) = release_then_allocate(&s, mark);
    assert!(
        release.is_some() && allocate.is_some() && release < allocate,
        "the release (answered) before the Allocate: {:?}",
        &s.requests[mark..]
    );
    assert_eq!(allocation_of(&s, HOST).as_deref(), Some("u2"));
    assert!(!run.rejected_437());
    assert_eq!(
        run.relayed().len(),
        2,
        "one relayed candidate per generation"
    );
    Ok(())
}

/// The same restart against a coturn-like server, which answers the release but keeps the
/// allocation for a second: without a reallocation delay the Allocate meets a 437. The engine
/// says so (`OnTurnRequestRejected`), has no other socket to try, and leaves the server alone
/// for two minutes (RFC 8656 section 7.4 SHOULD NOT): no Allocate is retried on the 5-tuple
/// for the rest of the generation. A restart after the two minutes allocates again.
#[test]
fn with_coturn_a_restart_on_one_socket_without_a_delay_meets_a_437_and_waits_two_minutes()
-> Result<()> {
    let mut run = Run::new(Instant::now());
    let mut s = server(run.now, Some(COTURN_LINGER));
    let mut p = Peer::new(run.now, &[HOST], None)?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(5))?;
    assert_eq!(allocation_of(&s, HOST).as_deref(), Some("u1"));

    p.restart(run.now, Some(config("u2", "p2")))?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(5))?;
    assert_eq!(mismatches(&s), 1, "{:?}", s.rejections);
    assert!(run.rejected_437(), "the application is told");
    assert_eq!(
        run.relayed().len(),
        1,
        "no relayed candidate for the restart"
    );
    let allocates = s.count(METHOD_ALLOCATE);
    run.for_(&mut p.pc, &mut s, Duration::from_secs(130))?;
    assert_eq!(
        s.count(METHOD_ALLOCATE),
        allocates,
        "no Allocate retried on the refused 5-tuple"
    );

    // Two minutes on: the next ICE generation allocates.
    p.restart(run.now, None)?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(5))?;
    assert_eq!(allocation_of(&s, HOST).as_deref(), Some("u2"));
    assert_eq!(mismatches(&s), 1);
    assert_eq!(run.relayed().len(), 2);
    Ok(())
}

/// `with_turn_reallocation_delay(2 s)` against the coturn-like server: the restart's
/// Allocate leaves two seconds after the release was answered, the allocation is gone by
/// then, and the new generation has its relayed candidate with no 437.
#[test]
fn with_coturn_a_restart_on_one_socket_with_the_reallocation_delay_allocates() -> Result<()> {
    let mut run = Run::new(Instant::now());
    let mut s = server(run.now, Some(COTURN_LINGER));
    let mut p = Peer::new(run.now, &[HOST], Some(Duration::from_secs(2)))?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(5))?;
    let mark = s.requests.len();

    let restart = run.now;
    p.restart(run.now, Some(config("u2", "p2")))?;
    run.for_(&mut p.pc, &mut s, Duration::from_secs(10))?;
    assert_eq!(mismatches(&s), 0, "{:?}", s.rejections);
    assert_eq!(allocation_of(&s, HOST).as_deref(), Some("u2"));
    assert_eq!(run.relayed().len(), 2);
    let (release, allocate) = release_then_allocate(&s, mark);
    assert!(release < allocate, "{:?}", &s.requests[mark..]);
    let released_at = s.deleted.last().map(|d| d.3).expect("released");
    assert!(released_at >= restart);
    Ok(())
}

/// A new peer connection on the socket a closed one has just released, against the
/// coturn-like server: it knows nothing of that release, allocates at once, and meets the
/// 437. `OnTurnRequestRejected` says so; with one socket the engine leaves the server alone
/// for the two minutes and the connection has no relayed candidate.
#[test]
fn with_coturn_the_next_peer_connection_on_the_socket_at_once_meets_a_437() -> Result<()> {
    let mut run = Run::new(Instant::now());
    let mut s = server(run.now, Some(COTURN_LINGER));
    let mut first = Peer::new(run.now, &[HOST], None)?;
    run.for_(&mut first.pc, &mut s, Duration::from_secs(5))?;
    first.pc.close()?;
    run.for_(&mut first.pc, &mut s, Duration::from_millis(100))?;
    assert_eq!(run.released(), 1, "the release was answered");

    let mut next = Run::new(run.now);
    let mut second = Peer::new(next.now, &[HOST], None)?;
    next.for_(&mut second.pc, &mut s, Duration::from_millis(500))?;
    assert_eq!(mismatches(&s), 1, "{:?}", s.rejections);
    assert!(next.rejected_437());
    let allocates = s.count(METHOD_ALLOCATE);
    next.for_(&mut second.pc, &mut s, Duration::from_secs(130))?;
    assert_eq!(s.count(METHOD_ALLOCATE), allocates, "no retry");
    assert!(next.relayed().is_empty());
    Ok(())
}

/// The application's remedies for that case: (1) wait for the server's hold after
/// `OnTurnAllocationReleased` (two seconds for coturn) before the next peer connection
/// gathers on the socket; (2) give the next peer connection another socket as well: the
/// engine moves the Allocate there on the 437 (RFC 8656 section 7.4).
#[test]
fn with_coturn_the_next_peer_connection_allocates_after_the_hold_or_from_another_socket()
-> Result<()> {
    // (1)
    let mut run = Run::new(Instant::now());
    let mut s = server(run.now, Some(COTURN_LINGER));
    let mut first = Peer::new(run.now, &[HOST], None)?;
    run.for_(&mut first.pc, &mut s, Duration::from_secs(5))?;
    first.pc.close()?;
    run.for_(&mut first.pc, &mut s, Duration::from_secs(2))?;
    assert_eq!(run.released(), 1);
    let mut next = Run::new(run.now);
    let mut second = Peer::new(next.now, &[HOST], None)?;
    next.for_(&mut second.pc, &mut s, Duration::from_secs(5))?;
    assert_eq!(mismatches(&s), 0, "{:?}", s.rejections);
    assert_eq!(next.relayed().len(), 1);
    assert!(
        next.relayed()[0].contains("rport 4000"),
        "{:?}",
        next.relayed()
    );

    // (2)
    let mut run = Run::new(Instant::now());
    let mut s = server(run.now, Some(COTURN_LINGER));
    let mut first = Peer::new(run.now, &[HOST], None)?;
    run.for_(&mut first.pc, &mut s, Duration::from_secs(5))?;
    first.pc.close()?;
    run.for_(&mut first.pc, &mut s, Duration::from_millis(100))?;
    assert_eq!(run.released(), 1);
    let mut next = Run::new(run.now);
    let mut second = Peer::new(next.now, &[HOST, HOST_2], None)?;
    next.for_(&mut second.pc, &mut s, Duration::from_secs(5))?;
    assert_eq!(
        mismatches(&s),
        1,
        "the first socket's Allocate: {:?}",
        s.rejections
    );
    assert!(next.rejected_437());
    let relayed = next.relayed();
    assert_eq!(relayed.len(), 1, "{relayed:?}");
    assert!(relayed[0].contains("rport 4001"), "{}", relayed[0]);
    Ok(())
}
