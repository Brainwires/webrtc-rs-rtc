//! Driven connections on virtual time: two `PeerDriver`s on one `MockRuntime`, its in-memory
//! network between them. Nothing touches a socket and the clock moves only when every task
//! waits, so a 30-second timeout costs no wall time and every run is the same.

mod common;

use common::{Peer, Result, connect_and_exchange, run_until};
use rtci::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtci_stream_driver::runtime::mock::{Fate, LinkConfig, MockDatagram};
use rtci_stream_driver::runtime::{MockRuntime, Runtime};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const A: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const B: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
/// The longest a driver waits in one step.
const STEP: Duration = Duration::from_millis(10);

fn peers(runtime: &MockRuntime) -> Result<(Peer, Peer)> {
    let shared: Arc<dyn Runtime> = Arc::new(runtime.clone());
    Ok((Peer::new(shared.clone(), A)?, Peer::new(shared, B)?))
}

#[test]
fn two_drivers_connect_and_exchange_a_data_channel_message_on_virtual_time() -> Result<()> {
    let runtime = MockRuntime::new();
    runtime.net().set_links(
        A,
        B,
        LinkConfig {
            delay: Duration::from_millis(20),
            ..Default::default()
        },
    );
    let (mut a, mut b) = peers(&runtime)?;
    runtime.run(connect_and_exchange(&mut a, &mut b, STEP, 10_000))?;
    assert!(a.connected() && b.connected());
    // Every datagram went over the mock network, from the drivers' own (mock) sockets.
    let log = runtime.net().log();
    assert!(log.iter().any(|d| d.from.ip() == A && d.to.ip() == B));
    assert!(log.iter().any(|d| d.from.ip() == B && d.to.ip() == A));
    assert!(
        log.iter().all(|d| matches!(d.fate, Fate::Delivered(1))),
        "{log:?}"
    );
    // With 20 ms each way the connection takes several round trips of virtual time.
    assert!(
        runtime.clock().elapsed() >= Duration::from_millis(80),
        "{:?}",
        runtime.clock().elapsed()
    );
    Ok(())
}

/// RFC 7675 section 5.1: "Consent expires after 30 seconds". The path between the two peers
/// goes dark after they connected; each driver reports its ICE connection (and its peer
/// connection) disconnected, then failed: at most 30 seconds after the last consent response
/// it had, or as the PAC timer expires when that is later (W3C webrtc-pc 5.6.4; the drivers'
/// applications relay the end of the candidates), and the whole wait takes no wall time worth
/// the name.
#[test]
fn consent_expiry_after_30_seconds_elapses_on_virtual_time_and_the_driver_reports_the_failure()
-> Result<()> {
    let runtime = MockRuntime::new();
    let (mut a, mut b) = peers(&runtime)?;
    // The application relays the end of the candidates: lost consent is "failed" then (W3C
    // webrtc-pc 5.6.4), "disconnected" without it.
    a.relay_end_of_candidates = true;
    b.relay_end_of_candidates = true;
    let begun = runtime.now();
    runtime.run(connect_and_exchange(&mut a, &mut b, STEP, 10_000))?;
    let dark = runtime.now();
    // "failed" also waits for the PAC timer, 39.5 s after the checks began (W3C webrtc-pc
    // 5.6.4, RFC 8863): consent that expires before that fails the connection then.
    let pac = (begun + Duration::from_millis(39_500)).saturating_duration_since(dark);
    runtime.net().set_links(
        A,
        B,
        LinkConfig {
            blocked: true,
            ..Default::default()
        },
    );
    let wall = Instant::now();
    let failed = |p: &Peer| {
        p.ice_states
            .iter()
            .any(|(s, _)| *s == RTCIceConnectionState::Failed)
    };
    let both = runtime.run(run_until(&mut a, &mut b, STEP, 100_000, |a, b| {
        failed(a) && failed(b)
    }))?;
    let wall = wall.elapsed();
    assert!(
        both,
        "both ICE connections fail: {:?} / {:?}",
        a.ice_states, b.ice_states
    );
    for (who, peer) in [("a", &a), ("b", &b)] {
        let at = |state| {
            peer.ice_states
                .iter()
                .find(|(s, t)| *s == state && *t >= dark)
                .map(|(_, t)| t.duration_since(dark))
        };
        let disconnected = at(RTCIceConnectionState::Disconnected).ok_or("disconnected")?;
        let failed = at(RTCIceConnectionState::Failed).ok_or("failed")?;
        assert!(disconnected < failed, "{who}: disconnected first");
        // The last consent response came at most one consent interval (5 s, drawn up to
        // 1.2 times) before the path went dark: consent expires 24 to 30 s after that.
        assert!(
            failed >= Duration::from_secs(20)
                && failed <= Duration::from_secs(31).max(pac + Duration::from_millis(250)),
            "{who}: failed {failed:?} after the path went dark (PAC timer {pac:?})"
        );
        assert!(
            peer.states
                .iter()
                .any(|(s, t)| *s == RTCPeerConnectionState::Failed && *t >= dark),
            "{who}: the peer connection reports failed: {:?}",
            peer.states
        );
    }
    assert!(
        wall < Duration::from_secs(10),
        "30 s of virtual time took {wall:?} of wall time"
    );
    Ok(())
}

/// A DTLS ClientHello record (content type 22, a DTLS version, handshake type 1).
fn is_client_hello(data: &[u8]) -> bool {
    data.len() > 13 && data[0] == 22 && data[1] == 0xfe && data[13] == 1
}

/// RFC 6347 section 4.2.4 (RFC 9147 section 5.8): a flight that gets no answer is sent again
/// when its timer fires. The network drops the first ClientHello; the client sends it again
/// when its first timer runs out on virtual time, and the peers connect. The engine's first
/// timer for DTLS-SRTP follows RFC 9147 section 5.8.2: 400 ms, or 1.5 times ICE's round trip
/// time and never under 100 ms (`DtlsFlightInterval::Rfc9147`).
#[test]
fn a_lost_client_hello_is_retransmitted_on_virtual_time_and_the_peers_connect() -> Result<()> {
    let runtime = MockRuntime::new();
    let hellos: Arc<Mutex<Vec<Instant>>> = Arc::default();
    let seen = hellos.clone();
    runtime
        .net()
        .set_filter(Box::new(move |d: &MockDatagram<'_>| {
            if !is_client_hello(d.data) {
                return true;
            }
            let mut seen = seen.lock().unwrap();
            seen.push(d.at);
            // The first one is lost.
            seen.len() > 1
        }));
    let (mut a, mut b) = peers(&runtime)?;
    runtime.run(connect_and_exchange(&mut a, &mut b, STEP, 10_000))?;
    let hellos = hellos.lock().unwrap().clone();
    assert!(
        hellos.len() >= 2,
        "the ClientHello was sent again: {hellos:?}"
    );
    let gap = hellos[1].duration_since(hellos[0]);
    assert!(
        gap >= Duration::from_millis(100) && gap <= Duration::from_millis(400),
        "retransmitted after its timer: {gap:?}"
    );
    let filtered = runtime
        .net()
        .log()
        .iter()
        .filter(|d| d.fate == Fate::Filtered)
        .count();
    assert_eq!(filtered, 1, "exactly one datagram was lost");
    Ok(())
}
