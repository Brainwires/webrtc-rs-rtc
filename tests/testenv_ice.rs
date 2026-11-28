//! ICE over real network topologies: TURN relay over UDP, TCP and TLS, STUN server-reflexive
//! candidates, and every pairing of RFC 4787 NAT types, with and without a TURN server.
//!
//! These need `scripts/test-env/run.sh` (network namespaces, iptables NAT routers, coturn) and
//! are ignored elsewhere. They replace `rtci-ice/src/candidate/candidate_relay_test.rs` and
//! `candidate_server_reflexive_test.rs`, which were written for the old async stack's in-process
//! TURN server (`turn::server`) that `rtci-turn` does not have; coturn plays that part here.

mod common;
mod testenv;

use rtci::data_channel::RTCDataChannelId;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use std::time::{Duration, Instant};
use testenv::{
    Env, EnvPeer, Gather, TurnTransport, negotiate, negotiate_without_end_of_candidates, pump,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Long enough for ICE to give up (the agent's failed timeout plus checks) on a pair of NATs
/// with no path between them.
const FAIL_TIMEOUT: Duration = Duration::from_secs(60);

fn new_pc() -> RTCPeerConnection {
    RTCPeerConnectionBuilder::new()
        .build(Instant::now())
        .expect("peer connection")
}

fn dc_open(p: &EnvPeer) -> Option<RTCDataChannelId> {
    p.events.iter().find_map(|e| match e {
        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => Some(*id),
        _ => None,
    })
}

fn got_text(p: &EnvPeer, want: &str) -> bool {
    p.reads.iter().any(|m| match &m.message {
        RTCMessage::DataChannelMessage(_, msg) => msg.data.as_ref() == want.as_bytes(),
        _ => false,
    })
}

/// Connects `a` (offerer, creates a data channel) and `b`, sends one message each way, and
/// returns the selected pair's candidate types as each side sees them.
fn connect_and_exchange(a: &mut EnvPeer, b: &mut EnvPeer) -> ((String, String), (String, String)) {
    a.pc.create_data_channel("testenv", None)
        .expect("data channel");
    negotiate(a, b).expect("negotiate");
    let mut sent = (false, false);
    let ok = pump(&mut [a, b], CONNECT_TIMEOUT, |p| {
        let (a, b) = p.split_at_mut(1);
        let (a, b) = (&mut *a[0], &mut *b[0]);
        for (peer, flag, text) in [
            (&mut *a, &mut sent.0, "from-a"),
            (&mut *b, &mut sent.1, "from-b"),
        ] {
            if !*flag
                && let Some(id) = dc_open(peer)
                && let Some(mut dc) = peer.pc.data_channel(id)
            {
                *flag = dc.send_text(Instant::now(), text.to_owned()).is_ok();
            }
        }
        a.connected() && b.connected() && got_text(b, "from-a") && got_text(a, "from-b")
    })
    .expect("pump");
    assert!(
        ok,
        "{} <-> {} did not connect and exchange messages: a state {:?} (sent direct {}, relayed {}, \
         turn errors {:?}), b state {:?} (sent direct {}, relayed {}, turn errors {:?})",
        a.netns,
        b.netns,
        a.connection_state(),
        a.sent_direct,
        a.sent_relayed,
        a.errors,
        b.connection_state(),
        b.sent_direct,
        b.sent_relayed,
        b.errors,
    );
    (
        a.selected_pair_types().expect("a selected pair"),
        b.selected_pair_types().expect("b selected pair"),
    )
}

fn peer(name: &str, ns: &str, gather: Gather, env: &Env) -> EnvPeer {
    EnvPeer::new(name, ns, gather, env, new_pc()).unwrap_or_else(|e| panic!("{name} in {ns}: {e}"))
}

fn relay_only(t: TurnTransport) {
    common::install_crypto_provider();
    let env = Env::get();
    // Both peers behind symmetric NATs: no direct path exists, so only the relay connects them.
    let mut a = peer("a", "h-symmetric-a", Gather::relay_only(t), &env);
    let mut b = peer("b", "h-symmetric-b", Gather::relay_only(t), &env);
    let (ta, tb) = connect_and_exchange(&mut a, &mut b);
    assert_eq!(ta.0, "relay", "a's local candidate {ta:?}");
    assert_eq!(tb.0, "relay", "b's local candidate {tb:?}");
    assert!(a.sent_relayed > 0 && b.sent_relayed > 0);
    assert_eq!(
        a.sent_direct + b.sent_direct,
        0,
        "relay-only peers sent directly"
    );
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn test_relay_only_connection_udp() {
    relay_only(TurnTransport::Udp);
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn test_relay_only_connection_tcp() {
    relay_only(TurnTransport::Tcp);
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn test_relay_only_connection_tls() {
    relay_only(TurnTransport::Tls);
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn test_server_reflexive_only_connection() {
    common::install_crypto_provider();
    let env = Env::get();
    // Full-cone NATs forward to the mapped port whoever sends, so two server-reflexive
    // candidates reach each other.
    let mut a = peer("a", "h-fullcone-a", Gather::SRFLX_ONLY, &env);
    let mut b = peer("b", "h-fullcone-b", Gather::SRFLX_ONLY, &env);
    assert!(
        a.srflx
            .is_some_and(|s| s.ip().to_string().starts_with("203.0.113."))
    );
    let (ta, tb) = connect_and_exchange(&mut a, &mut b);
    assert_eq!(ta.1, "srflx", "a's remote candidate {ta:?}");
    assert_eq!(tb.1, "srflx", "b's remote candidate {tb:?}");
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn test_host_candidates_on_the_open_internet() {
    common::install_crypto_provider();
    let env = Env::get();
    let mut a = peer("a", "open-a", Gather::HOST, &env);
    let mut b = peer("b", "open-b", Gather::HOST, &env);
    let (ta, tb) = connect_and_exchange(&mut a, &mut b);
    assert_eq!((ta.0.as_str(), ta.1.as_str()), ("host", "host"));
    assert_eq!((tb.0.as_str(), tb.1.as_str()), ("host", "host"));
}

/// Whether two NATs can be traversed without a relay (RFC 4787 / RFC 8445 hole punching): a
/// symmetric NAT allocates a new port per destination, so a peer whose own NAT filters by port
/// never accepts it.
fn traversable(x: &str, y: &str) -> bool {
    let hard = |n: &str| n == "symmetric";
    let port_filtering = |n: &str| n == "portrestricted" || n == "symmetric";
    !((hard(x) && port_filtering(y)) || (hard(y) && port_filtering(x)))
}

fn nat_pair(x: &str, y: &str, with_turn: bool) {
    common::install_crypto_provider();
    let env = Env::get();
    let gather = if with_turn {
        Gather::ALL
    } else {
        Gather::DIRECT
    };
    let mut a = peer("a", &format!("h-{x}-a"), gather, &env);
    let mut b = peer("b", &format!("h-{y}-b"), gather, &env);
    let direct = traversable(x, y);
    if with_turn || direct {
        let (ta, tb) = connect_and_exchange(&mut a, &mut b);
        let relayed = ta.0 == "relay" || ta.1 == "relay";
        eprintln!("NAT-MATRIX {x} <-> {y} turn={with_turn}: connected via a={ta:?} b={tb:?}");
        if direct {
            assert!(
                !relayed,
                "{x} <-> {y} has a direct path but ICE chose {ta:?} / {tb:?}"
            );
        } else {
            assert!(
                relayed,
                "{x} <-> {y} has no direct path, yet {ta:?} / {tb:?} connected"
            );
        }
    } else {
        a.pc.create_data_channel("testenv", None)
            .expect("data channel");
        negotiate(&mut a, &mut b).expect("negotiate");
        let failed = pump(&mut [&mut a, &mut b], FAIL_TIMEOUT, |p| {
            p[0].failed() && p[1].failed()
        })
        .expect("pump");
        eprintln!(
            "NAT-MATRIX {x} <-> {y} turn=false: no path, states a={:?} b={:?}",
            a.connection_state(),
            b.connection_state()
        );
        assert!(
            !a.connected() && !b.connected(),
            "{x} <-> {y} connected without a relay"
        );
        assert!(
            failed,
            "{x} <-> {y}: ICE never reported failure (a {:?}, b {:?})",
            a.connection_state(),
            b.connection_state()
        );
    }
}

macro_rules! nat_matrix {
    ($($name:ident: $x:literal, $y:literal;)*) => {
        mod nat_matrix_with_turn {
            $(
                #[test]
                #[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
                fn $name() { super::nat_pair($x, $y, true); }
            )*
        }
        mod nat_matrix_without_turn {
            $(
                #[test]
                #[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
                fn $name() { super::nat_pair($x, $y, false); }
            )*
        }
    };
}

nat_matrix! {
    fullcone_fullcone: "fullcone", "fullcone";
    fullcone_restricted: "fullcone", "restricted";
    fullcone_portrestricted: "fullcone", "portrestricted";
    fullcone_symmetric: "fullcone", "symmetric";
    restricted_restricted: "restricted", "restricted";
    restricted_portrestricted: "restricted", "portrestricted";
    restricted_symmetric: "restricted", "symmetric";
    portrestricted_portrestricted: "portrestricted", "portrestricted";
    portrestricted_symmetric: "portrestricted", "symmetric";
    symmetric_symmetric: "symmetric", "symmetric";
}

/// W3C webrtc-pc 5.6.4 on real NATs with no path between them (symmetric <-> symmetric, no
/// relay): "The failed and completed states require an indication that there are no additional
/// remote candidates". Without either peer's end of candidates the checks that all failed leave
/// both agents `disconnected` for as long as the test waits (`FAIL_TIMEOUT`, past the checking
/// timeout and the PAC timer); with `with_ice_failed_without_end_of_candidates(true)` (RFC 8863
/// section 5: "ICE agents MAY use the PAC timer to also serve as an end-of-candidates fallback")
/// they fail, as `nat_matrix_without_turn` does with the indications.
fn no_path_without_end_of_candidates(fallback: bool) {
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use rtci::peer_connection::state::RTCPeerConnectionState;
    common::install_crypto_provider();
    let env = Env::get();
    let pc = || {
        RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_ice_failed_without_end_of_candidates(fallback)
                    .build(),
            )
            .build(Instant::now())
            .expect("peer connection")
    };
    let mut a = EnvPeer::new("a", "h-symmetric-a", Gather::DIRECT, &env, pc()).expect("peer a");
    let mut b = EnvPeer::new("b", "h-symmetric-b", Gather::DIRECT, &env, pc()).expect("peer b");
    a.pc.create_data_channel("testenv", None)
        .expect("data channel");
    negotiate_without_end_of_candidates(&mut a, &mut b).expect("negotiate");
    let failed = pump(&mut [&mut a, &mut b], FAIL_TIMEOUT, |p| {
        p[0].failed() || p[1].failed()
    })
    .expect("pump");
    eprintln!(
        "NO-END-OF-CANDIDATES fallback={fallback}: states a={:?} b={:?}",
        a.connection_state(),
        b.connection_state()
    );
    assert!(
        !a.connected() && !b.connected(),
        "symmetric <-> symmetric connected without a relay"
    );
    if fallback {
        let both = pump(&mut [&mut a, &mut b], FAIL_TIMEOUT, |p| {
            p[0].failed() && p[1].failed()
        })
        .expect("pump");
        assert!(
            failed && both,
            "with the fallback ICE never reported failure (a {:?}, b {:?})",
            a.connection_state(),
            b.connection_state()
        );
    } else {
        assert!(
            !failed,
            "failed without an end-of-candidates indication (a {:?}, b {:?})",
            a.connection_state(),
            b.connection_state()
        );
        assert_eq!(
            (a.connection_state(), b.connection_state()),
            (
                Some(RTCPeerConnectionState::Disconnected),
                Some(RTCPeerConnectionState::Disconnected)
            )
        );
    }
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn without_end_of_candidates_a_pair_of_nats_with_no_path_stays_disconnected() {
    no_path_without_end_of_candidates(false);
}

#[test]
#[ignore = "needs the real-network test environment (coturn, NAT namespaces): scripts/test-env/run.sh"]
fn with_the_fallback_setting_a_pair_of_nats_with_no_path_fails_without_end_of_candidates() {
    no_path_without_end_of_candidates(true);
}
