//! The old async agent's tests, ported to the sans-I/O agent.
//!
//! Two agents are connected by carrying each one's `poll_write` output into the other's
//! `handle_read`, under virtual time driven with `handle_timeout`. No sockets and no wall clock:
//! every instant is `base` plus a fixed offset.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USERNAME;

use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::mdns::MulticastDnsMode;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

/// The two agents' host candidates: private addresses in one scope, so they pair.
const A_ADDR: &str = "192.168.0.1:5000";
const B_ADDR: &str = "192.168.0.2:5001";

/// How far virtual time advances between `handle_timeout` calls.
const STEP: Duration = Duration::from_millis(50);

fn host(addr: &str) -> Candidate {
    let addr: SocketAddr = addr.parse().unwrap();
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

/// A configuration with mDNS off, so the only datagrams carried between agents are ICE checks.
fn quiet_config() -> AgentConfig {
    AgentConfig {
        multicast_dns_mode: MulticastDnsMode::Disabled,
        ..Default::default()
    }
}

/// A configuration that gives up quickly: one second to disconnected, one more to failed, and
/// no keepalives.
fn short_timeouts_config() -> AgentConfig {
    AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(1)),
        failed_timeout: Some(Duration::from_secs(1)),
        keepalive_interval: Some(Duration::from_secs(0)),
        ..quiet_config()
    }
}

/// Two agents with one host candidate each, each holding the other's as its remote candidate.
fn agent_pair(base: Instant, cfg_a: AgentConfig, cfg_b: AgentConfig) -> Result<(Agent, Agent)> {
    let mut a = Agent::new(base, Arc::new(cfg_a), provider())?;
    let mut b = Agent::new(base, Arc::new(cfg_b), provider())?;
    a.add_local_candidate(host(A_ADDR))?;
    b.add_local_candidate(host(B_ADDR))?;
    a.add_remote_candidate(host(B_ADDR))?;
    b.add_remote_candidate(host(A_ADDR))?;
    Ok((a, b))
}

/// Signals each agent's credentials to the other and starts checks: `a` controls.
fn start_both(a: &mut Agent, b: &mut Agent, now: Instant) -> Result<()> {
    let a_credentials = a.get_local_credentials().clone();
    let b_credentials = b.get_local_credentials().clone();
    a.start_connectivity_checks(now, true, b_credentials.ufrag, b_credentials.pwd)?;
    b.start_connectivity_checks(now, false, a_credentials.ufrag, a_credentials.pwd)?;
    Ok(())
}

/// Hands one datagram `out` written by an agent to the agent at its destination, at `now`.
fn carry(out: TaggedBytesMut, to: &mut Agent, now: Instant) {
    // The receiver may refuse it (a bad credential, an unknown local address): that is the
    // behaviour under test, not an error of the harness.
    let _ = to.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: out.transport.peer_addr,
            peer_addr: out.transport.local_addr,
            transport_protocol: out.transport.transport_protocol,
            ecn: None,
        },
        message: out.message,
    });
}

/// Carries everything `from` has queued to `to`; returns how many datagrams moved.
fn deliver(from: &mut Agent, to: &mut Agent, now: Instant) -> usize {
    let mut moved = 0;
    while let Some(out) = from.poll_write() {
        carry(out, to, now);
        moved += 1;
    }
    moved
}

/// Carries datagrams both ways until neither agent has anything left to send.
fn settle(a: &mut Agent, b: &mut Agent, now: Instant) {
    for _ in 0..64 {
        if deliver(a, b, now) + deliver(b, a, now) == 0 {
            return;
        }
    }
    panic!("the agents kept answering each other without settling");
}

/// Discards what an agent has queued: the network between the agents is down.
fn drop_writes(a: &mut Agent) {
    while a.poll_write().is_some() {}
}

/// One tick: both agents handle `now`, then everything they send is carried.
fn step(a: &mut Agent, b: &mut Agent, now: Instant) -> Result<()> {
    a.handle_timeout(now)?;
    b.handle_timeout(now)?;
    settle(a, b, now);
    Ok(())
}

/// Ticks both agents from `base` until both are connected; returns the instant they were.
fn connect(a: &mut Agent, b: &mut Agent, base: Instant) -> Result<Instant> {
    let mut now = base;
    for _ in 0..200 {
        step(a, b, now)?;
        if a.state() == ConnectionState::Connected && b.state() == ConnectionState::Connected {
            return Ok(now);
        }
        now += STEP;
    }
    panic!(
        "the agents did not connect within 10s of virtual time: a {:?}, b {:?}",
        a.state(),
        b.state()
    );
}

/// The connection states an agent has reported since the last call, in order.
fn states(a: &mut Agent) -> Vec<ConnectionState> {
    std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::ConnectionStateChange(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// An agent with one local host candidate and remote credentials, ready for `handle_inbound`.
fn inbound_agent(base: Instant) -> Result<Agent> {
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;
    a.add_local_candidate(host("192.168.0.2:777"))?;
    a.set_remote_credentials("remoteufrag".to_owned(), "remotepwd".to_owned())?;
    Ok(a)
}

/// The USERNAME a peer puts in a check to `a`: `<a's ufrag>:<the peer's ufrag>`.
fn inbound_username(a: &Agent) -> String {
    a.ufrag_pwd.local_credentials.ufrag.clone() + ":remoteufrag"
}

fn build_msg(c: MessageClass, username: String, key: String) -> Result<Message> {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(METHOD_BINDING, c)),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            key,
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;
    Ok(msg)
}

/// Assert that an agent sends its first check on the first `handle_timeout` after starting, not
/// a check interval later, and that two agents connect from it without any further tick.
#[test]
fn test_connectivity_on_startup() -> Result<()> {
    let base = Instant::now();
    let cfg = || AgentConfig {
        keepalive_interval: Some(Duration::from_secs(3600)),
        check_interval: Duration::from_secs(3600),
        ..quiet_config()
    };
    let (mut a, mut b) = agent_pair(base, cfg(), cfg())?;
    start_both(&mut a, &mut b, base)?;

    assert_eq!(
        a.poll_timeout(),
        Some(base),
        "a started agent asks to be woken at once"
    );
    a.handle_timeout(base)?;
    let first = a.poll_write().expect("a check is sent on startup");
    let mut m = Message {
        raw: first.message.to_vec(),
        ..Message::default()
    };
    m.decode()?;
    assert_eq!(
        m.typ, BINDING_REQUEST,
        "the first datagram is a Binding request"
    );

    // From here each agent is woken only when it asks to be (the periodic look at the state
    // is an hour away): the triggered check, the nomination and their answers each leave
    // when Ta allows, and the two connect within a few of them.
    let mut now = base + Duration::from_millis(10);
    carry(first, &mut b, now);
    for _ in 0..100 {
        settle(&mut a, &mut b, now);
        if a.state() == ConnectionState::Connected && b.state() == ConnectionState::Connected {
            break;
        }
        let next = [a.poll_timeout(), b.poll_timeout()]
            .into_iter()
            .flatten()
            .min()
            .expect("an agent that is checking has a deadline");
        now = next.max(now);
        a.handle_timeout(now)?;
        b.handle_timeout(now)?;
    }

    assert_eq!(a.state(), ConnectionState::Connected);
    assert_eq!(b.state(), ConnectionState::Connected);
    assert!(
        now.duration_since(base) < Duration::from_millis(500),
        "connected after {:?}",
        now.duration_since(base)
    );

    a.close()?;
    b.close()?;
    Ok(())
}

#[test]
fn test_connectivity_lite() -> Result<()> {
    let base = Instant::now();
    let lite = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..quiet_config()
    };
    let (mut a, mut b) = agent_pair(base, quiet_config(), lite)?;
    start_both(&mut a, &mut b, base)?;

    connect(&mut a, &mut b, base)?;

    let (a_local, a_remote) = a
        .get_selected_candidate_pair()
        .expect("the full agent selected a pair");
    assert_eq!(a_local.addr(), SocketAddr::from_str(A_ADDR)?);
    assert_eq!(a_remote.addr(), SocketAddr::from_str(B_ADDR)?);
    let (b_local, b_remote) = b
        .get_selected_candidate_pair()
        .expect("the lite agent selected a pair");
    assert_eq!(b_local.addr(), SocketAddr::from_str(B_ADDR)?);
    assert_eq!(b_remote.addr(), SocketAddr::from_str(A_ADDR)?);

    a.close()?;
    b.close()?;
    Ok(())
}

#[test]
fn test_inbound_validity() -> Result<()> {
    let base = Instant::now();
    let remote = SocketAddr::from_str("172.17.0.3:999")?;

    // Invalid Binding requests are discarded.
    {
        let mut a = inbound_agent(base)?;
        let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
        let mut msg = build_msg(CLASS_REQUEST, "invalid".to_owned(), local_pwd)?;
        assert!(a.handle_inbound(base, &mut msg, 0, remote).is_err());
        assert_eq!(
            a.remote_candidates.len(),
            0,
            "Binding with invalid Username was able to create prflx candidate"
        );

        let mut msg = build_msg(CLASS_REQUEST, inbound_username(&a), "Invalid".to_owned())?;
        assert!(a.handle_inbound(base, &mut msg, 0, remote).is_err());
        assert_eq!(
            a.remote_candidates.len(),
            0,
            "Binding with invalid MessageIntegrity was able to create prflx candidate"
        );

        a.close()?;
    }

    // Invalid Binding success responses are discarded.
    {
        let mut a = inbound_agent(base)?;
        let mut msg = build_msg(
            CLASS_SUCCESS_RESPONSE,
            inbound_username(&a),
            "Invalid".to_owned(),
        )?;
        assert!(a.handle_inbound(base, &mut msg, 0, remote).is_err());
        assert_eq!(
            a.remote_candidates.len(),
            0,
            "success response with invalid MessageIntegrity was able to create prflx candidate"
        );

        a.close()?;
    }

    // An error response the peer did not sign (this one carries our own password, not the
    // peer's) is discarded, and so is a request of another method.
    {
        let mut a = inbound_agent(base)?;
        let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
        let mut msg = build_msg(
            CLASS_ERROR_RESPONSE,
            inbound_username(&a),
            local_pwd.clone(),
        )?;
        assert_eq!(
            a.handle_inbound(base, &mut msg, 0, remote).unwrap_err(),
            Error::ErrIntegrityMismatch
        );
        assert_eq!(
            a.remote_candidates.len(),
            0,
            "non-binding message was able to create prflxRemote"
        );

        let mut msg = Message::new();
        msg.build(&[
            Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, inbound_username(&a))),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                local_pwd,
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        assert_eq!(
            a.handle_inbound(base, &mut msg, 0, remote).unwrap_err(),
            Error::ErrUnhandledStunpacket
        );
        assert_eq!(
            a.remote_candidates.len(),
            0,
            "a non-binding request was able to create prflxRemote"
        );

        a.close()?;
    }

    // A valid Binding request creates the peer-reflexive candidate.
    {
        let mut a = inbound_agent(base)?;
        let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
        let mut msg = build_msg(CLASS_REQUEST, inbound_username(&a), local_pwd)?;
        a.handle_inbound(base, &mut msg, 0, remote)?;
        assert_eq!(
            a.remote_candidates.len(),
            1,
            "Binding with valid values was unable to create prflx candidate"
        );
        assert_eq!(
            a.remote_candidates[0].candidate_type(),
            CandidateType::PeerReflexive
        );
        assert_eq!(a.remote_candidates[0].addr(), remote);

        a.close()?;
    }

    // So does a valid one without FINGERPRINT.
    {
        let mut a = inbound_agent(base)?;
        let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
        let mut msg = Message::new();
        msg.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, inbound_username(&a))),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                local_pwd,
                provider().crypto(),
            )),
        ])?;
        a.handle_inbound(base, &mut msg, 0, remote)?;
        assert_eq!(
            a.remote_candidates.len(),
            1,
            "Binding with valid values (but no fingerprint) was unable to create prflx candidate"
        );

        a.close()?;
    }

    // An authenticated success response with an unknown transaction id creates nothing.
    {
        let mut a = inbound_agent(base)?;
        let mut t_id = TransactionId::default();
        t_id.0[..3].copy_from_slice(b"ABC");
        let mut msg = Message::new();
        msg.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(t_id),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "remotepwd".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        assert!(a.handle_inbound(base, &mut msg, 0, remote).is_err());
        assert_eq!(
            a.remote_candidates.len(),
            0,
            "unknown remote was able to create a candidate"
        );

        // From a known remote, the response is ignored: no candidate, and the pair it would
        // validate stays unchecked.
        a.add_remote_candidate(host("172.17.0.3:999"))?;
        assert_eq!(a.candidate_pairs.len(), 1);
        let mut msg = Message::new();
        msg.build(&[
            Box::new(BINDING_SUCCESS),
            Box::new(t_id),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                "remotepwd".to_owned(),
                provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        let _ = a.handle_inbound(base, &mut msg, 0, remote);
        assert_eq!(a.remote_candidates.len(), 1);
        assert_ne!(
            a.candidate_pairs[0].state,
            CandidatePairState::Succeeded,
            "a response to no request of ours validated a pair"
        );

        a.close()?;
    }

    Ok(())
}

#[test]
fn test_invalid_agent_starts() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;

    assert_eq!(
        a.start_connectivity_checks(base, true, String::new(), "bar".to_owned())
            .unwrap_err(),
        Error::ErrRemoteUfragEmpty
    );
    assert_eq!(
        a.start_connectivity_checks(base, true, "foo".to_owned(), String::new())
            .unwrap_err(),
        Error::ErrRemotePwdEmpty
    );
    assert_eq!(
        a.state(),
        ConnectionState::New,
        "a refused start leaves the agent where it was"
    );
    assert!(a.get_remote_credentials().is_none());

    a.start_connectivity_checks(base, true, "foo".to_owned(), "bar".to_owned())?;
    assert_eq!(a.state(), ConnectionState::Checking);

    a.close()?;
    Ok(())
}

#[test]
fn test_candidate_pair_stats() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;

    let host_local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    let relay_remote = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 2340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    }
    .new_candidate_relay()?;

    let srflx_remote = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19218,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43212,
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;

    let prflx_remote = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19217,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43211,
    }
    .new_candidate_peer_reflexive()?;

    let host_remote = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.5".to_owned(),
            port: 12350,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    let host_local_id = host_local.id().to_string();
    let relay_id = relay_remote.id().to_string();
    let srflx_id = srflx_remote.id().to_string();
    let prflx_id = prflx_remote.id().to_string();
    let host_id = host_remote.id().to_string();

    a.local_candidates.push(host_local);
    for remote in [relay_remote, srflx_remote, prflx_remote, host_remote] {
        a.remote_candidates.push(remote);
    }
    for remote_index in 0..a.remote_candidates.len() {
        if a.find_pair(0, remote_index).is_none() {
            a.add_pair(0, remote_index);
        }
    }

    // The host-prflx pair (remote index 2) has failed.
    let prflx_pair = a.find_pair(0, 2).expect("the host-prflx pair exists");
    a.candidate_pairs[prflx_pair].state = CandidatePairState::Failed;

    let stats = a.get_candidate_pairs_stats(base);
    assert_eq!(stats.len(), 4, "expected 4 candidate pairs stats");

    let (mut relay_seen, mut srflx_seen, mut prflx_seen, mut host_seen) =
        (false, false, false, false);
    for cps in stats {
        assert_eq!(
            cps.local_candidate_id, host_local_id,
            "invalid local candidate id"
        );

        if cps.remote_candidate_id == relay_id {
            relay_seen = true;
        } else if cps.remote_candidate_id == srflx_id {
            srflx_seen = true;
        } else if cps.remote_candidate_id == prflx_id {
            prflx_seen = true;
            assert_eq!(
                cps.state,
                CandidatePairState::Failed,
                "expected host-prflx pair to have state failed, it has state {:?} instead",
                cps.state
            );
        } else if cps.remote_candidate_id == host_id {
            host_seen = true;
        } else {
            panic!("invalid remote candidate ID");
        }
    }

    assert!(relay_seen, "missing host-relay pair stat");
    assert!(srflx_seen, "missing host-srflx pair stat");
    assert!(prflx_seen, "missing host-prflx pair stat");
    assert!(host_seen, "missing host-host pair stat");

    a.close()?;
    Ok(())
}

#[test]
fn test_local_candidate_stats() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;

    let host_local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    let srflx_local = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19217,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43212,
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;

    let expected = [host_local.clone(), srflx_local.clone()];
    a.local_candidates.push(host_local);
    a.local_candidates.push(srflx_local);

    let local_stats = a.get_local_candidates_stats(base);
    assert_eq!(
        local_stats.len(),
        2,
        "expected 2 local candidates stats, got {} instead",
        local_stats.len()
    );

    let mut seen = [false; 2];
    for stats in local_stats {
        let index = expected
            .iter()
            .position(|c| c.id() == stats.id)
            .expect("invalid local candidate ID");
        seen[index] = true;
        let candidate = &expected[index];

        assert_eq!(
            stats.candidate_type,
            candidate.candidate_type(),
            "invalid stats CandidateType"
        );
        assert_eq!(
            stats.priority,
            candidate.priority(),
            "invalid stats priority"
        );
        assert_eq!(stats.ip, candidate.address(), "invalid stats IP");
        assert_eq!(stats.port, candidate.port(), "invalid stats port");
        assert_eq!(
            stats.network_type,
            candidate.network_type(),
            "invalid stats network type"
        );
        assert_eq!(stats.timestamp, base);
    }

    assert!(seen[0], "missing host local stat");
    assert!(seen[1], "missing srflx local stat");

    a.close()?;
    Ok(())
}

#[test]
fn test_remote_candidate_stats() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;

    let relay_remote = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    }
    .new_candidate_relay()?;

    let srflx_remote = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19218,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43212,
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;

    let prflx_remote = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19217,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43211,
    }
    .new_candidate_peer_reflexive()?;

    let host_remote = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.5".to_owned(),
            port: 12350,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;

    let expected = vec![relay_remote, srflx_remote, prflx_remote, host_remote];
    for remote in &expected {
        a.remote_candidates.push(remote.clone());
    }

    let remote_stats = a.get_remote_candidates_stats(base);
    assert_eq!(
        remote_stats.len(),
        4,
        "expected 4 remote candidates stats, got {} instead",
        remote_stats.len()
    );

    let mut seen = [false; 4];
    for stats in remote_stats {
        let index = expected
            .iter()
            .position(|c| c.id() == stats.id)
            .expect("invalid remote candidate ID");
        seen[index] = true;
        let candidate = &expected[index];

        assert_eq!(
            stats.candidate_type,
            candidate.candidate_type(),
            "invalid stats CandidateType"
        );
        assert_eq!(
            stats.priority,
            candidate.priority(),
            "invalid stats priority"
        );
        assert_eq!(stats.ip, candidate.address(), "invalid stats IP");
        assert_eq!(stats.port, candidate.port(), "invalid stats port");
        assert_eq!(stats.timestamp, base);
    }

    assert!(seen[0], "missing relay remote stat");
    assert!(seen[1], "missing srflx remote stat");
    assert!(seen[2], "missing prflx remote stat");
    assert!(seen[3], "missing host remote stat");

    a.close()?;
    Ok(())
}

#[test]
fn test_binding_request_timeout() -> Result<()> {
    const EXPECTED_REMAINING: usize = 2;

    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;

    // Offsets are taken from an instant well after `base`, so no subtraction underflows.
    let now = base + Duration::from_secs(100);
    let destination = SocketAddr::from_str("0.0.0.0:0")?;
    for timestamp in [
        now,                               // valid
        now - Duration::from_millis(3900), // valid
        now - Duration::from_millis(4100), // expired
        now - Duration::from_secs(75),     // expired
    ] {
        // Each waits 4 seconds for its response.
        a.pending_binding_requests.push(BindingRequest::sent_once(
            timestamp,
            TransactionId::new(),
            destination,
            Duration::from_secs(4),
        ));
    }

    a.run_transactions(now);
    assert_eq!(
        a.pending_binding_requests.len(),
        EXPECTED_REMAINING,
        "Binding invalidation due to timeout did not remove the correct number of binding requests"
    );

    a.close()?;
    Ok(())
}

/// Local username fragments and passwords meet RFC 8445 §5.3: generated ones carry at least 24
/// and 128 bits, and configured ones shorter than that are refused.
#[test]
fn test_agent_credentials() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;
    assert!(a.get_local_credentials().ufrag.len() * 8 >= 24);
    assert!(a.get_local_credentials().pwd.len() * 8 >= 128);
    a.close()?;

    match Agent::new(
        base,
        Arc::new(AgentConfig {
            local_ufrag: "xx".to_owned(),
            ..Default::default()
        }),
        provider(),
    ) {
        Err(err) => assert_eq!(err, Error::ErrLocalUfragInsufficientBits),
        Ok(_) => panic!("expected error, but got ok"),
    }

    match Agent::new(
        base,
        Arc::new(AgentConfig {
            local_pwd: "xxxxxx".to_owned(),
            ..Default::default()
        }),
        provider(),
    ) {
        Err(err) => assert_eq!(err, Error::ErrLocalPwdInsufficientBits),
        Ok(_) => panic!("expected error, but got ok"),
    }

    Ok(())
}

/// Assert that an agent that fails deletes all its candidates; an ICE restart brings it back.
#[test]
fn test_connection_state_failed_delete_all_candidates() -> Result<()> {
    let base = Instant::now();
    let (mut a, mut b) = agent_pair(base, short_timeouts_config(), short_timeouts_config())?;
    start_both(&mut a, &mut b, base)?;
    let connected_at = connect(&mut a, &mut b, base)?;
    // No candidate is to come (W3C webrtc-pc 5.6.4: "failed" needs it).
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();

    // The network goes away: nothing `a` sends is answered. Consent lapses after 2 s; the
    // agent fails as the PAC timer expires, 39.5 s after the checks began (W3C webrtc-pc
    // 5.6.4: "or the PAC timer has expired").
    for i in 1..=500u32 {
        let now = connected_at + Duration::from_millis(100) * i;
        a.handle_timeout(now)?;
        drop_writes(&mut a);
        if a.state() == ConnectionState::Failed {
            break;
        }
    }

    assert_eq!(a.state(), ConnectionState::Failed);
    assert!(a.get_local_candidates().is_empty());
    assert!(a.get_remote_candidates().is_empty());
    assert!(a.get_selected_candidate_pair().is_none());

    a.close()?;
    b.close()?;
    Ok(())
}

/// Assert that both agents can go directly from Checking to Failed.
#[test]
fn test_connection_state_connecting_to_failed() -> Result<()> {
    let base = Instant::now();
    let (mut a, mut b) = agent_pair(base, short_timeouts_config(), short_timeouts_config())?;
    a.start_connectivity_checks(
        base,
        true,
        "InvalidFrag".to_owned(),
        "InvalidPwd".to_owned(),
    )?;
    b.start_connectivity_checks(
        base,
        false,
        "InvalidFrag".to_owned(),
        "InvalidPwd".to_owned(),
    )?;
    // Neither side has a candidate to come (W3C webrtc-pc 5.6.4: "failed" needs it).
    for agent in [&mut a, &mut b] {
        agent.set_local_gathering_complete();
        agent.set_remote_end_of_candidates();
    }

    // The checks get no valid answer: each is a transaction that ends after 39.5 seconds
    // (RFC 8489 Section 6.2.1), and only then, every pair failed, the agent fails (RFC 8445
    // Section 8.1.2), however short its timeouts.
    let (mut a_states, mut b_states) = (vec![], vec![]);
    for i in 0..600u32 {
        let now = base + Duration::from_millis(100) * i;
        step(&mut a, &mut b, now)?;
        a_states.extend(states(&mut a));
        b_states.extend(states(&mut b));
        if a.state() == ConnectionState::Failed && b.state() == ConnectionState::Failed {
            break;
        }
    }

    for (name, seen) in [("a", &a_states), ("b", &b_states)] {
        assert!(
            seen.contains(&ConnectionState::Checking),
            "{name} never reported Checking: {seen:?}"
        );
        assert!(
            seen.contains(&ConnectionState::Failed),
            "{name} never reported Failed: {seen:?}"
        );
        assert!(
            !seen.contains(&ConnectionState::Connected)
                && !seen.contains(&ConnectionState::Completed),
            "{name} connected with wrong credentials: {seen:?}"
        );
    }

    a.close()?;
    b.close()?;
    Ok(())
}

#[test]
fn test_agent_restart_when_closed() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;
    a.close()?;

    match a.restart(base, String::new(), String::new(), false) {
        Err(err) => assert_eq!(err, Error::ErrClosed),
        Ok(()) => panic!("restarting a closed agent must fail"),
    }
    assert_eq!(
        a.state(),
        ConnectionState::Closed,
        "a refused restart leaves the agent closed"
    );

    Ok(())
}

/// One side restarts: it no longer answers the other's checks, so the other side goes to
/// disconnected (or failed). The side that restarts stays connected (W3C webrtc-pc 5.6.4: the
/// path is kept until the new generation selects a pair; upstream went to checking).
#[test]
fn test_agent_restart_one_side() -> Result<()> {
    let base = Instant::now();
    let cfg = || AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(1)),
        failed_timeout: Some(Duration::from_secs(1)),
        ..quiet_config()
    };
    let (mut a, mut b) = agent_pair(base, cfg(), cfg())?;
    start_both(&mut a, &mut b, base)?;
    let connected_at = connect(&mut a, &mut b, base)?;
    let _ = states(&mut b);

    a.restart(connected_at, String::new(), String::new(), false)?;
    assert_eq!(a.state(), ConnectionState::Connected);
    assert!(
        a.get_remote_credentials().is_none(),
        "a restart waits for the peer's new credentials"
    );

    let mut b_states = vec![];
    for i in 1..=100u32 {
        let now = connected_at + Duration::from_millis(100) * i;
        step(&mut a, &mut b, now)?;
        b_states.extend(states(&mut b));
        if matches!(
            b.state(),
            ConnectionState::Disconnected | ConnectionState::Failed
        ) {
            break;
        }
    }

    assert!(
        b_states.contains(&ConnectionState::Disconnected)
            || b_states.contains(&ConnectionState::Failed),
        "the side that did not restart kept its connection: {b_states:?}"
    );

    a.close()?;
    b.close()?;
    Ok(())
}

/// Both sides restart, are given new candidates and each other's new credentials, and connect
/// again on the new candidates.
#[test]
fn test_agent_restart_both_side() -> Result<()> {
    const A_NEW_ADDR: &str = "192.168.0.1:6000";
    const B_NEW_ADDR: &str = "192.168.0.2:6001";

    let base = Instant::now();
    let cfg = || AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(1)),
        failed_timeout: Some(Duration::from_secs(1)),
        ..quiet_config()
    };
    let (mut a, mut b) = agent_pair(base, cfg(), cfg())?;
    start_both(&mut a, &mut b, base)?;
    let connected_at = connect(&mut a, &mut b, base)?;

    let a_first = a.get_local_credentials().clone();
    let b_first = b.get_local_credentials().clone();

    // Restart, re-gather (new ports) and re-signal.
    a.restart(connected_at, String::new(), String::new(), false)?;
    b.restart(connected_at, String::new(), String::new(), false)?;
    assert!(a.get_local_candidates().is_empty());
    assert!(b.get_local_candidates().is_empty());

    a.add_local_candidate(host(A_NEW_ADDR))?;
    b.add_local_candidate(host(B_NEW_ADDR))?;
    a.add_remote_candidate(host(B_NEW_ADDR))?;
    b.add_remote_candidate(host(A_NEW_ADDR))?;

    let a_credentials = a.get_local_credentials().clone();
    let b_credentials = b.get_local_credentials().clone();
    assert_ne!(a_credentials.ufrag, a_first.ufrag);
    assert_ne!(b_credentials.ufrag, b_first.ufrag);
    a.set_remote_credentials(b_credentials.ufrag, b_credentials.pwd)?;
    b.set_remote_credentials(a_credentials.ufrag, a_credentials.pwd)?;

    // Both stay connected through the restart (W3C webrtc-pc 5.6.4): run until each has
    // selected a pair of the new generation.
    let mut now = connected_at;
    for _ in 0..200 {
        step(&mut a, &mut b, now)?;
        if a.get_selected_candidate_pair().is_some() && b.get_selected_candidate_pair().is_some() {
            break;
        }
        now += STEP;
    }

    let (a_local, a_remote) = a
        .get_selected_candidate_pair()
        .expect("a selected a pair after the restart");
    assert_eq!(a_local.addr(), SocketAddr::from_str(A_NEW_ADDR)?);
    assert_eq!(a_remote.addr(), SocketAddr::from_str(B_NEW_ADDR)?);
    let (b_local, b_remote) = b
        .get_selected_candidate_pair()
        .expect("b selected a pair after the restart");
    assert_eq!(b_local.addr(), SocketAddr::from_str(B_NEW_ADDR)?);
    assert_eq!(b_remote.addr(), SocketAddr::from_str(A_NEW_ADDR)?);

    a.close()?;
    b.close()?;
    Ok(())
}

#[test]
fn test_get_remote_credentials() -> Result<()> {
    let base = Instant::now();
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider())?;
    assert!(a.get_remote_credentials().is_none());

    a.set_remote_credentials("remoteUfrag".to_owned(), "remotePwd".to_owned())?;

    let actual = a
        .get_remote_credentials()
        .expect("remote credentials were set");
    assert_eq!(actual.ufrag, "remoteUfrag");
    assert_eq!(actual.pwd, "remotePwd");

    a.close()?;
    Ok(())
}

/// Assert that a lite agent goes to disconnected and then failed once its peer goes away.
#[test]
fn test_lite_lifecycle() -> Result<()> {
    let base = Instant::now();
    let lite = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        check_interval: Duration::from_millis(500),
        ..short_timeouts_config()
    };
    let (mut a, mut b) = agent_pair(base, quiet_config(), lite)?;
    start_both(&mut a, &mut b, base)?;

    let connected_at = connect(&mut a, &mut b, base)?;
    assert!(
        states(&mut b).contains(&ConnectionState::Connected),
        "the lite agent reported Connected"
    );
    // No candidate is to come (W3C webrtc-pc 5.6.4: "failed" needs it).
    b.set_local_gathering_complete();
    b.set_remote_end_of_candidates();

    a.close()?;

    let mut b_states = vec![];
    for i in 1..=100u32 {
        let now = connected_at + Duration::from_millis(100) * i;
        b.handle_timeout(now)?;
        drop_writes(&mut b);
        b_states.extend(states(&mut b));
        if b.state() == ConnectionState::Failed {
            break;
        }
    }

    let disconnected = b_states
        .iter()
        .position(|s| *s == ConnectionState::Disconnected)
        .expect("the lite agent went to disconnected");
    let failed = b_states
        .iter()
        .position(|s| *s == ConnectionState::Failed)
        .expect("the lite agent went to failed");
    assert!(
        disconnected < failed,
        "disconnected comes before failed: {b_states:?}"
    );

    b.close()?;
    Ok(())
}

/// Runs `a` alone (its peer gone) from `from` until `done` or 60 s of virtual time; the
/// connection states it reported, and the time it stopped.
fn run_alone(
    a: &mut Agent,
    from: Instant,
    done: impl Fn(&Agent) -> bool,
) -> Result<(Vec<ConnectionState>, Instant)> {
    let mut seen = vec![];
    let mut now = from;
    while now < from + Duration::from_secs(60) {
        a.handle_timeout(now)?;
        while a.poll_write().is_some() {}
        seen.extend(states(a));
        if done(a) {
            break;
        }
        now += STEP;
    }
    Ok((seen, now))
}

fn short_timeouts() -> AgentConfig {
    AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(1)),
        failed_timeout: Some(Duration::from_secs(1)),
        ..quiet_config()
    }
}

/// W3C webrtc-pc 5.6.4 (RTCIceTransportState): "An ICE restart causes candidate gathering and
/// connectivity checks to begin anew, causing a transition to connected if begun in the
/// completed state". Begun in connected it stays connected: no checking on the way.
#[test]
fn test_a_restart_from_connected_or_completed_is_connected() -> Result<()> {
    let base = Instant::now();
    let (mut a, mut b) = agent_pair(base, short_timeouts(), short_timeouts())?;
    start_both(&mut a, &mut b, base)?;
    let connected_at = connect(&mut a, &mut b, base)?;
    let _ = states(&mut a);
    a.restart(connected_at, String::new(), String::new(), true)?;
    assert_eq!(a.state(), ConnectionState::Connected);
    assert!(states(&mut a).is_empty(), "no checking on the way");

    let (mut a, mut b) = agent_pair(base, short_timeouts(), short_timeouts())?;
    start_both(&mut a, &mut b, base)?;
    let mut now = connect(&mut a, &mut b, base)?;
    a.set_remote_end_of_candidates();
    a.set_local_gathering_complete();
    for _ in 0..200 {
        step(&mut a, &mut b, now)?;
        if a.state() == ConnectionState::Completed {
            break;
        }
        now += STEP;
    }
    assert_eq!(a.state(), ConnectionState::Completed);
    let _ = states(&mut a);
    a.restart(now, String::new(), String::new(), true)?;
    assert_eq!(states(&mut a), [ConnectionState::Connected]);
    Ok(())
}

/// "If begun in the transient disconnected state, it causes a transition to checking"; and
/// begun in failed. An agent connected through a restart whose kept path's consent expires
/// (RFC 7675 section 5.1) before the new generation selects a pair is checking.
#[test]
fn test_a_restart_from_disconnected_or_failed_is_checking() -> Result<()> {
    let base = Instant::now();
    for target in [ConnectionState::Disconnected, ConnectionState::Failed] {
        // Disconnected is transient: with a long failed timeout it lasts.
        let cfg = || match target {
            ConnectionState::Disconnected => AgentConfig {
                failed_timeout: Some(Duration::from_secs(25)),
                ..short_timeouts()
            },
            _ => short_timeouts(),
        };
        let (mut a, mut b) = agent_pair(base, cfg(), cfg())?;
        start_both(&mut a, &mut b, base)?;
        let connected_at = connect(&mut a, &mut b, base)?;
        if target == ConnectionState::Failed {
            // W3C webrtc-pc 5.6.4: "failed" needs the end of the candidates.
            a.set_local_gathering_complete();
            a.set_remote_end_of_candidates();
        }
        let (_, at) = run_alone(&mut a, connected_at, |a| a.state() == target)?;
        assert_eq!(a.state(), target);
        a.restart(at, String::new(), String::new(), true)?;
        assert_eq!(
            states(&mut a),
            [ConnectionState::Checking],
            "from {target:?}"
        );
    }

    let (mut a, mut b) = agent_pair(base, short_timeouts(), short_timeouts())?;
    start_both(&mut a, &mut b, base)?;
    let connected_at = connect(&mut a, &mut b, base)?;
    a.restart(connected_at, String::new(), String::new(), true)?;
    assert_eq!(a.state(), ConnectionState::Connected);
    let (seen, _) = run_alone(&mut a, connected_at, |a| {
        a.state() != ConnectionState::Connected
    })?;
    assert_eq!(seen.first(), Some(&ConnectionState::Checking), "{seen:?}");
    Ok(())
}
