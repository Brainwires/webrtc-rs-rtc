//! Rows of the RFC 8445, RFC 8838, RFC 6544, RFC 7675 and RFC 6762 audits that were open:
//! two lite agents, Ta agreed with the peer, IPv6 link-local pairing, what the transport
//! reports (ICMP, TCP connections), candidates after the nomination, consent over TCP, and
//! the mDNS options. Read from the wire in virtual time, as the other agent tests.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USERNAME;

use super::agent_rfc8445_test::*;
use super::agent_selector::{MAX_TCP_CONNECTION_ATTEMPTS_PER_ADDRESS, TransportError};
use super::*;
use crate::candidate::candidate_host::CandidateHostConfig;

const MS: Duration = Duration::from_millis(1);

fn candidate(
    network: &str,
    address: &str,
    port: u16,
    priority: u32,
    tcp_type: TcpType,
) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: network.to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            priority,
            ..Default::default()
        },
        tcp_type,
    }
    .new_candidate_host()
    .unwrap()
}

fn udp(address: &str, port: u16, priority: u32) -> Candidate {
    candidate("udp", address, port, priority, TcpType::Unspecified)
}

fn path(local: &str, remote: &str, transport_protocol: TransportProtocol) -> TransportContext {
    TransportContext {
        local_addr: addr(local),
        peer_addr: addr(remote),
        ecn: None,
        transport_protocol,
    }
}

fn events(a: &mut Agent) -> Vec<Event> {
    std::iter::from_fn(|| a.poll_event())
        .map(|e| e.event)
        .collect()
}

fn selected(a: &Agent) -> Option<SocketAddr> {
    a.get_selected_candidate_pair().map(|(_, r)| r.addr())
}

// --- RFC 8445 Sections 6.1.1, 6.2, 8.2: two lite agents ---

fn lite_agent(now: Instant, controlling: bool, remotes: &[Candidate]) -> Agent {
    lite_agent_with(now, controlling, &[], remotes)
}

/// [`lite_agent`] with the local candidates `locals` beside its UDP one.
fn lite_agent_with(
    now: Instant,
    controlling: bool,
    locals: &[Candidate],
    remotes: &[Candidate],
) -> Agent {
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(controlling)
    };
    let mut a = bare_agent(now, cfg);
    for local in locals {
        assert!(a.add_local_candidate(local.clone()).unwrap());
    }
    a.set_remote_lite(true);
    for remote in remotes {
        a.add_remote_candidate(remote.clone()).unwrap();
    }
    a.start_connectivity_checks(
        now,
        controlling,
        REMOTE_UFRAG.to_owned(),
        REMOTE_PWD.to_owned(),
    )
    .unwrap();
    a
}

/// RFC 6544 Section 4.4: "In the lite mode, for TCP candidates, only passive host candidates
/// are gathered, unless active candidates are needed as the default candidates. Otherwise,
/// the procedures described for lite mode in [RFC5245] also apply to TCP candidates." A lite
/// agent that has a UDP host candidate on an address takes a passive TCP candidate on it, and
/// an active one (the default candidate of the updated offer of two lite agents whose offerer
/// connects, Section 6.1; a lite agent cannot add it later without a restart, RFC 8839
/// Section 4.4.1.3): one of each per address, as RFC 8445 Section 5.2 has one UDP candidate
/// per address. A second of a kind and a simultaneous-open candidate are not taken.
#[test]
fn test_a_lite_agent_takes_one_passive_and_one_active_tcp_candidate_per_address() {
    let now = Instant::now();
    let mut a = lite_agent(now, false, &[]);
    let tcp = |port, tcp_type| candidate("tcp", "192.168.0.2", port, 0, tcp_type);
    assert!(a.add_local_candidate(tcp(2000, TcpType::Passive)).unwrap());
    assert!(a.add_local_candidate(tcp(9, TcpType::Active)).unwrap());
    assert!(
        !a.add_local_candidate(tcp(2001, TcpType::SimultaneousOpen))
            .unwrap(),
        "no simultaneous-open candidate"
    );
    assert!(
        !a.add_local_candidate(tcp(2002, TcpType::Passive)).unwrap(),
        "a second passive candidate on the address"
    );
    assert!(
        !a.add_local_candidate(udp("192.168.0.2", 1001, 0)).unwrap(),
        "a second UDP candidate on the address"
    );
    let kinds: Vec<(bool, TcpType)> = a
        .get_local_candidates()
        .iter()
        .map(|c| (c.network_type().is_tcp(), c.tcp_type()))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (false, TcpType::Unspecified),
            (true, TcpType::Passive),
            (true, TcpType::Active)
        ]
    );
}

/// RFC 8445 Section 8.2 with RFC 6544 Sections 6.1 and 6.2: two lite agents pair without
/// checks, and an active TCP candidate of the peer is the remote side of the pair with a
/// local passive one (the peer opens its connection, RFC 6544 Section 6.1). It is a remote
/// candidate like any other, not one only the peer's checks could pair (a full agent, or a
/// lite one with a full peer, still drops it: there the peer's checks find it). A controlled
/// agent with several pairs waits for the controlling agent's updated candidate exchange
/// (RFC 8445 Section 8.2) until it takes it.
#[test]
fn test_two_lite_agents_pair_the_peers_active_tcp_candidate() {
    let now = Instant::now();
    let active = candidate("tcp", "192.168.0.3", 9, 1000, TcpType::Active);
    let peer_udp = udp("192.168.0.3", 2000, 2000);
    let passive = candidate("tcp", "192.168.0.2", 2000, 0, TcpType::Passive);
    let mut b = lite_agent_with(
        now,
        false,
        std::slice::from_ref(&passive),
        &[active.clone(), peer_udp],
    );
    run(&mut b, now, now + Duration::from_secs(1));
    assert!(b.is_remote_lite());
    assert_eq!(
        b.get_remote_candidates().len(),
        2,
        "the active candidate is a remote candidate"
    );
    assert!(
        b.awaits_lite_update(),
        "several pairs: the update is to come"
    );

    let later = now + Duration::from_secs(1);
    assert!(b.replace_remote_candidates(later, vec![active.clone()]));
    run(&mut b, later, later + Duration::from_secs(1));
    assert!(!b.awaits_lite_update(), "the update was taken");
    let (local, remote) = b.get_selected_candidate_pair().expect("a pair");
    assert_eq!(
        (
            local.tcp_type(),
            local.addr(),
            remote.tcp_type(),
            remote.addr()
        ),
        (
            TcpType::Passive,
            addr("192.168.0.2:2000"),
            TcpType::Active,
            addr("192.168.0.3:9")
        )
    );

    // The controlling agent sends the update; it waits for none.
    let mut a = lite_agent_with(
        now,
        true,
        &[passive],
        &[active.clone(), udp("192.168.0.3", 2000, 0)],
    );
    run(&mut a, now, now + Duration::from_secs(1));
    assert!(a.get_selected_candidate_pair().is_some());
    assert!(!a.awaits_lite_update());

    // A lite agent with a full peer, and a full agent, drop it.
    let mut with_full_peer = bare_agent(
        now,
        AgentConfig {
            lite: true,
            candidate_types: vec![CandidateType::Host],
            ..config(false)
        },
    );
    assert!(!with_full_peer.is_remote_lite());
    assert!(!with_full_peer.add_remote_candidate(active.clone()).unwrap());
    assert!(with_full_peer.get_remote_candidates().is_empty());
    let mut full = started_agent(now, config(false), &[]);
    assert!(!full.add_remote_candidate(active).unwrap());
    assert!(full.get_remote_candidates().is_empty());
}

/// Section 6.1.1, both lite: "no connectivity checks are ever sent. Rather, once the
/// candidates are exchanged, each agent performs the processing described in Section 8
/// without connectivity checks." Section 8.2: "if there is only one candidate pair, that pair
/// is added to the valid list. [...] If all of the components for all data streams had one
/// pair, the state of ICE processing is Completed." Either role; the only STUN either sends
/// is the Binding indication that keeps the path alive (Section 11).
#[test]
fn test_two_lite_agents_select_the_one_pair_without_checks() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = lite_agent(now, controlling, &[udp("192.168.0.3", 2000, 0)]);
        a.set_local_gathering_complete();
        a.set_remote_end_of_candidates();
        let out = run(&mut a, now, now + Duration::from_secs(60));
        assert!(
            requests(&out).is_empty(),
            "a lite agent sent a Binding request (controlling: {controlling})"
        );
        assert!(!out.is_empty(), "keepalives");
        assert!(
            out.iter()
                .all(|(m, to)| m.typ.class == CLASS_INDICATION && *to == addr(REMOTE_A))
        );
        assert_eq!(selected(&a), Some(addr(REMOTE_A)));
        assert_eq!(a.media_path().unwrap().peer_addr, addr(REMOTE_A));
        // No Binding request ever arrives either: the state does not decay.
        assert_eq!(a.state(), ConnectionState::Completed);
        assert!(
            !events(&mut a)
                .iter()
                .any(|e| matches!(e, Event::LiteCandidateUpdate(..))),
            "one pair needs no updated candidate exchange"
        );
    }
}

/// Section 8.2, more than one pair: "it is RECOMMENDED that an agent follow the procedures of
/// RFC 6724 to select a pair", and "the controlling agent MUST send an updated candidate list
/// to reconcile different agents selecting different candidate pairs". The destination on the
/// local candidate's own network wins over one elsewhere (longest matching prefix), whatever
/// the candidate priorities say; the controlling agent asks for the updated exchange, once;
/// the controlled agent takes the update and uses the pair it names.
#[test]
fn test_two_lite_agents_with_several_pairs_select_by_rfc6724_and_update() {
    let now = Instant::now();
    let elsewhere = udp("10.0.0.1", 5000, 3000);
    let same_network = udp("192.168.0.9", 5000, 1000);
    let mut a = lite_agent(now, true, &[elsewhere.clone(), same_network.clone()]);
    let out = run(&mut a, now, now + Duration::from_secs(5));
    assert!(requests(&out).is_empty());
    assert_eq!(selected(&a), Some(addr("192.168.0.9:5000")));
    let updates: Vec<(SocketAddr, SocketAddr)> = events(&mut a)
        .into_iter()
        .filter_map(|e| match e {
            Event::LiteCandidateUpdate(local, remote) => Some((local.addr(), remote.addr())),
            _ => None,
        })
        .collect();
    assert_eq!(updates, vec![(addr(LOCAL), addr("192.168.0.9:5000"))]);
    run(
        &mut a,
        now + Duration::from_secs(5),
        now + Duration::from_secs(30),
    );
    assert!(events(&mut a).is_empty(), "the update is asked for once");

    // The controlled agent chose by the same rule; the controlling agent's update names
    // another candidate, and that is the pair from then on.
    let mut b = lite_agent(now, false, &[elsewhere.clone(), same_network]);
    run(&mut b, now, now + Duration::from_secs(1));
    assert_eq!(selected(&b), Some(addr("192.168.0.9:5000")));
    assert!(
        events(&mut b)
            .iter()
            .all(|e| !matches!(e, Event::LiteCandidateUpdate(..)))
    );
    let later = now + Duration::from_secs(1);
    assert!(b.replace_remote_candidates(later, vec![elsewhere]));
    run(&mut b, later, later + Duration::from_secs(1));
    assert_eq!(selected(&b), Some(addr("10.0.0.1:5000")));
    assert_eq!(b.get_remote_candidates().len(), 1);

    // It is the procedure of two lite agents only.
    let mut full = started_agent(now, config(true), &[REMOTE_A]);
    assert!(!full.replace_remote_candidates(now, vec![]));
    assert_eq!(full.get_remote_candidates().len(), 1);
}

/// RFC 8839 Section 4.4.2.2: a lite answerer offered `a=remote-candidates` forms its pair
/// with the local candidate the attribute names, even where the RFC 6724 preference would
/// take another local candidate (here the one on the remote's own network).
#[test]
fn test_a_lite_answerer_takes_the_local_candidate_remote_candidates_names() {
    let now = Instant::now();
    let remote = udp("192.168.0.9", 5000, 1000);
    let mut b = lite_agent(now, false, std::slice::from_ref(&remote));
    b.add_local_candidate(udp("10.0.0.2", 1000, 500)).unwrap();
    run(&mut b, now, now + Duration::from_secs(1));
    let local = |a: &Agent| a.get_selected_candidate_pair().map(|(l, _)| l.addr());
    assert_eq!(
        local(&b),
        Some(addr(LOCAL)),
        "the preference: the same network"
    );

    let later = now + Duration::from_secs(1);
    assert!(b.replace_remote_candidates_pinning(
        later,
        vec![remote.clone()],
        Some(addr("10.0.0.2:1000"))
    ));
    run(&mut b, later, later + Duration::from_secs(1));
    assert_eq!(
        local(&b),
        Some(addr("10.0.0.2:1000")),
        "the named local candidate"
    );
    assert_eq!(selected(&b), Some(addr("192.168.0.9:5000")));

    // Without a name, the preference decides again.
    let later = later + Duration::from_secs(1);
    assert!(b.replace_remote_candidates(later, vec![remote]));
    run(&mut b, later, later + Duration::from_secs(1));
    assert_eq!(local(&b), Some(addr(LOCAL)));
}

/// A lite agent whose peer is full still waits for the nomination (Section 8.2): the pair is
/// not selected from the candidate exchange.
#[test]
fn test_lite_agent_with_a_full_peer_waits_for_the_nomination() {
    let now = Instant::now();
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(false)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    run(&mut a, now, now + Duration::from_secs(2));
    assert_eq!(selected(&a), None);
}

// --- Section 14.2: Ta is agreed with the peer ---

/// "If an agent wants to use a Ta value other than the default value, the agent MUST indicate
/// the proposed value to its peer [...] Both agents MUST use the higher out of the two
/// proposed values."
#[test]
fn test_ta_is_the_higher_of_the_two_proposals() {
    let now = Instant::now();
    // Nothing configured: nothing to propose, and 50 ms.
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    assert_eq!(a.proposed_pacing(), None);
    assert_eq!(a.pacing(), 50 * MS);
    // The peer proposes more: its value.
    a.set_remote_pacing(Some(120 * MS));
    assert_eq!(a.pacing(), 120 * MS);
    // The peer proposes less than the default this agent uses: the default stays.
    a.set_remote_pacing(Some(10 * MS));
    assert_eq!(a.pacing(), 50 * MS);

    // 20 ms configured: proposed, and used only if the peer proposes no more.
    let cfg = AgentConfig {
        ta: Some(20 * MS),
        ..config(true)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    assert_eq!(a.proposed_pacing(), Some(20 * MS));
    a.set_remote_pacing(None);
    assert_eq!(
        a.pacing(),
        50 * MS,
        "a peer that proposes nothing uses 50 ms"
    );
    a.set_remote_pacing(Some(30 * MS));
    assert_eq!(a.pacing(), 30 * MS);
    a.set_remote_pacing(Some(20 * MS));
    assert_eq!(a.pacing(), 20 * MS);
    a.set_remote_pacing(Some(MS));
    assert_eq!(a.pacing(), 20 * MS);

    // The default written out is no proposal; under 5 ms is 5 ms (Section 14.2).
    let cfg = AgentConfig {
        ta: Some(50 * MS),
        ..config(true)
    };
    assert_eq!(started_agent(now, cfg, &[]).proposed_pacing(), None);
    let cfg = AgentConfig {
        ta: Some(MS),
        ..config(true)
    };
    assert_eq!(started_agent(now, cfg, &[]).proposed_pacing(), Some(5 * MS));
}

/// The agreed Ta is the one the checks are paced by.
#[test]
fn test_checks_are_paced_by_the_agreed_ta() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    for n in 1..=3 {
        a.add_remote_candidate(udp(&format!("192.168.1.{n}"), 5000, 1000 - n))
            .unwrap();
    }
    a.set_remote_pacing(Some(100 * MS));
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let mut started = vec![];
    let mut at = now;
    while at <= now + 450 * MS {
        a.handle_timeout(at).unwrap();
        while let Some(t) = a.poll_write() {
            started.push(t.now.duration_since(now));
        }
        at = match a.poll_timeout() {
            Some(next) => next.max(at + MS),
            None => break,
        };
    }
    assert_eq!(started, vec![Duration::ZERO, 100 * MS, 200 * MS]);
}

// --- Section 6.1.2.2: IPv6 link-local addresses ---

/// "IPv6 link-local addresses MUST NOT be paired with other than link-local addresses", in
/// either direction, and no setting lifts it.
#[test]
fn test_ipv6_link_local_pairs_only_with_link_local() {
    let now = Instant::now();
    let cfg = AgentConfig {
        allow_link_local_remote_candidates: true,
        ..config(true)
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(udp("fe80::1", 1000, 0)).unwrap();
    a.add_local_candidate(udp("2001:db8::1", 1000, 0)).unwrap();
    a.add_remote_candidate(udp("fe80::2", 2000, 0)).unwrap();
    a.add_remote_candidate(udp("2001:db8::2", 2000, 0)).unwrap();
    let mut pairs: Vec<(String, String)> = a
        .candidate_pairs
        .iter()
        .map(|p| {
            (
                a.local_candidates[p.local_index].addr().ip().to_string(),
                a.remote_candidates[p.remote_index].addr().ip().to_string(),
            )
        })
        .collect();
    pairs.sort();
    assert_eq!(
        pairs,
        vec![
            ("2001:db8::1".to_owned(), "2001:db8::2".to_owned()),
            ("fe80::1".to_owned(), "fe80::2".to_owned()),
        ]
    );
}

// --- Section 7.2.5.2.2 and RFC 6544 Section 7.1: what the transport reports ---

/// "If the agent supports processing of ICMP errors, and if a Binding request generates a
/// hard ICMP error, the agent SHOULD set the state of the candidate pair to Failed." The
/// check stops being retransmitted. An ICMP error is not authenticated: it fails neither a
/// pair that no check is in flight on nor one a check has validated.
#[test]
fn test_hard_icmp_error_fails_the_pair_whose_check_is_in_flight() {
    let now = Instant::now();
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(false)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A, REMOTE_B]);
    // Only A's check has started (Ta).
    let out = run(&mut a, now, now + 10 * MS);
    assert_eq!(requests(&out).len(), 1);
    let udp_path = |remote: &str| path(LOCAL, remote, TransportProtocol::UDP);
    assert!(
        !a.handle_transport_error(
            now + 10 * MS,
            udp_path(REMOTE_B),
            TransportError::IcmpHardError
        ),
        "no check is in flight on that pair"
    );
    assert!(!a.handle_transport_error(
        now + 10 * MS,
        udp_path("192.168.0.77:1"),
        TransportError::IcmpHardError
    ));
    assert!(a.handle_transport_error(
        now + 10 * MS,
        udp_path(REMOTE_A),
        TransportError::IcmpHardError
    ));
    let pair_to = |a: &Agent, remote: &str| {
        a.candidate_pairs[a
            .find_pair(0, a.find_remote_candidate(addr(remote)).unwrap())
            .unwrap()]
    };
    assert_eq!(pair_to(&a, REMOTE_A).state, CandidatePairState::Failed);
    // B is checked and answers; nothing more goes to A.
    let out = run_answering(
        &mut a,
        now + 10 * MS,
        now + Duration::from_secs(10),
        |_, _| true,
    );
    assert!(requests(&out).iter().all(|(_, to)| *to == addr(REMOTE_B)));
    assert!(pair_to(&a, REMOTE_B).valid);
    // A valid pair is not failed by an ICMP error.
    assert!(!a.handle_transport_error(
        now + Duration::from_secs(10),
        udp_path(REMOTE_B),
        TransportError::IcmpHardError
    ));
    assert_eq!(pair_to(&a, REMOTE_B).state, CandidatePairState::Succeeded);
}

/// A controlling agent with one active TCP candidate and `n` remote passive candidates on one
/// IP address (ports 5001...), each with a foundation of its own: candidates of one type on one
/// address would share a foundation, and RFC 8445 Section 6.1.2.6 then leaves all but the best
/// pair Frozen until it succeeds, so only one connection would ever be attempted.
fn tcp_agent(now: Instant, n: u16) -> Agent {
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(candidate("tcp", "192.168.0.2", 9, 0, TcpType::Active))
        .unwrap();
    for i in 1..=n {
        a.add_remote_candidate(
            CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "tcp".to_owned(),
                    address: "192.168.0.3".to_owned(),
                    port: 5000 + i,
                    component: 1,
                    priority: 10_000 - u32::from(i),
                    foundation: format!("t{i}"),
                    ..Default::default()
                },
                tcp_type: TcpType::Passive,
            }
            .new_candidate_host()
            .unwrap(),
        )
        .unwrap();
    }
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a
}

fn tcp_path(remote_port: u16) -> TransportContext {
    path(
        "192.168.0.2:40000",
        &format!("192.168.0.3:{remote_port}"),
        TransportProtocol::TCP,
    )
}

fn tcp_state(a: &Agent, remote_port: u16) -> CandidatePairState {
    let remote = addr(&format!("192.168.0.3:{remote_port}"));
    a.candidate_pairs[a
        .find_pair(0, a.find_remote_candidate(remote).unwrap())
        .unwrap()]
    .state
}

/// RFC 6544 Section 12: "an ICE agent SHOULD NOT have more than 5 outstanding TCP connection
/// attempts with the same peer to the same IP address." Section 7.1: "If the TCP connection
/// cannot be established, the check is considered to have failed, and a full-mode agent MUST
/// update the pair state to Failed": the transport says so, the pair fails at once (not 39.5
/// seconds later), and the next attempt takes its place.
#[test]
fn test_tcp_connection_attempts_are_limited_and_a_failed_connection_fails_the_pair() {
    let now = Instant::now();
    let mut a = tcp_agent(now, 8);
    let out = run(&mut a, now, now + Duration::from_secs(2));
    let attempted: Vec<u16> = requests(&out).iter().map(|(_, to)| to.port()).collect();
    assert_eq!(attempted, vec![5001, 5002, 5003, 5004, 5005]);
    assert_eq!(attempted.len(), MAX_TCP_CONNECTION_ATTEMPTS_PER_ADDRESS);
    assert_eq!(tcp_state(&a, 5006), CandidatePairState::Waiting);

    let later = now + Duration::from_secs(2);
    assert!(a.handle_transport_error(later, tcp_path(5002), TransportError::ConnectionFailed));
    assert_eq!(tcp_state(&a, 5002), CandidatePairState::Failed);
    let out = run(&mut a, later, later + Duration::from_secs(2));
    let attempted: Vec<u16> = requests(&out).iter().map(|(_, to)| to.port()).collect();
    assert_eq!(attempted, vec![5006], "one attempt ended, one more starts");

    // A connection that fails before its check started fails its pair as well.
    let later = later + Duration::from_secs(2);
    assert_eq!(tcp_state(&a, 5008), CandidatePairState::Waiting);
    assert!(a.handle_transport_error(later, tcp_path(5008), TransportError::ConnectionFailed));
    assert_eq!(tcp_state(&a, 5008), CandidatePairState::Failed);
    // And it is a report about TCP: the same call for a UDP path changes nothing.
    assert!(!a.handle_transport_error(
        later,
        path(
            "192.168.0.2:40000",
            "192.168.0.3:5007",
            TransportProtocol::UDP
        ),
        TransportError::ConnectionFailed
    ));
}

/// RFC 6544 Section 7.1: "If the response to the first connectivity check on the established
/// TCP connection is something other than a STUN message, the remote candidate address
/// apparently was not one of the peer's addresses, and the agent SHOULD close the connection
/// and consider all pairs with that remote candidate as failed."
#[test]
fn test_first_answer_that_is_not_stun_fails_the_pairs_of_that_remote_candidate() {
    let now = Instant::now();
    let mut a = tcp_agent(now, 2);
    run(&mut a, now, now + 10 * MS);
    assert_eq!(tcp_state(&a, 5001), CandidatePairState::InProgress);
    // No check is in flight to 5002 yet: nothing is concluded about it.
    assert!(!a.handle_transport_error(now + 10 * MS, tcp_path(5002), TransportError::NotStun));
    assert!(a.handle_transport_error(now + 10 * MS, tcp_path(5001), TransportError::NotStun));
    assert_eq!(tcp_state(&a, 5001), CandidatePairState::Failed);
    assert_ne!(tcp_state(&a, 5002), CandidatePairState::Failed);
    assert!(a.pending_binding_requests.is_empty());
}

/// The same, as the peer connection reports it (`Agent::handle_non_stun_before_validation`):
/// non-STUN data on a TCP connection this agent opened, from its active candidate, while the
/// check is in flight. Over UDP it concludes nothing.
#[test]
fn test_non_stun_data_on_a_connection_this_agent_opened_fails_the_pairs() {
    let now = Instant::now();
    let mut a = tcp_agent(now, 2);
    run(&mut a, now, now + 10 * MS);
    assert_eq!(tcp_state(&a, 5001), CandidatePairState::InProgress);
    let mut udp = tcp_path(5001);
    udp.transport_protocol = TransportProtocol::UDP;
    assert!(!a.handle_non_stun_before_validation(now + 10 * MS, udp));
    assert_eq!(tcp_state(&a, 5001), CandidatePairState::InProgress);
    assert!(a.handle_non_stun_before_validation(now + 10 * MS, tcp_path(5001)));
    assert_eq!(tcp_state(&a, 5001), CandidatePairState::Failed);
}

// --- RFC 6544 Sections 4.1, 4.2, 4.5: relayed TCP candidates (RFC 6062 allocations) ---

const RELAYED: &str = "203.0.113.5";

/// A relayed TCP candidate of a TURN TCP allocation (RFC 6062) at `RELAYED:port`.
fn relayed_tcp(port: u16, tcp_type: TcpType) -> Candidate {
    let mut c = crate::candidate::candidate_relay::CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: RELAYED.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 40000,
        url: None,
    }
    .new_candidate_relay()
    .unwrap();
    c.set_tcp_type(tcp_type);
    c
}

/// RFC 6544 Section 4.1: "the agent SHOULD obtain [...] passive relayed candidates [...] it
/// SHOULD also include an active candidate" (of the relayed address, port 9: Section 4.5); the
/// application holds the TURN TCP allocation (`rtci_turn` `Relay::connect`, `DataConnection`)
/// and hands the agent the relayed candidates. Section 6.2: they pair by `tcptype` like host
/// ones. The active relayed candidate's check goes to the peer's passive candidate on the
/// relayed path (the application opens it with a Connect and a data connection); a check from
/// the peer's active side that arrives on the passive relayed candidate (an accepted
/// ConnectionAttempt's data connection) is answered on that path.
#[test]
fn test_relayed_tcp_candidates_pair_by_tcptype_and_check_on_the_relayed_path() {
    let now = Instant::now();
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    let passive = relayed_tcp(5000, TcpType::Passive);
    let active = relayed_tcp(9, TcpType::Active);
    // Section 4.2: direction-pref 6 (active) and 4 (passive) for relayed candidates, as for
    // host ones.
    assert!(active.priority() > passive.priority());
    a.add_local_candidate(passive).unwrap();
    a.add_local_candidate(active).unwrap();
    a.add_remote_candidate(candidate("tcp", "192.168.0.3", 6000, 0, TcpType::Passive))
        .unwrap();
    // A signalled active candidate (port 9) is reached as the peer-reflexive candidate its
    // checks make, as for host candidates.
    assert!(
        !a.add_remote_candidate(candidate("tcp", "192.168.0.3", 9, 0, TcpType::Active))
            .unwrap()
    );
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();

    let local = |port: u16| {
        a.find_local_candidate(addr(&format!("{RELAYED}:{port}")), TransportProtocol::TCP)
    };
    let remote =
        |a: &Agent, port: u16| a.find_remote_candidate(addr(&format!("192.168.0.3:{port}")));
    let (lp, la) = (local(5000).unwrap(), local(9).unwrap());
    let rp = remote(&a, 6000).unwrap();
    assert!(
        a.find_pair(la, rp).is_some(),
        "active relayed with remote passive"
    );
    assert!(a.find_pair(lp, rp).is_none(), "passive with passive");

    // The active relayed candidate's check: to the peer's passive address, from the relayed
    // address, over TCP.
    a.handle_timeout(now + 10 * MS).unwrap();
    let out: Vec<TaggedBytesMut> = std::iter::from_fn(|| a.poll_write()).collect();
    let check = out
        .iter()
        .find(|t| t.transport.peer_addr == addr("192.168.0.3:6000"))
        .expect("a check to the passive remote candidate");
    assert_eq!(check.transport.transport_protocol, TransportProtocol::TCP);
    assert_eq!(
        check.transport.local_addr.ip(),
        addr(&format!("{RELAYED}:9")).ip()
    );
    assert!(
        out.iter()
            .all(|t| t.transport.peer_addr != addr("192.168.0.3:9")),
        "nothing goes to an active candidate's port 9"
    );

    // The peer's check over a data connection the TURN server accepted for the passive
    // relayed candidate: from the peer's ephemeral port, answered on the same path.
    let request = peer_request(
        &a,
        vec![
            Box::new(crate::attributes::control::AttrControlled(1)),
            Box::new(crate::attributes::priority::PriorityAttr(1)),
        ],
    );
    a.handle_read(TaggedBytesMut {
        now: now + 20 * MS,
        transport: TransportContext {
            local_addr: addr(&format!("{RELAYED}:5000")),
            peer_addr: addr("192.168.0.3:51000"),
            ecn: None,
            transport_protocol: TransportProtocol::TCP,
        },
        message: BytesMut::from(&request.raw[..]),
    })
    .unwrap();
    let answers: Vec<TaggedBytesMut> = std::iter::from_fn(|| a.poll_write()).collect();
    let answer = answers
        .iter()
        .find(|t| t.transport.peer_addr == addr("192.168.0.3:51000"))
        .expect("the check is answered");
    assert_eq!(
        answer.transport.local_addr,
        addr(&format!("{RELAYED}:5000"))
    );
    assert_eq!(answer.transport.transport_protocol, TransportProtocol::TCP);
    let mut m = Message {
        raw: answer.message.to_vec(),
        ..Message::default()
    };
    m.decode().unwrap();
    assert_eq!(m.typ, BINDING_SUCCESS);
    // The peer's active side is now a peer-reflexive candidate, paired with the passive
    // relayed one.
    let learned = remote(&a, 51000).expect("a peer-reflexive candidate for the peer's connection");
    assert_eq!(a.remote_candidates[learned].tcp_type(), TcpType::Active);
    assert!(
        a.find_pair(lp, learned).is_some(),
        "passive relayed with the peer's active side"
    );
}

/// RFC 6544 Section 4.2: for server-reflexive candidates the direction-pref order is
/// simultaneous-open (6), then active (4), then passive (2): an active or S-O srflx candidate
/// can work through a NAT that a passive one cannot.
#[test]
fn test_server_reflexive_tcp_direction_preferences() {
    let srflx = |tcp_type: TcpType| {
        let mut c = crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: "198.51.100.7".to_owned(),
                port: 7000,
                component: 1,
                ..Default::default()
            },
            rel_addr: "192.168.0.2".to_owned(),
            rel_port: 40000,
            url: None,
        }
        .new_candidate_server_reflexive()
        .unwrap();
        c.set_tcp_type(tcp_type);
        c.priority()
    };
    let (so, active, passive) = (
        srflx(TcpType::SimultaneousOpen),
        srflx(TcpType::Active),
        srflx(TcpType::Passive),
    );
    assert!(so > active && active > passive, "{so} {active} {passive}");
}

// --- RFC 8838 Section 13: no candidate after the nomination ---

/// "In all cases, an agent MUST NOT trickle any new candidates within an ICE session after
/// nomination of a candidate pair": a local candidate gathered after it is not taken (and so
/// not announced); an ICE restart takes candidates again.
#[test]
fn test_local_candidates_are_refused_after_the_nomination() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    assert!(a.add_local_candidate(udp("192.168.0.20", 1000, 0)).unwrap());
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    assert!(a.get_selected_candidate_pair().is_some());
    let before = a.get_local_candidates().len();
    assert!(!a.add_local_candidate(udp("192.168.0.21", 1000, 0)).unwrap());
    assert_eq!(a.get_local_candidates().len(), before);

    a.restart(
        now + Duration::from_secs(2),
        String::new(),
        String::new(),
        true,
    )
    .unwrap();
    assert!(a.add_local_candidate(udp("192.168.0.21", 1000, 0)).unwrap());
}

// `Agent::withdraw_local_candidate` and the staged ICE restart, one test per row of the table
// in its documentation (with or without a restart staged, before and after `apply_restart`,
// discard, revert, gathered again). The other "which generation" questions while a restart is
// staged have their own tests: the staged credentials are what `get_local_credentials` gives
// while the live session keeps authenticating with its own
// (`agent_ported_test.rs::test_staged_ice_restart_keeps_live_session_authenticating`, and
// `test_staged_credentials_are_the_next_generation_s` below); a candidate gathered while staged
// is the next generation's
// (`test_a_candidate_gathered_for_a_staged_restart_is_kept_and_not_paired_before_it`).

const OTHER: &str = "192.168.0.22:1000";

/// A controlling agent with `LOCAL` and `OTHER`, its pair `LOCAL`-`REMOTE_A` selected.
fn selected_agent(now: Instant) -> Agent {
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    assert!(a.add_local_candidate(udp("192.168.0.22", 1000, 0)).unwrap());
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    assert!(
        a.get_selected_candidate_pair().is_some(),
        "a pair is selected"
    );
    a
}

fn selected_local(a: &Agent) -> Option<SocketAddr> {
    a.get_selected_candidate_pair().map(|(l, _)| l.addr())
}

fn pairs_of(a: &Agent, local: SocketAddr) -> usize {
    a.get_candidate_pairs()
        .iter()
        .filter(|(l, _)| l.addr() == local)
        .count()
}

fn signalled(a: &Agent, local: SocketAddr) -> bool {
    a.get_local_candidates_to_signal()
        .iter()
        .any(|c| c.addr() == local)
}

fn held(a: &Agent, local: SocketAddr) -> bool {
    a.get_local_candidates().iter().any(|c| c.addr() == local)
}

const UDP: shared::TransportProtocol = shared::TransportProtocol::UDP;

/// Row "its other pairs" and "new pairs": a candidate that carries no data loses its pairs,
/// forms none with a later remote candidate, is not signalled, and the next restart drops it;
/// the selected pair is untouched.
#[test]
fn test_withdrawing_a_candidate_that_carries_no_data_removes_its_pairs() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    let other = [addr(LOCAL), addr(OTHER)]
        .into_iter()
        .find(|c| *c != selected)
        .unwrap();
    assert!(pairs_of(&a, other) > 0);
    assert!(a.withdraw_local_candidate(now, other, UDP));
    assert_eq!(pairs_of(&a, other), 0, "its pairs are removed");
    assert!(!a.withdraw_local_candidate(now, other, UDP), "once");
    a.add_remote_candidate(udp("10.0.0.9", 7000, 0)).unwrap();
    assert_eq!(
        pairs_of(&a, other),
        0,
        "no pair with a later remote candidate"
    );
    assert!(signalled(&a, selected) && !signalled(&a, other));
    assert_eq!(
        selected_local(&a),
        Some(selected),
        "the selected pair is untouched"
    );
    a.restart(now, String::new(), String::new(), true).unwrap();
    assert!(!held(&a, other), "the next restart drops it");
    assert!(held(&a, selected));
}

/// Row "its selected pair", no restart staged: the pair that carries the data stays (data and
/// consent go on), the candidate's other pairs go, it forms no new ones, it is not signalled;
/// the next restart drops it and runs its previous media path on it.
#[test]
fn test_withdrawing_the_candidate_of_the_selected_pair_keeps_that_pair() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    a.add_remote_candidate(udp("10.0.0.9", 7000, 0)).unwrap();
    assert!(a.withdraw_local_candidate(now, selected, UDP));
    assert_eq!(
        selected_local(&a),
        Some(selected),
        "the selected pair stays"
    );
    assert_eq!(pairs_of(&a, selected), 1, "only the selected pair is left");
    assert!(a.media_path().is_some_and(|p| p.local_addr == selected));
    assert!(!signalled(&a, selected));
    a.restart(now, String::new(), String::new(), true).unwrap();
    assert!(!held(&a, selected), "the next session does not have it");
    assert!(
        a.media_path().is_some_and(|p| p.local_addr == selected),
        "the restart's previous media path runs on it until the new pair"
    );
}

/// The same with a restart staged (the case of a host candidate added between createOffer
/// and setLocalDescription, which makes the engine start the next generation's links): the
/// staged credentials are what `get_local_credentials` gives, the current session keeps its
/// selected pair and media path, and `apply_restart` drops the candidate.
#[test]
fn test_a_candidate_withdrawn_while_a_restart_is_staged_leaves_the_current_session() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    assert!(a.withdraw_local_candidate(now, selected, UDP));
    assert_eq!(
        selected_local(&a),
        Some(selected),
        "the current session keeps it"
    );
    assert!(a.media_path().is_some_and(|p| p.local_addr == selected));
    a.apply_restart(now, true).unwrap();
    assert!(!held(&a, selected), "the new session does not have it");
    assert!(
        a.media_path().is_some_and(|p| p.local_addr == selected),
        "the previous path stays until the restart selects a pair"
    );
}

/// Row "staged credentials": while a restart is staged `get_local_credentials` gives the staged
/// credentials (the generation new candidates and the engine's gathering belong to), the live
/// session's stay in force, and `apply_restart` makes the staged ones current.
#[test]
fn test_staged_credentials_are_the_next_generation_s() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let live = a.ufrag_pwd.local_credentials.ufrag.clone();
    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    let staged = a.get_local_credentials().ufrag.clone();
    assert_ne!(staged, live);
    assert_eq!(
        a.ufrag_pwd.local_credentials.ufrag, live,
        "the live session's stay"
    );
    a.apply_restart(now, true).unwrap();
    assert_eq!(a.ufrag_pwd.local_credentials.ufrag, staged);
    assert_eq!(a.get_local_credentials().ufrag, staged);
}

/// Row "after the next apply_restart" for a candidate withdrawn only once the new session has
/// it (a restart that keeps the local candidates carried it over): its pairs in the new session
/// go, it forms none, and the previous media path, which is not a pair of the session, is not
/// affected.
#[test]
fn test_a_candidate_withdrawn_after_the_restart_leaves_the_new_session_only() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    a.restart(now, String::new(), String::new(), true).unwrap();
    assert!(held(&a, selected), "kept into the new session");
    a.add_remote_candidate(udp("10.0.0.9", 7000, 0)).unwrap();
    assert!(pairs_of(&a, selected) > 0, "paired in the new session");
    assert!(a.withdraw_local_candidate(now, selected, UDP));
    assert_eq!(pairs_of(&a, selected), 0, "no pair of the new session");
    assert!(
        a.media_path().is_some_and(|p| p.local_addr == selected),
        "the previous path is untouched"
    );
}

/// Row `discard_restart_credentials`: a staged restart abandoned after the withdrawal leaves the
/// current session as it was (its selected pair), the candidate withdrawn, and the next restart
/// drops it.
#[test]
fn test_a_withdrawal_outlives_an_abandoned_staged_restart() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    assert!(a.withdraw_local_candidate(now, selected, UDP));
    a.discard_restart_credentials();
    assert_eq!(selected_local(&a), Some(selected));
    assert!(!signalled(&a, selected));
    a.restart(now, String::new(), String::new(), true).unwrap();
    assert!(!held(&a, selected), "the next restart drops it");
}

/// Row `revert_restart`: a restart taken back restores the session as it was when the restart
/// was applied, so a withdrawal made after that is undone (the engine withdraws again); a
/// withdrawal then keeps the restored selected pair.
#[test]
fn test_a_reverted_restart_restores_the_session_and_a_new_withdrawal_keeps_its_pair() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    a.apply_restart_revertible(now, true).unwrap();
    assert!(a.withdraw_local_candidate(now, selected, UDP));
    assert!(a.revert_restart(now));
    assert_eq!(selected_local(&a), Some(selected), "the session is back");
    assert!(signalled(&a, selected), "as it was before the withdrawal");
    assert!(
        a.withdraw_local_candidate(now, selected, UDP),
        "withdrawn again"
    );
    assert_eq!(
        selected_local(&a),
        Some(selected),
        "its selected pair stays"
    );
}

/// Row "gathered again": a withdrawn candidate added again is not taken back.
#[test]
fn test_a_withdrawn_candidate_gathered_again_stays_withdrawn() {
    let now = Instant::now();
    let mut a = selected_agent(now);
    let selected = selected_local(&a).unwrap();
    let other = [addr(LOCAL), addr(OTHER)]
        .into_iter()
        .find(|c| *c != selected)
        .unwrap();
    assert!(a.withdraw_local_candidate(now, other, UDP));
    assert!(
        !a.add_local_candidate(udp(&other.ip().to_string(), other.port(), 0))
            .unwrap()
    );
    assert!(!signalled(&a, other));
    assert_eq!(pairs_of(&a, other), 0);
}

/// The same rule binds the session the nomination was made in, not the one a staged restart
/// begins: a candidate gathered while the restart is staged is taken, but not paired with the
/// current session's remote candidates, and the restart keeps it even when it discards the
/// previous generation's local candidates. A candidate held already that is gathered again in
/// that window is kept too; one that is not is discarded.
#[test]
fn test_a_candidate_gathered_for_a_staged_restart_is_kept_and_not_paired_before_it() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    assert!(a.add_local_candidate(udp("192.168.0.20", 1000, 0)).unwrap());
    assert!(a.add_local_candidate(udp("192.168.0.22", 1000, 0)).unwrap());
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    assert!(a.get_selected_candidate_pair().is_some());
    let pairs = a.get_candidate_pairs().len();

    a.generate_restart_credentials(String::new(), String::new())
        .unwrap();
    assert!(a.add_local_candidate(udp("192.168.0.21", 1000, 0)).unwrap());
    assert!(!a.add_local_candidate(udp("192.168.0.20", 1000, 0)).unwrap());
    assert_eq!(
        a.get_candidate_pairs().len(),
        pairs,
        "not paired in the session that nominated"
    );
    let staged: Vec<String> = a
        .get_restart_generation_local_candidates()
        .iter()
        .map(|c| c.address().to_owned())
        .collect();
    assert_eq!(staged, ["192.168.0.20", "192.168.0.21"]);

    a.apply_restart(now + Duration::from_secs(2), false)
        .unwrap();
    let kept: Vec<String> = a
        .get_local_candidates()
        .iter()
        .map(|c| c.address().to_owned())
        .collect();
    assert_eq!(kept, ["192.168.0.20", "192.168.0.21"]);
    assert!(a.get_restart_generation_local_candidates().is_empty());
}

// --- RFC 7675 Section 5.1 ---

/// "Consent checks run over every transport": on a TCP pair they are Binding requests on the
/// connection, 4 to 6 seconds apart, each a transaction of its own sent once.
#[test]
fn test_consent_checks_run_on_a_tcp_pair() {
    let now = Instant::now();
    let mut a = tcp_agent(now, 1);
    let answer = |a: &mut Agent, from: Instant, until: Instant| {
        let mut out = vec![];
        let mut at = from;
        loop {
            a.handle_timeout(at).unwrap();
            while let Some(t) = a.poll_write() {
                assert_eq!(t.transport.transport_protocol, TransportProtocol::TCP);
                let mut m = Message {
                    raw: t.message.to_vec(),
                    ..Message::default()
                };
                m.decode().unwrap();
                let response = peer_response(
                    BINDING_SUCCESS,
                    m.transaction_id,
                    addr("192.168.0.2:40000"),
                    None,
                );
                a.handle_read(TaggedBytesMut {
                    now: at,
                    transport: tcp_path(5001),
                    message: BytesMut::from(&response.raw[..]),
                })
                .unwrap();
                out.push((t.now, m));
            }
            match a.poll_timeout() {
                Some(next) if next <= until => at = next.max(at + MS),
                _ => return out,
            }
        }
    };
    answer(&mut a, now, now + Duration::from_secs(1));
    assert_eq!(a.state(), ConnectionState::Connected);
    let consent = answer(
        &mut a,
        now + Duration::from_secs(1),
        now + Duration::from_secs(31),
    );
    assert!(
        consent.len() >= 5,
        "{} consent checks in 30 s",
        consent.len()
    );
    let mut ids: Vec<TransactionId> = consent.iter().map(|(_, m)| m.transaction_id).collect();
    ids.dedup();
    assert_eq!(ids.len(), consent.len(), "each one is sent once");
    for pair in consent.windows(2) {
        let gap = pair[1].0.duration_since(pair[0].0);
        assert!(
            (Duration::from_secs(4)..=Duration::from_secs(6)).contains(&gap),
            "{gap:?}"
        );
    }
    assert_eq!(a.state(), ConnectionState::Connected);
}

/// Consent on a TCP pair whose round trip is long (RFC 7675 Section 5.1: "consent checks MUST
/// be performed over all transport connections, including TCP"): each consent request is
/// answered 800 ms later, or 6 s later, more than the initial RTO, and each answer renews
/// consent. The pair is never given up.
#[test]
fn test_consent_is_kept_on_a_tcp_pair_whose_round_trip_is_long() {
    for round_trip in [800 * MS, 6000 * MS] {
        let now = Instant::now();
        let mut a = tcp_agent(now, 1);
        // Responses on their way: when each arrives.
        let mut in_flight: Vec<(Instant, Message)> = vec![];
        let mut states = vec![];
        let mut consent_requests = 0;
        let until = now + Duration::from_secs(120);
        let mut at = now;
        loop {
            in_flight.retain(|(arrival, response)| {
                if *arrival > at {
                    return true;
                }
                a.handle_read(TaggedBytesMut {
                    now: at,
                    transport: tcp_path(5001),
                    message: BytesMut::from(&response.raw[..]),
                })
                .unwrap();
                false
            });
            a.handle_timeout(at).unwrap();
            while let Some(t) = a.poll_write() {
                assert_eq!(t.transport.transport_protocol, TransportProtocol::TCP);
                let mut m = Message {
                    raw: t.message.to_vec(),
                    ..Message::default()
                };
                m.decode().unwrap();
                let response = peer_response(
                    BINDING_SUCCESS,
                    m.transaction_id,
                    addr("192.168.0.2:40000"),
                    None,
                );
                // The checks are answered at once; the consent requests after the round
                // trip.
                if a.get_selected_candidate_pair().is_some() {
                    consent_requests += 1;
                    in_flight.push((at + round_trip, response));
                } else {
                    in_flight.push((at, response));
                }
            }
            states.extend(events(&mut a).into_iter().filter_map(|e| match e {
                Event::ConnectionStateChange(s) => Some(s),
                _ => None,
            }));
            let arrival = in_flight.iter().map(|(arrival, _)| *arrival).min();
            let next = match (a.poll_timeout(), arrival) {
                (Some(timer), Some(arrival)) => Some(timer.min(arrival)),
                (timer, arrival) => timer.or(arrival),
            };
            match next {
                Some(next) if next <= until => at = next.max(at + Duration::from_micros(1)),
                _ => break,
            }
        }
        assert!(
            consent_requests >= 15,
            "{consent_requests} consent requests"
        );
        assert!(
            !states.contains(&ConnectionState::Failed),
            "{round_trip:?}: {states:?}"
        );
        if round_trip < Duration::from_secs(5) {
            assert!(
                !states.contains(&ConnectionState::Disconnected),
                "{round_trip:?}: {states:?}"
            );
        }
        let (_, remote) = a.get_selected_candidate_pair().unwrap();
        assert!(
            until - remote.last_consent().unwrap() < Duration::from_secs(7),
            "{round_trip:?}"
        );
    }
}

/// "After consent is lost, the same ICE credentials MUST NOT be used on the affected 5-tuple
/// again. That means that a new session, or an ICE restart, is needed": the agent that lost
/// consent is `Failed` and silent, and what a restart sends on the same 5-tuple carries
/// another username, also when the application pinned its credentials.
#[test]
fn test_after_consent_is_lost_the_same_credentials_are_not_used_again() {
    let now = Instant::now();
    let cfg = AgentConfig {
        local_ufrag: "pinnedufrag".to_owned(),
        local_pwd: "pinnedpasswordpinnedpassword".to_owned(),
        ..config(true)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    // No candidate is to come: losing consent fails the agent (W3C webrtc-pc 5.6.4).
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    let out = run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    let username = |m: &Message| String::from_utf8(m.get(ATTR_USERNAME).unwrap()).unwrap();
    let before = username(&requests(&out)[0].0);
    assert_eq!(before, format!("{REMOTE_UFRAG}:pinnedufrag"));

    // The peer falls silent: consent expires.
    run(
        &mut a,
        now + Duration::from_secs(1),
        now + Duration::from_secs(40),
    );
    assert_eq!(a.state(), ConnectionState::Failed);
    let silent = run(
        &mut a,
        now + Duration::from_secs(40),
        now + Duration::from_secs(80),
    );
    assert!(silent.is_empty(), "nothing is sent without consent");

    // An ICE restart, the application still asking for its pinned credentials.
    let later = now + Duration::from_secs(80);
    a.restart(
        later,
        "pinnedufrag".to_owned(),
        "pinnedpasswordpinnedpassword".to_owned(),
        false,
    )
    .unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    a.start_connectivity_checks(later, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = run(&mut a, later, later + Duration::from_secs(1));
    let after = username(&requests(&out)[0].0);
    assert_ne!(after, before, "the same credentials on the same 5-tuple");
}

// --- mDNS (RFC 6762, draft-ietf-mmusic-mdns-ice-candidates) ---

const MDNS_GROUP: &str = "224.0.0.251:5353";
const NAME: &str = "61b445d2-6503-41ac-96ce-ee3edac00e9f.local";

fn mdns_candidate() -> Candidate {
    unmarshal_candidate(&format!(
        "1114572465 1 udp 2113939711 {NAME} 61163 typ host"
    ))
    .unwrap()
}

/// When the agent's first mDNS datagram leaves, after `from`.
fn first_mdns_write(a: &mut Agent, from: Instant) -> Option<Duration> {
    let mut at = from;
    for _ in 0..1000 {
        a.handle_timeout(at).unwrap();
        while let Some(t) = a.poll_write() {
            if t.transport.peer_addr == addr(MDNS_GROUP) {
                return Some(t.now.duration_since(from));
            }
        }
        at = a.poll_timeout()?.max(at + MS);
        if at > from + Duration::from_secs(2) {
            return None;
        }
    }
    None
}

/// RFC 6762 Section 5.2: "the interval between the first two queries MUST be at least one
/// second [...] a Multicast DNS querier SHOULD also delay the first query of the series by a
/// randomly chosen amount in the range 20-120 ms." It is the agent's default;
/// `multicast_dns_first_query_delay: Some(false)` asks at once.
#[test]
fn test_first_mdns_query_waits_20_to_120_ms_by_default() {
    let now = Instant::now();
    let mut a = Agent::new(now, Arc::new(AgentConfig::default()), provider()).unwrap();
    assert!(!a.add_remote_candidate(mdns_candidate()).unwrap());
    let delay = first_mdns_write(&mut a, now).expect("a query");
    assert!((20 * MS..=120 * MS).contains(&delay), "{delay:?}");
    // The unresolved candidate is submitted, not held.
    assert_eq!(a.pending_mdns_candidates().count(), 1);
    assert!(a.get_remote_candidates().is_empty());

    let cfg = AgentConfig {
        multicast_dns_first_query_delay: Some(false),
        ..AgentConfig::default()
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    a.add_remote_candidate(mdns_candidate()).unwrap();
    assert_eq!(first_mdns_write(&mut a, now), Some(Duration::ZERO));
}

/// draft-ietf-mmusic-mdns-ice-candidates Section 7.1: the rate limit is the
/// implementation's, not one agent's. Two agents given clones of one `MdnsRateLimit` spend one
/// budget: with a budget of one message, the second agent's query waits for the first one's.
#[test]
fn test_agents_share_one_mdns_rate_limit() {
    let now = Instant::now();
    let limit = mdns::MdnsRateLimit::new(1, 1);
    let agent = |limit: Option<mdns::MdnsRateLimit>| {
        let cfg = AgentConfig {
            multicast_dns_first_query_delay: Some(false),
            multicast_dns_rate_limit: limit,
            ..AgentConfig::default()
        };
        let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
        a.add_remote_candidate(mdns_candidate()).unwrap();
        a
    };
    let (mut first, mut second) = (agent(Some(limit.clone())), agent(Some(limit)));
    assert_eq!(first_mdns_write(&mut first, now), Some(Duration::ZERO));
    let waited = first_mdns_write(&mut second, now).expect("the second agent's query");
    assert!(waited >= Duration::from_millis(900), "{waited:?}");

    // With limits of their own neither waits for the other.
    let (mut first, mut second) = (agent(None), agent(None));
    assert_eq!(first_mdns_write(&mut first, now), Some(Duration::ZERO));
    assert_eq!(first_mdns_write(&mut second, now), Some(Duration::ZERO));
}

/// RFC 6762 Section 6.7: a query from a source port other than 5353 is a legacy unicast
/// query and gets a conventional unicast reply. It reaches the mDNS connection because what
/// arrives on the mDNS socket (local port 5353) is mDNS whatever its source port; the reply
/// goes back to that port.
#[test]
fn test_legacy_unicast_query_is_answered_by_unicast() {
    let now = Instant::now();
    let cfg = AgentConfig {
        multicast_dns_mode: MulticastDnsMode::QueryAndGather,
        ..AgentConfig::default()
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    let name = a.get_local_candidates()[0].address().to_owned();
    assert!(name.ends_with(".local"));
    // Past the announcements.
    let mut at = now;
    while at < now + Duration::from_secs(5) {
        a.handle_timeout(at).unwrap();
        while a.poll_write().is_some() {}
        at = a
            .poll_timeout()
            .map_or(at + Duration::from_secs(1), |t| t.max(at + MS));
    }

    // A one-question query for the name, as a conventional DNS client sends it.
    let mut query = vec![0x12, 0x34, 0x00, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    a.handle_read(TaggedBytesMut {
        now: at,
        transport: path("0.0.0.0:5353", "192.168.0.50:40123", TransportProtocol::UDP),
        message: BytesMut::from(&query[..]),
    })
    .unwrap();
    a.handle_timeout(at).unwrap();
    let replies: Vec<TaggedBytesMut> = std::iter::from_fn(|| a.poll_write()).collect();
    assert_eq!(replies.len(), 1, "one reply");
    assert_eq!(replies[0].transport.peer_addr, addr("192.168.0.50:40123"));
    assert_eq!(&replies[0].message[..2], &[0x12, 0x34], "the query's ID");
    assert_ne!(replies[0].message[2] & 0x80, 0, "a response");
}

/// RFC 6762 Section 9: a host that finds its name in use by another "MUST [...] choose a new
/// name". The agent's probe for the name it was configured with meets a defender: the
/// candidate gets a new `<uuid>.local` name, which the responder answers for, and is reported
/// for the application to convey again.
#[test]
fn test_lost_mdns_name_is_replaced_and_the_candidate_announced_again() {
    use mdns::{Mdns, MdnsConfig, MdnsProbePolicy};

    let now = Instant::now();
    let lost = "ice-agent-host.local";
    let cfg = AgentConfig {
        multicast_dns_mode: MulticastDnsMode::QueryAndGather,
        multicast_dns_local_name: lost.to_owned(),
        multicast_dns_local_ip: Some("192.168.0.2".parse().unwrap()),
        ..AgentConfig::default()
    };
    let mut a = Agent::new(now, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    assert_eq!(a.get_local_candidates()[0].address(), lost);
    let id = a.get_local_candidates()[0].id().to_owned();
    // The first probe for the name goes out.
    let probed = first_mdns_write(&mut a, now).expect("a probe");
    let at = now + probed;

    // Another host owns the name and says so.
    let mut owner = Mdns::new(
        now,
        MdnsConfig::new()
            .with_local_names(vec![lost.to_owned()])
            .with_local_ip("192.168.0.77".parse().unwrap())
            .with_probe_policy(MdnsProbePolicy::Never),
    );
    owner.handle_timeout(at).unwrap();
    let announcement = owner.poll_write().expect("the owner announces its name");
    a.handle_read(TaggedBytesMut {
        now: at,
        transport: path(MDNS_GROUP, "192.168.0.77:5353", TransportProtocol::UDP),
        message: announcement.message,
    })
    .unwrap();

    let renamed: Vec<Candidate> = events(&mut a)
        .into_iter()
        .filter_map(|e| match e {
            Event::LocalCandidateRenamed(c) => Some(*c),
            _ => None,
        })
        .collect();
    assert_eq!(renamed.len(), 1);
    let name = renamed[0].address().to_owned();
    assert_ne!(name, lost);
    assert!(crate::mdns::is_ice_mdns_name(&name), "{name}");
    assert_eq!(renamed[0].id(), id, "the same candidate");
    assert_eq!(a.get_local_candidates()[0].address(), name);
    assert_eq!(
        a.get_local_candidates_to_signal()[0].marshal(),
        renamed[0].marshal()
    );
    assert!(renamed[0].marshal().contains(&name));
    // A candidate added later on that address is published under the new name too.
    a.add_local_candidate(udp("192.168.0.2", 1001, 0)).unwrap();
    assert_eq!(a.get_local_candidates()[1].address(), name);
}

/// RFC 8839 section 5.4: `ice-ufrag` is 4 to 256 `ice-char`s (letters, digits, `+`, `/`) and
/// "MUST NOT be longer than 32 characters when sending"; `ice-pwd` is 22 to 256. Credentials
/// the application supplies outside that are refused, when the agent is made and when it
/// restarts with them; the bounds themselves are taken.
#[test]
fn test_supplied_credentials_are_held_to_the_rfc_8839_grammar() {
    let now = Instant::now();
    let made = |ufrag: &str, pwd: &str| {
        Agent::new(
            now,
            Arc::new(AgentConfig {
                local_ufrag: ufrag.to_owned(),
                local_pwd: pwd.to_owned(),
                ..Default::default()
            }),
            provider(),
        )
        .map(|_| ())
    };
    let pwd = "p".repeat(22);
    assert_eq!(made("abc", &pwd), Err(Error::ErrLocalUfragInsufficientBits));
    assert_eq!(
        made("abcd", &"p".repeat(21)),
        Err(Error::ErrLocalPwdInsufficientBits)
    );
    assert_eq!(
        made(&"u".repeat(33), &pwd),
        Err(Error::ErrLocalUfragInvalid)
    );
    assert_eq!(made("ab-d", &pwd), Err(Error::ErrLocalUfragInvalid));
    assert_eq!(made("ab d", &pwd), Err(Error::ErrLocalUfragInvalid));
    assert_eq!(
        made("abcd", &"p".repeat(257)),
        Err(Error::ErrLocalPwdInvalid)
    );
    assert_eq!(
        made("abcd", &format!("{}:", "p".repeat(22))),
        Err(Error::ErrLocalPwdInvalid)
    );
    assert_eq!(made("abcd", &pwd), Ok(()));
    assert_eq!(made(&"u".repeat(32), &"p".repeat(256)), Ok(()));
    assert_eq!(made("a+/9", &format!("{}+/", "p".repeat(20))), Ok(()));

    let mut a = Agent::new(now, Arc::new(AgentConfig::default()), provider()).unwrap();
    assert_eq!(
        a.restart(now, "ab-d".to_owned(), pwd.clone(), false),
        Err(Error::ErrLocalUfragInvalid)
    );
    a.restart(now, "abcd".to_owned(), pwd, false).unwrap();
    assert_eq!(a.get_local_credentials().ufrag, "abcd");
}

/// RFC 8839 section 5.1: `raddr` and `rport` "MUST be present for server reflexive,
/// peer-reflexive and relayed candidates". A local server-reflexive or relayed candidate
/// without a related address would be written `raddr  rport 0`: the agent refuses it; with
/// one (or `0.0.0.0 0`, how a hidden base is written) it is taken.
#[test]
fn test_a_local_reflexive_candidate_needs_its_related_address() {
    use crate::candidate::candidate_relay::CandidateRelayConfig;
    use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
    let now = Instant::now();
    let mut a = Agent::new(now, Arc::new(AgentConfig::default()), provider()).unwrap();
    let base = |port: u16| CandidateConfig {
        network: "udp".to_owned(),
        address: "198.51.100.7".to_owned(),
        port,
        component: 1,
        ..Default::default()
    };
    let srflx = |rel_addr: &str, port: u16| {
        CandidateServerReflexiveConfig {
            base_config: base(port),
            rel_addr: rel_addr.to_owned(),
            rel_port: 5000,
            url: None,
        }
        .new_candidate_server_reflexive()
        .unwrap()
    };
    let relay = |rel_addr: &str, port: u16| {
        CandidateRelayConfig {
            base_config: base(port),
            rel_addr: rel_addr.to_owned(),
            rel_port: 5000,
            url: None,
        }
        .new_candidate_relay()
        .unwrap()
    };
    assert_eq!(
        a.add_local_candidate(srflx("", 6000)),
        Err(Error::ErrLocalCandidateWithoutRelatedAddress)
    );
    assert_eq!(
        a.add_local_candidate(relay("", 6001)),
        Err(Error::ErrLocalCandidateWithoutRelatedAddress)
    );
    assert_eq!(a.add_local_candidate(srflx("192.0.2.1", 6002)), Ok(true));
    assert_eq!(a.add_local_candidate(relay("0.0.0.0", 6003)), Ok(true));
}
