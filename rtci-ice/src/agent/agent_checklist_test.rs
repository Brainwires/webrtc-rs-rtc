//! The checklist of RFC 8445 (pair states, pruning, the pair limit, Ta, the triggered-check
//! queue, STUN transactions, the valid list, nomination, checklist states) and what RFC 8838
//! adds to it, read from the wire in virtual time.

use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USE_CANDIDATE;
use stun::error_code::CODE_BAD_REQUEST;

use super::agent_rfc8445_test::*;
use super::agent_selector::ChecklistState;
use super::*;
use crate::attributes::control::{AttrControlled, AttrControlling};
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
use crate::candidate::candidate_host::CandidateHostConfig;

const MS: Duration = Duration::from_millis(1);

/// One datagram the agent sent: when, the decoded message, where to, the raw bytes.
struct Sent {
    at: Duration,
    message: Message,
    to: SocketAddr,
    raw: Vec<u8>,
}

/// What the peer does with a request: nothing, a success response reporting `mapped` as the
/// source it saw, or an error response.
enum Answer {
    Silence,
    Success(SocketAddr),
    Error(stun::error_code::ErrorCode),
}

/// Runs the agent from `start + from` to `start + until`, waking it only when it asks to be,
/// and returns what it sent (times relative to `start`). Each Binding request gets `answer`'s
/// reply, from its destination, at once.
fn run_with(
    a: &mut Agent,
    start: Instant,
    from: Duration,
    until: Duration,
    mut answer: impl FnMut(&Sent) -> Answer,
) -> Vec<Sent> {
    let mut out = vec![];
    let mut now = start + from;
    loop {
        a.handle_timeout(now).unwrap();
        while let Some(t) = a.poll_write() {
            // An agent that publishes `.local` names also writes mDNS (from port 5353): not
            // a connectivity check.
            if t.transport.local_addr.port() == mdns::MDNS_PORT {
                continue;
            }
            let mut message = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            message.decode().unwrap();
            let sent = Sent {
                at: t.now.duration_since(start),
                message,
                to: t.transport.peer_addr,
                raw: t.message.to_vec(),
            };
            if sent.message.typ == BINDING_REQUEST {
                let id = sent.message.transaction_id;
                let reply = match answer(&sent) {
                    Answer::Silence => None,
                    Answer::Success(mapped) => {
                        Some(peer_response(BINDING_SUCCESS, id, mapped, None))
                    }
                    Answer::Error(code) => {
                        Some(peer_response(BINDING_ERROR, id, addr(LOCAL), Some(code)))
                    }
                };
                if let Some(reply) = reply {
                    let _ = deliver(a, now, &reply, &sent.to.to_string());
                }
            }
            out.push(sent);
        }
        match a.poll_timeout() {
            Some(next) if next <= start + until => now = next.max(now + Duration::from_micros(1)),
            _ => return out,
        }
    }
}

fn silent(a: &mut Agent, start: Instant, from: Duration, until: Duration) -> Vec<Sent> {
    run_with(a, start, from, until, |_| Answer::Silence)
}

fn answered(a: &mut Agent, start: Instant, from: Duration, until: Duration) -> Vec<Sent> {
    run_with(a, start, from, until, |_| Answer::Success(addr(LOCAL)))
}

fn requests_of(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|s| s.message.typ == BINDING_REQUEST)
        .collect()
}

/// The first transmission of each transaction, in the order they were started.
fn checks_started(sent: &[Sent]) -> Vec<&Sent> {
    let mut seen = vec![];
    requests_of(sent)
        .into_iter()
        .filter(|s| {
            let new = !seen.contains(&s.message.transaction_id);
            seen.push(s.message.transaction_id);
            new
        })
        .collect()
}

/// A remote host candidate at `10.0.0.<n>:5000` with the given priority and foundation.
fn remote(n: u8, priority: u32, foundation: &str) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: format!("10.0.0.{n}"),
            port: 5000,
            component: 1,
            priority,
            foundation: foundation.to_owned(),
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

fn remote_addr(n: u8) -> SocketAddr {
    format!("10.0.0.{n}:5000").parse().unwrap()
}

/// A checking agent with one local candidate and the remote candidates `(n, priority)`, each
/// with a foundation of its own, added in the order given. It never times out of checking.
fn agent_with(start: Instant, cfg: AgentConfig, remotes: &[(u8, u32)]) -> Agent {
    let controlling = cfg.is_controlling;
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..cfg
        },
    );
    for (n, priority) in remotes {
        a.add_remote_candidate(remote(*n, *priority, &format!("f{n}")))
            .unwrap();
    }
    a.start_connectivity_checks(
        start,
        controlling,
        REMOTE_UFRAG.to_owned(),
        REMOTE_PWD.to_owned(),
    )
    .unwrap();
    a
}

fn state_of(a: &Agent, n: u8) -> CandidatePairState {
    let remote_index = a.find_remote_candidate(remote_addr(n)).unwrap();
    a.candidate_pairs[a.find_pair(0, remote_index).unwrap()].state
}

fn states(a: &mut Agent) -> Vec<ConnectionState> {
    std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::ConnectionStateChange(s) => Some(s),
            _ => None,
        })
        .collect()
}

// --- Sections 6.1.2.3, 6.1.4.2, 14.2: order and pacing ---

/// Section 6.1.4.2: one check per Ta (50 ms by default, Section 14.2), the highest-priority
/// Waiting pair first (the checklist is ordered by pair priority, Section 6.1.2.3), whatever
/// order the candidates arrived in.
#[test]
fn test_checks_are_started_one_per_ta_in_priority_order() {
    let start = Instant::now();
    let mut a = agent_with(
        start,
        config(true),
        &[(3, 300), (1, 500), (5, 100), (2, 400), (4, 200)],
    );
    let out = silent(&mut a, start, Duration::ZERO, 450 * MS);
    let started = checks_started(&out);
    assert_eq!(started.len(), 5);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        (1..=5).map(remote_addr).collect::<Vec<_>>(),
        "decreasing pair priority"
    );
    assert_eq!(
        started.iter().map(|s| s.at).collect::<Vec<_>>(),
        (0..5).map(|i| 50 * MS * i).collect::<Vec<_>>(),
        "one check per Ta, none sooner"
    );
    // Nothing else left in the first 450 ms: no retransmission before the RTO.
    assert_eq!(requests_of(&out).len(), 5);
}

/// Section 14.2: Ta is configurable, and never under 5 ms.
#[test]
fn test_ta_is_configurable_and_at_least_five_milliseconds() {
    for (configured, effective) in [(20 * MS, 20 * MS), (MS, 5 * MS)] {
        let start = Instant::now();
        let cfg = AgentConfig {
            ta: Some(configured),
            ..config(false)
        };
        let mut a = agent_with(start, cfg, &[(1, 500), (2, 400), (3, 300)]);
        let out = silent(&mut a, start, Duration::ZERO, 400 * MS);
        let started = checks_started(&out);
        assert_eq!(
            started.iter().map(|s| s.at).collect::<Vec<_>>(),
            vec![Duration::ZERO, effective, effective * 2]
        );
    }
}

/// RFC 8838 Section 8: a checklist without pairs is no reason to send anything.
#[test]
fn test_empty_checklist_sends_nothing() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[]);
    assert!(silent(&mut a, start, Duration::ZERO, Duration::from_secs(5)).is_empty());
    assert_eq!(a.state(), ConnectionState::Checking);
}

// --- Section 14.3 and RFC 8489 Section 6.2.1: the transaction behind a check ---

/// An unanswered check is one STUN transaction: the same request (same transaction id, same
/// bytes) is retransmitted after RTO, 2 RTO, 4 RTO, ... (RTO is 500 ms at least), seven
/// requests in all, and the pair fails 16 RTO after the last one (Section 7.2.5.2.3).
#[test]
fn test_unanswered_check_is_retransmitted_with_backoff_and_then_fails_the_pair() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 39_499 * MS);

    let requests = requests_of(&out);
    assert_eq!(
        requests.iter().map(|s| s.at).collect::<Vec<_>>(),
        [0u32, 500, 1500, 3500, 7500, 15500, 31500]
            .map(|ms| MS * ms)
            .to_vec()
    );
    assert!(
        requests.iter().all(|s| s.raw == requests[0].raw),
        "a retransmission is the same message"
    );
    assert_eq!(state_of(&a, 1), CandidatePairState::InProgress);

    silent(&mut a, start, 39_499 * MS, 39_500 * MS);
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    assert!(a.pending_binding_requests.is_empty());
    // A failed pair is not checked again on the agent's own initiative.
    assert!(silent(&mut a, start, 39_500 * MS, Duration::from_secs(80)).is_empty());
}

/// Section 14.3: RTO = MAX(500 ms, Ta * (pairs Waiting + In-Progress)), taken when the check
/// starts: with 20 pairs to check the first one's is a second.
#[test]
fn test_rto_follows_the_number_of_pairs_still_to_check() {
    let start = Instant::now();
    let remotes: Vec<(u8, u32)> = (1..=20).map(|n| (n, 1000 - u32::from(n))).collect();
    let mut a = agent_with(start, config(true), &remotes);
    let out = silent(&mut a, start, Duration::ZERO, 1500 * MS);
    let to_first: Vec<Duration> = requests_of(&out)
        .iter()
        .filter(|s| s.to == remote_addr(1))
        .map(|s| s.at)
        .collect();
    assert_eq!(to_first, vec![Duration::ZERO, 1000 * MS]);
    // In-Progress pairs count as well as Waiting ones: the eleventh, started at 500 ms with
    // all twenty still unanswered, gets a second too.
    let to_eleventh: Vec<Duration> = requests_of(&out)
        .iter()
        .filter(|s| s.to == remote_addr(11))
        .map(|s| s.at)
        .collect();
    assert_eq!(to_eleventh, vec![500 * MS, 1500 * MS]);
}

/// `max_binding_requests` is Rc: with one request the pair fails 16 RTO later.
#[test]
fn test_request_count_of_a_transaction_is_configurable() {
    let start = Instant::now();
    let cfg = AgentConfig {
        max_binding_requests: Some(1),
        ..config(true)
    };
    let mut a = agent_with(start, cfg, &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 8 * Duration::from_secs(1));
    assert_eq!(requests_of(&out).len(), 1);
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
}

/// RFC 6544 Section 7.1: over TCP a check is sent once (the transport retransmits) and the
/// transaction waits Ti, 39.5 s.
#[test]
fn test_check_over_tcp_is_sent_once() {
    let start = Instant::now();
    let tcp = |address: &str, port: u16, tcp_type: TcpType| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: address.to_owned(),
                port,
                component: 1,
                ..Default::default()
            },
            tcp_type,
        }
        .new_candidate_host()
        .unwrap()
    };
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    };
    let mut a = Agent::new(start, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(tcp("192.168.0.2", 9, TcpType::Active))
        .unwrap();
    a.add_remote_candidate(tcp("10.0.0.1", 5000, TcpType::Passive))
        .unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = silent(&mut a, start, Duration::ZERO, 39_499 * MS);
    assert_eq!(requests_of(&out).len(), 1);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::InProgress);
    silent(&mut a, start, 39_499 * MS, 39_500 * MS);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
}

/// RFC 6544 Section 7: TCP and UDP pairs are in one checklist, ordered by pair priority (RFC
/// 8445 Section 6.1.2.3); Section 4.1 with RFC 8445 Section 6.1.4.2: a TCP check takes its
/// Ta like a UDP one. With a UDP and an active TCP local candidate and remote pairs whose
/// priorities alternate between the transports, the checks start one per Ta in decreasing
/// pair priority, UDP, TCP, UDP, TCP.
#[test]
fn test_tcp_and_udp_pairs_share_one_checklist_paced_one_per_ta() {
    let start = Instant::now();
    let tcp = |address: &str, tcp_type: TcpType, priority: u32, foundation: &str| {
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: address.to_owned(),
                port: if tcp_type == TcpType::Active { 9 } else { 5000 },
                component: 1,
                priority,
                foundation: foundation.to_owned(),
                ..Default::default()
            },
            tcp_type,
        }
        .new_candidate_host()
        .unwrap()
    };
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(true)
        },
    );
    a.add_local_candidate(tcp("192.168.0.2", TcpType::Active, 0, ""))
        .unwrap();
    a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
    a.add_remote_candidate(tcp("10.0.0.2", TcpType::Passive, 400, "f2"))
        .unwrap();
    a.add_remote_candidate(remote(3, 300, "f3")).unwrap();
    a.add_remote_candidate(tcp("10.0.0.4", TcpType::Passive, 200, "f4"))
        .unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert_eq!(
        a.candidate_pairs.len(),
        4,
        "a pair per transport, none across"
    );

    let out = silent(&mut a, start, Duration::ZERO, 450 * MS);
    let started = checks_started(&out);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        (1..=4).map(remote_addr).collect::<Vec<_>>(),
        "decreasing pair priority across both transports"
    );
    assert_eq!(
        started.iter().map(|s| s.at).collect::<Vec<_>>(),
        (0..4).map(|i| 50 * MS * i).collect::<Vec<_>>(),
        "one check per Ta, the TCP ones included"
    );
}

// --- Sections 6.1.2.6, 6.1.4.2, 7.2.5.3.3 and RFC 8838 Section 12: Frozen ---

/// Section 6.1.2.6: of the pairs with one foundation exactly one starts Waiting, the one with
/// the highest priority; the others are Frozen and are not checked while it is in progress.
/// Section 7.2.5.3.3: when it succeeds they become Waiting.
#[test]
fn test_pairs_of_one_foundation_wait_for_the_first_to_succeed() {
    let start = Instant::now();
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(false)
        },
    );
    a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
    a.add_remote_candidate(remote(1, 500, "shared")).unwrap();
    a.add_remote_candidate(remote(3, 300, "shared")).unwrap();
    a.add_remote_candidate(remote(4, 100, "other")).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Waiting);
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen);
    assert_eq!(state_of(&a, 3), CandidatePairState::Frozen);
    assert_eq!(state_of(&a, 4), CandidatePairState::Waiting);

    // Nobody answers for 400 ms: only the two Waiting pairs are checked.
    let out = silent(&mut a, start, Duration::ZERO, 400 * MS);
    assert_eq!(
        checks_started(&out)
            .iter()
            .map(|s| s.to)
            .collect::<Vec<_>>(),
        vec![remote_addr(1), remote_addr(4)]
    );
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen);

    // The retransmission to 1 (at 500 ms) is answered: its foundation is unfrozen.
    let out = run_with(&mut a, start, 400 * MS, 700 * MS, |s| {
        if s.to == remote_addr(1) {
            Answer::Success(addr(LOCAL))
        } else {
            Answer::Silence
        }
    });
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);
    let started: Vec<SocketAddr> = checks_started(&out)
        .iter()
        .map(|s| s.to)
        .filter(|to| *to == remote_addr(2) || *to == remote_addr(3))
        .collect();
    assert_eq!(started, vec![remote_addr(2), remote_addr(3)]);
}

/// Section 6.1.4.2, step 2: with no pair Waiting, a Frozen pair whose foundation has nothing
/// Waiting or In-Progress is unfrozen, here because the pair ahead of it failed.
#[test]
fn test_frozen_pair_is_unfrozen_when_its_foundation_has_nothing_in_flight() {
    let start = Instant::now();
    let mut a = bare_agent(
        start,
        AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(false)
        },
    );
    a.add_remote_candidate(remote(1, 500, "shared")).unwrap();
    a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen);

    let out = run_with(&mut a, start, Duration::ZERO, 200 * MS, |s| {
        if s.to == remote_addr(1) {
            Answer::Error(CODE_BAD_REQUEST)
        } else {
            Answer::Silence
        }
    });
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    let started = checks_started(&out);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        vec![remote_addr(1), remote_addr(2)]
    );
    assert_eq!(started[1].at, 50 * MS, "at the next Ta");
}

/// RFC 8838 Section 12, a pair formed while checks run: Waiting when it is the best of its
/// foundation (rule 1) or a pair of its foundation has succeeded (rule 2), Frozen otherwise
/// (rule 3).
#[test]
fn test_trickled_pair_starts_in_the_state_its_foundation_gives_it() {
    let start = Instant::now();
    let mut a = agent_with(start, config(false), &[]);
    a.add_remote_candidate(remote(1, 500, "shared")).unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Waiting, "rule 1");
    a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
    assert_eq!(state_of(&a, 2), CandidatePairState::Frozen, "rule 3");
    a.add_remote_candidate(remote(3, 600, "shared")).unwrap();
    assert_eq!(state_of(&a, 3), CandidatePairState::Waiting, "rule 1");

    run_with(&mut a, start, Duration::ZERO, 20 * MS, |_| {
        Answer::Success(addr(LOCAL))
    });
    assert_eq!(state_of(&a, 3), CandidatePairState::Succeeded);
    a.add_remote_candidate(remote(4, 100, "shared")).unwrap();
    assert_eq!(state_of(&a, 4), CandidatePairState::Waiting, "rule 2");
}

// --- Sections 5.1.3, 6.1.2.2, 6.1.2.4, 6.1.2.5: which pairs exist ---

fn srflx(address: &str, port: u16, base: SocketAddr) -> Candidate {
    crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        rel_addr: base.ip().to_string(),
        rel_port: base.port(),
        url: None,
    }
    .new_candidate_server_reflexive()
    .unwrap()
}

/// Section 6.1.2.4: a server-reflexive local candidate stands for its base, so its pair with
/// a remote candidate is redundant with the host candidate's and is pruned: one pair, one
/// check from the socket, whichever candidate came first.
#[test]
fn test_server_reflexive_pair_is_pruned_for_its_base() {
    for srflx_first in [false, true] {
        let start = Instant::now();
        let cfg = AgentConfig {
            failed_timeout: Some(Duration::ZERO),
            ..config(true)
        };
        let mut a = Agent::new(start, Arc::new(cfg), provider()).unwrap();
        let reflexive = srflx("203.0.113.5", 4000, addr(LOCAL));
        if srflx_first {
            a.add_local_candidate(reflexive).unwrap();
            a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
            a.add_local_candidate(host(addr(LOCAL))).unwrap();
        } else {
            a.add_local_candidate(host(addr(LOCAL))).unwrap();
            a.add_local_candidate(reflexive).unwrap();
            a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
        }
        assert_eq!(a.local_candidates.len(), 2);
        assert_eq!(a.candidate_pairs.len(), 1, "srflx first: {srflx_first}");
        let pair = a.candidate_pairs[0];
        assert_eq!(
            a.local_candidates[pair.local_index].candidate_type(),
            CandidateType::Host,
            "the higher-priority pair stays"
        );

        a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
            .unwrap();
        let out = silent(&mut a, start, Duration::ZERO, 400 * MS);
        assert_eq!(
            requests_of(&out).len(),
            1,
            "one check, not one per candidate"
        );
    }
}

/// Section 5.1.3: a candidate whose address and base equal another's is redundant and is not
/// kept: a server-reflexive candidate equal to its host candidate (no NAT), a relayed
/// candidate identical to a host candidate (Section 5.1.1.2).
#[test]
fn test_redundant_local_candidates_are_not_kept() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    let local = addr(LOCAL);
    assert!(a.add_local_candidate(host(local)).unwrap());
    assert!(
        !a.add_local_candidate(srflx(&local.ip().to_string(), local.port(), local))
            .unwrap()
    );
    let relay = crate::candidate::candidate_relay::CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local.ip().to_string(),
            port: local.port(),
            component: 1,
            ..Default::default()
        },
        rel_addr: "0.0.0.0".to_owned(),
        rel_port: 0,
        url: None,
    }
    .new_candidate_relay()
    .unwrap();
    assert!(!a.add_local_candidate(relay).unwrap());
    // A real mapping is another transport address: kept.
    assert!(
        a.add_local_candidate(srflx("203.0.113.5", 4000, local))
            .unwrap()
    );
    assert_eq!(a.local_candidates.len(), 2);
}

/// Section 6.1.2.2: candidates are paired only within a component. The agent has the RTP
/// component alone, so a candidate the peer signals for RTCP (pion and webrtc-rs signal every
/// candidate for both components, on the same address) is not held, and does not keep the RTP
/// candidate with that address out, whichever of the two arrives or resolves first.
#[test]
fn test_candidates_of_another_component_are_ignored() {
    let mut a = bare_agent(Instant::now(), config(true));
    let mut rtcp = remote(1, 500, "f1");
    rtcp.set_component(2);
    assert!(!a.add_remote_candidate(rtcp).unwrap());
    assert!(a.remote_candidates.is_empty());
    assert!(a.candidate_pairs.is_empty());
    // The RTP candidate on the same address is taken and paired.
    assert!(a.add_remote_candidate(remote(1, 500, "f1")).unwrap());
    assert_eq!(a.candidate_pairs.len(), 1);

    // The same for names: of an RTCP and an RTP candidate behind one mDNS name, only the RTP
    // one is resolved.
    let named = |component: u16| {
        let mut c = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "9b36eaac-bb2e-49bb-bb78-21c41c499900.local".to_owned(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap();
        c.set_component(component);
        c
    };
    let cfg = AgentConfig {
        multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryOnly,
        ..config(true)
    };
    let mut a = bare_agent(Instant::now(), cfg);
    a.add_remote_candidate(named(2)).unwrap();
    assert!(a.mdns_queries.is_empty());
    a.add_remote_candidate(named(1)).unwrap();
    assert_eq!(a.mdns_queries.len(), 1);
}

/// Section 6.1.2.5: the checklist holds 100 pairs by default, the limit is configurable, and
/// when it is full a better pair takes the place of the worst one that has not been checked
/// (RFC 8838 Section 11: of a Failed one first).
#[test]
fn test_checklist_is_limited_to_100_pairs_and_keeps_the_best() {
    let start = Instant::now();
    let mut a = bare_agent(start, config(true));
    for n in 1..=120u8 {
        a.add_remote_candidate(remote(n, 1000 + u32::from(n), &format!("f{n}")))
            .unwrap();
    }
    assert_eq!(a.candidate_pairs.len(), 100);
    let lowest = a
        .candidate_pairs
        .iter()
        .map(|p| p.remote_priority)
        .min()
        .unwrap();
    assert_eq!(lowest, 1021, "the 100 highest-priority pairs");

    // Configured: 3 pairs. A worse pair is dropped; a Failed pair gives way to any new one.
    let cfg = AgentConfig {
        max_candidate_pairs: Some(3),
        ..config(true)
    };
    let mut a = bare_agent(start, cfg);
    for n in [5u8, 6, 7] {
        a.add_remote_candidate(remote(n, 1000 + u32::from(n), &format!("f{n}")))
            .unwrap();
    }
    a.add_remote_candidate(remote(1, 1001, "f1")).unwrap();
    assert_eq!(a.candidate_pairs.len(), 3);
    assert!(a.find_pair(0, 3).is_none(), "a worse pair does not get in");
    let failed = a
        .find_pair(0, a.find_remote_candidate(remote_addr(7)).unwrap())
        .unwrap();
    a.candidate_pairs[failed].state = CandidatePairState::Failed;
    a.add_remote_candidate(remote(2, 1002, "f2")).unwrap();
    assert_eq!(a.candidate_pairs.len(), 3);
    let priorities: Vec<u32> = a
        .candidate_pairs
        .iter()
        .map(|p| p.remote_priority)
        .collect();
    assert!(priorities.contains(&1002) && !priorities.contains(&1007));
}

// --- Sections 6.1.4.1, 7.3.1.4: the triggered-check queue ---

/// Sections 6.1.4.1 and 6.1.4.2: a request from the peer puts its pair on the triggered-check
/// queue, which is served, first in first out, before the ordinary checks, one check per Ta.
#[test]
fn test_triggered_checks_go_first_in_arrival_order() {
    let start = Instant::now();
    let mut a = agent_with(
        start,
        config(false),
        &[(1, 500), (2, 400), (3, 300), (4, 200), (5, 100)],
    );
    // The first check (to 1) has gone; 2 would be next.
    let out = silent(&mut a, start, Duration::ZERO, 10 * MS);
    assert_eq!(checks_started(&out).len(), 1);

    let from = |n: u8| format!("10.0.0.{n}:5000");
    for n in [5u8, 4] {
        let request = peer_request(
            &a,
            vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
        );
        deliver(&mut a, start + 20 * MS, &request, &from(n)).unwrap();
    }
    assert_eq!(state_of(&a, 5), CandidatePairState::Waiting);
    assert_eq!(a.triggered_queue.len(), 2);

    let out = silent(&mut a, start, 20 * MS, 260 * MS);
    let started = checks_started(&out);
    assert_eq!(
        started.iter().map(|s| s.to).collect::<Vec<_>>(),
        [5u8, 4, 2, 3].map(remote_addr).to_vec()
    );
    assert_eq!(
        started.iter().map(|s| s.at).collect::<Vec<_>>(),
        [50u32, 100, 150, 200].map(|ms| MS * ms).to_vec(),
        "triggered checks are paced by Ta as well"
    );
}

/// Section 7.3.1.4: a request on a pair whose check is In-Progress cancels that transaction
/// (no more retransmissions, no failure) and triggers a new check; a late response to the
/// cancelled transaction is still taken.
#[test]
fn test_request_on_an_in_progress_pair_cancels_the_transaction_and_checks_again() {
    let start = Instant::now();
    let mut a = agent_with(start, config(false), &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 100 * MS);
    let first = checks_started(&out)[0].message.transaction_id;
    assert_eq!(state_of(&a, 1), CandidatePairState::InProgress);

    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start + 100 * MS, &request, "10.0.0.1:5000").unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Waiting);

    let out = silent(&mut a, start, 100 * MS, 3000 * MS);
    let ids: Vec<TransactionId> = requests_of(&out)
        .iter()
        .map(|s| s.message.transaction_id)
        .collect();
    assert!(!ids.is_empty());
    assert!(
        !ids.contains(&first),
        "the cancelled transaction is not retransmitted"
    );
    assert_eq!(
        requests_of(&out)[0].at,
        100 * MS,
        "the new check leaves at once"
    );

    // The answer to the first request arrives after all.
    let response = peer_response(BINDING_SUCCESS, first, addr(LOCAL), None);
    deliver(&mut a, start + 3000 * MS, &response, "10.0.0.1:5000").unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);
    // And the second transaction, now moot, does not fail the pair when it runs out.
    silent(&mut a, start, 3000 * MS, Duration::from_secs(60));
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);
}

/// Section 7.3.1.4: the pair of a request is (the local candidate it arrived on, its source),
/// and that local candidate is never a server-reflexive one, also when the server-reflexive
/// candidate was added first.
#[test]
fn test_request_is_credited_to_the_host_candidate_not_its_reflexive_one() {
    let start = Instant::now();
    let mut a = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
    a.add_local_candidate(srflx("203.0.113.5", 4000, addr(LOCAL)))
        .unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start, &request, REMOTE_A).unwrap();
    assert_eq!(a.candidate_pairs.len(), 1);
    let local = &a.local_candidates[a.candidate_pairs[0].local_index];
    assert_eq!(local.candidate_type(), CandidateType::Host);
}

/// Section 7.3.1.4: the local candidate has "the transport address (as seen by the agent) on
/// which the STUN request was received". An unspecified local address (what a socket bound to
/// `0.0.0.0` / `[::]` reports as its own) is no host candidate's: a request on it is discarded
/// as before (no pair, no peer-reflexive candidate, no response), and the log line says why
/// instead of the generic one. Matching is unchanged: a server-reflexive candidate whose
/// related address is that unspecified address still takes it.
#[test]
fn test_a_request_on_an_unspecified_local_address_is_discarded_and_the_log_says_why() {
    use super::agent_proto::unmatched_local_address_log;

    let start = Instant::now();
    let mut a = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    for wildcard in ["0.0.0.0:1000", "[::]:1000"] {
        let transport = TransportContext {
            local_addr: addr(wildcard),
            peer_addr: addr(REMOTE_A),
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        };
        let result = a.handle_read(TaggedBytesMut {
            now: start,
            transport,
            message: BytesMut::from(&request.raw[..]),
        });
        assert_eq!(result.unwrap_err(), Error::ErrUnhandledStunpacket);
        assert!(a.candidate_pairs.is_empty(), "{wildcard}: no pair");
        assert!(a.remote_candidates.is_empty(), "{wildcard}: no prflx");
        assert!(a.poll_write().is_none(), "{wildcard}: no response");

        let line = unmatched_local_address_log("controlled", &transport);
        assert!(
            line.contains(&format!("its local address {wildcard} is unspecified"))
                && line.contains("concrete address each datagram was received on")
                && line.contains("relayed address"),
            "{line}"
        );
    }

    // A concrete address that is no candidate's keeps the generic line.
    let concrete = TransportContext {
        local_addr: addr("192.168.0.9:1000"),
        peer_addr: addr(REMOTE_A),
        ecn: None,
        transport_protocol: TransportProtocol::UDP,
    };
    assert_eq!(
        unmatched_local_address_log("controlled", &concrete),
        "[controlled]: Discarded message, not a valid local candidate from UDP:192.168.0.9:1000"
    );

    // The same request on the host candidate's own address is taken.
    deliver(&mut a, start, &request, REMOTE_A).unwrap();
    assert_eq!(a.candidate_pairs.len(), 1);

    // Matching is unchanged: the reflexive-on-base match still credits an unspecified address
    // to a server-reflexive candidate whose related address it is.
    let mut b = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
    b.add_local_candidate(srflx("203.0.113.5", 4000, addr("0.0.0.0:1000")))
        .unwrap();
    assert_eq!(
        b.find_local_candidate(addr("0.0.0.0:1000"), TransportProtocol::UDP),
        Some(0)
    );
}

// --- Section 7.2.5: responses ---

/// Section 7.2.5.2.1: the response must come from where the request went. One that carries
/// the right transaction id and the peer's signature but another source fails the pair.
#[test]
fn test_response_from_another_source_fails_the_pair() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400)]);
    let out = silent(&mut a, start, Duration::ZERO, 10 * MS);
    let check = checks_started(&out)[0];
    assert_eq!(check.to, remote_addr(1));
    let response = peer_response(
        BINDING_SUCCESS,
        check.message.transaction_id,
        addr(LOCAL),
        None,
    );
    deliver(&mut a, start + 10 * MS, &response, "10.0.0.2:5000").unwrap();
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    assert_ne!(state_of(&a, 2), CandidatePairState::Succeeded);
    assert!(a.remote_candidates[1].last_consent().is_none());
}

/// Section 7.2.5.2.1: ... and must arrive where the request left from. A response on another
/// local candidate fails the pair instead of being credited to that candidate's pair.
#[test]
fn test_response_on_another_local_candidate_fails_the_pair() {
    let start = Instant::now();
    let other_local = "192.168.0.9:1000";
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    };
    let mut a = bare_agent(start, cfg);
    a.add_local_candidate(host(addr(other_local))).unwrap();
    a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = silent(&mut a, start, Duration::ZERO, 10 * MS);
    let check = checks_started(&out)[0];
    let sent_pair = a.find_pair_exact(0, 0).unwrap();
    let other_pair = a.find_pair_exact(1, 0).unwrap();
    assert_eq!(
        a.candidate_pairs[sent_pair].state,
        CandidatePairState::InProgress
    );

    let response = peer_response(
        BINDING_SUCCESS,
        check.message.transaction_id,
        addr(LOCAL),
        None,
    );
    a.handle_read(TaggedBytesMut {
        now: start + 10 * MS,
        transport: TransportContext {
            local_addr: addr(other_local),
            peer_addr: remote_addr(1),
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(&response.raw[..]),
    })
    .unwrap();
    assert_eq!(
        a.candidate_pairs[sent_pair].state,
        CandidatePairState::Failed
    );
    assert_ne!(
        a.candidate_pairs[other_pair].state,
        CandidatePairState::Succeeded
    );
}

/// Sections 7.2.5.3.1 and 7.2.5.3.2: a mapped address that is no local candidate is a new
/// local peer-reflexive candidate (base: the candidate the request left from; priority: the
/// request's PRIORITY), and the valid pair is (that candidate, the request's destination).
/// The pair that was checked and the valid pair are both Succeeded; the valid pair is the one
/// nominated and selected, and data leaves from its base. The learned candidate is not one to
/// signal.
#[test]
fn test_mapped_address_makes_a_local_peer_reflexive_candidate_and_the_valid_pair() {
    let start = Instant::now();
    let mapped: SocketAddr = "203.0.113.5:4000".parse().unwrap();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    run_with(&mut a, start, Duration::ZERO, 300 * MS, |_| {
        Answer::Success(mapped)
    });

    assert_eq!(a.local_candidates.len(), 2);
    let learned = &a.local_candidates[1];
    assert_eq!(learned.candidate_type(), CandidateType::PeerReflexive);
    assert_eq!(learned.addr(), mapped);
    assert_eq!(learned.base_addr(), addr(LOCAL));
    assert_eq!(
        learned.priority(),
        1862270975,
        "the PRIORITY the request carried"
    );
    assert_eq!(a.get_local_candidates_to_signal().len(), 1);

    assert_eq!(a.candidate_pairs.len(), 2);
    let checked = a.candidate_pairs[a.find_pair_exact(0, 0).unwrap()];
    let valid = a.candidate_pairs[a.find_pair_exact(1, 0).unwrap()];
    assert_eq!(checked.state, CandidatePairState::Succeeded);
    assert!(!checked.valid, "the valid list holds the constructed pair");
    assert_eq!(valid.state, CandidatePairState::Succeeded);
    assert!(valid.valid && valid.nominated);

    let (local, remote) = a.get_selected_candidate_pair().unwrap();
    assert_eq!(local.addr(), mapped);
    assert_eq!(remote.addr(), remote_addr(1));
    let path = a.media_path().unwrap();
    assert_eq!(path.local_addr, addr(LOCAL));
    assert_eq!(path.peer_addr, remote_addr(1));

    // An ICE restart that keeps the local candidates does not keep the learned one.
    a.restart(
        start + Duration::from_secs(1),
        String::new(),
        String::new(),
        true,
    )
    .unwrap();
    assert_eq!(a.local_candidates.len(), 1);
}

/// Section 7.2.5.3.2: when the mapped address is a local candidate the agent knows (its
/// server-reflexive one), the valid pair is that candidate's, and no candidate is made.
#[test]
fn test_mapped_address_of_a_known_candidate_makes_its_pair_valid() {
    let start = Instant::now();
    let cfg = AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(false)
    };
    let mut a = bare_agent(start, cfg);
    a.add_local_candidate(srflx("203.0.113.5", 4000, addr(LOCAL)))
        .unwrap();
    a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    run_with(&mut a, start, Duration::ZERO, 100 * MS, |_| {
        Answer::Success("203.0.113.5:4000".parse().unwrap())
    });
    assert_eq!(a.local_candidates.len(), 2, "no new candidate");
    let valid = a.candidate_pairs[a.find_pair_exact(1, 0).expect("the srflx pair")];
    assert!(valid.valid);
    assert_eq!(valid.state, CandidatePairState::Succeeded);
    assert_eq!(
        a.candidate_pairs[a.find_pair_exact(0, 0).unwrap()].valid_pair,
        a.find_pair_exact(1, 0)
    );
}

// --- Section 8: nomination, checklist and ICE states ---

/// Section 8.1.1: the controlling agent nominates one pair, with one transaction, and no
/// other afterwards. Section 8.1.2: from then on the checklist is Completed, the other pairs'
/// transactions are cancelled and no ordinary check is started; only consent checks go out.
#[test]
fn test_controlling_agent_nominates_once_and_the_checklist_completes() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400), (3, 300)]);
    assert_eq!(a.checklist_state(), ChecklistState::Running);

    // 1 answers; 2 and 3 never do.
    let out = run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(60),
        |s| {
            if s.to == remote_addr(1) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        },
    );
    assert_eq!(a.checklist_state(), ChecklistState::Completed);
    assert_eq!(a.state(), ConnectionState::Connected);
    let (_, remote) = a.get_selected_candidate_pair().unwrap();
    assert_eq!(remote.addr(), remote_addr(1));

    let nominations: Vec<&Sent> = requests_of(&out)
        .into_iter()
        .filter(|s| s.message.contains(ATTR_USE_CANDIDATE))
        .collect();
    // One pair is nominated, with one request: the consent checks that follow are plain
    // Binding requests (RFC 8445 Section 7.1.2: USE-CANDIDATE is sent "in order to nominate").
    assert_eq!(nominations.len(), 1, "one nomination, one request");
    assert_eq!(nominations[0].to, remote_addr(1));
    let nominated_at = nominations[0].at;

    // After the nomination nothing more goes to 2 or 3: no ordinary check for 3, no
    // retransmission for 2. Both are out of the checklist ("MUST remove all candidate pairs
    // for the same component from the checklist"): Failed, by the nomination and not by a
    // timeout (nothing was sent to them after it).
    assert!(
        requests_of(&out)
            .iter()
            .all(|s| s.to == remote_addr(1) || s.at <= nominated_at),
    );
    assert_eq!(state_of(&a, 2), CandidatePairState::Failed);
    assert_eq!(state_of(&a, 3), CandidatePairState::Failed);
    // What goes to 1 afterwards are consent checks: at least 4 seconds apart.
    let later: Vec<Duration> = requests_of(&out)
        .iter()
        .filter(|s| s.at > nominated_at)
        .map(|s| s.at)
        .collect();
    assert!(later.len() >= 9);
    assert!(
        later
            .windows(2)
            .all(|w| w[1] - w[0] >= Duration::from_secs(4))
    );
}

/// Section 8.1.2: once a pair is nominated, "the ICE agent MUST remove all candidate pairs for
/// the same component from the checklist and from the triggered-check queue", Frozen pairs
/// included. Here two remote candidates share a foundation, so at the nomination the second of
/// them is still Frozen (Section 6.1.2.6: its foundation's first pair is still being checked);
/// the nomination takes it out of the checklist as Failed, it is never checked, and the
/// pair's stats say `failed`. Either role: the controlling agent concludes on the success
/// response to its nomination, the controlled one on the peer's USE-CANDIDATE request.
#[test]
fn a_pair_still_frozen_at_the_nomination_is_taken_out_of_the_checklist() {
    for controlling in [true, false] {
        let role = if controlling {
            "controlling"
        } else {
            "controlled"
        };
        let start = Instant::now();
        let mut a = bare_agent(
            start,
            AgentConfig {
                failed_timeout: Some(Duration::ZERO),
                ..config(controlling)
            },
        );
        a.add_remote_candidate(remote(1, 500, "own")).unwrap();
        a.add_remote_candidate(remote(2, 400, "shared")).unwrap();
        a.add_remote_candidate(remote(3, 300, "shared")).unwrap();
        a.start_connectivity_checks(
            start,
            controlling,
            REMOTE_UFRAG.to_owned(),
            REMOTE_PWD.to_owned(),
        )
        .unwrap();
        assert_eq!(state_of(&a, 3), CandidatePairState::Frozen, "{role}");

        // 1's ordinary checks are answered; a nomination is not answered yet, 2 and 3 never.
        let before = run_with(&mut a, start, Duration::ZERO, 200 * MS, |s| {
            if s.to == remote_addr(1) && !s.message.contains(ATTR_USE_CANDIDATE) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        });
        // The precondition: nothing nominated yet, 1 succeeded, 2 still being checked and so
        // 3, of the same foundation, still Frozen.
        assert!(a.get_selected_candidate_pair().is_none(), "{role}");
        assert_eq!(a.checklist_state(), ChecklistState::Running, "{role}");
        assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded, "{role}");
        assert!(
            matches!(
                state_of(&a, 2),
                CandidatePairState::Waiting | CandidatePairState::InProgress
            ),
            "{role}: {}",
            state_of(&a, 2)
        );
        assert_eq!(
            state_of(&a, 3),
            CandidatePairState::Frozen,
            "{role}: Frozen just before the nomination"
        );
        assert!(
            !requests_of(&before).iter().any(|s| s.to == remote_addr(3)),
            "{role}: a Frozen pair is not checked"
        );

        // The nomination.
        let at = start + 200 * MS;
        if controlling {
            let nomination = requests_of(&before)
                .into_iter()
                .find(|s| s.message.contains(ATTR_USE_CANDIDATE))
                .expect("controlling: the nomination was sent")
                .message
                .transaction_id;
            let response = peer_response(BINDING_SUCCESS, nomination, addr(LOCAL), None);
            deliver(&mut a, at, &response, "10.0.0.1:5000").unwrap();
        } else {
            let nominate = peer_request(
                &a,
                vec![
                    Box::new(AttrControlling(1)),
                    Box::new(PriorityAttr(1000)),
                    Box::new(UseCandidateAttr::new()),
                ],
            );
            deliver(&mut a, at, &nominate, "10.0.0.1:5000").unwrap();
        }
        assert_eq!(
            a.get_selected_candidate_pair().unwrap().1.addr(),
            remote_addr(1),
            "{role}"
        );
        assert_eq!(a.checklist_state(), ChecklistState::Completed, "{role}");
        assert_eq!(
            state_of(&a, 3),
            CandidatePairState::Failed,
            "{role}: the pair Frozen at the nomination is out of the checklist"
        );
        assert_eq!(state_of(&a, 2), CandidatePairState::Failed, "{role}");

        // Its stats say so.
        let three = a.find_remote_candidate(remote_addr(3)).unwrap();
        let three_id = a.remote_candidates[three].id().to_string();
        let stats = a.get_candidate_pairs_stats(at);
        let stat = stats
            .iter()
            .find(|s| s.remote_candidate_id == three_id)
            .expect("the pair's stats");
        assert_eq!(stat.state, CandidatePairState::Failed, "{role}");
        assert_eq!(stat.state.to_string(), "failed", "{role}");

        // Never checked afterwards: nothing goes to 3 (its foundation has nothing in flight
        // any more, which would otherwise unfreeze it) nor to 2.
        let after = run_with(&mut a, start, 200 * MS, Duration::from_secs(10), |s| {
            if s.to == remote_addr(1) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        });
        assert!(
            requests_of(&after).iter().all(|s| s.to == remote_addr(1)),
            "{role}: a check on a pair the nomination took out of the checklist"
        );
        assert_eq!(state_of(&a, 3), CandidatePairState::Failed, "{role}");
    }
}

/// Section 8.1.1: the nomination the controlling agent queued is sent, also when a second
/// success response for the same pair arrives before Ta starts it. Here the pair's first
/// check is cancelled by the peer's request (Section 7.3.1.4) and checked again, and both
/// transactions are answered: the first answer makes the pair valid and queues its
/// nomination, the second used to take the pair off the triggered-check queue as a check
/// done, so the nomination never left and the agent stayed in checking until its failed
/// timeout (seen against the `webrtc` 0.17 peer in `test_data_channel_create_rtc_to_webrtc`).
#[test]
fn test_a_second_success_response_does_not_drop_the_queued_nomination() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    let out = silent(&mut a, start, Duration::ZERO, 60 * MS);
    let first = checks_started(&out)[0].message.transaction_id;

    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start + 60 * MS, &request, "10.0.0.1:5000").unwrap();
    let out = silent(&mut a, start, 60 * MS, 70 * MS);
    let second = checks_started(&out)
        .iter()
        .map(|s| s.message.transaction_id)
        .find(|id| *id != first)
        .expect("the triggered check");

    for (at, id) in [(71, first), (72, second)] {
        let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
        deliver(&mut a, start + at * MS, &response, "10.0.0.1:5000").unwrap();
    }
    assert_eq!(state_of(&a, 1), CandidatePairState::Succeeded);

    let out = answered(&mut a, start, 72 * MS, Duration::from_secs(2));
    let nomination = requests_of(&out)
        .into_iter()
        .find(|s| s.message.contains(ATTR_USE_CANDIDATE))
        .expect("the nomination is sent");
    assert!(
        nomination.at <= 200 * MS,
        "the nomination leaves at the next Ta, not at {:?}",
        nomination.at
    );
    assert_eq!(a.state(), ConnectionState::Connected);
}

/// Consent checks are plain Binding requests (RFC 7675 Section 5.1; RFC 8445 Section 7.1.2
/// has USE-CANDIDATE sent to nominate, and "the controlled agent MUST NOT include" it).
/// `nominate_on_consent_checks` is libwebrtc's behaviour: the controlling agent's consent
/// checks carry USE-CANDIDATE. The controlled agent's never do.
#[test]
fn test_consent_checks_carry_use_candidate_only_when_set_to_and_controlling() {
    for (controlling, setting) in [(true, false), (true, true), (false, false), (false, true)] {
        let start = Instant::now();
        let cfg = AgentConfig {
            nominate_on_consent_checks: setting,
            ..config(controlling)
        };
        let mut a = agent_with(start, cfg, &[(1, 500)]);
        if !controlling {
            let nominate = peer_request(
                &a,
                vec![
                    Box::new(AttrControlling(1)),
                    Box::new(PriorityAttr(1000)),
                    Box::new(UseCandidateAttr::new()),
                ],
            );
            deliver(&mut a, start, &nominate, "10.0.0.1:5000").unwrap();
        }
        answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
        assert!(a.get_selected_candidate_pair().is_some());
        let out = answered(
            &mut a,
            start,
            Duration::from_secs(1),
            Duration::from_secs(20),
        );
        let consent = requests_of(&out);
        assert!(consent.len() >= 3);
        assert!(
            consent
                .iter()
                .all(|s| s.message.contains(ATTR_USE_CANDIDATE) == (controlling && setting)),
            "controlling: {controlling}, nominate_on_consent_checks: {setting}"
        );
        assert_eq!(a.state(), ConnectionState::Connected);
    }
}

/// When consent comes back the agent leaves `Disconnected` with the response, not at its
/// next consent check seconds later.
#[test]
fn test_agent_is_connected_again_as_soon_as_consent_returns() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    silent(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(15),
    );
    assert_eq!(a.state(), ConnectionState::Disconnected);
    let _ = states(&mut a);
    // The next consent check is answered.
    let mut now = start + Duration::from_secs(15);
    let answered_at = loop {
        a.handle_timeout(now).unwrap();
        if let Some((m, to)) = sent(&mut a)
            .into_iter()
            .find(|(m, _)| m.typ == BINDING_REQUEST)
        {
            let response = peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
            deliver(&mut a, now, &response, &to.to_string()).unwrap();
            break now;
        }
        now = a
            .poll_timeout()
            .unwrap()
            .max(now + Duration::from_micros(1));
    };
    assert_eq!(a.poll_timeout().map(|t| t <= answered_at), Some(true));
    a.handle_timeout(answered_at).unwrap();
    assert_eq!(states(&mut a), vec![ConnectionState::Connected]);
}

/// The transport state is `Connected` once a pair is nominated and `Completed` once, in
/// addition, both sides have no more candidates to offer (W3C `RTCIceTransportState`); a
/// disconnected agent comes back to the state it had.
#[test]
fn test_completed_needs_a_nominated_pair_and_both_ends_of_candidates() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500)]);
    a.set_local_gathering_complete();
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert_eq!(
        states(&mut a),
        vec![ConnectionState::Checking, ConnectionState::Connected]
    );

    a.set_remote_end_of_candidates();
    answered(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    assert_eq!(states(&mut a), vec![ConnectionState::Completed]);
    assert_eq!(a.checklist_state(), ChecklistState::Completed);

    // Silence, then answers again.
    silent(
        &mut a,
        start,
        Duration::from_secs(2),
        Duration::from_secs(20),
    );
    assert_eq!(states(&mut a), vec![ConnectionState::Disconnected]);
    answered(
        &mut a,
        start,
        Duration::from_secs(20),
        Duration::from_secs(30),
    );
    assert_eq!(states(&mut a), vec![ConnectionState::Completed]);
}

/// Whether a check of `a` is in flight or queued: a pair In-Progress, or the triggered-check
/// queue not empty (consent checks on the selected pair leave it Succeeded).
fn checking_a_pair(a: &Agent) -> Option<String> {
    if !a.triggered_queue.is_empty() {
        return Some(format!("triggered queue {:?}", a.triggered_queue));
    }
    a.candidate_pairs
        .iter()
        .find(|p| p.state == CandidatePairState::InProgress)
        .map(|p| format!("pair {p} In-Progress"))
}

/// Runs `a` from `from` to `until` in 1 ms steps, answering checks to `10.0.0.1` only, and
/// fails when it is `Completed` while a check is in flight.
fn run_asserting_completed_only_when_done(
    a: &mut Agent,
    start: Instant,
    from: Duration,
    until: Duration,
) {
    let mut t = from;
    while t < until {
        run_with(a, start, t, t + MS, |s| {
            if s.to == remote_addr(1) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        });
        t += MS;
        if a.state() == ConnectionState::Completed
            && let Some(checking) = checking_a_pair(a)
        {
            panic!("Completed at {t:?} while checking: {checking}");
        }
    }
}

/// W3C webrtc 5.6.4 `RTCIceTransportState`: "completed": the transport "has finished
/// gathering, received an indication that there are no more remote candidates, finished
/// checking all candidate pairs and found a connection"; "connected": it "has found a usable
/// connection, but is still checking other candidate pairs". Both sides are done with their
/// candidates from the start; 1 answers, 2 and 3 never do. The agent is never `Completed`
/// while one of its checks is in flight (RFC 8445 Section 8.1.2 ends the others' transactions
/// at the nomination).
#[test]
fn test_completed_is_never_reported_while_a_check_is_in_flight() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400), (3, 300)]);
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    run_asserting_completed_only_when_done(&mut a, start, Duration::ZERO, Duration::from_secs(10));
    assert_eq!(a.state(), ConnectionState::Completed);
    let (_, remote) = a.get_selected_candidate_pair().unwrap();
    assert_eq!(remote.addr(), remote_addr(1));
}

/// Section 7.2.5.4 with RFC 8838 Sections 8 and 14 and RFC 8863 Section 4: when every pair
/// has failed and none is valid the checklist is Failed, provided no candidate is to come any
/// more (local gathering complete, end-of-candidates received) and the PAC timer has expired:
/// 39.5 s after checking began (the transaction timeout with the defaults), not the 30 s of
/// the agent's own timeout. While candidates may still come it keeps Running, and so it does
/// while the timer runs (RFC 8863 Section 3.3: pairs that fail at once, here by error
/// responses; Section 3.1: no pair at all), a peer's check may still make a pair.
#[test]
fn test_checklist_fails_when_all_pairs_failed_and_no_candidate_is_to_come() {
    let start = Instant::now();
    let refuse = |_: &Sent| Answer::Error(CODE_BAD_REQUEST);

    // Candidates may still come: Running, with its one pair Failed.
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(5),
        refuse,
    );
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
    assert_eq!(a.state(), ConnectionState::Checking);
    assert_eq!(a.checklist_state(), ChecklistState::Running);

    // The same once both sides are done: Running while the PAC timer runs, Failed as it
    // expires.
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    run_with(&mut a, start, Duration::from_secs(5), PAC - MS, refuse);
    assert_eq!(a.state(), ConnectionState::Checking);
    assert_eq!(a.checklist_state(), ChecklistState::Running);
    run_with(&mut a, start, PAC - MS, PAC + LOOK, refuse);
    assert_eq!(a.state(), ConnectionState::Failed);
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    assert!(a.poll_timeout().is_none());

    // No pair at all and nothing to come: Failed as the PAC timer expires, not before.
    let mut a = started_agent(start, config(false), &[]);
    a.set_local_gathering_complete();
    silent(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert_eq!(a.state(), ConnectionState::Checking);
    a.set_remote_end_of_candidates();
    silent(&mut a, start, Duration::from_secs(1), PAC - MS);
    assert_eq!(a.state(), ConnectionState::Checking);
    silent(&mut a, start, PAC - MS, PAC + LOOK);
    assert_eq!(a.state(), ConnectionState::Failed);
}

/// RFC 8863 Section 4: the PAC timer, "equal to the agent's connectivity check transaction
/// timeout, including all retransmissions": 39.5 s with the default RTO (500 ms) and Rc (7).
const PAC: Duration = Duration::from_millis(39_500);

/// How long after a deadline a checking agent with no selected pair looks at its state at
/// the latest (its check interval, 200 ms).
const LOOK: Duration = Duration::from_millis(200);

/// RFC 8863 Sections 3.1 and 5 with RFC 8445 Sections 7.3.1.3 and 7.3.1.4: the peer
/// signalled end-of-candidates and no candidate at all (it may have none it wants to signal;
/// it has ours), so the agent's checklist is empty; the peer's check arrives a few seconds
/// later, from an address the agent has never heard of: a peer-reflexive remote candidate,
/// its pair, the triggered check, and the agent connects over it. Before the PAC timer the
/// agent failed the empty checklist the moment both sides had signalled end-of-candidates,
/// and the check came to a failed agent.
#[test]
fn an_empty_checklist_after_end_of_candidates_waits_for_the_peers_check_and_connects() {
    for checked_at in [Duration::from_secs(3), PAC - Duration::from_secs(1)] {
        let start = Instant::now();
        let mut a = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
        a.add_local_candidate(host(addr(LOCAL))).unwrap();
        a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
            .unwrap();
        a.set_local_gathering_complete();
        a.set_remote_end_of_candidates();
        silent(&mut a, start, Duration::ZERO, checked_at);
        assert!(a.candidate_pairs.is_empty(), "{checked_at:?}");
        assert!(a.remote_candidates.is_empty(), "{checked_at:?}");
        assert_eq!(a.state(), ConnectionState::Checking, "{checked_at:?}");
        assert_eq!(
            a.checklist_state(),
            ChecklistState::Running,
            "{checked_at:?}"
        );

        let from = addr(REMOTE_A);
        peer_checks(
            &mut a,
            start + checked_at,
            OnlyCandidate::MdnsResolutionOff,
            from,
        );
        assert_eq!(
            a.media_path().map(|p| p.peer_addr),
            Some(from),
            "{checked_at:?}: selected over the pair the check formed"
        );
        assert_eq!(
            a.remote_candidates[a.candidate_pairs[0].remote_index].candidate_type(),
            CandidateType::PeerReflexive,
            "{checked_at:?}"
        );
        let reached = states(&mut a);
        assert!(
            !reached.contains(&ConnectionState::Failed)
                && reached
                    .iter()
                    .any(|s| matches!(s, ConnectionState::Connected | ConnectionState::Completed)),
            "{checked_at:?}: {reached:?}"
        );
    }
}

/// RFC 8863 Section 4: "When the timer period eventually elapses, the ICE agent MUST resume
/// typical ICE processing, including setting the state of any checklists to Failed if they
/// have no pairs left to check": the empty checklist of the test above, with no check from
/// the peer, fails once, as the timer expires; and a lite agent, which runs no ICE processing
/// of its own, has no PAC timer.
#[test]
fn an_empty_checklist_that_no_check_fills_fails_when_the_pac_timer_expires() {
    let start = Instant::now();
    let mut a = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    silent(&mut a, start, Duration::ZERO, PAC + Duration::from_secs(5));
    let failed_at: Vec<Duration> = std::iter::from_fn(|| a.poll_event())
        .filter(|e| {
            matches!(
                e.event,
                Event::ConnectionStateChange(ConnectionState::Failed)
            )
        })
        .map(|e| e.now.duration_since(start))
        .collect();
    assert_eq!(failed_at.len(), 1, "{failed_at:?}");
    assert!(
        failed_at[0] >= PAC && failed_at[0] <= PAC + LOOK,
        "failed at {:?}",
        failed_at[0]
    );

    // Rc of one request: the transaction, and the timer, last 16 RTO (8 s).
    let cfg = AgentConfig {
        max_binding_requests: Some(1),
        ..config(false)
    };
    let mut a = Agent::new(start, Arc::new(cfg), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    silent(&mut a, start, Duration::ZERO, Duration::from_secs(8) - MS);
    assert_eq!(a.state(), ConnectionState::Checking);
    silent(
        &mut a,
        start,
        Duration::from_secs(8) - MS,
        Duration::from_secs(8) + LOOK,
    );
    assert_eq!(a.state(), ConnectionState::Failed);
}

/// RFC 8445 Section 6.2: "Lite implementations skip most of the steps in Section 6 except for
/// verifying the peer's ICE support and determining its role in the ICE processing": the
/// checklist and its Failed state (Section 6.1.2.1) are a full agent's, and a lite agent sends
/// no check (Section 2.5) that could fail a pair. A lite agent with no pair, its gathering
/// complete and nothing more to come from the peer, is not failed at once:
/// - with a full peer (end-of-candidates signalled) its pair comes from the peer's check (RFC
///   8838 Appendix B: "the connectivity checks would be enough for the ICE-lite implementation
///   to discover all potentially useful candidates as peer-reflexive"); its checking timeout
///   (`disconnected_timeout + failed_timeout`, 30 s) still fails it when none comes;
/// - with a lite peer whose description cannot trickle (no `a=ice-options:trickle`: the
///   engine's lite descriptions had none before ice-36, another implementation's may have
///   none), a candidate the peer still sends (the engine's TCP candidates, trickled once
///   their listeners are bound) forms the pair, selected without checks (Section
///   8.2). Before this the agent failed the empty checklist at its first look (train 36 round
///   10, run 46038516696:
///   `two_lite_agents_connect_over_tcp_from_an_active_candidate_in_the_offer`).
#[test]
fn a_lite_agent_with_no_pair_is_not_failed_when_no_candidate_is_to_come() {
    let start = Instant::now();
    let lite = |controlling| AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(controlling)
    };

    // A full peer.
    let mut a = bare_agent(start, lite(false));
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    silent(&mut a, start, Duration::ZERO, Duration::from_secs(29));
    let seen = timed_states(&mut a, start);
    assert!(
        !seen.iter().any(|(_, s)| *s == ConnectionState::Failed),
        "a full peer: {seen:?}"
    );
    assert_eq!(
        a.state(),
        ConnectionState::Checking,
        "a full peer: {seen:?}"
    );
    silent(
        &mut a,
        start,
        Duration::from_secs(29),
        Duration::from_secs(32),
    );
    let seen = timed_states(&mut a, start);
    let failed = seen
        .iter()
        .find(|(_, s)| *s == ConnectionState::Failed)
        .map(|(at, _)| *at);
    assert!(
        failed.is_some_and(|at| at >= Duration::from_secs(30)),
        "a full peer: the checking timeout fails it: {seen:?}"
    );

    // A lite peer that cannot trickle, whose candidate comes anyway.
    let mut a = bare_agent(start, lite(true));
    a.set_remote_lite(true);
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_trickles(false);
    silent(&mut a, start, Duration::ZERO, Duration::from_secs(3));
    let seen = timed_states(&mut a, start);
    assert!(
        !seen.iter().any(|(_, s)| *s == ConnectionState::Failed),
        "a lite peer: {seen:?}"
    );
    assert_eq!(
        a.state(),
        ConnectionState::Checking,
        "a lite peer: {seen:?}"
    );
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    silent(
        &mut a,
        start,
        Duration::from_secs(3),
        Duration::from_secs(4),
    );
    assert!(
        a.get_selected_candidate_pair().is_some(),
        "a lite peer: the pair is selected without checks"
    );
    let seen = timed_states(&mut a, start);
    assert!(
        seen.iter().any(|(_, s)| *s == ConnectionState::Connected)
            && !seen.iter().any(|(_, s)| *s == ConnectionState::Failed),
        "a lite peer: {seen:?}"
    );
}

// --- W3C webrtc-pc 5.6.4: "failed" needs the end of the candidates ---

/// The connection states `a` reported since the last call, each with its time since `start`.
fn timed_states(a: &mut Agent, start: Instant) -> Vec<(Duration, ConnectionState)> {
    std::iter::from_fn(|| a.poll_event())
        .filter_map(|e| match e.event {
            Event::ConnectionStateChange(s) => Some((e.now.duration_since(start), s)),
            _ => None,
        })
        .collect()
}

/// Whether `at` is in `[from, from + LOOK]`: the agent's next look at its state after `from`.
fn by_next_look(at: Duration, from: Duration) -> bool {
    at >= from && at <= from + LOOK + MS
}

/// W3C webrtc-pc 5.6.4, `RTCIceTransportState`: "failed": the transport "has finished
/// gathering, received an indication that there are no more remote candidates, finished
/// checking all candidate pairs, and all pairs have either failed connectivity checks or lost
/// consent"; "disconnected": "Alternatively, the RTCIceTransport has finished checking all
/// existing candidates pairs and not found a connection [...], but it is still gathering
/// and/or waiting for additional remote candidates"; and "The failed and completed states
/// require an indication that there are no additional remote candidates. This can be
/// indicated by calling addIceCandidate with a candidate value whose candidate property is set
/// to an empty string or by canTrickleIceCandidates being set to false." The one pair fails at
/// once (error responses); past the checking timeout and the PAC timer the agent is
/// `Disconnected`, never `Failed`, for as long as one indication is missing (local gathering,
/// or the peer's), and `Failed` the moment the last one comes: the peer's end-of-candidates,
/// local gathering, or a description that cannot trickle. Before ice-32 the checking timeout
/// failed it at 39.5 s whatever was signalled.
#[test]
fn checks_that_all_failed_are_disconnected_until_no_candidate_is_to_come() {
    let refuse = |_: &Sent| Answer::Error(CODE_BAD_REQUEST);
    let last = Duration::from_secs(70);
    for case in [
        "remote end-of-candidates",
        "local gathering",
        "remote cannot trickle",
    ] {
        let start = Instant::now();
        let mut a = started_agent(start, config(true), &[REMOTE_A]);
        match case {
            "remote end-of-candidates" | "remote cannot trickle" => {
                a.set_local_gathering_complete()
            }
            _ => a.set_remote_end_of_candidates(),
        }
        run_with(&mut a, start, Duration::ZERO, last, refuse);
        assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
        let seen = timed_states(&mut a, start);
        assert_eq!(
            seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
            vec![ConnectionState::Checking, ConnectionState::Disconnected],
            "{case}: {seen:?}"
        );
        assert!(by_next_look(seen[1].0, PAC), "{case}: {seen:?}");
        assert_eq!(
            a.checklist_state(),
            ChecklistState::Running,
            "{case}: RFC 8838 Section 8, Running while candidates may come"
        );
        assert!(a.poll_timeout().is_some(), "{case}: the agent goes on");

        match case {
            "remote end-of-candidates" => a.set_remote_end_of_candidates(),
            "local gathering" => a.set_local_gathering_complete(),
            _ => a.set_remote_trickles(false),
        }
        run_with(&mut a, start, last, last + Duration::from_secs(1), refuse);
        let seen = timed_states(&mut a, start);
        assert_eq!(seen.len(), 1, "{case}: {seen:?}");
        assert_eq!(seen[0].1, ConnectionState::Failed, "{case}");
        assert!(by_next_look(seen[0].0, last), "{case}: {seen:?}");
        assert_eq!(a.checklist_state(), ChecklistState::Failed);
        assert!(a.poll_timeout().is_none());
    }
}

/// W3C webrtc-pc 5.6.4: a transport that is "disconnected" with its checks failed checks again
/// when a candidate comes ("(disconnected, new local candidates): checking"), here a remote
/// one that answers: `Checking`, then `Connected`; a new local candidate whose pair fails too:
/// `Checking`, and `Disconnected` again by the checking timeout counted from then.
#[test]
fn a_candidate_that_comes_after_the_checks_failed_is_checked() {
    let at = Duration::from_secs(45);
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    let answer = |s: &Sent| {
        if s.to == addr(REMOTE_B) {
            Answer::Success(addr(LOCAL))
        } else {
            Answer::Error(CODE_BAD_REQUEST)
        }
    };
    run_with(&mut a, start, Duration::ZERO, at, answer);
    assert_eq!(a.state(), ConnectionState::Disconnected);
    let _ = timed_states(&mut a, start);
    a.add_remote_candidate(host(addr(REMOTE_B))).unwrap();
    run_with(&mut a, start, at, at + Duration::from_secs(2), answer);
    let seen = timed_states(&mut a, start);
    assert_eq!(
        seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
        vec![ConnectionState::Checking, ConnectionState::Connected],
        "{seen:?}"
    );
    assert_eq!(
        a.get_selected_candidate_pair().unwrap().1.addr(),
        addr(REMOTE_B)
    );

    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    let refuse = |_: &Sent| Answer::Error(CODE_BAD_REQUEST);
    run_with(&mut a, start, Duration::ZERO, at, refuse);
    assert_eq!(a.state(), ConnectionState::Disconnected);
    let _ = timed_states(&mut a, start);
    a.add_local_candidate(host(addr("192.168.0.5:1001")))
        .unwrap();
    run_with(&mut a, start, at, at + Duration::from_secs(40), refuse);
    let seen = timed_states(&mut a, start);
    assert_eq!(
        seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
        vec![ConnectionState::Checking, ConnectionState::Disconnected],
        "{seen:?}"
    );
    assert!(
        by_next_look(seen[1].0, at + Duration::from_secs(30)),
        "the checking timeout counts from the new checks: {seen:?}"
    );
}

/// W3C webrtc-pc 5.6.4, "connected": "If consent checks [RFC7675] fail on the connection in
/// use, and there are no other successful candidate pairs available, then the state
/// transitions to [...] "disconnected" (if there are no candidate pairs to check, but the
/// peer is still gathering and/or waiting for additional remote candidates)"; "failed" once
/// no candidate is to come. RFC 7675 Section 5.1 holds either way: nothing is sent on the
/// pair once consent has expired, and "the same ICE credentials MUST NOT be used on the
/// affected 5-tuple again": not for a check, not for the answer to the peer's request.
#[test]
fn consent_lost_before_the_end_of_candidates_is_disconnected_and_then_failed() {
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert_eq!(a.state(), ConnectionState::Connected);
    let _ = timed_states(&mut a, start);
    let out = silent(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(60),
    );
    let seen = timed_states(&mut a, start);
    assert!(
        !seen.iter().any(|(_, s)| *s == ConnectionState::Failed),
        "failed without the end of the candidates: {seen:?}"
    );
    assert_eq!(a.state(), ConnectionState::Disconnected, "{seen:?}");
    assert!(a.media_path().is_none(), "nothing is sent without consent");
    assert!(a.get_selected_candidate_pair().is_none());
    // Consent expired 30 s after the last response (under 1 s in): nothing to the peer after.
    assert!(
        !requests_of(&out)
            .iter()
            .any(|s| s.at > Duration::from_secs(32)),
        "a request on the 5-tuple whose consent was lost"
    );
    // The peer's request on that 5-tuple is not answered.
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    let _ = deliver(&mut a, start + Duration::from_secs(60), &request, REMOTE_A);
    assert!(
        a.poll_write().is_none(),
        "an answer on the 5-tuple whose consent was lost"
    );

    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    silent(
        &mut a,
        start,
        Duration::from_secs(60),
        Duration::from_secs(61),
    );
    let seen = timed_states(&mut a, start);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].1, ConnectionState::Failed);
    assert!(by_next_look(seen[0].0, Duration::from_secs(60)), "{seen:?}");
}

/// W3C webrtc-pc 5.6.4: "failed" also needs "either zero local candidates were gathered or
/// the PAC timer has expired [RFC8863]", and "completed": "If consent checks [RFC7675]
/// subsequently fail on all successful candidate pairs, the state transitions to failed".
/// Both sides are done with their candidates and consent expires (short timeouts: 2 s) well
/// inside the PAC timer: the media path goes at once (RFC 7675 Section 5.1), the agent is
/// `Disconnected` until the timer expires (39.5 s), then `Failed`.
#[test]
fn consent_lost_inside_the_pac_timer_is_failed_as_the_timer_expires() {
    let start = Instant::now();
    let cfg = AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(1)),
        failed_timeout: Some(Duration::from_secs(1)),
        ..config(true)
    };
    let mut a = started_agent(start, cfg, &[REMOTE_A]);
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert!(a.media_path().is_some());
    let _ = timed_states(&mut a, start);
    silent(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(10),
    );
    assert!(a.media_path().is_none(), "nothing is sent without consent");
    assert_eq!(a.state(), ConnectionState::Disconnected);
    silent(&mut a, start, Duration::from_secs(10), PAC + LOOK + MS);
    let seen = timed_states(&mut a, start);
    assert!(
        !seen
            .iter()
            .any(|(at, s)| *s == ConnectionState::Failed && *at < PAC),
        "failed inside the PAC timer: {seen:?}"
    );
    let failed = seen
        .iter()
        .find(|(_, s)| *s == ConnectionState::Failed)
        .map(|(at, _)| *at)
        .expect("failed");
    assert!(by_next_look(failed, PAC), "{seen:?}");
}

/// RFC 8445 Section 8.1.2: once a pair is nominated, "the ICE agent MUST remove all candidate
/// pairs for the same component from the checklist", and Section 8.1.1: "the agent MUST NOT
/// nominate another pair for same component of the data stream within the ICE session. Doing
/// so requires an ICE restart". W3C webrtc-pc 5.6.4, "completed": "If consent checks
/// [RFC7675] subsequently fail on all successful candidate pairs, the state transitions to
/// "failed"", once the PAC timer has expired. So a completed agent whose nomination left a
/// pair unchecked (here the peer never answers the second candidate) does not check that
/// pair when consent on the selected pair expires inside the PAC timer: `Disconnected`, then
/// `Failed` as the timer expires. It went back to `Checking`, checked the leftover pair and
/// failed by a second checking timeout, 30 s later (`virtual_time.rs` in the stream driver:
/// failed 60 s after the path went dark). Either role: the controlled agent concludes on the
/// peer's nomination.
#[test]
fn consent_lost_after_completion_does_not_check_the_pairs_the_nomination_retired() {
    for controlling in [true, false] {
        let start = Instant::now();
        let mut a = started_agent(start, config(controlling), &[REMOTE_A, REMOTE_B]);
        a.set_local_gathering_complete();
        a.set_remote_end_of_candidates();
        if !controlling {
            let nominate = peer_request(
                &a,
                vec![
                    Box::new(AttrControlling(1)),
                    Box::new(PriorityAttr(1000)),
                    Box::new(UseCandidateAttr::new()),
                ],
            );
            deliver(&mut a, start, &nominate, REMOTE_A).unwrap();
        }
        let only_a = |s: &Sent| {
            if s.to == addr(REMOTE_A) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        };
        run_with(
            &mut a,
            start,
            Duration::ZERO,
            Duration::from_secs(1),
            only_a,
        );
        let role = if controlling {
            "controlling"
        } else {
            "controlled"
        };
        assert_eq!(a.state(), ConnectionState::Completed, "{role}");
        assert_eq!(
            a.get_selected_candidate_pair().unwrap().1.addr(),
            addr(REMOTE_A),
            "{role}"
        );
        // The second pair's check was not completed (at most its first request left) and the
        // nomination took it out of the checklist (Section 8.1.2): Failed.
        let b = a.find_remote_candidate(addr(REMOTE_B)).unwrap();
        let b = a.candidate_pairs[a.find_pair(0, b).unwrap()];
        assert!(
            b.requests_sent <= 1 && b.state == CandidatePairState::Failed,
            "{role}: the second pair was taken out of the checklist unchecked: {} ({} sent)",
            b.state,
            b.requests_sent
        );
        let _ = timed_states(&mut a, start);
        let out = silent(&mut a, start, Duration::from_secs(1), PAC + LOOK + MS);
        let seen = timed_states(&mut a, start);
        assert!(
            !seen.iter().any(|(_, s)| *s == ConnectionState::Checking),
            "{role}: checking again after consent was lost: {seen:?}"
        );
        assert!(
            !requests_of(&out).iter().any(|s| s.to == addr(REMOTE_B)),
            "{role}: a check on a pair the nomination retired"
        );
        let failed = seen
            .iter()
            .find(|(_, s)| *s == ConnectionState::Failed)
            .map(|(at, _)| *at);
        assert!(
            failed.is_some_and(|at| by_next_look(at, PAC)),
            "{role}: failed as the PAC timer expires: {seen:?}"
        );
    }
}

/// RFC 8445 Section 8.1.2 removes from the checklist the pairs a nomination leaves unchecked;
/// a pair formed later is checked as any other. This one is formed after consent on the
/// selected pair was lost while the peer had not signalled its end-of-candidates (the agent
/// is `Disconnected`, W3C webrtc-pc 5.6.4: "consent checks [RFC7675] once successful, have
/// now failed, but it is still gathering and/or waiting for additional remote candidates"),
/// so it is `Checking` again ("(disconnected, new local candidates): checking") and the
/// pair's check fails. Then:
///
/// - with the peer's end-of-candidates at 50 s: every pair of the checklist has failed and no
///   candidate is to come (RFC 8445 Sections 7.2.5.4 and 8.1.2, RFC 8838 Section 8), the PAC
///   timer expired at 39.5 s (RFC 8863), so the transport is "failed" (5.6.4) at the agent's
///   next look after the indication;
/// - without it: the checking timeout, `disconnected_timeout + failed_timeout` (30 s by
///   default) from the new checks at 45 s, ends the checks, and the agent is "disconnected"
///   again at 75 s, not "failed": the indication is still missing.
///
/// The pairs the nomination took out of the checklist (Failed since) hold neither: they are
/// not checks in progress and they count as done for the checklist. Either role.
#[test]
fn a_pair_formed_after_consent_loss_fails_and_the_retired_pairs_do_not_hold_the_failure() {
    const REMOTE_C: &str = "192.168.0.5:4000";
    let new_checks = Duration::from_secs(45);
    let end_of_candidates = Duration::from_secs(50);
    let checking_timeout = new_checks + Duration::from_secs(30);
    for controlling in [true, false] {
        for with_end_of_candidates in [true, false] {
            let case = format!(
                "{}, {}",
                if controlling {
                    "controlling"
                } else {
                    "controlled"
                },
                if with_end_of_candidates {
                    "end-of-candidates at 50 s"
                } else {
                    "no end-of-candidates"
                }
            );
            let start = Instant::now();
            let mut a = started_agent(start, config(controlling), &[REMOTE_A, REMOTE_B]);
            a.set_local_gathering_complete();
            if !controlling {
                let nominate = peer_request(
                    &a,
                    vec![
                        Box::new(AttrControlling(1)),
                        Box::new(PriorityAttr(1000)),
                        Box::new(UseCandidateAttr::new()),
                    ],
                );
                deliver(&mut a, start, &nominate, REMOTE_A).unwrap();
            }
            let only_a = |s: &Sent| {
                if s.to == addr(REMOTE_A) {
                    Answer::Success(addr(LOCAL))
                } else {
                    Answer::Silence
                }
            };
            run_with(
                &mut a,
                start,
                Duration::ZERO,
                Duration::from_secs(1),
                only_a,
            );
            // Without the peer's end-of-candidates the transport is "connected", not
            // "completed" (5.6.4), but the nomination completed the checklist.
            assert_eq!(a.state(), ConnectionState::Connected, "{case}");
            assert_eq!(a.checklist_state(), ChecklistState::Completed, "{case}");
            let b = a.find_remote_candidate(addr(REMOTE_B)).unwrap();
            assert!(
                a.candidate_pairs[a.find_pair(0, b).unwrap()].requests_sent <= 1,
                "{case}: the second pair was not checked to the end"
            );
            silent(&mut a, start, Duration::from_secs(1), new_checks);
            assert_eq!(
                a.state(),
                ConnectionState::Disconnected,
                "{case}: consent lost"
            );
            let _ = timed_states(&mut a, start);

            a.add_remote_candidate(host(addr(REMOTE_C))).unwrap();
            let refuse_c = |s: &Sent| {
                if s.to == addr(REMOTE_C) {
                    Answer::Error(CODE_BAD_REQUEST)
                } else {
                    Answer::Silence
                }
            };
            let until = if with_end_of_candidates {
                run_with(&mut a, start, new_checks, end_of_candidates, refuse_c);
                a.set_remote_end_of_candidates();
                end_of_candidates + LOOK + MS
            } else {
                checking_timeout + Duration::from_secs(5)
            };
            let from = if with_end_of_candidates {
                end_of_candidates
            } else {
                new_checks
            };
            run_with(&mut a, start, from, until, refuse_c);
            let seen = timed_states(&mut a, start);
            assert_eq!(
                seen.first().map(|(_, s)| *s),
                Some(ConnectionState::Checking),
                "{case}: the new pair is checked: {seen:?}"
            );
            if with_end_of_candidates {
                let failed = seen
                    .iter()
                    .find(|(_, s)| *s == ConnectionState::Failed)
                    .map(|(at, _)| *at);
                assert!(
                    failed.is_some_and(|at| by_next_look(at, end_of_candidates)),
                    "{case}: failed at the next look after the end-of-candidates: {seen:?}"
                );
            } else {
                assert_eq!(
                    seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
                    vec![ConnectionState::Checking, ConnectionState::Disconnected],
                    "{case}: {seen:?}"
                );
                assert!(
                    by_next_look(seen[1].0, checking_timeout),
                    "{case}: disconnected by the checking timeout counted from the new checks: {seen:?}"
                );
            }
        }
    }
}

/// W3C webrtc-pc 5.6.4: "If begun in the transient "disconnected" state, it causes a
/// transition to "checking"": an ICE restart of an agent whose checks failed before the end
/// of the candidates checks the new generation and connects over it.
#[test]
fn a_restart_of_an_agent_whose_checks_failed_checks_and_connects() {
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    let refuse = |_: &Sent| Answer::Error(CODE_BAD_REQUEST);
    let at = Duration::from_secs(45);
    run_with(&mut a, start, Duration::ZERO, at, refuse);
    assert_eq!(a.state(), ConnectionState::Disconnected);
    let _ = timed_states(&mut a, start);

    a.restart(start + at, String::new(), String::new(), false)
        .unwrap();
    assert_eq!(a.state(), ConnectionState::Checking);
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a.add_remote_candidate(host(addr(REMOTE_B))).unwrap();
    a.start_connectivity_checks(
        start + at,
        true,
        REMOTE_UFRAG.to_owned(),
        REMOTE_PWD.to_owned(),
    )
    .unwrap();
    answered(&mut a, start, at, at + Duration::from_secs(2));
    let seen = timed_states(&mut a, start);
    assert_eq!(
        seen.first().map(|(_, s)| *s),
        Some(ConnectionState::Checking),
        "{seen:?}"
    );
    assert_eq!(a.state(), ConnectionState::Connected, "{seen:?}");
    assert!(!seen.iter().any(|(_, s)| *s == ConnectionState::Failed));
}

/// RFC 8445 Section 7.2.5.3.4 (`FailedNomination::FailChecklist`, the default): a nomination
/// answered with an error fails its pair and the checklist; before the end of the candidates
/// the agent is `Disconnected` with its checklist Failed and nominates nothing more (W3C
/// webrtc-pc 5.6.4), and `Failed` once both sides are done and the PAC timer has expired.
#[test]
fn a_failed_nomination_before_the_end_of_candidates_is_disconnected() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400)]);
    let out = run_with(&mut a, start, Duration::ZERO, Duration::from_secs(5), |s| {
        if s.message.contains(ATTR_USE_CANDIDATE) {
            Answer::Error(CODE_BAD_REQUEST)
        } else {
            Answer::Success(addr(LOCAL))
        }
    });
    let seen = timed_states(&mut a, start);
    assert_eq!(nominations(&out).len(), 1, "no other pair is nominated");
    assert_eq!(
        seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
        vec![ConnectionState::Checking, ConnectionState::Disconnected],
        "{seen:?}"
    );
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    assert!(a.get_selected_candidate_pair().is_none());

    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    // "and either zero local candidates were gathered or the PAC timer has expired": failed
    // as the timer expires.
    let out = run_with(
        &mut a,
        start,
        Duration::from_secs(5),
        PAC + LOOK + MS,
        |_| Answer::Success(addr(LOCAL)),
    );
    assert!(nominations(&out).is_empty());
    let seen = timed_states(&mut a, start);
    assert_eq!(
        seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
        vec![ConnectionState::Failed],
        "{seen:?}"
    );
    assert!(by_next_look(seen[0].0, PAC), "{seen:?}");
}

/// A lite agent (no checks of its own, RFC 8445 Section 2.5) whose full peer falls silent:
/// `Disconnected` 5 s after the peer's last request, and, past `disconnected_timeout +
/// failed_timeout`, still `Disconnected` until no candidate is to come (W3C webrtc-pc 5.6.4),
/// then `Failed`. With `set_failed_without_end_of_candidates` (it has no PAC timer, RFC 8863
/// Section 4 being for full agents) it fails at 30 s, as before ice-32.
#[test]
fn a_lite_agent_whose_peer_falls_silent_is_failed_only_after_the_end_of_candidates() {
    for fallback in [false, true] {
        let start = Instant::now();
        let cfg = AgentConfig {
            lite: true,
            candidate_types: vec![CandidateType::Host],
            ..config(false)
        };
        let mut a = started_agent(start, cfg, &[REMOTE_A]);
        a.set_failed_without_end_of_candidates(fallback);
        let nominating = peer_request(
            &a,
            vec![
                Box::new(AttrControlling(1)),
                Box::new(PriorityAttr(1000)),
                Box::new(UseCandidateAttr::new()),
            ],
        );
        deliver(&mut a, start, &nominating, REMOTE_A).unwrap();
        assert!(a.get_selected_candidate_pair().is_some());
        silent(&mut a, start, Duration::ZERO, Duration::from_secs(60));
        let seen = timed_states(&mut a, start);
        let at = |state| seen.iter().find(|(_, s)| *s == state).map(|(at, _)| *at);
        let disconnected = at(ConnectionState::Disconnected).expect("disconnected");
        assert!(
            by_next_look(disconnected, Duration::from_secs(5)),
            "{fallback}: {seen:?}"
        );
        if fallback {
            let failed = at(ConnectionState::Failed).expect("failed");
            assert!(
                by_next_look(failed, Duration::from_secs(30)),
                "{fallback}: {seen:?}"
            );
            continue;
        }
        assert_eq!(at(ConnectionState::Failed), None, "{seen:?}");
        assert_eq!(a.state(), ConnectionState::Disconnected);
        a.set_local_gathering_complete();
        a.set_remote_end_of_candidates();
        silent(
            &mut a,
            start,
            Duration::from_secs(60),
            Duration::from_secs(61),
        );
        let seen = timed_states(&mut a, start);
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert_eq!(seen[0].1, ConnectionState::Failed);
        assert!(by_next_look(seen[0].0, Duration::from_secs(60)), "{seen:?}");
    }
}

/// `Agent::set_failed_without_end_of_candidates`, libwebrtc's form and the end-of-candidates
/// fallback RFC 8863 Section 5 allows ("ICE agents MAY use the PAC timer to also serve as an
/// end-of-candidates fallback"): with nothing signalled, the checks that failed fail the
/// agent as the PAC timer expires (39.5 s), and consent lost fails it too, at the latest as
/// the timer expires.
#[test]
fn the_pac_timer_ends_the_candidates_when_set_to() {
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    a.set_failed_without_end_of_candidates(true);
    assert!(a.failed_without_end_of_candidates());
    run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(45),
        |_| Answer::Error(CODE_BAD_REQUEST),
    );
    let seen = timed_states(&mut a, start);
    assert_eq!(
        seen.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
        vec![ConnectionState::Checking, ConnectionState::Failed],
        "{seen:?}"
    );
    assert!(by_next_look(seen[1].0, PAC), "{seen:?}");

    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    a.set_failed_without_end_of_candidates(true);
    answered(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    silent(
        &mut a,
        start,
        Duration::from_secs(1),
        Duration::from_secs(45),
    );
    let seen = timed_states(&mut a, start);
    let failed = seen
        .iter()
        .find(|(_, s)| *s == ConnectionState::Failed)
        .map(|(at, _)| *at)
        .expect("failed");
    assert!(by_next_look(failed, PAC), "{seen:?}");
}

// --- A pair still to come from the peer's check (RFC 8445 7.3.1.3, RFC 8838 8) ---

/// The local passive TCP candidate of the scenarios below.
const LISTENER: &str = "192.168.0.2:7000";
/// A `<uuid>.local` name, as browsers signal their host candidates.
const PEER_MDNS_NAME: &str = "9b36eaac-bb2e-49bb-bb78-21c41c499900.local";

/// The peer's only candidates in the scenarios below: what it signals, and where its check
/// comes from.
#[derive(Clone, Copy, Debug)]
enum OnlyCandidate {
    /// A `tcptype active` host candidate (port 9, RFC 6544 Section 4.5); the agent has a
    /// passive one. The peer's check arrives on the connection it opens to it.
    ActiveTcp,
    /// A UDP host candidate behind a `<uuid>.local` name, the agent's mDNS resolution off.
    MdnsResolutionOff,
    /// The same with resolution on but unanswered: the query times out after a second.
    MdnsQueryTimesOut,
}

fn tcp_candidate(address: SocketAddr, tcp_type: TcpType) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: address.ip().to_string(),
            port: address.port(),
            component: 1,
            ..Default::default()
        },
        tcp_type,
    }
    .new_candidate_host()
    .unwrap()
}

/// A controlled agent, checking, with the agent's timeouts at their defaults (5 s
/// disconnected + 25 s failed): the peer has signalled `only` and end-of-candidates, local
/// gathering is complete.
fn agent_whose_peer_signalled(start: Instant, only: OnlyCandidate) -> Agent {
    agent_whose_peer_signalled_with(start, only, None)
}

/// [`agent_whose_peer_signalled`] with `failed_timeout` in place of the default 25 s.
fn agent_whose_peer_signalled_with(
    start: Instant,
    only: OnlyCandidate,
    failed_timeout: Option<Duration>,
) -> Agent {
    let mdns_mode = match only {
        OnlyCandidate::MdnsResolutionOff => crate::mdns::MulticastDnsMode::Disabled,
        _ => crate::mdns::MulticastDnsMode::QueryOnly,
    };
    let cfg = AgentConfig {
        multicast_dns_mode: mdns_mode,
        multicast_dns_query_timeout: Some(Duration::from_secs(1)),
        multicast_dns_first_query_delay: Some(false),
        failed_timeout: failed_timeout.or(config(false).failed_timeout),
        ..config(false)
    };
    let mut a = Agent::new(start, Arc::new(cfg), provider()).unwrap();
    let remote = match only {
        OnlyCandidate::ActiveTcp => {
            a.add_local_candidate(tcp_candidate(addr(LISTENER), TcpType::Passive))
                .unwrap();
            tcp_candidate(addr("192.168.0.3:9"), TcpType::Active)
        }
        OnlyCandidate::MdnsResolutionOff | OnlyCandidate::MdnsQueryTimesOut => {
            a.add_local_candidate(host(addr(LOCAL))).unwrap();
            CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: PEER_MDNS_NAME.to_owned(),
                    port: 2000,
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .unwrap()
        }
    };
    assert!(
        !a.add_remote_candidate(remote).unwrap(),
        "{only:?}: not paired"
    );
    a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    a
}

/// The peer's check (controlling, nominating) arriving at `at` from `from`, our triggered
/// check back and the peer's answer to it: over the TCP connection on `LISTENER`, or as UDP
/// datagrams on `LOCAL`.
fn peer_checks(a: &mut Agent, at: Instant, only: OnlyCandidate, from: SocketAddr) {
    let (local, protocol) = match only {
        OnlyCandidate::ActiveTcp => (addr(LISTENER), TransportProtocol::TCP),
        _ => (addr(LOCAL), TransportProtocol::UDP),
    };
    let read = |a: &mut Agent, m: &Message| {
        a.handle_read(TaggedBytesMut {
            now: at,
            transport: TransportContext {
                local_addr: local,
                peer_addr: from,
                ecn: None,
                transport_protocol: protocol,
            },
            message: BytesMut::from(&m.raw[..]),
        })
        .unwrap();
    };
    let request = peer_request(
        a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    read(a, &request);
    a.handle_timeout(at).unwrap();
    let check = std::iter::from_fn(|| a.poll_write())
        .filter(|t| t.transport.peer_addr == from)
        .map(|t| {
            let mut m = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            m.decode().unwrap();
            m
        })
        .find(|m| m.typ == BINDING_REQUEST)
        .expect("a triggered check back to the peer");
    read(
        a,
        &peer_response(BINDING_SUCCESS, check.transaction_id, local, None),
    );
    a.handle_timeout(at).unwrap();
}

/// RFC 8445 Section 7.3.1.3 (a check from an unknown source gives a peer-reflexive remote
/// candidate, and Section 7.3.1.4 its pair) with RFC 8838 Section 8 ("a Trickle ICE agent
/// MUST keep each checklist in the Running state as long as it expects candidate pairs to be
/// incrementally added to the checklist"): a peer whose only candidates reach the agent by
/// its own checks does not fail the empty checklist when both sides have signalled
/// end-of-candidates. A `tcptype active` candidate dials the agent's passive one (RFC 6544
/// Section 7.2: "STUN requests received on a passive TCP candidate will typically produce a
/// remote peer reflexive candidate"); a `.local` name the agent does not resolve still sends
/// checks (draft-ietf-mmusic-mdns-ice-candidates Section 5.3: "Through the process of
/// learning peer-reflexive candidates [...] allowing ICE to succeed even though the legacy
/// endpoint cannot resolve the mDNS names"). The peer's check then forms the pair and the
/// agent connects over it.
#[test]
fn a_peer_reached_only_by_its_own_checks_keeps_the_empty_checklist_running_and_connects() {
    for (only, from) in [
        (OnlyCandidate::ActiveTcp, "192.168.0.3:40001"),
        (OnlyCandidate::MdnsResolutionOff, REMOTE_A),
        (OnlyCandidate::MdnsQueryTimesOut, REMOTE_A),
    ] {
        let start = Instant::now();
        let mut a = agent_whose_peer_signalled(start, only);
        // Three seconds of nothing (the query, when there is one, timed out at one).
        silent(&mut a, start, Duration::ZERO, Duration::from_secs(3));
        assert!(a.candidate_pairs.is_empty(), "{only:?}");
        assert!(a.mdns_queries.is_empty(), "{only:?}");
        assert_eq!(a.state(), ConnectionState::Checking, "{only:?}");
        assert_eq!(a.checklist_state(), ChecklistState::Running, "{only:?}");

        // The peer's check.
        let from = addr(from);
        peer_checks(&mut a, start + Duration::from_secs(3), only, from);
        assert_eq!(
            a.media_path().map(|p| p.peer_addr),
            Some(from),
            "{only:?}: selected over the pair the check formed"
        );
        assert_eq!(
            a.remote_candidates[a.candidate_pairs[0].remote_index].candidate_type(),
            CandidateType::PeerReflexive,
            "{only:?}"
        );
        let reached = states(&mut a);
        assert!(
            !reached.contains(&ConnectionState::Failed)
                && reached
                    .iter()
                    .any(|s| matches!(s, ConnectionState::Connected | ConnectionState::Completed)),
            "{only:?}: {reached:?}"
        );
    }
}

/// The agent's timeouts still end a checklist nobody fills: when the peer of the scenarios
/// above never sends its check, the agent fails once `disconnected_timeout + failed_timeout`
/// after checking began has passed and the PAC timer has expired (RFC 8863 Section 4: 39.5 s),
/// at its next look at the state (every 200 ms while checking), and not before: with the
/// default 5 + 25 s at the PAC timer, with 5 + 60 s at 65 s (past the PAC timer the
/// checklist still keeps Running: a pair is still expected from the peer's check, RFC 8838
/// Section 8).
#[test]
fn a_peer_reached_only_by_its_own_checks_that_never_checks_fails_by_the_timeout() {
    for (failed_timeout, expected) in [
        (None, PAC),
        (Some(Duration::from_secs(60)), Duration::from_secs(65)),
    ] {
        for only in [
            OnlyCandidate::ActiveTcp,
            OnlyCandidate::MdnsResolutionOff,
            OnlyCandidate::MdnsQueryTimesOut,
        ] {
            let start = Instant::now();
            let mut a = agent_whose_peer_signalled_with(start, only, failed_timeout);
            silent(&mut a, start, Duration::ZERO, Duration::from_secs(70));
            let failed_at: Vec<Duration> = std::iter::from_fn(|| a.poll_event())
                .filter(|e| {
                    matches!(
                        e.event,
                        Event::ConnectionStateChange(ConnectionState::Failed)
                    )
                })
                .map(|e| e.now.duration_since(start))
                .collect();
            assert_eq!(
                failed_at.len(),
                1,
                "{only:?} {failed_timeout:?}: {failed_at:?}"
            );
            assert!(
                failed_at[0] >= expected && failed_at[0] <= expected + LOOK,
                "{only:?} {failed_timeout:?}: failed at {:?}",
                failed_at[0]
            );
            assert_eq!(a.state(), ConnectionState::Failed);
        }
    }
}

/// RFC 8838 Section 8 with RFC 8445 Section 7.2.5.4: an empty checklist fails once both
/// sides have signalled end-of-candidates and the PAC timer has expired (RFC 8863 Section 4),
/// without waiting for the checking timeout, when the only candidate the peer signalled cannot
/// form a pair by its own check: its `tcptype active` candidate has no passive candidate of
/// the agent to dial (RFC 6544 Section 6.2: "tcp-active" pairs with "tcp-passive" only): the
/// agent's candidates are UDP, active TCP, simultaneous-open, or of the other address family.
/// The peer may still check one of the agent's other candidates from an address of its own
/// (RFC 8863 Section 3.2), so until the timer expires the checklist keeps Running.
#[test]
fn an_active_tcp_candidate_with_nothing_of_ours_to_dial_fails_the_empty_checklist_with_the_pac_timer()
 {
    for local in [
        host(addr(LOCAL)),
        tcp_candidate(addr("192.168.0.2:9"), TcpType::Active),
        tcp_candidate(addr(LISTENER), TcpType::SimultaneousOpen),
        tcp_candidate(addr("[fd00::2]:7000"), TcpType::Passive),
    ] {
        let start = Instant::now();
        let mut a = Agent::new(start, Arc::new(config(false)), provider()).unwrap();
        let described = format!("{} {}", local.network_type(), local.tcp_type());
        a.add_local_candidate(local).unwrap();
        a.add_remote_candidate(tcp_candidate(addr("192.168.0.3:9"), TcpType::Active))
            .unwrap();
        a.start_connectivity_checks(start, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
            .unwrap();
        a.set_local_gathering_complete();
        a.set_remote_end_of_candidates();
        silent(&mut a, start, Duration::ZERO, PAC - MS);
        assert_eq!(a.state(), ConnectionState::Checking, "local {described}");
        silent(&mut a, start, PAC - MS, PAC + LOOK);
        assert_eq!(a.state(), ConnectionState::Failed, "local {described}");
    }
}

/// RFC 8838 Section 14 with Section 15: what the peer signalled of a generation is that
/// generation's. After an ICE restart, a new peer that signals nothing but end-of-candidates
/// fails the empty checklist when the PAC timer the restart started expires (RFC 8863 Section
/// 4), without waiting for the checking timeout as the generation before, which had an active
/// TCP candidate that dialled the agent, would have.
#[test]
fn an_ice_restart_forgets_the_candidates_that_could_only_dial_us() {
    let start = Instant::now();
    // A checking timeout (5 + 60 s) past the PAC timer: a checklist the previous generation's
    // candidate kept Running would fail only by it.
    let mut a = agent_whose_peer_signalled_with(
        start,
        OnlyCandidate::ActiveTcp,
        Some(Duration::from_secs(60)),
    );
    silent(&mut a, start, Duration::ZERO, Duration::from_secs(1));
    assert_eq!(a.state(), ConnectionState::Checking);
    a.restart(start, String::new(), String::new(), true)
        .unwrap();
    a.set_remote_credentials(REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    silent(&mut a, start, Duration::from_secs(1), PAC - MS);
    assert_eq!(a.state(), ConnectionState::Checking);
    silent(&mut a, start, PAC - MS, PAC + LOOK);
    assert_eq!(a.state(), ConnectionState::Failed);
}

/// RFC 8838 Section 14: "After an agent has received an end-of-candidates indication, it MUST
/// ignore any newly received candidates". Section 13: no local candidate follows the local
/// indication either. An ICE restart starts over.
#[test]
fn test_candidates_after_end_of_candidates_are_ignored() {
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    a.set_remote_end_of_candidates();
    assert!(!a.add_remote_candidate(host(addr(REMOTE_B))).unwrap());
    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.candidate_pairs.len(), 1);

    a.set_local_gathering_complete();
    assert!(
        !a.add_local_candidate(host(addr("192.168.0.9:1000")))
            .unwrap()
    );
    assert_eq!(a.local_candidates.len(), 1);

    // A peer-reflexive candidate is not a signalled one: checks still teach them.
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start, &request, REMOTE_B).unwrap();
    assert_eq!(a.remote_candidates.len(), 2);

    a.restart(start, String::new(), String::new(), true)
        .unwrap();
    assert!(a.add_remote_candidate(host(addr(REMOTE_B))).unwrap());
    assert!(
        a.add_local_candidate(host(addr("192.168.0.9:1000")))
            .unwrap()
    );
}

/// RFC 8838 Section 11: a signalled candidate with the address of a peer-reflexive one the
/// agent learned from a check replaces it: one candidate, one pair, with the signalled
/// priority; not a second candidate whose pair could never succeed.
#[test]
fn test_signalled_candidate_replaces_the_peer_reflexive_one_it_duplicates() {
    let start = Instant::now();
    let mut a = started_agent(start, config(false), &[]);
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, start, &request, REMOTE_A).unwrap();
    assert_eq!(
        a.remote_candidates[0].candidate_type(),
        CandidateType::PeerReflexive
    );
    answered(&mut a, start, Duration::ZERO, 100 * MS);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    let id = a.remote_candidates[0].id().to_owned();

    assert!(
        a.add_remote_candidate(host_with_priority(addr(REMOTE_A), 2130706431))
            .unwrap()
    );
    // The pair keeps its identity (its statistics are keyed by the candidates' ids).
    assert_eq!(a.remote_candidates[0].id(), id);
    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.remote_candidates[0].candidate_type(), CandidateType::Host);
    assert_eq!(a.remote_candidates[0].priority(), 2130706431);
    assert_eq!(a.candidate_pairs.len(), 1);
    assert_eq!(a.candidate_pairs[0].remote_priority, 2130706431);
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    // No check is spent on a duplicate.
    assert!(requests_of(&silent(&mut a, start, 100 * MS, 3000 * MS)).is_empty());
}

/// With `FailedNomination::Retry`, Section 7.3.1.5: the controlled agent's check that a
/// nomination triggered fails: the pair is Failed and the nomination with it, and the checklist
/// keeps running while the controlling agent can still nominate another pair.
#[test]
fn test_controlled_nomination_dies_with_its_triggered_check() {
    let start = Instant::now();
    let cfg = AgentConfig {
        max_binding_requests: Some(2),
        failed_nomination: FailedNomination::Retry,
        ..config(false)
    };
    let mut a = agent_with(start, cfg, &[(1, 500), (2, 400)]);
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, start, &nominate, "10.0.0.1:5000").unwrap();
    let pair = a.find_pair(0, 0).unwrap();
    assert!(a.candidate_pairs[pair].nomination_pending);

    // 1 never answers our checks; 2 does.
    run_with(
        &mut a,
        start,
        Duration::ZERO,
        Duration::from_secs(20),
        |s| {
            if s.to == remote_addr(2) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        },
    );
    assert_eq!(state_of(&a, 1), CandidatePairState::Failed);
    assert!(!a.candidate_pairs[pair].nomination_pending);
    assert!(a.get_selected_candidate_pair().is_none());
    assert_eq!(a.state(), ConnectionState::Checking);

    // The controlling agent nominates the pair that works.
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(
        &mut a,
        start + Duration::from_secs(20),
        &nominate,
        "10.0.0.2:5000",
    )
    .unwrap();
    assert_eq!(
        a.get_selected_candidate_pair().unwrap().1.addr(),
        remote_addr(2)
    );
}

/// A controlled agent nominated on the pair to remote 1, whose triggered check is answered by
/// `answer`; the agent with the states it went through. Remote 2 answers every check.
fn controlled_nomination(
    start: Instant,
    answer: impl FnMut(&Sent) -> Answer,
) -> (Agent, Vec<ConnectionState>) {
    let cfg = AgentConfig {
        max_binding_requests: Some(2),
        ..config(false)
    };
    let mut a = agent_with(start, cfg, &[(1, 500), (2, 400)]);
    // Both sides are done with their candidates: the failed checklist fails the agent (W3C
    // webrtc-pc 5.6.4).
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, start, &nominate, "10.0.0.1:5000").unwrap();
    assert!(a.candidate_pairs[a.find_pair(0, 0).unwrap()].nomination_pending);
    // Past the PAC timer, which "failed" waits for (W3C webrtc-pc 5.6.4).
    run_with(
        &mut a,
        start,
        Duration::ZERO,
        PAC + Duration::from_secs(1),
        answer,
    );
    let seen = states(&mut a);
    (a, seen)
}

/// RFC 8445 Sections 7.2.5.3.4 and 7.3.1.5, the default: "If the triggered request fails, the
/// agent MUST remove the candidate pair from the valid list, set the candidate pair state to
/// Failed, and set the checklist state to Failed." The controlled agent's check that a
/// received USE-CANDIDATE triggered times out (Section 7.2.5.2.3) and the checklist fails,
/// though another pair works.
#[test]
fn test_a_controlled_nomination_whose_triggered_check_times_out_fails_the_checklist() {
    let start = Instant::now();
    let (a, seen) = controlled_nomination(start, |s| {
        if s.to == remote_addr(2) {
            Answer::Success(addr(LOCAL))
        } else {
            Answer::Silence
        }
    });
    assert!(seen.contains(&ConnectionState::Failed), "{seen:?}");
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    assert!(a.get_selected_candidate_pair().is_none());
}

/// The same when the triggered check is answered with an unrecoverable error (Section
/// 7.2.5.2.4).
#[test]
fn test_a_controlled_nomination_whose_triggered_check_gets_an_error_fails_the_checklist() {
    let start = Instant::now();
    let (a, seen) = controlled_nomination(start, |s| {
        if s.to == remote_addr(2) {
            Answer::Success(addr(LOCAL))
        } else {
            Answer::Error(CODE_BAD_REQUEST)
        }
    });
    assert!(seen.contains(&ConnectionState::Failed), "{seen:?}");
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
}

// --- Heavy loss: a nomination whose requests or responses are all lost ---

/// A controlling agent with one remote candidate and the checking timer on (the defaults):
/// plain checks are answered, nominations only when `answer_nominations` says so, and the
/// peer, which has accepted the nomination on its side, sends a consent request every
/// `peer_every` (none when `None`). Both sides are done with their candidates (W3C webrtc-pc
/// 5.6.4: a failure is "failed" only then). Returns what the agent sent and the states it
/// reported, with the time (since `start`) of each, until `until`.
fn nominating_over_loss(
    start: Instant,
    cfg: AgentConfig,
    until: Duration,
    peer_every: Option<Duration>,
    mut answer_nominations: impl FnMut(Duration) -> bool,
) -> (Agent, Vec<Sent>, Vec<(Duration, ConnectionState)>) {
    let mut a = bare_agent(start, cfg);
    a.add_remote_candidate(remote(1, 500, "f1")).unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    let mut out = vec![];
    let mut seen = vec![];
    let step = peer_every.unwrap_or(Duration::from_secs(1));
    let mut at = Duration::ZERO;
    while at < until {
        let next = (at + step).min(until);
        out.extend(run_with(&mut a, start, at, next, |s| {
            if !s.message.contains(ATTR_USE_CANDIDATE) || answer_nominations(s.at) {
                Answer::Success(addr(LOCAL))
            } else {
                Answer::Silence
            }
        }));
        seen.extend(states(&mut a).into_iter().map(|s| (next, s)));
        at = next;
        if peer_every.is_some() && a.state() != ConnectionState::Failed {
            let request = peer_request(
                &a,
                vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
            );
            deliver(&mut a, start + at, &request, "10.0.0.1:5000").unwrap();
        }
    }
    (a, out, seen)
}

/// The nominations among `out`, one per transaction: (first transmission, transmissions).
fn nominations(out: &[Sent]) -> Vec<(Duration, usize)> {
    checks_started(out)
        .into_iter()
        .filter(|s| s.message.contains(ATTR_USE_CANDIDATE))
        .map(|first| {
            let id = first.message.transaction_id;
            let count = requests_of(out)
                .iter()
                .filter(|s| s.message.transaction_id == id)
                .count();
            (first.at, count)
        })
        .collect()
}

/// RFC 8445 Sections 6.1.4.2 and 8.1.2: the checklist fails when every pair has failed, and
/// Section 14.3 / RFC 8489 Section 6.2.1: a check is a transaction of `Rc` (7) requests,
/// RTO, 2 RTO, 4 RTO, ... apart, that ends 39.5 s after it started at an RTO of 500 ms. At
/// 30 and 40 % loss (`tests/lossy_link_rtc2rtc.rs`, seeds 0x4a, 0xff, 0x127 and 0x1c, 0x21)
/// the controlling agent failed 30 seconds in, still checking, 29.5 seconds after the success
/// response that validated its pair, while its nomination's transaction was still open (six
/// requests sent, every response lost) and the peer, which had accepted the nomination, was
/// connected and sending consent requests: the inherited checking timer
/// (`disconnected_timeout + failed_timeout`, 30 s from entering checking) failed the agent.
///
/// Now the timer fails the agent only once nothing is left in progress. The pair has received a
/// success response, so it stays Succeeded, and with `FailedNomination::Retry` the nomination
/// whose transaction timed out is sent again while the peer is heard from; once a response
/// comes the pair is selected.
#[test]
fn test_an_unanswered_nomination_is_sent_again_while_the_peer_is_heard_from() {
    let start = Instant::now();
    let answered_from = Duration::from_secs(45);
    let (a, out, seen) = nominating_over_loss(
        start,
        retrying(config(true)),
        Duration::from_secs(60),
        Some(Duration::from_secs(5)),
        |at| at >= answered_from,
    );
    assert!(
        !seen.iter().any(|(_, s)| *s == ConnectionState::Failed),
        "the agent failed with its nomination in progress: {seen:?}"
    );
    let nominations = nominations(&out);
    assert!(nominations.len() >= 2, "nominated again: {nominations:?}");
    let (first_at, first_count) = nominations[0];
    assert_eq!(
        first_count, 7,
        "the first nomination is a whole transaction"
    );
    let (second_at, _) = nominations[1];
    assert!(
        second_at >= first_at + Duration::from_millis(39_400),
        "the second nomination follows the end of the first transaction: {nominations:?}"
    );
    // (Completed: both sides are done with their candidates.)
    assert_eq!(a.state(), ConnectionState::Completed);
    assert!(a.get_selected_candidate_pair().is_some());
    assert!(
        seen.iter()
            .any(|(at, s)| *s == ConnectionState::Connected && *at >= answered_from)
    );
}

/// The bound of [`test_an_unanswered_nomination_is_sent_again_while_the_peer_is_heard_from`]: with
/// `FailedNomination::Retry` and the peer silent, the nomination is given up 30 seconds (the
/// consent expiry, RFC 7675 Section 5.1) after the peer was last heard from or the nomination
/// started, and the pair fails with it. With no pair left the checklist fails, but not while
/// the PAC timer runs (RFC 8863 Section 4: "MUST NOT update a checklist state from Running to
/// Failed, even if there are no pairs left in the checklist to check"): at 39.5 s, not at the
/// give-up 30 s after the nomination.
#[test]
fn test_a_nomination_is_given_up_when_the_peer_is_not_heard_from_for_thirty_seconds() {
    let start = Instant::now();
    let (a, out, seen) = nominating_over_loss(
        start,
        retrying(config(true)),
        Duration::from_secs(45),
        None,
        |_| false,
    );
    let (nominated_at, _) = nominations(&out)[0];
    let given_up = nominated_at + Duration::from_secs(30);
    assert!(given_up < PAC, "the give-up comes inside the PAC timer");
    let failed_at = seen
        .iter()
        .find(|(_, s)| *s == ConnectionState::Failed)
        .map(|(at, _)| *at)
        .expect("the agent fails");
    // `seen` is sampled once a second.
    assert!(
        failed_at >= PAC && failed_at <= PAC + Duration::from_secs(1),
        "failed at {failed_at:?}, nominated at {nominated_at:?}"
    );
    assert_eq!(a.state(), ConnectionState::Failed);
}

/// `AgentConfig::failed_nomination` with `FailedNomination::Retry`.
fn retrying(cfg: AgentConfig) -> AgentConfig {
    AgentConfig {
        failed_nomination: FailedNomination::Retry,
        ..cfg
    }
}

/// When the agent failed, if it did, among `seen`.
fn failed_at(seen: &[(Duration, ConnectionState)]) -> Option<Duration> {
    seen.iter()
        .find(|(_, s)| *s == ConnectionState::Failed)
        .map(|(at, _)| *at)
}

/// RFC 8445 Section 7.2.5.3.4, the default (`FailedNomination::FailChecklist`): "If the request
/// fails (Section 7.2.5.2), the agent MUST remove the candidate pair from the valid list, set
/// the candidate pair state to Failed, and set the checklist state to Failed." A request fails
/// by timing out (Section 7.2.5.2.3) at the end of its transaction: `Rc` (7) requests, RTO,
/// 2 RTO, ... apart, the last given `Rm` (16) RTOs (Section 14.3, RFC 8489 Section 6.2.1),
/// 39.5 s at an RTO of 500 ms. The pair and the checklist fail then, also while the peer is
/// heard from; not at the 30 second checking timer before that, and the nomination is not
/// sent again.
#[test]
fn test_a_nomination_that_times_out_fails_the_pair_and_the_checklist() {
    let start = Instant::now();
    let (a, out, seen) = nominating_over_loss(
        start,
        config(true),
        Duration::from_secs(50),
        Some(Duration::from_secs(5)),
        |_| false,
    );
    let nominations = nominations(&out);
    assert_eq!(nominations.len(), 1, "not nominated again: {nominations:?}");
    let (nominated_at, count) = nominations[0];
    assert_eq!(count, 7, "a whole transaction");
    let failed_at = failed_at(&seen).expect("the agent fails");
    assert!(
        failed_at >= nominated_at + Duration::from_millis(39_400)
            && failed_at <= nominated_at + Duration::from_secs(45),
        "failed at {failed_at:?}, nominated at {nominated_at:?}"
    );
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    // (A failed agent clears its pairs: none is left valid.)
    assert!(!a.candidate_pairs.iter().any(|p| p.valid));
    assert!(a.get_selected_candidate_pair().is_none());
}

/// The same with the peer silent: the nomination fails when its transaction does, 39.5 s
/// after it was sent, and not when the peer has not been heard from for 30 s (that bound is
/// `FailedNomination::Retry`'s).
#[test]
fn test_a_nomination_to_a_silent_peer_fails_at_the_end_of_its_transaction() {
    let start = Instant::now();
    let (a, out, seen) =
        nominating_over_loss(start, config(true), Duration::from_secs(50), None, |_| {
            false
        });
    let nominations = nominations(&out);
    assert_eq!(nominations.len(), 1, "{nominations:?}");
    let (nominated_at, count) = nominations[0];
    assert_eq!(count, 7, "a whole transaction");
    let failed_at = failed_at(&seen).expect("the agent fails");
    assert!(
        failed_at >= nominated_at + Duration::from_millis(39_400)
            && failed_at <= nominated_at + Duration::from_secs(41),
        "failed at {failed_at:?}, nominated at {nominated_at:?}"
    );
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
}

/// Sections 7.2.5.2.4 and 7.2.5.3.4: a nomination answered with an unrecoverable error
/// response has failed; the pair leaves the valid list and the checklist fails, though another
/// valid pair is left.
#[test]
fn test_a_nomination_answered_with_an_error_fails_the_checklist() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400)]);
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    // Past the PAC timer, which "failed" waits for (W3C webrtc-pc 5.6.4).
    let out = run_with(
        &mut a,
        start,
        Duration::ZERO,
        PAC + Duration::from_secs(1),
        |s| {
            if s.message.contains(ATTR_USE_CANDIDATE) {
                Answer::Error(CODE_BAD_REQUEST)
            } else {
                Answer::Success(addr(LOCAL))
            }
        },
    );
    let seen = states(&mut a);
    assert_eq!(nominations(&out).len(), 1, "no other pair is nominated");
    assert!(seen.contains(&ConnectionState::Failed), "{seen:?}");
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    assert!(!a.candidate_pairs.iter().any(|p| p.valid));
    assert!(a.get_selected_candidate_pair().is_none());
}

/// With `FailedNomination::Retry` an error response fails the pair only, and the next valid
/// pair is nominated and selected.
#[test]
fn test_a_nomination_answered_with_an_error_moves_on_when_set_to_retry() {
    let start = Instant::now();
    let mut a = agent_with(start, retrying(config(true)), &[(1, 500), (2, 400)]);
    let mut first = true;
    let out = run_with(&mut a, start, Duration::ZERO, Duration::from_secs(5), |s| {
        if s.message.contains(ATTR_USE_CANDIDATE) && std::mem::take(&mut first) {
            Answer::Error(CODE_BAD_REQUEST)
        } else {
            Answer::Success(addr(LOCAL))
        }
    });
    assert_eq!(nominations(&out).len(), 2);
    assert_ne!(a.checklist_state(), ChecklistState::Failed);
    assert!(a.get_selected_candidate_pair().is_some());
}

/// Sections 7.2.5.2.1 and 7.2.5.3.4: a success response to a nomination from another address
/// than the request went to is a failed request; the pair and the checklist fail.
#[test]
fn test_a_nomination_answered_from_another_address_fails_the_checklist() {
    let start = Instant::now();
    let mut a = agent_with(start, config(true), &[(1, 500), (2, 400)]);
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    let mut nomination = None;
    run_with(&mut a, start, Duration::ZERO, Duration::from_secs(5), |s| {
        if s.message.contains(ATTR_USE_CANDIDATE) {
            nomination.get_or_insert((s.message.transaction_id, s.to));
            Answer::Silence
        } else {
            Answer::Success(addr(LOCAL))
        }
    });
    let (id, to) = nomination.expect("a pair is nominated");
    let other = [remote_addr(1), remote_addr(2)]
        .into_iter()
        .find(|r| *r != to)
        .unwrap();
    let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
    deliver(
        &mut a,
        start + Duration::from_secs(5),
        &response,
        &other.to_string(),
    )
    .unwrap();
    // Past the PAC timer, which "failed" waits for (W3C webrtc-pc 5.6.4).
    silent(
        &mut a,
        start,
        Duration::from_secs(5),
        PAC + Duration::from_secs(1),
    );
    let seen = states(&mut a);
    assert!(seen.contains(&ConnectionState::Failed), "{seen:?}");
    assert_eq!(a.checklist_state(), ChecklistState::Failed);
    assert!(a.get_selected_candidate_pair().is_none());
}

/// RFC 8445 Section 14.2: "all agents together send no more than one transaction per 5 ms".
/// Two agents of one application share a `PacingGroup`: stepped together, every new
/// transaction (a check's first request) of either starts at least 5 ms after the previous
/// one of both; without the group the two agents start theirs at the same instants.
#[test]
fn test_agents_that_share_a_pacing_group_start_one_transaction_per_5_ms_together() {
    let start = Instant::now();
    let starts = |group: Option<std::sync::Arc<PacingGroup>>| {
        let cfg = || AgentConfig {
            ta: Some(Duration::from_millis(5)),
            pacing_group: group.clone(),
            ..config(true)
        };
        let mut agents = [
            agent_with(start, cfg(), &[(1, 500), (2, 400), (3, 300)]),
            agent_with(start, cfg(), &[(4, 500), (5, 400), (6, 300)]),
        ];
        let mut seen = std::collections::HashSet::new();
        let mut times = vec![];
        for ms in 0..100 {
            let now = start + Duration::from_millis(ms);
            for a in agents.iter_mut() {
                a.handle_timeout(now).unwrap();
                while let Some(t) = a.poll_write() {
                    let mut m = Message {
                        raw: t.message.to_vec(),
                        ..Message::default()
                    };
                    m.decode().unwrap();
                    if m.typ == BINDING_REQUEST && seen.insert(m.transaction_id) {
                        times.push(now);
                    }
                }
            }
        }
        times
    };
    let shared = starts(Some(PacingGroup::new()));
    assert!(shared.len() >= 6, "every pair is checked: {}", shared.len());
    for w in shared.windows(2) {
        assert!(
            w[1].duration_since(w[0]) >= Duration::from_millis(5),
            "{:?} apart",
            w[1].duration_since(w[0])
        );
    }
    let alone = starts(None);
    assert!(
        alone.windows(2).any(|w| w[1] == w[0]),
        "without the group two agents start together"
    );
}

/// draft-ietf-mmusic-mdns-ice-candidates section 3.3.1: "Statistics related to ICE
/// candidates that are accessible to the web application MUST NOT contain the IP address of a
/// local or remote mDNS candidate". With the host address hidden behind a name
/// (`QueryAndGather`), a local peer-reflexive candidate learnt from a mapped address that is
/// that host address shows the name, not the address, and does not give its base in the
/// related address; the selected pair the application reads carries neither.
#[test]
fn test_a_local_peer_reflexive_candidate_does_not_show_a_hidden_host_address() {
    let start = Instant::now();
    let hidden = addr(LOCAL).ip();
    let mapped = SocketAddr::new(hidden, 4000);
    let cfg = AgentConfig {
        multicast_dns_mode: MulticastDnsMode::QueryAndGather,
        ..config(true)
    };
    let mut a = agent_with(start, cfg, &[(1, 500)]);
    run_with(&mut a, start, Duration::ZERO, 300 * MS, |_| {
        Answer::Success(mapped)
    });
    let name = a.local_candidates[0].address().to_owned();
    assert!(name.ends_with(".local"), "the host is hidden: {name}");
    let learned = a
        .local_candidates
        .iter()
        .find(|c| c.candidate_type() == CandidateType::PeerReflexive)
        .expect("a local peer-reflexive candidate");
    assert_eq!(
        learned.addr(),
        mapped,
        "the agent itself still uses the address"
    );
    assert_eq!(learned.address(), name, "shown under the host's name");
    assert_eq!(
        learned.signalled_related_address().map(|r| r.address),
        Some("0.0.0.0".to_owned()),
        "its base is not shown"
    );
    // What the peer connection gives the application of the selected pair: the address and
    // the signalled related address.
    let (local, _) = a.get_selected_candidate_pair().unwrap();
    let shown = format!(
        "{} {:?}",
        local.address(),
        local.signalled_related_address()
    );
    assert!(
        !shown.contains(&hidden.to_string()),
        "the selected pair's local candidate: {shown}"
    );
}
