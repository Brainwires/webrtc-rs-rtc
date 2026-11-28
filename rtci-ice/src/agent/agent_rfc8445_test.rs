//! RFC 8445 behaviour, read from what the agent puts on the wire: every test here delivers
//! datagrams through `handle_read`, advances time through `handle_timeout` and decodes what
//! `poll_write` returns.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::{
    ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING, ATTR_PRIORITY, ATTR_USE_CANDIDATE, ATTR_USERNAME,
};
use stun::error_code::{CODE_BAD_REQUEST, CODE_ROLE_CONFLICT, ErrorCode, ErrorCodeAttribute};

use super::*;
use crate::attributes::control::{AttrControlled, AttrControlling};
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
use crate::candidate::candidate_host::CandidateHostConfig;

pub(super) fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

pub(super) const LOCAL: &str = "192.168.0.2:1000";
pub(super) const REMOTE_A: &str = "192.168.0.3:2000";
pub(super) const REMOTE_B: &str = "192.168.0.4:3000";
pub(super) const REMOTE_UFRAG: &str = "remoteufrag";
pub(super) const REMOTE_PWD: &str = "remotepwdremotepwdremotepwd";

pub(super) fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub(super) fn host(addr: SocketAddr) -> Candidate {
    host_with_priority(addr, 0)
}

pub(super) fn host_with_priority(addr: SocketAddr, priority: u32) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            priority,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap()
}

/// An agent with one local host candidate (`LOCAL`) and nothing from the peer yet.
pub(super) fn bare_agent(now: Instant, config: AgentConfig) -> Agent {
    let mut a = Agent::new(now, Arc::new(config), provider()).unwrap();
    a.add_local_candidate(host(addr(LOCAL))).unwrap();
    a
}

/// `bare_agent` with the peer's credentials and the remote candidates `remotes`, checking.
pub(super) fn started_agent(now: Instant, config: AgentConfig, remotes: &[&str]) -> Agent {
    let controlling = config.is_controlling;
    let mut a = bare_agent(now, config);
    for remote in remotes {
        a.add_remote_candidate(host(addr(remote))).unwrap();
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

pub(super) fn config(controlling: bool) -> AgentConfig {
    AgentConfig {
        is_controlling: controlling,
        ..AgentConfig::default()
    }
}

/// The peer's Binding request to `a`: USERNAME `<a's ufrag>:<peer's>`, the given attributes,
/// MESSAGE-INTEGRITY with `a`'s password, FINGERPRINT.
pub(super) fn peer_request(a: &Agent, extra: Vec<Box<dyn Setter>>) -> Message {
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":" + REMOTE_UFRAG;
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
    ];
    setters.extend(extra);
    setters.push(Box::new(
        MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider.crypto(),
        ),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut msg = Message::new();
    msg.build(&setters).unwrap();
    msg
}

/// The peer's response of type `typ` to the agent's request `id`, signed with the peer's
/// password.
pub(super) fn peer_response(
    typ: MessageType,
    id: TransactionId,
    mapped: SocketAddr,
    error: Option<ErrorCode>,
) -> Message {
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![Box::new(typ), Box::new(id)];
    match error {
        Some(code) => setters.push(Box::new(code)),
        None => setters.push(Box::new(XorMappedAddress {
            ip: mapped.ip(),
            port: mapped.port(),
        })),
    }
    setters.push(Box::new(
        MessageIntegrity::new_short_term_integrity_with_provider(
            REMOTE_PWD.to_owned(),
            provider.crypto(),
        ),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut msg = Message::new();
    msg.build(&setters).unwrap();
    msg
}

/// Delivers `raw` to the agent as a UDP datagram from `from` on its local candidate.
pub(super) fn deliver_raw(a: &mut Agent, now: Instant, raw: &[u8], from: &str) -> Result<()> {
    a.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: addr(LOCAL),
            peer_addr: addr(from),
            ecn: None,
            transport_protocol: TransportProtocol::UDP,
        },
        message: BytesMut::from(raw),
    })
}

pub(super) fn deliver(a: &mut Agent, now: Instant, m: &Message, from: &str) -> Result<()> {
    deliver_raw(a, now, &m.raw, from)
}

/// What the agent wrote since the last call: decoded STUN messages with their destination.
pub(super) fn sent(a: &mut Agent) -> Vec<(Message, SocketAddr)> {
    let mut out = vec![];
    while let Some(t) = a.poll_write() {
        let mut m = Message {
            raw: t.message.to_vec(),
            ..Message::default()
        };
        m.decode().unwrap();
        out.push((m, t.transport.peer_addr));
    }
    out
}

pub(super) fn requests(sent: &[(Message, SocketAddr)]) -> Vec<&(Message, SocketAddr)> {
    sent.iter()
        .filter(|(m, _)| m.typ == BINDING_REQUEST)
        .collect()
}

pub(super) fn error_code(m: &Message) -> u16 {
    let mut code = ErrorCodeAttribute::default();
    code.get_from(m).unwrap();
    code.code.0
}

/// Runs the agent's timer up to `until`, answering nothing; returns everything it sent.
pub(super) fn run(a: &mut Agent, from: Instant, until: Instant) -> Vec<(Message, SocketAddr)> {
    let mut out = vec![];
    let mut now = from;
    loop {
        a.handle_timeout(now).unwrap();
        out.extend(sent(a));
        match a.poll_timeout() {
            Some(next) if next <= until => now = next.max(now + Duration::from_millis(1)),
            _ => break,
        }
        if now > until {
            break;
        }
    }
    out
}

/// Runs the agent's timer up to `until`. Every Binding request it sends is answered with a
/// success response from its destination when `answer(request, destination)` says so.
pub(super) fn run_answering(
    a: &mut Agent,
    from: Instant,
    until: Instant,
    mut answer: impl FnMut(&Message, SocketAddr) -> bool,
) -> Vec<(Message, SocketAddr)> {
    let mut out = vec![];
    let mut now = from;
    loop {
        a.handle_timeout(now).unwrap();
        loop {
            let batch = sent(a);
            if batch.is_empty() {
                break;
            }
            for (m, to) in &batch {
                if m.typ == BINDING_REQUEST && answer(m, *to) {
                    let response =
                        peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
                    let _ = deliver(a, now, &response, &to.to_string());
                }
            }
            out.extend(batch);
        }
        match a.poll_timeout() {
            Some(next) if next <= until => now = next.max(now + Duration::from_millis(1)),
            _ => break,
        }
    }
    out
}

fn first_check(a: &mut Agent, now: Instant) -> (Message, SocketAddr) {
    let out = run(a, now, now + Duration::from_millis(100));
    requests(&out)
        .first()
        .map(|(m, to)| (m.clone(), *to))
        .expect("the agent sends a check")
}

/// Section 16.1: an agent "MAY change the number when an ICE restart occurs". With
/// `AgentConfig::new_tie_breaker_on_restart` a restart draws a new tiebreaker, and the next
/// generation's checks carry it; a restart taken back (RFC 9429 section 5.7) gives the old one
/// back. By default the tiebreaker stays across restarts.
#[test]
fn test_ice_restart_draws_a_new_tie_breaker_only_when_configured() {
    const FIXED: u64 = 0x0123_4567_89ab_cdef;
    let controlling_value = |m: &Message| {
        let mut attr = AttrControlling::default();
        attr.get_from(m).unwrap();
        attr.0
    };
    for new_on_restart in [true, false] {
        let now = Instant::now();
        let cfg = AgentConfig {
            tie_breaker: Some(FIXED),
            new_tie_breaker_on_restart: new_on_restart,
            ..config(true)
        };
        let mut a = started_agent(now, cfg, &[REMOTE_A]);
        let (check, _) = first_check(&mut a, now);
        assert_eq!(controlling_value(&check), FIXED);

        let later = now + Duration::from_secs(1);
        a.restart(later, String::new(), String::new(), true)
            .unwrap();
        let after = a.tie_breaker();
        if new_on_restart {
            assert_ne!(after, FIXED, "a new tiebreaker is drawn");
        } else {
            assert_eq!(after, FIXED, "the tiebreaker stays");
        }
        // The new generation's checks carry it.
        a.set_remote_credentials(
            "restartufrag".to_owned(),
            "restartpwdrestartpwdrestart".to_owned(),
        )
        .unwrap();
        a.add_remote_candidate(host(addr(REMOTE_B))).unwrap();
        let (check, _) = first_check(&mut a, later);
        assert_eq!(controlling_value(&check), after);

        // A revertible restart that is taken back keeps the tiebreaker of the session it
        // returns to.
        let before = a.tie_breaker();
        a.generate_restart_credentials(String::new(), String::new())
            .unwrap();
        a.apply_restart_revertible(later, true).unwrap();
        assert_eq!(a.tie_breaker() != before, new_on_restart);
        assert!(a.revert_restart(later));
        assert_eq!(a.tie_breaker(), before);
    }
    assert!(!AgentConfig::default().new_tie_breaker_on_restart);
}

// --- Section 7.3.1.1 and RFC 8489 Section 14.5: role attributes and MESSAGE-INTEGRITY ---

/// Someone on the path replays a valid check with the opposite role attribute appended after
/// MESSAGE-INTEGRITY. Nothing after MESSAGE-INTEGRITY is authenticated: the role must stand.
#[test]
fn test_role_attribute_after_message_integrity_is_ignored() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    a.tie_breaker = 100;
    let _ = sent(&mut a);

    // The genuine check carries FINGERPRINT: with anything appended it no longer verifies
    // (and is no longer last), so the replay is discarded whole.
    let mut m = peer_request(
        &a,
        vec![Box::new(AttrControlling(5)), Box::new(PriorityAttr(1000))],
    );
    // Appended by the attacker: ICE-CONTROLLED with tiebreaker 0 (we would "win" and switch).
    m.add(ATTR_ICE_CONTROLLED, &0u64.to_be_bytes());
    assert!(m.contains(ATTR_ICE_CONTROLLED));
    assert!(deliver(&mut a, now, &m, REMOTE_A).is_err());
    assert!(!a.is_controlling);
    assert!(sent(&mut a).is_empty());

    // A check without FINGERPRINT: the integrity still verifies with the attribute appended,
    // and the attribute is not read.
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            a.ufrag_pwd.local_credentials.ufrag.clone() + ":" + REMOTE_UFRAG,
        )),
        Box::new(AttrControlling(5)),
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider().crypto(),
        )),
    ])
    .unwrap();
    m.add(ATTR_ICE_CONTROLLED, &0u64.to_be_bytes());
    assert!(m.contains(ATTR_ICE_CONTROLLED));

    deliver(&mut a, now, &m, REMOTE_A).unwrap();

    assert!(
        !a.is_controlling,
        "an unauthenticated attribute flipped the role"
    );
    let out = sent(&mut a);
    let answers: Vec<_> = out
        .iter()
        .filter(|(r, _)| r.transaction_id == m.transaction_id)
        .collect();
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].0.typ, BINDING_SUCCESS);
}

fn conflict_case(
    controlling: bool,
    own: u64,
    theirs: u64,
) -> (Agent, Vec<(Message, SocketAddr)>, TransactionId) {
    let now = Instant::now();
    let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
    a.tie_breaker = own;
    let _ = sent(&mut a);
    let role: Box<dyn Setter> = if controlling {
        Box::new(AttrControlling(theirs))
    } else {
        Box::new(AttrControlled(theirs))
    };
    let m = peer_request(&a, vec![role, Box::new(PriorityAttr(1000))]);
    deliver(&mut a, now, &m, REMOTE_A).unwrap();
    let out = sent(&mut a)
        .into_iter()
        .filter(|(r, _)| r.transaction_id == m.transaction_id)
        .collect();
    (a, out, m.transaction_id)
}

/// Section 7.3.1.1: controlling, the request has ICE-CONTROLLING, own tiebreaker larger or
/// equal: one answer, the 487, and the role is kept.
#[test]
fn test_role_conflict_controlling_winner_answers_487_only() {
    for theirs in [100, 500] {
        let (a, out, _) = conflict_case(true, 500, theirs);
        assert!(a.is_controlling);
        assert_eq!(out.len(), 1, "one transaction, one response");
        assert_eq!(out[0].0.typ, BINDING_ERROR);
        assert_eq!(error_code(&out[0].0), CODE_ROLE_CONFLICT.0);
        assert_eq!(out[0].1, addr(REMOTE_A));
    }
}

/// Section 7.3.1.1: controlling, own tiebreaker smaller: switch to controlled and answer the
/// request (with success, nothing else).
#[test]
fn test_role_conflict_controlling_loser_switches_and_answers_success_only() {
    let (a, out, _) = conflict_case(true, 100, 500);
    assert!(!a.is_controlling);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_SUCCESS);
}

/// Section 7.3.1.1: controlled, the request has ICE-CONTROLLED, own tiebreaker larger *or
/// equal*: switch to controlling, answer with success.
#[test]
fn test_role_conflict_controlled_winner_or_equal_switches_to_controlling() {
    for theirs in [3, 7] {
        let (a, out, _) = conflict_case(false, 7, theirs);
        assert!(a.is_controlling, "tiebreaker 7 against {theirs}");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.typ, BINDING_SUCCESS);
    }
}

/// Section 7.3.1.1: controlled, own tiebreaker smaller: 487 and nothing else, role kept.
#[test]
fn test_role_conflict_controlled_loser_answers_487_only() {
    let (a, out, _) = conflict_case(false, 7, 9);
    assert!(!a.is_controlling);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_ERROR);
    assert_eq!(error_code(&out[0].0), CODE_ROLE_CONFLICT.0);
}

/// Section 7.2.5.1: a 487 answer to a request sent with ICE-CONTROLLING makes the agent
/// controlled (with ICE-CONTROLLED: controlling), changes the tiebreaker, and the pair is
/// checked again in the new role.
#[test]
fn test_487_response_switches_role_changes_tiebreaker_and_rechecks() {
    for controlling in [true, false] {
        role_conflict_response_case(controlling);
    }
}

fn role_conflict_response_case(controlling: bool) {
    let (was, becomes) = if controlling {
        (ATTR_ICE_CONTROLLING, ATTR_ICE_CONTROLLED)
    } else {
        (ATTR_ICE_CONTROLLED, ATTR_ICE_CONTROLLING)
    };
    let now = Instant::now();
    let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
    let tie_breaker = a.tie_breaker;
    let (check, to) = first_check(&mut a, now);
    assert!(check.contains(was));

    let later = now + Duration::from_millis(120);
    let response = peer_response(
        BINDING_ERROR,
        check.transaction_id,
        addr(LOCAL),
        Some(CODE_ROLE_CONFLICT),
    );
    deliver(&mut a, later, &response, &to.to_string()).unwrap();

    assert_eq!(
        a.is_controlling, !controlling,
        "a 487 response must switch the role"
    );
    assert_ne!(a.tie_breaker, tie_breaker, "the tiebreaker must change");

    let out = run(&mut a, later, later + Duration::from_secs(1));
    let again = requests(&out);
    let (recheck, recheck_to) = again.first().expect("the pair is checked again");
    assert_eq!(*recheck_to, to);
    assert_ne!(recheck.transaction_id, check.transaction_id);
    assert!(recheck.contains(becomes));
    assert!(!recheck.contains(was));
    let new_tie_breaker = u64::from_be_bytes(recheck.get(becomes).unwrap().try_into().unwrap());
    assert_eq!(new_tie_breaker, a.tie_breaker);
}

/// A 487 nobody signed, or for a transaction the agent does not have, changes nothing.
#[test]
fn test_unauthenticated_or_unsolicited_487_is_ignored() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);

    let mut unsigned = Message::new();
    unsigned
        .build(&[
            Box::new(BINDING_ERROR),
            Box::new(check.transaction_id),
            Box::new(CODE_ROLE_CONFLICT),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    let _ = deliver(&mut a, now, &unsigned, &to.to_string());
    assert!(a.is_controlling);

    let unsolicited = peer_response(
        BINDING_ERROR,
        TransactionId::new(),
        addr(LOCAL),
        Some(CODE_ROLE_CONFLICT),
    );
    let _ = deliver(&mut a, now, &unsolicited, &to.to_string());
    assert!(a.is_controlling);
}

/// Section 7.2.5.2.4: an unrecoverable error response fails the pair.
#[test]
fn test_error_response_fails_the_pair() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let response = peer_response(
        BINDING_ERROR,
        check.transaction_id,
        addr(LOCAL),
        Some(CODE_BAD_REQUEST),
    );
    deliver(&mut a, now, &response, &to.to_string()).unwrap();
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
    assert!(a.is_controlling);
}

// --- Section 7.3: requests before the peer's candidate information ---

/// Section 7.3: a Binding request that arrives before the remote description is answered at
/// once (the answerer starts checking as soon as it has sent its answer).
#[test]
fn test_binding_request_before_remote_credentials_is_answered() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    assert!(a.ufrag_pwd.remote_credentials.is_none());

    let m = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1234))],
    );
    deliver(&mut a, now, &m, REMOTE_A).unwrap();

    let out = sent(&mut a);
    assert_eq!(out.len(), 1, "exactly the response");
    let (response, to) = &out[0];
    assert_eq!(response.typ, BINDING_SUCCESS);
    assert_eq!(response.transaction_id, m.transaction_id);
    assert_eq!(*to, addr(REMOTE_A));
    let mut mapped = XorMappedAddress::default();
    mapped.get_from(response).unwrap();
    assert_eq!(SocketAddr::new(mapped.ip, mapped.port), addr(REMOTE_A));
    // Signed with the local password, as every response is, and closed by FINGERPRINT.
    FINGERPRINT.check(response).unwrap();
    assert_eq!(
        response.attributes.0.last().unwrap().typ,
        stun::attributes::ATTR_FINGERPRINT
    );
    let mut copy = response.clone();
    MessageIntegrity::check(
        &mut copy,
        a.ufrag_pwd.local_credentials.pwd.as_bytes(),
        provider().crypto(),
    )
    .unwrap();
}

/// Without the right password an early request gets no success response: it is answered 401
/// (RFC 8489 Section 9.1.3), unsigned, and nothing of it is remembered.
#[test]
fn test_early_request_with_a_wrong_password_is_answered_401() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            a.ufrag_pwd.local_credentials.ufrag.clone() + ":x",
        )),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "not the password".to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    assert!(deliver(&mut a, now, &m, REMOTE_A).is_err());
    let out = sent(&mut a);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_ERROR);
    assert_eq!(out[0].0.transaction_id, m.transaction_id);
    assert_eq!(error_code(&out[0].0), 401);
    assert!(a.early_requests.is_empty());
}

/// Section 7.3: once the peer's credentials arrive, the early request is processed as in
/// Sections 7.3.1.3 to 7.3.1.5: its source becomes a peer-reflexive candidate with the
/// request's PRIORITY and a triggered check goes to it.
#[test]
fn test_early_request_triggers_a_check_when_credentials_arrive() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    let m = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1234))],
    );
    deliver(&mut a, now, &m, REMOTE_A).unwrap();
    let _ = sent(&mut a);
    assert!(a.remote_candidates.is_empty());

    let later = now + Duration::from_millis(30);
    a.start_connectivity_checks(later, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    let out = run(&mut a, later, later + Duration::from_millis(200));

    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(
        a.remote_candidates[0].candidate_type(),
        CandidateType::PeerReflexive
    );
    assert_eq!(a.remote_candidates[0].priority(), 1234);
    let checks = requests(&out);
    assert!(
        checks.iter().any(|(_, to)| *to == addr(REMOTE_A)),
        "a triggered check goes to the early request's source"
    );
    // The early request was answered once, when it arrived: no second response.
    assert!(out.iter().all(|(r, _)| r.typ != BINDING_SUCCESS));
}

/// Section 7.3: the username is valid when its first part is the agent's own fragment.
#[test]
fn test_username_is_valid_when_its_first_part_is_the_local_ufrag() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let _ = sent(&mut a);
    let provider = provider();
    let build = |username: String| {
        let mut m = Message::new();
        m.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, username)),
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(99)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                a.ufrag_pwd.local_credentials.pwd.clone(),
                provider.crypto(),
            )),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
        m
    };
    let ufrag = a.ufrag_pwd.local_credentials.ufrag.clone();
    let other_second_part = build(format!("{ufrag}:someoneelse"));
    let wrong_first_part = build(format!("x{ufrag}:{REMOTE_UFRAG}"));
    let no_colon = build(ufrag.clone());
    let fragment_is_a_prefix_only = build(format!("{ufrag}x:{REMOTE_UFRAG}"));

    deliver(&mut a, now, &other_second_part, REMOTE_A).unwrap();
    assert_eq!(sent(&mut a)[0].0.typ, BINDING_SUCCESS);
    assert!(deliver(&mut a, now, &wrong_first_part, REMOTE_A).is_err());
    assert!(deliver(&mut a, now, &no_colon, REMOTE_A).is_err());
    assert!(deliver(&mut a, now, &fragment_is_a_prefix_only, REMOTE_A).is_err());
    // A username that is not valid here: 401 (RFC 8489 Section 9.1.3), never a success.
    let out = sent(&mut a);
    assert_eq!(out.len(), 3);
    assert!(
        out.iter()
            .all(|(m, _)| m.typ == BINDING_ERROR && error_code(m) == 401)
    );
}

// --- Section 7.1.1 and 7.3.1.3: PRIORITY ---

/// Section 7.1.1: PRIORITY is the priority the local candidate would have as a peer-reflexive
/// one: type preference 110 with the candidate's local preference and component.
#[test]
fn test_check_carries_the_peer_reflexive_priority() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        let (check, _) = first_check(&mut a, now);
        let mut priority = PriorityAttr::default();
        priority.get_from(&check).unwrap();
        assert_eq!(a.local_candidates[0].priority(), 2130706431);
        assert_eq!(priority.0, (110 << 24) + (65535 << 8) + 255);
        assert_eq!(priority.0, 1862270975);
    }
}

/// Section 7.3.1.3: a peer-reflexive remote candidate takes its priority from the request.
#[test]
fn test_peer_reflexive_remote_candidate_takes_priority_from_the_request() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let m = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1845501695)),
        ],
    );
    deliver(&mut a, now, &m, REMOTE_B).unwrap();
    let index = a.find_remote_candidate(addr(REMOTE_B)).unwrap();
    let prflx = &a.remote_candidates[index];
    assert_eq!(prflx.candidate_type(), CandidateType::PeerReflexive);
    assert_eq!(prflx.priority(), 1845501695);
    assert_eq!(prflx.component(), a.local_candidates[0].component());
    // Its foundation is no other remote candidate's (Section 7.3.1.3).
    assert_ne!(prflx.foundation(), a.remote_candidates[0].foundation());
}

// --- Section 6.2 / 7.3.2: lite ---

/// Section 7.3.2: a lite agent builds the pair from a request with USE-CANDIDATE, selects it,
/// and sends no connectivity check of its own, then or later.
#[test]
fn test_lite_agent_selects_on_use_candidate_and_sends_no_checks() {
    let now = Instant::now();
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(false)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    let plain = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, now, &plain, REMOTE_A).unwrap();
    assert!(a.get_selected_candidate_pair().is_none());

    let nominating = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, now, &nominating, REMOTE_A).unwrap();

    let (_, remote) = a
        .get_selected_candidate_pair()
        .expect("USE-CANDIDATE alone selects the pair on a lite agent");
    assert_eq!(remote.addr(), addr(REMOTE_A));
    // Section 8.2: the nomination concludes ICE for a lite agent.
    assert_eq!(
        a.checklist_state(),
        crate::agent::agent_selector::ChecklistState::Completed
    );
    let mut out = sent(&mut a);
    out.extend(run(&mut a, now, now + Duration::from_secs(3)));
    assert!(
        requests(&out).is_empty(),
        "a lite agent sends no Binding requests"
    );
    assert_eq!(
        out.iter().filter(|(m, _)| m.typ == BINDING_SUCCESS).count(),
        2
    );
}

// --- Section 7.3.1.4: triggered checks on the controlled side ---

/// Section 7.3.1.4: a request on a pair that already succeeded needs no check in return: one
/// datagram out, the response.
#[test]
fn test_request_on_a_succeeded_pair_triggers_no_check() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        let end = now + Duration::from_millis(300);
        run_answering(&mut a, now, end, |_, _| true);
        assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
        let _ = sent(&mut a);

        let role: Box<dyn Setter> = if controlling {
            Box::new(AttrControlled(1))
        } else {
            Box::new(AttrControlling(1))
        };
        let m = peer_request(&a, vec![role, Box::new(PriorityAttr(1000))]);
        deliver(&mut a, end, &m, REMOTE_A).unwrap();
        let out = sent(&mut a);
        assert_eq!(out.len(), 1, "controlling={controlling}");
        assert_eq!(out[0].0.typ, BINDING_SUCCESS);
    }
}

/// Section 7.3.1.4: a request on a Failed pair puts the pair back to work: it is checked
/// again, with a fresh budget, on the controlled side as well.
#[test]
fn test_request_on_a_failed_pair_rechecks_it() {
    for controlling in [true, false] {
        let now = Instant::now();
        // Two requests per transaction: sent at 0 and 0.5 s, given up 8 s later.
        let cfg = AgentConfig {
            max_binding_requests: Some(2),
            ..config(controlling)
        };
        let mut a = started_agent(now, cfg, &[REMOTE_A]);
        // Nobody answers: the pair fails.
        let mut end = now;
        while a.candidate_pairs.first().map(|p| p.state) != Some(CandidatePairState::Failed) {
            end += Duration::from_millis(100);
            run(&mut a, end, end);
            assert!(end < now + Duration::from_secs(60), "the pair never failed");
            assert_ne!(a.state(), ConnectionState::Failed, "agent failed first");
        }
        let _ = sent(&mut a);

        let role: Box<dyn Setter> = if controlling {
            Box::new(AttrControlled(1))
        } else {
            Box::new(AttrControlling(1))
        };
        let m = peer_request(&a, vec![role, Box::new(PriorityAttr(1000))]);
        deliver(&mut a, end, &m, REMOTE_A).unwrap();
        assert_ne!(
            a.candidate_pairs[0].state,
            CandidatePairState::Failed,
            "controlling={controlling}"
        );
        // If the first triggered check is lost the pair is still retried.
        let mut out = sent(&mut a);
        out.extend(run(&mut a, end, end + Duration::from_secs(2)));
        assert!(
            requests(&out).len() >= 2,
            "controlling={controlling}: {} requests",
            requests(&out).len()
        );
    }
}

// --- Section 8.1.1 / 7.2.5.3.4: a nomination that fails ---

/// With `FailedNomination::Retry`: the controlling agent has two valid pairs and nominates the
/// better one; the path dies before the nomination is answered. It gives that pair up and
/// nominates the other one instead of repeating the nomination until the agent fails. (By
/// default, RFC 8445 Section 7.2.5.3.4, the checklist fails instead:
/// `agent_checklist_test.rs::test_a_nomination_that_times_out_fails_the_pair_and_the_checklist`.)
#[test]
fn test_failed_nomination_falls_back_to_the_next_valid_pair() {
    let now = Instant::now();
    let mut a = bare_agent(
        now,
        AgentConfig {
            failed_nomination: FailedNomination::Retry,
            ..config(true)
        },
    );
    a.add_remote_candidate(host_with_priority(addr(REMOTE_A), 2130706431))
        .unwrap();
    a.add_remote_candidate(host_with_priority(addr(REMOTE_B), 2130706175))
        .unwrap();
    a.start_connectivity_checks(now, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();

    let mut states = vec![];
    let mut nominated_a = 0;
    let end = now + Duration::from_secs(70);
    // Plain checks are answered by both; a nomination only by B.
    let out = run_answering(&mut a, now, end, |m, to| {
        if m.contains(ATTR_USE_CANDIDATE) && to == addr(REMOTE_A) {
            nominated_a += 1;
            return false;
        }
        true
    });
    while let Some(e) = a.poll_event() {
        if let Event::ConnectionStateChange(s) = e.event {
            states.push(s);
        }
    }
    assert!(nominated_a >= 1, "the better pair is nominated first");
    assert!(
        !states.contains(&ConnectionState::Failed),
        "the agent failed with a valid pair left: {states:?}"
    );
    let (_, remote) = a
        .get_selected_candidate_pair()
        .expect("the other valid pair is selected");
    assert_eq!(remote.addr(), addr(REMOTE_B));
    assert!(
        out.iter()
            .any(|(m, to)| m.contains(ATTR_USE_CANDIDATE) && *to == addr(REMOTE_B))
    );
}

// --- Section 9: restart ---

/// Section 9: a restart changes both the fragment and the password, also when the application
/// offers the ones in use (pinned credentials).
#[test]
fn test_restart_with_the_credentials_in_use_generates_new_ones() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    let old = a.get_local_credentials().clone();
    a.generate_restart_credentials(old.ufrag.clone(), old.pwd.clone())
        .unwrap();
    let new = a.get_local_credentials().clone();
    assert_ne!(new.ufrag, old.ufrag);
    assert_ne!(new.pwd, old.pwd);
    assert!(new.ufrag.len() * 8 >= 24 && new.pwd.len() * 8 >= 128);

    // Different ones are taken as given.
    a.generate_restart_credentials(
        "freshufrag".to_owned(),
        "freshpwdfreshpwdfreshpwd".to_owned(),
    )
    .unwrap();
    assert_eq!(a.get_local_credentials().ufrag, "freshufrag");
}

/// Section 6.1.1 / 9: an ICE restart does not redetermine the roles.
#[test]
fn test_restart_keeps_the_role() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A]);
        a.restart(now, String::new(), String::new(), true).unwrap();
        assert_eq!(a.role(), controlling);
    }
}

// --- What the agent's own messages carry (Sections 7.1, 7.2.4, 7.3, 16.1) ---

/// Sections 7.1.1 to 7.1.3, 7.2.4, 16.1: a check carries PRIORITY, the role attribute with
/// the session's one tiebreaker, MESSAGE-INTEGRITY with the peer's password and FINGERPRINT;
/// the controlled agent never sends USE-CANDIDATE.
#[test]
fn test_checks_carry_role_tiebreaker_integrity_and_fingerprint() {
    for controlling in [true, false] {
        let now = Instant::now();
        let mut a = started_agent(now, config(controlling), &[REMOTE_A, REMOTE_B]);
        let out = run(&mut a, now, now + Duration::from_secs(2));
        let checks = requests(&out);
        assert!(checks.len() >= 2);
        for (m, _) in checks {
            assert!(m.contains(ATTR_PRIORITY));
            let mut username = Username::new(ATTR_USERNAME, String::new());
            username.get_from(m).unwrap();
            assert_eq!(
                username.to_string(),
                format!("{REMOTE_UFRAG}:{}", a.ufrag_pwd.local_credentials.ufrag)
            );
            if controlling {
                let mut attr = AttrControlling::default();
                attr.get_from(m).unwrap();
                assert_eq!(attr.0, a.tie_breaker);
                assert!(!m.contains(ATTR_ICE_CONTROLLED));
            } else {
                let mut attr = AttrControlled::default();
                attr.get_from(m).unwrap();
                assert_eq!(attr.0, a.tie_breaker);
                assert!(!m.contains(ATTR_ICE_CONTROLLING));
                assert!(!m.contains(ATTR_USE_CANDIDATE));
            }
            let mut copy = m.clone();
            MessageIntegrity::check(&mut copy, REMOTE_PWD.as_bytes(), provider().crypto()).unwrap();
            FINGERPRINT.check(m).unwrap();
            assert_eq!(
                m.attributes.0.last().unwrap().typ,
                stun::attributes::ATTR_FINGERPRINT
            );
        }
    }
}

// --- Section 5.1.2.1, RFC 8421 Section 4, RFC 6544 Section 4.2: local preferences ---

fn candidate(network: &str, address: &str, port: u16, tcp_type: TcpType) -> Candidate {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: network.to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        tcp_type,
    }
    .new_candidate_host()
    .unwrap()
}

/// Section 5.1.2.1: candidates of one type get a unique local preference each, so no two local
/// candidates share a priority; one address alone keeps 65535. RFC 8421 Section 4: the two
/// address families are interleaved, through the local preference.
#[test]
fn test_local_candidates_of_one_type_get_unique_interleaved_priorities() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    for (address, port) in [
        ("192.0.2.1", 1000),
        ("192.0.2.2", 1000),
        ("192.0.2.3", 1000),
        ("2001:db8::1", 1000),
        ("2001:db8::2", 1000),
    ] {
        assert!(
            a.add_local_candidate(candidate("udp", address, port, TcpType::Unspecified))
                .unwrap()
        );
    }
    let local_preference = |i: usize| -> u32 { (a.local_candidates[i].priority() >> 8) & 0xffff };
    // The first candidate of the type keeps the largest value.
    assert_eq!(a.local_candidates[0].priority(), 2130706431);
    // IPv4 came first: IPv4 takes 65535, 65533, 65531; IPv6 takes 65534, 65532.
    assert_eq!(
        (0..5).map(local_preference).collect::<Vec<_>>(),
        vec![65535, 65533, 65531, 65534, 65532]
    );
    // Section 5.1.2.2: relayed candidates from several TURN servers differ as well.
    for (address, server) in [
        ("198.51.100.1", "turn:one.example"),
        ("198.51.100.2", "turn:two.example"),
    ] {
        let relay = crate::candidate::candidate_relay::CandidateRelayConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: address.to_owned(),
                port: 3478,
                component: 1,
                ..Default::default()
            },
            rel_addr: "192.0.2.1".to_owned(),
            rel_port: 1000,
            url: Some(server.to_owned()),
        }
        .new_candidate_relay()
        .unwrap();
        assert!(a.add_local_candidate(relay).unwrap());
    }
    assert_eq!(a.local_candidates[5].priority(), 16777215);
    assert_eq!(a.local_candidates[6].priority(), 16777215 - (2 << 8));
    let mut priorities: Vec<u32> = a.local_candidates.iter().map(|c| c.priority()).collect();
    priorities.sort_unstable();
    priorities.dedup();
    assert_eq!(priorities.len(), 7, "priorities are unique");
    for c in &a.local_candidates {
        assert!((1..=(1u32 << 31) - 1).contains(&c.priority()));
    }
}

/// RFC 8421 Section 4: "Implementations should prioritize IPv6 candidates by putting some of
/// them first in the intermingled checklist", with the head start `Hi = (N_4 + N_6) / N_4`:
/// "If a host has two IPv4 addresses and six IPv6 addresses, it will insert an IPv4 address
/// after four IPv6 addresses". Candidates gathered together and ranked together get that
/// order whatever order they come in; a host with one address keeps 65535 (RFC 8445 Section
/// 5.1.2.1).
#[test]
fn test_candidates_gathered_together_give_ipv6_a_head_start() {
    let udp = |address: &str| candidate("udp", address, 1000, TcpType::Unspecified);
    let mut set: Vec<Candidate> = [
        "192.0.2.1",
        "192.0.2.2",
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
        "2001:db8::4",
        "2001:db8::5",
        "2001:db8::6",
    ]
    .into_iter()
    .map(udp)
    .collect();
    crate::candidate::rank_local_candidates(&mut set);
    let mut by_priority: Vec<&Candidate> = set.iter().collect();
    by_priority.sort_by_key(|c| std::cmp::Reverse(c.priority()));
    let order: Vec<String> = by_priority.iter().map(|c| c.address().to_owned()).collect();
    assert_eq!(
        order,
        vec![
            "2001:db8::1",
            "2001:db8::2",
            "2001:db8::3",
            "2001:db8::4",
            "192.0.2.1",
            "2001:db8::5",
            "192.0.2.2",
            "2001:db8::6",
        ]
    );
    assert_eq!(by_priority[0].priority(), 2130706431);

    // Through the agent: one IPv4 and one IPv6 added together, IPv4 first: IPv6 leads; a
    // candidate added later takes the next free rank.
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    let added = a
        .add_local_candidates(vec![udp("192.0.2.1"), udp("2001:db8::1")])
        .unwrap();
    assert_eq!(added, vec![true, true]);
    a.add_local_candidate(udp("192.0.2.2")).unwrap();
    let local_preference = |c: &Candidate| (c.priority() >> 8) & 0xffff;
    assert_eq!(
        a.local_candidates
            .iter()
            .map(|c| (c.address().to_owned(), local_preference(c)))
            .collect::<Vec<_>>(),
        vec![
            ("192.0.2.1".to_owned(), 65534),
            ("2001:db8::1".to_owned(), 65535),
            ("192.0.2.2".to_owned(), 65533),
        ]
    );

    // One family: in order, the first keeps 65535; a rank given by the application is kept
    // and not given out again.
    let mut set = vec![udp("192.0.2.1"), udp("192.0.2.2"), udp("192.0.2.3")];
    set[1].set_local_preference_rank(0);
    crate::candidate::rank_local_candidates(&mut set);
    assert_eq!(
        set.iter()
            .map(|c| c.local_preference_rank())
            .collect::<Vec<_>>(),
        vec![Some(1), Some(0), Some(2)]
    );
}

/// RFC 6544 Section 4.2: TCP candidates with the same type preference and direction-pref have
/// a unique other-pref; a single one keeps 8191.
#[test]
fn test_tcp_candidates_of_one_direction_get_unique_other_prefs() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    a.add_local_candidate(candidate("tcp", "192.168.1.2", 4000, TcpType::Passive))
        .unwrap();
    a.add_local_candidate(candidate("tcp", "10.0.0.2", 4000, TcpType::Passive))
        .unwrap();
    a.add_local_candidate(candidate("tcp", "192.168.1.2", 9, TcpType::Active))
        .unwrap();
    let pref = |i: usize| a.local_candidates[i].local_preference();
    assert_eq!(pref(0), (4 << 13) + 8191);
    // (The odd ranks are the other address family's.)
    assert_eq!(pref(1), (4 << 13) + 8189);
    // Another direction is another group: it starts at 8191 again.
    assert_eq!(pref(2), (6 << 13) + 8191);
    assert_ne!(
        a.local_candidates[0].priority(),
        a.local_candidates[1].priority()
    );
}

/// A priority or a rank the application chose is kept, and the candidates around it still get
/// preferences of their own (RFC 8421 Section 3: an unreliable interface goes last).
#[test]
fn test_application_priorities_and_ranks_are_kept() {
    let mut a = Agent::new(Instant::now(), Arc::new(config(true)), provider()).unwrap();
    a.add_local_candidate(host_with_priority(addr("192.0.2.1:1000"), 12345))
        .unwrap();
    let mut unreliable = host(addr("192.0.2.2:1000"));
    unreliable.set_local_preference_rank(1000);
    a.add_local_candidate(unreliable).unwrap();
    a.add_local_candidate(host(addr("192.0.2.3:1000"))).unwrap();
    assert_eq!(a.local_candidates[0].priority(), 12345);
    assert_eq!(a.local_candidates[1].local_preference(), 65535 - 1000);
    assert_eq!(a.local_candidates[2].local_preference(), 65535);
}

/// Section 7.3.1.3: a peer-reflexive remote candidate is paired with the local candidate the
/// request arrived on, and with no other local candidate.
#[test]
fn test_peer_reflexive_remote_candidate_is_paired_with_the_arrival_candidate_only() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(false));
    a.add_local_candidate(host(addr("192.168.0.9:1000")))
        .unwrap();
    a.start_connectivity_checks(now, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert!(a.candidate_pairs.is_empty());

    let m = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(77))],
    );
    deliver(&mut a, now, &m, REMOTE_A).unwrap();

    assert_eq!(a.remote_candidates.len(), 1);
    assert_eq!(a.candidate_pairs.len(), 1);
    let pair = a.candidate_pairs[0];
    assert_eq!(a.local_candidates[pair.local_index].addr(), addr(LOCAL));
    assert_eq!(pair.remote_priority, 77);
}

// --- RFC 8489 Sections 6.3 and 14.7 on the agent's receive path ---

/// A request with an unknown comprehension-required attribute is answered 420 (Unknown
/// Attribute) with the attribute listed, signed like every response, and does nothing else.
#[test]
fn test_request_with_an_unknown_required_attribute_is_answered_420() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[]);
    let _ = sent(&mut a);
    let unknown = stun::attributes::AttrType(0x7f00);
    let m = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(stun::attributes::RawAttribute {
                typ: unknown,
                length: 4,
                value: vec![1, 2, 3, 4],
            }),
        ],
    );
    assert!(deliver(&mut a, now, &m, REMOTE_A).is_err());
    let out = sent(&mut a);
    assert_eq!(out.len(), 1);
    let (response, to) = &out[0];
    assert_eq!(*to, addr(REMOTE_A));
    assert_eq!(response.typ, BINDING_ERROR);
    assert_eq!(response.transaction_id, m.transaction_id);
    assert_eq!(error_code(response), 420);
    let mut listed = stun::uattrs::UnknownAttributes(vec![]);
    listed.get_from(response).unwrap();
    assert_eq!(listed.0, vec![unknown]);
    let mut copy = response.clone();
    MessageIntegrity::check(
        &mut copy,
        a.ufrag_pwd.local_credentials.pwd.as_bytes(),
        provider().crypto(),
    )
    .unwrap();
    assert!(
        a.remote_candidates.is_empty(),
        "no candidate from such a request"
    );
}

/// FINGERPRINT is verified on what the agent receives: a request or a response whose
/// FINGERPRINT does not match is discarded, whatever its MESSAGE-INTEGRITY.
#[test]
fn test_message_with_a_wrong_fingerprint_is_discarded() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);

    let corrupt = |m: &Message| {
        let mut raw = m.raw.clone();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        raw
    };
    let response = peer_response(BINDING_SUCCESS, check.transaction_id, addr(LOCAL), None);
    assert!(deliver_raw(&mut a, now, &corrupt(&response), &to.to_string()).is_err());
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::InProgress);
    assert_eq!(
        a.pending_binding_requests.len(),
        1,
        "the transaction is still open"
    );

    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    assert!(deliver_raw(&mut a, now, &corrupt(&request), REMOTE_B).is_err());
    assert!(sent(&mut a).is_empty(), "nothing is answered");
    assert_eq!(a.remote_candidates.len(), 1);

    // The same messages intact are taken.
    deliver(&mut a, now, &response, &to.to_string()).unwrap();
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
}

// --- RFC 8489 Section 9.1.3 (through RFC 8445 Section 7.3): requests that fail authentication ---

/// A Binding request to `a` with the given USERNAME and, when `password` is given,
/// MESSAGE-INTEGRITY made with it. ICE-CONTROLLING, PRIORITY and FINGERPRINT as in a check.
fn request_with(username: Option<String>, password: Option<&str>) -> Message {
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> =
        vec![Box::new(BINDING_REQUEST), Box::new(TransactionId::new())];
    if let Some(username) = username {
        setters.push(Box::new(Username::new(ATTR_USERNAME, username)));
    }
    setters.push(Box::new(AttrControlling(1)));
    setters.push(Box::new(PriorityAttr(1000)));
    if let Some(password) = password {
        setters.push(Box::new(
            MessageIntegrity::new_short_term_integrity_with_provider(
                password.to_owned(),
                provider.crypto(),
            ),
        ));
    }
    setters.push(Box::new(FINGERPRINT));
    let mut msg = Message::new();
    msg.build(&setters).unwrap();
    msg
}

fn valid_username(a: &Agent) -> String {
    a.ufrag_pwd.local_credentials.ufrag.clone() + ":" + REMOTE_UFRAG
}

/// "If the message does not contain 1) a MESSAGE-INTEGRITY or a MESSAGE-INTEGRITY-SHA256
/// attribute and 2) a USERNAME attribute: If the message is a request, the server MUST reject
/// the request with an error response. This response MUST use an error code of 400 (Bad
/// Request)." "If the USERNAME does not contain a username value currently valid within the
/// server: [...] 401 (Unauthenticated)", and the same for a MESSAGE-INTEGRITY that does not
/// match.
#[test]
fn test_unauthenticated_requests_are_answered_400_or_401() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let _ = sent(&mut a);
    let pwd = a.ufrag_pwd.local_credentials.pwd.clone();
    let cases: Vec<(&str, Message, u16)> = vec![
        ("no credentials at all", request_with(None, None), 400),
        (
            "USERNAME without MESSAGE-INTEGRITY",
            request_with(Some(valid_username(&a)), None),
            400,
        ),
        (
            "MESSAGE-INTEGRITY without USERNAME",
            request_with(None, Some(&pwd)),
            400,
        ),
        (
            "a username that is not this agent's",
            request_with(Some(format!("someoneelse:{REMOTE_UFRAG}")), Some(&pwd)),
            401,
        ),
        (
            "a MESSAGE-INTEGRITY made with another password",
            request_with(Some(valid_username(&a)), Some("not the password at all")),
            401,
        ),
    ];
    for (what, request, code) in cases {
        assert!(deliver(&mut a, now, &request, REMOTE_B).is_err(), "{what}");
        let out = sent(&mut a);
        assert_eq!(out.len(), 1, "{what}");
        let (response, to) = &out[0];
        assert_eq!(*to, addr(REMOTE_B), "{what}");
        assert_eq!(response.typ, BINDING_ERROR, "{what}");
        assert_eq!(response.transaction_id, request.transaction_id, "{what}");
        assert_eq!(error_code(response), code, "{what}");
        // Nothing to sign it with, and nothing in it but the code: no reflection of any use.
        assert!(!response.contains(ATTR_MESSAGE_INTEGRITY), "{what}");
        assert!(response.contains(ATTR_FINGERPRINT), "{what}");
        assert!(response.raw.len() <= request.raw.len(), "{what}");
        assert_eq!(response.raw.len(), 36, "{what}");
    }
    // None of it touched the agent: no candidate for the source, no role change.
    assert!(a.find_remote_candidate(addr(REMOTE_B)).is_none());
    assert!(!a.is_controlling);
}

/// The error responses cannot be used to reflect traffic: a burst of five, then one per
/// 200 ms, whatever arrives; never a response longer than its request; nothing for an
/// indication; nothing at all with `UnauthenticatedRequests::Drop`.
#[test]
fn test_error_responses_to_unauthenticated_requests_are_rate_limited() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let _ = sent(&mut a);

    for _ in 0..50 {
        let _ = deliver(&mut a, now, &request_with(None, None), REMOTE_B);
    }
    assert_eq!(
        sent(&mut a).len(),
        MAX_UNAUTHENTICATED_RESPONSE_BURST as usize
    );

    // 200 ms later: one more, however many arrive.
    let later = now + UNAUTHENTICATED_RESPONSE_INTERVAL;
    for _ in 0..50 {
        let _ = deliver(&mut a, later, &request_with(None, None), REMOTE_B);
    }
    assert_eq!(sent(&mut a).len(), 1);

    // After a quiet spell the burst is back, and no larger.
    let much_later = later + Duration::from_secs(60);
    for _ in 0..50 {
        let _ = deliver(&mut a, much_later, &request_with(None, None), REMOTE_B);
    }
    assert_eq!(
        sent(&mut a).len(),
        MAX_UNAUTHENTICATED_RESPONSE_BURST as usize
    );

    // A request shorter than the response would be (a bare header) is not answered: the
    // agent never sends more bytes than it was sent.
    let much_later = much_later + Duration::from_secs(60);
    let mut bare = Message::new();
    bare.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new())])
        .unwrap();
    assert_eq!(bare.raw.len(), 20);
    let _ = deliver(&mut a, much_later, &bare, REMOTE_B);
    assert!(sent(&mut a).is_empty());

    // "If the message is an indication, the agent MUST silently discard the indication."
    let mut indication = Message::new();
    indication
        .build(&[
            Box::new(MessageType::new(METHOD_BINDING, CLASS_INDICATION)),
            Box::new(TransactionId::new()),
            Box::new(PriorityAttr(1)),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    let _ = deliver(&mut a, much_later, &indication, REMOTE_B);
    assert!(sent(&mut a).is_empty());

    // A source the destination policy refuses is not answered either.
    let _ = deliver(&mut a, much_later, &request_with(None, None), "127.0.0.1:9");
    assert!(sent(&mut a).is_empty());
}

/// The setting that keeps the earlier behaviour: nothing is sent.
#[test]
fn test_unauthenticated_requests_can_be_dropped_silently() {
    let now = Instant::now();
    let cfg = AgentConfig {
        unauthenticated_requests: UnauthenticatedRequests::Drop,
        ..config(false)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    let _ = sent(&mut a);
    let pwd = a.ufrag_pwd.local_credentials.pwd.clone();
    for request in [
        request_with(None, None),
        request_with(Some(format!("someoneelse:{REMOTE_UFRAG}")), Some(&pwd)),
        request_with(Some(valid_username(&a)), Some("not the password at all")),
    ] {
        assert!(deliver(&mut a, now, &request, REMOTE_B).is_err());
    }
    assert!(sent(&mut a).is_empty());
}

// --- Sections 5.2, 6.1.1, 7.3.1.1: the tiebreaker, roles, and a conflict after the nomination ---

/// Section 5.2 / 7.1.3: a configured tiebreaker is the one the checks carry.
#[test]
fn test_configured_tiebreaker_is_sent() {
    let now = Instant::now();
    let cfg = AgentConfig {
        tie_breaker: Some(0x0123_4567_89ab_cdef),
        ..config(true)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    assert_eq!(a.tie_breaker(), 0x0123_4567_89ab_cdef);
    let (check, _) = first_check(&mut a, now);
    assert_eq!(
        check.get(ATTR_ICE_CONTROLLING).unwrap(),
        0x0123_4567_89ab_cdef_u64.to_be_bytes()
    );
}

/// Section 6.1.2.3: the pair priority depends on the role, so a role set from outside (the
/// roles are determined again when an agent changes between full and lite, Section 6.1.1)
/// re-prioritises the pairs, and a nomination in the making is dropped.
#[test]
fn test_set_role_reprioritises_the_pairs() {
    let now = Instant::now();
    let mut a = bare_agent(now, config(true));
    a.add_remote_candidate(host_with_priority(addr(REMOTE_A), 5000))
        .unwrap();
    let controlling = a.candidate_pairs[0].priority();
    a.candidate_pairs[0].nominate = true;
    a.nominated_pair = Some(0);
    a.set_role(false);
    assert!(!a.role());
    assert_ne!(a.candidate_pairs[0].priority(), controlling);
    assert!(!a.candidate_pairs[0].nominate);
    assert_eq!(a.nominated_pair, None);
    a.set_role(true);
    assert_eq!(a.candidate_pairs[0].priority(), controlling);
}

/// A connected, controlling agent with the given tiebreaker and its selected pair to
/// `REMOTE_A`.
fn connected_controlling(now: Instant, tie_breaker: u64) -> Agent {
    let cfg = AgentConfig {
        tie_breaker: Some(tie_breaker),
        ..config(true)
    };
    let mut a = started_agent(now, cfg, &[REMOTE_A]);
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    assert_eq!(a.state(), ConnectionState::Connected);
    while a.poll_event().is_some() {}
    a
}

/// Section 7.3.1.1 after the nomination, the agent's tiebreaker being the larger one: a peer
/// that lost its state without an ICE restart (a new agent with the same address and
/// credentials, which believes it is controlling) is answered 487 and takes the controlled
/// role, and it has no nominated pair. The agent keeps its role and its selected pair, and
/// nominates that pair again: one more check with USE-CANDIDATE, on no other pair. Without
/// it the peer waited forever for a nomination that had been made before it existed.
#[test]
fn test_controlling_agent_that_wins_a_conflict_after_nominating_repeats_the_nomination() {
    let now = Instant::now();
    let mut a = connected_controlling(now, 100);
    let later = now + Duration::from_secs(2);

    let conflicting = peer_request(
        &a,
        vec![Box::new(AttrControlling(5)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, later, &conflicting, REMOTE_A).unwrap();
    let out = sent(&mut a);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_ERROR);
    assert_eq!(error_code(&out[0].0), CODE_ROLE_CONFLICT.0);
    assert!(a.role(), "the larger tiebreaker keeps the controlling role");

    let out = run_answering(&mut a, later, later + Duration::from_secs(1), |_, _| true);
    let nominations: Vec<_> = requests(&out)
        .into_iter()
        .filter(|(m, _)| m.contains(ATTR_USE_CANDIDATE))
        .collect();
    assert_eq!(nominations.len(), 1, "the nomination is repeated, once");
    let (nomination, to) = nominations[0];
    assert_eq!(*to, addr(REMOTE_A));
    assert_eq!(
        nomination.get(ATTR_ICE_CONTROLLING).unwrap(),
        100u64.to_be_bytes()
    );
    // The selected pair did not change, and nothing was reported.
    assert_eq!(
        a.get_selected_candidate_pair().unwrap().1.addr(),
        addr(REMOTE_A)
    );
    assert_eq!(a.state(), ConnectionState::Connected);
    assert!(a.poll_event().is_none());

    // The consent checks that follow are plain again.
    let out = run_answering(
        &mut a,
        later + Duration::from_secs(1),
        later + Duration::from_secs(20),
        |_, _| true,
    );
    assert!(requests(&out).len() >= 3);
    assert!(
        requests(&out)
            .iter()
            .all(|(m, _)| !m.contains(ATTR_USE_CANDIDATE))
    );
}

/// The same conflict with the smaller tiebreaker: the agent "switches to the controlled
/// role", answers the check, keeps its selected pair, and takes the peer's nomination of that
/// pair without reporting a change. Its consent checks are a controlled agent's from then on.
#[test]
fn test_controlling_agent_that_loses_a_conflict_after_nominating_becomes_controlled() {
    let now = Instant::now();
    let mut a = connected_controlling(now, 5);
    let later = now + Duration::from_secs(2);

    let conflicting = peer_request(
        &a,
        vec![Box::new(AttrControlling(100)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut a, later, &conflicting, REMOTE_A).unwrap();
    let out = sent(&mut a);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0.typ, BINDING_SUCCESS);
    assert!(!a.role());
    let events: Vec<Event> = std::iter::from_fn(|| a.poll_event())
        .map(|e| e.event)
        .collect();
    assert!(matches!(events.as_slice(), [Event::RoleChange(false)]));

    let nomination = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(100)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, later, &nomination, REMOTE_A).unwrap();
    assert_eq!(sent(&mut a)[0].0.typ, BINDING_SUCCESS);
    assert_eq!(
        a.get_selected_candidate_pair().unwrap().1.addr(),
        addr(REMOTE_A)
    );
    assert_eq!(a.state(), ConnectionState::Connected);
    assert!(a.poll_event().is_none(), "the pair in use did not change");

    let out = run_answering(&mut a, later, later + Duration::from_secs(20), |_, _| true);
    assert!(requests(&out).len() >= 3);
    assert!(requests(&out).iter().all(|(m, _)| {
        m.contains(ATTR_ICE_CONTROLLED)
            && !m.contains(ATTR_ICE_CONTROLLING)
            && !m.contains(ATTR_USE_CANDIDATE)
    }));
    assert_eq!(a.state(), ConnectionState::Connected);
}

// --- Section 12: sending and receiving data ---

fn datagram(local: &str, from: &str) -> TransportContext {
    TransportContext {
        local_addr: addr(local),
        peer_addr: addr(from),
        ecn: None,
        transport_protocol: TransportProtocol::UDP,
    }
}

/// A controlled agent whose checks to A and B were answered (two valid pairs), with a third
/// remote candidate that never answered, and no nomination yet.
fn two_valid_pairs(now: Instant, cfg: AgentConfig) -> Agent {
    const SILENT: &str = "192.168.0.5:4000";
    let mut a = started_agent(now, cfg, &[REMOTE_A, REMOTE_B, SILENT]);
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, to| {
        to != addr(SILENT)
    });
    assert!(a.get_selected_candidate_pair().is_none());
    assert_eq!(a.candidate_pairs.iter().filter(|p| p.valid).count(), 2);
    a
}

fn nominate(a: &mut Agent, now: Instant, from: &str) {
    let m = peer_request(
        a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(a, now, &m, from).unwrap();
    let _ = sent(a);
}

/// Section 12.2: "ICE implementations SHOULD by default be prepared to receive data on any of
/// the candidates provided in the most recent candidate exchange", from the peer, which the
/// agent knows "as a consequence of the STUN exchange": the remote candidate of a valid pair.
/// Not from a candidate no check was answered from, not from an address that is no candidate.
#[test]
fn test_data_is_accepted_from_every_valid_pair() {
    let now = Instant::now();
    let mut a = two_valid_pairs(now, config(false));
    // Section 12.1: nothing is selected, so there is nothing to send on, and nothing is taken.
    assert!(a.media_path().is_none());
    assert!(!a.accepts_data(datagram(LOCAL, REMOTE_A)));

    nominate(&mut a, now + Duration::from_secs(1), REMOTE_A);
    assert_eq!(a.media_path().unwrap().peer_addr, addr(REMOTE_A));
    assert!(matches!(
        a.data_path(datagram(LOCAL, REMOTE_A)),
        Some(DataPath::InUse)
    ));
    match a.data_path(datagram(LOCAL, REMOTE_B)) {
        Some(DataPath::Valid(local, remote)) => {
            assert_eq!(local.addr(), addr(LOCAL));
            assert_eq!(remote.addr(), addr(REMOTE_B));
        }
        other => panic!("data from the other valid pair: {other:?}"),
    }
    assert!(
        !a.accepts_data(datagram(LOCAL, "192.168.0.5:4000")),
        "a remote candidate no check was answered from"
    );
    assert!(
        !a.accepts_data(datagram(LOCAL, "192.168.0.9:4000")),
        "an address that is no candidate"
    );
    assert!(
        !a.accepts_data(datagram("192.168.0.2:1001", REMOTE_B)),
        "an address that is no local candidate"
    );
    // Data is still sent on the selected pair only (Section 12.1).
    assert_eq!(a.media_path().unwrap().peer_addr, addr(REMOTE_A));
}

/// Sections 12.1 and 12.2, controlling agent: while the responses to its nomination are lost,
/// the nominated pair (valid, and selected by the peer when the first request reached it)
/// carries data both ways: the peer's DTLS handshake is received and answered, not dropped
/// until a response comes. When the nomination fails, so does the path.
#[test]
fn test_data_flows_on_the_pair_being_nominated_until_its_response_comes() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    assert!(a.media_path().is_none(), "nothing is valid yet");

    // The ordinary check is answered; no response to the nomination's requests comes.
    let out = run_answering(&mut a, now, now + Duration::from_secs(1), |m, _| {
        !m.contains(ATTR_USE_CANDIDATE)
    });
    assert!(
        requests(&out)
            .iter()
            .any(|(m, to)| m.contains(ATTR_USE_CANDIDATE) && *to == addr(REMOTE_A)),
        "the pair is being nominated"
    );
    assert!(a.get_selected_candidate_pair().is_none());
    let path = a.media_path().expect("the nominated pair's path");
    assert_eq!(path.local_addr, addr(LOCAL));
    assert_eq!(path.peer_addr, addr(REMOTE_A));
    assert!(matches!(
        a.data_path(datagram(LOCAL, REMOTE_A)),
        Some(DataPath::InUse)
    ));

    // 30 seconds after the last success response consent has expired (RFC 7675 Section
    // 5.1): no data, although the nomination's transaction (39.5 seconds) is still open.
    let _ = run(
        &mut a,
        now + Duration::from_secs(1),
        now + Duration::from_secs(31),
    );
    assert_eq!(
        a.nominated_pair,
        Some(0),
        "the nomination is still in flight"
    );
    assert!(a.media_path().is_none());
    assert!(!a.accepts_data(datagram(LOCAL, REMOTE_A)));

    // The nomination's transaction ends unanswered (Section 7.2.5.3.4): no path either.
    let _ = run(
        &mut a,
        now + Duration::from_secs(31),
        now + Duration::from_secs(60),
    );
    assert!(a.media_path().is_none());
}

/// `data_from_selected_pair_only`, the fork's hardening: the selected pair's remote address
/// and no other.
#[test]
fn test_data_can_be_restricted_to_the_selected_pair() {
    let now = Instant::now();
    let cfg = AgentConfig {
        data_from_selected_pair_only: true,
        ..config(false)
    };
    let mut a = two_valid_pairs(now, cfg);
    nominate(&mut a, now + Duration::from_secs(1), REMOTE_A);
    assert!(a.accepts_data(datagram(LOCAL, REMOTE_A)));
    assert!(!a.accepts_data(datagram(LOCAL, REMOTE_B)));
}

/// Section 12.1: "An ICE agent MAY send data on any valid pair before selected pairs have
/// been produced for the data stream. Once selected pairs have been produced for a data
/// stream, an agent MUST send data on those pairs only." With
/// `send_data_before_nomination` the path is the best valid pair's until a pair is selected.
#[test]
fn test_data_can_be_sent_on_a_valid_pair_before_the_nomination() {
    let now = Instant::now();
    let cfg = AgentConfig {
        send_data_before_nomination: true,
        ..config(false)
    };
    let mut a = bare_agent(now, cfg);
    a.add_remote_candidate(host_with_priority(addr(REMOTE_A), 1000))
        .unwrap();
    a.add_remote_candidate(host_with_priority(addr(REMOTE_B), 2000))
        .unwrap();
    a.start_connectivity_checks(now, false, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    assert!(a.media_path().is_none(), "no valid pair yet");
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    assert!(a.get_selected_candidate_pair().is_none());
    let path = a.media_path().expect("the best valid pair");
    assert_eq!(path.peer_addr, addr(REMOTE_B));
    assert_eq!(path.local_addr, addr(LOCAL));
    assert!(a.accepts_data(datagram(LOCAL, REMOTE_A)));

    // The nomination decides from then on, whatever the priorities.
    nominate(&mut a, now + Duration::from_secs(1), REMOTE_A);
    assert_eq!(a.media_path().unwrap().peer_addr, addr(REMOTE_A));
}

// --- RFC 8489 Sections 6.3.1, 6.3.3, 7 and 9.1.3: the Binding transactions of ICE ---

/// RFC 8489 Section 6.3.1: a retransmitted request (the same transaction id) is answered
/// again, and the answer leaves the same state (Binding is idempotent: recomputed). Each
/// success response carries XOR-MAPPED-ADDRESS with the request's source (6.3.1.1), no
/// USERNAME (9.1.3), MESSAGE-INTEGRITY with the local password and FINGERPRINT last (7).
#[test]
fn test_a_retransmitted_check_gets_the_same_answer_and_changes_nothing() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let _ = sent(&mut a);
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1234))],
    );
    let mut answers = vec![];
    for at in [now, now + Duration::from_millis(500)] {
        deliver(&mut a, at, &request, REMOTE_A).unwrap();
        let out = sent(&mut a);
        let responses: Vec<_> = out
            .iter()
            .filter(|(m, _)| m.typ == BINDING_SUCCESS)
            .cloned()
            .collect();
        assert_eq!(
            responses.len(),
            1,
            "each copy of the request is answered once"
        );
        answers.push(responses[0].clone());
        assert_eq!(
            a.remote_candidates.len(),
            1,
            "no candidate learned from a copy"
        );
        assert_eq!(a.candidate_pairs.len(), 1);
    }
    for (response, to) in &answers {
        assert_eq!(*to, addr(REMOTE_A));
        assert_eq!(response.transaction_id, request.transaction_id);
        let mut mapped = XorMappedAddress::default();
        mapped.get_from(response).unwrap();
        assert_eq!(SocketAddr::new(mapped.ip, mapped.port), addr(REMOTE_A));
        assert!(
            !response.contains(ATTR_USERNAME),
            "a response carries no USERNAME"
        );
        let mut copy = response.clone();
        MessageIntegrity::check(
            &mut copy,
            a.ufrag_pwd.local_credentials.pwd.as_bytes(),
            provider().crypto(),
        )
        .unwrap();
        FINGERPRINT.check(response).unwrap();
        assert_eq!(
            response.attributes.0.last().unwrap().typ,
            stun::attributes::ATTR_FINGERPRINT
        );
    }
    let types = |m: &Message| m.attributes.0.iter().map(|a| a.typ).collect::<Vec<_>>();
    assert_eq!(
        types(&answers[0].0),
        types(&answers[1].0),
        "the same answer"
    );
}

/// RFC 8489 Section 7: where FINGERPRINT is used, every message sent carries it: the checks,
/// their retransmissions and the answers of an agent.
#[test]
fn test_every_message_the_agent_sends_ends_with_fingerprint() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A, REMOTE_B]);
    let mut out = run(&mut a, now, now + Duration::from_secs(3));
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1234))],
    );
    deliver(&mut a, now + Duration::from_secs(3), &request, REMOTE_A).unwrap();
    out.extend(sent(&mut a));
    assert!(
        out.iter().filter(|(m, _)| m.typ == BINDING_REQUEST).count() > 2,
        "checks and retransmissions"
    );
    assert!(out.iter().any(|(m, _)| m.typ == BINDING_SUCCESS));
    for (m, _) in &out {
        FINGERPRINT.check(m).unwrap();
        assert_eq!(
            m.attributes.0.last().unwrap().typ,
            stun::attributes::ATTR_FINGERPRINT
        );
    }
}

/// The peer's Binding request to `a` like [`peer_request`], authenticated by
/// MESSAGE-INTEGRITY-SHA256 alone.
fn peer_request_sha256(a: &Agent, extra: Vec<Box<dyn Setter>>) -> Message {
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":" + REMOTE_UFRAG;
    let provider = provider();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
    ];
    setters.extend(extra);
    setters.push(Box::new(
        MessageIntegritySha256::short_term(&a.ufrag_pwd.local_credentials.pwd, provider.crypto())
            .unwrap(),
    ));
    setters.push(Box::new(FINGERPRINT));
    let mut msg = Message::new();
    msg.build(&setters).unwrap();
    msg
}

/// RFC 8489 Section 9.1.3: "A response to a request that contains a MESSAGE-INTEGRITY-SHA256
/// attribute MUST include the MESSAGE-INTEGRITY-SHA256 attribute, computed using the password
/// utilized to authenticate the request [...] only one of these attributes can appear in a
/// response." The success response, the 487 and the 420 to such requests carry
/// MESSAGE-INTEGRITY-SHA256 with the local password and no MESSAGE-INTEGRITY; a request with
/// MESSAGE-INTEGRITY is still answered with MESSAGE-INTEGRITY only.
#[test]
fn test_a_request_with_message_integrity_sha256_is_answered_with_it_only() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    a.tie_breaker = 500;
    let _ = sent(&mut a);
    let provider = provider();
    let key = a.ufrag_pwd.local_credentials.pwd.clone();
    let answer_to = |a: &mut Agent, m: &Message| -> Message {
        let _ = deliver(a, now, m, REMOTE_A);
        let mut answers: Vec<Message> = sent(a)
            .into_iter()
            .filter(|(r, _)| r.transaction_id == m.transaction_id)
            .map(|(r, _)| r)
            .collect();
        assert_eq!(answers.len(), 1, "one answer");
        answers.remove(0)
    };
    let sha256_only = |r: &Message| {
        assert!(r.contains(stun::attributes::ATTR_MESSAGE_INTEGRITY_SHA256));
        assert!(!r.contains(stun::attributes::ATTR_MESSAGE_INTEGRITY));
        MessageIntegritySha256::check(r, key.as_bytes(), provider.crypto())
            .expect("MESSAGE-INTEGRITY-SHA256 with the local password");
        FINGERPRINT.check(r).unwrap();
    };

    // Success response.
    let check = peer_request_sha256(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    let success = answer_to(&mut a, &check);
    assert_eq!(success.typ, BINDING_SUCCESS);
    sha256_only(&success);

    // 487: ICE-CONTROLLING with a smaller tiebreaker to a controlling agent.
    let conflict = peer_request_sha256(
        &a,
        vec![Box::new(AttrControlling(100)), Box::new(PriorityAttr(1000))],
    );
    let error = answer_to(&mut a, &conflict);
    assert_eq!(error.typ, BINDING_ERROR);
    assert_eq!(error_code(&error), CODE_ROLE_CONFLICT.0);
    sha256_only(&error);

    // 420: an unknown comprehension-required attribute.
    let unknown = peer_request_sha256(
        &a,
        vec![
            Box::new(AttrControlled(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(stun::attributes::RawAttribute {
                typ: stun::attributes::AttrType(0x7f00),
                length: 4,
                value: vec![1, 2, 3, 4],
            }),
        ],
    );
    let error = answer_to(&mut a, &unknown);
    assert_eq!(error_code(&error), 420);
    sha256_only(&error);

    // MESSAGE-INTEGRITY in, MESSAGE-INTEGRITY out.
    let check = peer_request(
        &a,
        vec![Box::new(AttrControlled(1)), Box::new(PriorityAttr(1000))],
    );
    let success = answer_to(&mut a, &check);
    assert!(success.contains(stun::attributes::ATTR_MESSAGE_INTEGRITY));
    assert!(!success.contains(stun::attributes::ATTR_MESSAGE_INTEGRITY_SHA256));
}

/// RFC 8489 Section 6.3.3: "For the Binding method, the client checks that the
/// XOR-MAPPED-ADDRESS attribute is present in the response", and processes it only if the
/// checks succeed. A success response without it, otherwise authentic, makes no pair valid
/// and refreshes nothing; the transaction goes on, and a proper response to it is taken.
#[test]
fn test_a_success_response_without_xor_mapped_address_is_discarded() {
    let now = Instant::now();
    let mut a = started_agent(now, config(true), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let provider = provider();
    let mut bare = Message::new();
    bare.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(check.transaction_id),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            REMOTE_PWD.to_owned(),
            provider.crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    let at = now + Duration::from_millis(150);
    deliver(&mut a, at, &bare, &to.to_string()).unwrap();
    assert_eq!(a.get_best_valid_candidate_pair(), None, "no valid pair");
    assert!(a.remote_candidates[0].last_consent.is_none());

    let response = peer_response(BINDING_SUCCESS, check.transaction_id, addr(LOCAL), None);
    deliver(&mut a, at, &response, &to.to_string()).unwrap();
    assert!(
        a.get_best_valid_candidate_pair().is_some(),
        "the transaction was still open"
    );
}

// --- Sections 5.2, 7.2.4, 7.3, 12.1, 12.1.1: lite candidates, no RFC 3489, data gates ---

fn lite_config() -> AgentConfig {
    AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(false)
    }
}

/// Section 5.2: "lite implementations [...] MUST only use host candidates", zero or one per
/// IP address. A lite agent configured for other types is refused; given a second candidate on
/// an address it has, or a server-reflexive one, it does not take it; another address it does.
#[test]
fn test_a_lite_agent_has_one_host_candidate_per_ip_address() {
    let now = Instant::now();
    let refused = Agent::new(
        now,
        Arc::new(AgentConfig {
            lite: true,
            candidate_types: vec![CandidateType::Host, CandidateType::ServerReflexive],
            ..config(false)
        }),
        provider(),
    );
    assert!(refused.is_err(), "a lite agent with reflexive candidates");

    let mut a = bare_agent(now, lite_config());
    assert!(
        !a.add_local_candidate(host(addr("192.168.0.2:1001")))
            .unwrap(),
        "same IP"
    );
    let srflx = crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "203.0.113.9".to_owned(),
            port: 4000,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(),
        rel_port: 1000,
        url: None,
    }
    .new_candidate_server_reflexive()
    .unwrap();
    assert!(
        !a.add_local_candidate(srflx).unwrap(),
        "not a host candidate"
    );
    assert!(
        a.add_local_candidate(host(addr("192.168.0.7:1000")))
            .unwrap()
    );
    assert_eq!(a.get_local_candidates().len(), 2);
}

/// Sections 7.2.4 and 7.3: no RFC 3489 backwards compatibility and no ALTERNATE-SERVER. A
/// Binding request without the magic cookie (RFC 3489's form) is not STUN to the agent: it is
/// not answered and triggers nothing; an ordinary request is answered with a success response
/// that has no ALTERNATE-SERVER, never a 300 (Try Alternate).
#[test]
fn test_no_rfc_3489_compatibility_and_no_alternate_server() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let _ = run(&mut a, now, now + Duration::from_millis(1));
    let request = peer_request(
        &a,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    let mut rfc3489 = request.raw.clone();
    rfc3489[4..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    let _ = deliver_raw(&mut a, now, &rfc3489, REMOTE_A);
    let answers: Vec<_> = sent(&mut a)
        .into_iter()
        .filter(|(m, _)| m.transaction_id == request.transaction_id)
        .collect();
    assert!(
        answers.is_empty(),
        "a request without the magic cookie is not answered"
    );

    deliver(&mut a, now, &request, REMOTE_A).unwrap();
    let answers: Vec<_> = sent(&mut a)
        .into_iter()
        .filter(|(m, _)| m.transaction_id == request.transaction_id)
        .collect();
    assert_eq!(answers.len(), 1);
    let (answer, _) = &answers[0];
    assert_eq!(answer.typ, stun::message::BINDING_SUCCESS);
    assert!(!answer.contains(stun::attributes::ATTR_ALTERNATE_SERVER));
}

/// Section 12.1: without a selected pair the agent does not go on sending data: a failed
/// agent has no path for data. Section 12.1.1: a lite agent sends none before a nomination
/// gives it a valid pair.
#[test]
fn test_no_data_path_without_a_pair() {
    let now = Instant::now();
    let mut lite = started_agent(now, lite_config(), &[REMOTE_A]);
    let plain = peer_request(
        &lite,
        vec![Box::new(AttrControlling(1)), Box::new(PriorityAttr(1000))],
    );
    deliver(&mut lite, now, &plain, REMOTE_A).unwrap();
    assert!(
        lite.media_path().is_none(),
        "lite: no data before the nomination"
    );
    let nominating = peer_request(
        &lite,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut lite, now, &nominating, REMOTE_A).unwrap();
    assert!(lite.media_path().is_some(), "after it");

    let mut a = started_agent(
        now,
        AgentConfig {
            failed_timeout: Some(Duration::from_secs(1)),
            disconnected_timeout: Some(Duration::from_secs(1)),
            ..config(true)
        },
        &[REMOTE_A],
    );
    // No candidate is to come: consent that expires fails the agent (W3C webrtc-pc 5.6.4).
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    run_answering(&mut a, now, now + Duration::from_secs(1), |_, _| true);
    assert!(a.media_path().is_some(), "connected: a path");
    run_answering(&mut a, now, now + Duration::from_secs(60), |_, _| false);
    assert_eq!(a.state(), ConnectionState::Failed);
    assert!(a.media_path().is_none(), "failed: none");
}

// --- RFC 8489 Sections 6.3.2 to 6.3.4 as the ICE usage receives STUN ---

/// A response or indication of the peer's with an unknown comprehension-required attribute
/// (0x0099) ahead of its MESSAGE-INTEGRITY.
fn with_unknown_attribute(
    typ: MessageType,
    id: TransactionId,
    error: Option<ErrorCode>,
) -> Message {
    let provider = provider();
    let mut m = Message::new();
    m.set_type(typ);
    m.transaction_id = id;
    m.write_header();
    match error {
        Some(code) => code.add_to(&mut m).unwrap(),
        None => XorMappedAddress {
            ip: addr(LOCAL).ip(),
            port: addr(LOCAL).port(),
        }
        .add_to(&mut m)
        .unwrap(),
    }
    m.add(stun::attributes::AttrType(0x0099), &[1, 2, 3, 4]);
    if typ.class != stun::message::CLASS_INDICATION {
        MessageIntegrity::new_short_term_integrity_with_provider(
            REMOTE_PWD.to_owned(),
            provider.crypto(),
        )
        .add_to(&mut m)
        .unwrap();
    }
    FINGERPRINT.add_to(&mut m).unwrap();
    m
}

/// RFC 8489 Section 6.3.4: an error response with an unknown comprehension-required attribute
/// means the transaction failed: the pair fails at once (RFC 8445 Section 7.2.5.2.4), not when
/// the transaction times out.
#[test]
fn test_an_error_response_with_an_unknown_required_attribute_fails_the_transaction() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let response =
        with_unknown_attribute(BINDING_ERROR, check.transaction_id, Some(CODE_BAD_REQUEST));
    let _ = deliver(&mut a, now, &response, &to.to_string());
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Failed);
}

/// RFC 8489 Section 6.3.3: a success response with one is discarded and the transaction goes
/// on: the pair is not validated by it, and the next (good) response validates it.
#[test]
fn test_a_success_response_with_an_unknown_required_attribute_is_discarded() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let (check, to) = first_check(&mut a, now);
    let response = with_unknown_attribute(BINDING_SUCCESS, check.transaction_id, None);
    assert!(deliver(&mut a, now, &response, &to.to_string()).is_err());
    assert_ne!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
    let good = peer_response(BINDING_SUCCESS, check.transaction_id, addr(LOCAL), None);
    deliver(&mut a, now, &good, &to.to_string()).unwrap();
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::Succeeded);
}

/// RFC 8489 Section 6.3.2: an indication with one is discarded: it does not count as
/// something received from the peer (a lite peer's keepalive is a Binding indication).
#[test]
fn test_an_indication_with_an_unknown_required_attribute_is_discarded() {
    let now = Instant::now();
    let mut a = started_agent(now, config(false), &[REMOTE_A]);
    let indication = with_unknown_attribute(
        stun::message::MessageType::new(
            stun::message::METHOD_BINDING,
            stun::message::CLASS_INDICATION,
        ),
        TransactionId::new(),
        None,
    );
    let _ = deliver(&mut a, now, &indication, REMOTE_A);
    assert_eq!(a.remote_candidates[0].last_received(), None);
    let mut plain = Message::new();
    plain
        .build(&[
            Box::new(indication.typ),
            Box::new(TransactionId::new()),
            Box::new(FINGERPRINT),
        ])
        .unwrap();
    deliver(&mut a, now, &plain, REMOTE_A).unwrap();
    assert_eq!(a.remote_candidates[0].last_received(), Some(now));
}
