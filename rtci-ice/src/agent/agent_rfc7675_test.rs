//! RFC 7675 (consent freshness), read from the wire and the agent's events in virtual time.

use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USERNAME;

use super::agent_rfc8445_test::*;
use super::*;
use crate::attributes::control::AttrControlling;
use crate::attributes::priority::PriorityAttr;

/// What happened while the agent's timer ran: Binding requests it sent (when, what, where to)
/// and its connection states (when, which).
#[derive(Default)]
struct Trace {
    requests: Vec<(Instant, Message, SocketAddr)>,
    states: Vec<(Instant, ConnectionState)>,
    /// When the media path went away (consent expired), if it did. The agent is `Failed` then
    /// or, within the PAC timer, when the timer expires (W3C webrtc-pc 5.6.4).
    lost: Option<Instant>,
}

/// Runs the agent's timer from `from` to `until`, waking it exactly when it asks to be woken.
/// A Binding request is answered (success, signed with the peer's password) when `answer`
/// says so.
fn run_traced(
    a: &mut Agent,
    from: Instant,
    until: Instant,
    mut answer: impl FnMut(Instant, &Message) -> bool,
) -> Trace {
    let mut trace = Trace::default();
    let mut now = from;
    loop {
        let had_path = a.media_path().is_some();
        a.handle_timeout(now).unwrap();
        if had_path && a.media_path().is_none() {
            trace.lost.get_or_insert(now);
        }
        while let Some(t) = a.poll_write() {
            let mut m = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            m.decode().unwrap();
            if m.typ != BINDING_REQUEST {
                continue;
            }
            if answer(now, &m) {
                let response = peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
                let _ = deliver(a, now, &response, &t.transport.peer_addr.to_string());
            }
            trace.requests.push((t.now, m, t.transport.peer_addr));
        }
        while let Some(e) = a.poll_event() {
            if let Event::ConnectionStateChange(s) = e.event {
                trace.states.push((e.now, s));
            }
        }
        match a.poll_timeout() {
            Some(next) if next <= until => now = next.max(now + Duration::from_micros(1)),
            _ => return trace,
        }
    }
}

/// A connected controlling agent (one pair, `LOCAL` to `REMOTE_A`) and the instant it is at.
fn connected(config: AgentConfig) -> (Agent, Instant) {
    let start = Instant::now();
    let mut a = started_agent(start, config, &[REMOTE_A]);
    let now = start + Duration::from_millis(500);
    run_traced(&mut a, start, now, |_, _| true);
    assert_eq!(a.state(), ConnectionState::Connected);
    assert!(a.get_selected_candidate_pair().is_some());
    (a, now)
}

fn intervals(trace: &Trace) -> Vec<Duration> {
    trace
        .requests
        .windows(2)
        .map(|w| w[1].0.duration_since(w[0].0))
        .collect()
}

/// Section 5.1: each interval between consent checks is 0.8 to 1.2 times the period, 5 seconds
/// by default (4 to 6 seconds), randomized; each check is a new transaction; an agent whose
/// checks are answered is never Disconnected between two of them.
#[test]
fn test_consent_checks_are_four_to_six_seconds_apart_and_randomized() {
    let (mut a, now) = connected(config(true));
    let trace = run_traced(&mut a, now, now + Duration::from_secs(600), |_, _| true);

    let gaps = intervals(&trace);
    assert!(
        (100..=150).contains(&trace.requests.len()),
        "{} consent checks in 600 s",
        trace.requests.len()
    );
    let (min, max) = (gaps.iter().min().unwrap(), gaps.iter().max().unwrap());
    assert!(*min >= Duration::from_secs(4), "shortest interval {min:?}");
    assert!(*max <= Duration::from_secs(6), "longest interval {max:?}");
    assert!(
        *max - *min > Duration::from_millis(500),
        "intervals are not randomized: {min:?} to {max:?}"
    );
    let mut ids: Vec<_> = trace
        .requests
        .iter()
        .map(|(_, m, _)| m.transaction_id)
        .collect();
    ids.sort_by_key(|id| id.0);
    ids.dedup();
    assert_eq!(
        ids.len(),
        trace.requests.len(),
        "a transaction id was reused"
    );
    assert!(
        trace
            .requests
            .iter()
            .all(|(_, _, to)| *to == addr(REMOTE_A))
    );
    assert!(trace.states.is_empty(), "state changed: {:?}", trace.states);
}

/// Section 5.1: "Implementations MUST NOT set the period between checks to less than 4
/// seconds." A shorter configured period is raised.
#[test]
fn test_a_consent_period_under_the_minimum_is_raised() {
    for period in [Duration::from_millis(100), Duration::from_secs(4)] {
        let (mut a, now) = connected(AgentConfig {
            keepalive_interval: Some(period),
            ..config(true)
        });
        let trace = run_traced(&mut a, now, now + Duration::from_secs(120), |_, _| true);
        let gaps = intervals(&trace);
        assert!(gaps.len() >= 15);
        assert!(
            gaps.iter().all(|gap| *gap >= Duration::from_secs(4)),
            "period {period:?}: {:?}",
            gaps.iter().min()
        );
    }
}

/// Section 5.1: consent expires 30 seconds after the last valid response, and no configuration
/// stretches that: not long timeouts, not a zero `failed_timeout`.
#[test]
fn test_consent_expires_after_thirty_seconds_whatever_the_timeouts() {
    for (disconnected, failed) in [
        (Duration::from_secs(5), Duration::ZERO),
        (Duration::from_secs(3600), Duration::from_secs(3600)),
    ] {
        let (mut a, now) = connected(AgentConfig {
            disconnected_timeout: Some(disconnected),
            failed_timeout: Some(failed),
            ..config(true)
        });
        // No candidate is to come: consent that expires fails the agent (W3C webrtc-pc 5.6.4).
        a.set_local_gathering_complete();
        a.set_remote_end_of_candidates();
        let last_consent = a.remote_candidates[0].last_consent().unwrap();
        // The peer goes away.
        let trace = run_traced(&mut a, now, now + Duration::from_secs(120), |_, _| false);
        let lost_at = trace.lost.expect("consent expires");
        assert_eq!(
            lost_at.duration_since(last_consent),
            Duration::from_secs(30)
        );
        assert_eq!(a.state(), ConnectionState::Failed);
        assert!(a.media_path().is_none(), "nothing is sent without consent");
        // "All outstanding STUN consent transactions [...] MUST be discarded".
        assert!(a.pending_binding_requests.is_empty());
        // Consent checks were made, once each, until then.
        assert!(trace.requests.len() >= 4);
        assert!(a.poll_timeout().is_none());
    }
}

/// A shorter configured sum fails the agent sooner than 30 seconds.
#[test]
fn test_shorter_timeouts_fail_a_silent_pair_sooner() {
    let (mut a, now) = connected(AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(5)),
        failed_timeout: Some(Duration::from_secs(7)),
        ..config(true)
    });
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
    let last_consent = a.remote_candidates[0].last_consent().unwrap();
    let trace = run_traced(&mut a, now, now + Duration::from_secs(60), |_, _| false);
    let lost_at = trace.lost.expect("consent expires");
    assert_eq!(
        lost_at.duration_since(last_consent),
        Duration::from_secs(12)
    );
    assert_eq!(a.state(), ConnectionState::Failed, "{:?}", trace.states);
}

/// The agent is Disconnected when a consent request has gone unanswered for
/// `disconnected_timeout`, and Connected again when a later one is answered.
#[test]
fn test_disconnected_after_an_unanswered_consent_request_and_back() {
    let (mut a, now) = connected(config(true));
    let silent_from = now + Duration::from_secs(20);
    let silent_until = silent_from + Duration::from_secs(14);
    let trace = run_traced(&mut a, now, now + Duration::from_secs(60), |at, _| {
        at < silent_from || at >= silent_until
    });

    let first_unanswered = trace
        .requests
        .iter()
        .map(|(at, _, _)| *at)
        .find(|at| *at >= silent_from)
        .unwrap();
    assert_eq!(trace.states.len(), 2, "{:?}", trace.states);
    assert_eq!(trace.states[0].1, ConnectionState::Disconnected);
    assert_eq!(
        trace.states[0].0.duration_since(first_unanswered),
        Duration::from_secs(5)
    );
    assert_eq!(trace.states[1].1, ConnectionState::Connected);
    assert!(trace.states[1].0 >= silent_until);
    assert!(a.media_path().is_some());
}

/// The peer's request on the old generation, as it keeps sending them during a restart.
fn old_generation_request(local: &Credentials) -> Message {
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(
            ATTR_USERNAME,
            local.ufrag.clone() + ":" + REMOTE_UFRAG,
        )),
        Box::new(AttrControlling(1)),
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local.pwd.clone(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    msg
}

/// Section 5.1: "an endpoint that continues to send traffic on the previously validated
/// candidate pair during ICE restart MUST continue to perform consent freshness on that
/// candidate pair". The checks go on, with the old generation's credentials, and while they
/// are answered the path stays.
#[test]
fn test_consent_checks_continue_on_the_previous_path_during_a_restart() {
    for keep_local_candidates in [true, false] {
        let (mut a, now) = connected(config(true));
        let old_local = a.ufrag_pwd.local_credentials.clone();
        let path = a.media_path().unwrap();

        a.restart(now, String::new(), String::new(), keep_local_candidates)
            .unwrap();
        assert_ne!(a.ufrag_pwd.local_credentials.ufrag, old_local.ufrag);
        assert_eq!(a.media_path(), Some(path));

        // The peer's new description never arrives; it keeps answering on the old pair.
        let trace = run_traced(&mut a, now, now + Duration::from_secs(90), |_, _| true);
        assert_eq!(a.media_path(), Some(path), "an answered path was dropped");
        assert!(
            trace.requests.len() >= 14,
            "{} checks",
            trace.requests.len()
        );
        for gap in intervals(&trace) {
            assert!(gap >= Duration::from_secs(4) && gap <= Duration::from_secs(6));
        }
        for (_, m, to) in &trace.requests {
            assert_eq!(*to, path.peer_addr);
            let mut username = Username::new(ATTR_USERNAME, String::new());
            username.get_from(m).unwrap();
            assert_eq!(
                username.to_string(),
                format!("{REMOTE_UFRAG}:{}", old_local.ufrag),
                "consent on the old pair uses the old generation's credentials"
            );
            let mut copy = m.clone();
            MessageIntegrity::check(&mut copy, REMOTE_PWD.as_bytes(), provider().crypto()).unwrap();
        }
    }
}

/// Section 5.1: without a response for 30 seconds the path kept across the restart is given
/// up, whatever the timeouts (a zero `failed_timeout` kept it for ever).
#[test]
fn test_previous_path_is_dropped_when_its_consent_expires() {
    let (mut a, now) = connected(AgentConfig {
        failed_timeout: Some(Duration::ZERO),
        ..config(true)
    });
    let last_consent = a.remote_candidates[0].last_consent().unwrap();
    a.restart(now, String::new(), String::new(), true).unwrap();
    assert!(a.media_path().is_some());

    // The peer has gone away: nothing is answered.
    let mut dropped_at = None;
    let mut t = now;
    while t < now + Duration::from_secs(60) {
        // One timeout at `t` exactly, nothing answered: a drop at `t` is the agent's, not a
        // later instant a helper stepped to.
        a.handle_timeout(t).unwrap();
        while a.poll_write().is_some() {}
        while a.poll_event().is_some() {}
        if a.media_path().is_none() {
            dropped_at = Some(t);
            break;
        }
        // Straight to the agent's next timer, which must lie after `t`: a deadline left in
        // the past is a path not dropped when due. (Stepping at least a millisecond, as this loop did, jumped past the expiry when a
        // consent request fell less than a millisecond before it: the randomized 4 to 6 s
        // intervals put one there about once in five thousand runs.)
        let next = a
            .poll_timeout()
            .expect("a timer runs while the path is kept");
        assert!(next > t, "the agent's timer does not advance past {t:?}");
        t = next;
    }
    let dropped_at = dropped_at.expect("the path is dropped");
    assert_eq!(
        dropped_at.duration_since(last_consent),
        Duration::from_secs(30)
    );
    assert!(a.previous_generation.is_none());
}

/// During a restart the peer goes on asking for consent on the old pair, with the old
/// credentials: those requests are answered (or the peer would stop sending to us), and they
/// are not taken for checks of the new generation.
#[test]
fn test_old_generation_consent_requests_are_answered_during_a_restart() {
    for lite in [false, true] {
        let cfg = AgentConfig {
            lite,
            candidate_types: if lite {
                vec![CandidateType::Host]
            } else {
                vec![]
            },
            ..config(false)
        };
        let start = Instant::now();
        let mut a = started_agent(start, cfg, &[REMOTE_A]);
        if lite {
            let nominate = peer_request(
                &a,
                vec![
                    Box::new(AttrControlling(1)),
                    Box::new(PriorityAttr(1000)),
                    Box::new(crate::attributes::use_candidate::UseCandidateAttr::new()),
                ],
            );
            deliver(&mut a, start, &nominate, REMOTE_A).unwrap();
        } else {
            a.candidate_pairs[0].state = CandidatePairState::Succeeded;
            a.remote_candidates[0].last_consent = Some(start);
            a.candidate_pairs[0].last_consent = Some(start);
            a.set_selected_pair(Some(start), Some(0));
        }
        let _ = sent(&mut a);
        let old_local = a.ufrag_pwd.local_credentials.clone();
        let now = start + Duration::from_secs(1);
        a.restart(now, String::new(), String::new(), false).unwrap();
        assert!(a.local_candidates.is_empty());

        let request = old_generation_request(&old_local);
        deliver(&mut a, now, &request, REMOTE_A).unwrap();
        let out = sent(&mut a);
        assert_eq!(out.len(), 1, "lite={lite}");
        let (response, to) = &out[0];
        assert_eq!(response.typ, BINDING_SUCCESS);
        assert_eq!(response.transaction_id, request.transaction_id);
        assert_eq!(*to, addr(REMOTE_A));
        let mut copy = response.clone();
        MessageIntegrity::check(&mut copy, old_local.pwd.as_bytes(), provider().crypto()).unwrap();
        assert!(
            a.remote_candidates.is_empty(),
            "no candidate of the new generation"
        );

        // From another address the old credentials open nothing (the restart dropped the
        // local candidates: the datagram is for no candidate of the agent, and is not answered).
        assert!(deliver(&mut a, now, &old_generation_request(&old_local), REMOTE_B).is_err());
        assert!(sent(&mut a).is_empty());
    }
}

/// A lite agent sends no consent requests; the path it keeps across a restart lives on the
/// peer's authenticated requests and ends without them.
#[test]
fn test_lite_previous_path_lives_on_the_peers_requests() {
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        ..config(false)
    };
    let start = Instant::now();
    let mut a = started_agent(start, cfg, &[REMOTE_A]);
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(crate::attributes::use_candidate::UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, start, &nominate, REMOTE_A).unwrap();
    let old_local = a.ufrag_pwd.local_credentials.clone();
    a.restart(start, String::new(), String::new(), true)
        .unwrap();
    let _ = sent(&mut a);

    let mut now = start;
    for _ in 0..10 {
        now += Duration::from_secs(5);
        deliver(&mut a, now, &old_generation_request(&old_local), REMOTE_A).unwrap();
        let trace = run_traced(&mut a, now, now, |_, _| false);
        assert!(trace.requests.is_empty(), "a lite agent sent a request");
        assert!(a.media_path().is_some());
    }
    let _ = sent(&mut a);
    run_traced(&mut a, now, now + Duration::from_secs(31), |_, _| false);
    assert!(a.media_path().is_none());
}

/// RFC 8445 Section 11: an agent keeps its selected pair alive. A lite agent cannot send
/// Binding requests, so after 15 silent seconds it sends a Binding indication, which carries
/// FINGERPRINT and no authentication.
#[test]
fn test_lite_agent_sends_binding_indications_as_keepalives() {
    let cfg = AgentConfig {
        lite: true,
        candidate_types: vec![CandidateType::Host],
        // The peer is quiet in this test; it must not count as gone.
        disconnected_timeout: Some(Duration::ZERO),
        failed_timeout: Some(Duration::ZERO),
        ..config(false)
    };
    let start = Instant::now();
    let mut a = started_agent(start, cfg, &[REMOTE_A]);
    let nominate = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(crate::attributes::use_candidate::UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, start, &nominate, REMOTE_A).unwrap();
    let _ = sent(&mut a);

    let mut indications = vec![];
    let mut now = start;
    while now < start + Duration::from_secs(100) {
        a.handle_timeout(now).unwrap();
        while let Some(t) = a.poll_write() {
            let mut m = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            m.decode().unwrap();
            assert_eq!(m.typ, MessageType::new(METHOD_BINDING, CLASS_INDICATION));
            assert_eq!(t.transport.peer_addr, addr(REMOTE_A));
            assert_eq!(m.attributes.0.len(), 1, "FINGERPRINT and nothing else");
            FINGERPRINT.check(&m).unwrap();
            indications.push(t.now);
        }
        now = a
            .poll_timeout()
            .unwrap()
            .max(now + Duration::from_millis(1));
    }
    assert!(
        (4..=7).contains(&indications.len()),
        "{}",
        indications.len()
    );
    for pair in indications.windows(2) {
        assert!(pair[1].duration_since(pair[0]) >= Duration::from_secs(15));
    }
}

/// Section 5.1: consent lasts 30 seconds from the last response. A controlled agent whose own
/// check validated the pair at once, and whose peer nominates it 15 seconds later (every
/// response to the peer's checks was lost), has 15 seconds of consent left when it selects the
/// pair: its first consent check goes at the selection, not an interval later (the check that
/// validated the pair was sent 15 seconds before, so the period between checks stays above
/// four seconds). With the first check an interval later, three lost consent checks lapsed
/// consent at 10 % loss (`tests/lossy_link_rtc2rtc.rs` sweep, aws-lc-rs seed 1049).
#[test]
fn test_a_pair_selected_long_after_its_last_consent_is_checked_at_once() {
    use crate::attributes::use_candidate::UseCandidateAttr;
    let start = Instant::now();
    let mut a = started_agent(start, config(false), &[REMOTE_A]);
    run_traced(&mut a, start, start + Duration::from_millis(500), |_, _| {
        true
    });
    assert!(
        a.get_selected_candidate_pair().is_none(),
        "controlled: waits"
    );

    let later = start + Duration::from_secs(15);
    let nomination = peer_request(
        &a,
        vec![
            Box::new(AttrControlling(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(UseCandidateAttr::new()),
        ],
    );
    deliver(&mut a, later, &nomination, REMOTE_A).unwrap();
    assert!(a.get_selected_candidate_pair().is_some());
    while a.poll_write().is_some() {}
    let trace = run_traced(&mut a, later, later + Duration::from_secs(1), |_, _| true);
    assert_eq!(
        1,
        trace.requests.len(),
        "a consent check at the selection: {:?}",
        trace
            .requests
            .iter()
            .map(|(at, _, _)| *at - later)
            .collect::<Vec<_>>()
    );
}

/// A pair selected right after its validating response keeps the first consent check one
/// interval (4 to 6 seconds) later.
#[test]
fn test_a_pair_selected_at_once_is_checked_an_interval_later() {
    let (mut a, now) = connected(config(true));
    let trace = run_traced(&mut a, now, now + Duration::from_secs(10), |_, _| true);
    let first = trace.requests.first().expect("a consent check").0;
    let after = first - now;
    assert!(after >= Duration::from_millis(3500), "{after:?}");
}
