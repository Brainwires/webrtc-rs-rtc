//! Consent freshness (RFC 7675 Section 5.1) on a path that is slow, or becomes slow: the peer
//! answers every consent request, late. Read from the wire and the agent's events in virtual
//! time: the peer here answers each Binding request after the round trip the test gives it.
//!
//! What decides is how long a consent request's transaction is in progress (RFC 8489 Section
//! 6.3: a response is processed when "the transaction ID matches a transaction that is still
//! in progress"). RFC 7675 Section 5.1: "An endpoint SHOULD await a binding response for each
//! request it sends for a time based on the estimated round-trip time (RTT) (see Section 7.2.1
//! of [RFC5389]) with an allowance for variation in network delay", and "a response might be
//! for a previous request (rather than for the most recently sent request)". The wait is `Rm`
//! (16) times the pair's RTO (RFC 8489 Section 6.2.1), which is 500 ms until the responses
//! show a longer round trip: 8 seconds at least, the consent expiry (30 seconds) at most.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use sansio::Protocol;

use super::agent_rfc8445_test::*;
use super::*;
use crate::attributes::control::AttrControlling;
use crate::attributes::priority::PriorityAttr;
use crate::candidate::candidate_host::CandidateHostConfig;

const MS: Duration = Duration::from_millis(1);
const S: Duration = Duration::from_secs(1);

/// What happened while the agent ran against the slow peer.
#[derive(Default)]
struct Trace {
    /// The first transmission of each Binding request: when, its transaction, where to.
    requests: Vec<(Instant, TransactionId, SocketAddr)>,
    states: Vec<(Instant, ConnectionState)>,
    /// The responses that renewed the consent of the remote candidate they came from: when
    /// they arrived, and the transaction they answered.
    renewed: Vec<(Instant, TransactionId)>,
    /// The responses that arrived and renewed nothing.
    ignored: Vec<(Instant, TransactionId)>,
    /// The most consent transactions the agent held open at once.
    most_open_consent_transactions: usize,
    /// When the agent's media path went away (consent expired, RFC 7675 Section 5.1), if it
    /// did. The agent is `Failed` then or, within the PAC timer, when the timer expires (W3C
    /// webrtc-pc 5.6.4).
    lost: Option<Instant>,
}

impl Trace {
    fn saw(&self, state: ConnectionState) -> bool {
        self.states.iter().any(|(_, s)| *s == state)
    }

    fn at(&self, state: ConnectionState) -> Option<Instant> {
        self.states
            .iter()
            .find(|(_, s)| *s == state)
            .map(|(at, _)| *at)
    }

    fn sent_at(&self, id: TransactionId) -> Instant {
        self.requests.iter().find(|r| r.1 == id).unwrap().0
    }
}

/// A peer behind a slow path: its response to a Binding request reaches the agent one round
/// trip after the request left.
#[derive(Default)]
struct SlowPeer {
    /// Responses on their way, by arrival time (and a sequence number for ties): the
    /// response and the address it comes from.
    in_flight: BTreeMap<(Instant, u64), (Message, SocketAddr)>,
    sequence: u64,
}

impl SlowPeer {
    /// Runs the agent from `from` to `until`, waking it when it asks to be and when a
    /// response arrives. The first transmission of each Binding request is answered after
    /// `round_trip(when it left, how many requests left before it, where it went)`, from the
    /// address it went to; `None` is a request or a response the path lost. A
    /// retransmission is not answered again.
    fn run(
        &mut self,
        a: &mut Agent,
        from: Instant,
        until: Instant,
        mut round_trip: impl FnMut(Instant, usize, SocketAddr) -> Option<Duration>,
    ) -> Trace {
        let mut trace = Trace::default();
        let mut now = from;
        loop {
            while let Some(entry) = self.in_flight.first_entry() {
                if entry.key().0 > now {
                    break;
                }
                let (response, peer) = entry.remove();
                Self::arrive(a, now, &response, peer, &mut trace);
            }
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
                if m.typ != BINDING_REQUEST
                    || trace.requests.iter().any(|r| r.1 == m.transaction_id)
                {
                    continue;
                }
                let to = t.transport.peer_addr;
                let sent_before = trace.requests.len();
                trace.requests.push((now, m.transaction_id, to));
                if let Some(round_trip) = round_trip(now, sent_before, to) {
                    let response =
                        peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
                    if round_trip.is_zero() {
                        Self::arrive(a, now, &response, to, &mut trace);
                    } else {
                        self.sequence += 1;
                        self.in_flight
                            .insert((now + round_trip, self.sequence), (response, to));
                    }
                }
            }
            while let Some(e) = a.poll_event() {
                if let Event::ConnectionStateChange(s) = e.event {
                    trace.states.push((e.now, s));
                }
            }
            trace.most_open_consent_transactions = trace.most_open_consent_transactions.max(
                a.pending_binding_requests
                    .iter()
                    .filter(|r| r.consent)
                    .count(),
            );
            let arrival = self.in_flight.first_key_value().map(|(key, _)| key.0);
            let next = match (a.poll_timeout(), arrival) {
                (Some(timer), Some(arrival)) => Some(timer.min(arrival)),
                (timer, arrival) => timer.or(arrival),
            };
            match next {
                Some(next) if next <= until => now = next.max(now + Duration::from_micros(1)),
                _ => return trace,
            }
        }
    }

    fn arrive(a: &mut Agent, now: Instant, response: &Message, peer: SocketAddr, t: &mut Trace) {
        let consent = |a: &Agent| {
            a.find_remote_candidate(peer)
                .and_then(|index| a.remote_candidates[index].last_consent())
        };
        let before = consent(a);
        let _ = deliver(a, now, response, &peer.to_string());
        if consent(a) == Some(now) && before != Some(now) {
            t.renewed.push((now, response.transaction_id));
        } else {
            t.ignored.push((now, response.transaction_id));
        }
    }
}

/// A controlling agent connected to `REMOTE_A` over a path with a round trip of 20 ms, one
/// second after it started, and that instant.
fn connected(config: AgentConfig) -> (Agent, SlowPeer, Instant) {
    let start = Instant::now();
    let mut a = started_agent(start, config, &[REMOTE_A]);
    let mut peer = SlowPeer::default();
    peer.run(&mut a, start, start + S, |_, _, _| Some(20 * MS));
    assert_eq!(a.state(), ConnectionState::Connected);
    (a, peer, start + S)
}

/// Tells `a` that no candidate is to come on either side, so that consent that expires fails
/// it (W3C webrtc-pc 5.6.4: "failed" needs the end of the candidates; without it the agent is
/// disconnected).
fn no_more_candidates(a: &mut Agent) {
    a.set_local_gathering_complete();
    a.set_remote_end_of_candidates();
}

fn fixed(wait: Duration) -> AgentConfig {
    AgentConfig {
        consent_response_wait: ConsentResponseWait::Fixed(wait),
        ..config(true)
    }
}

/// Whether `at` is `expected`: the instant itself, or the step of a microsecond the run
/// takes when two of the agent's timers fall closer together than that.
fn is_at(at: Option<Instant>, expected: Instant) -> bool {
    at.is_some_and(|at| at >= expected && at - expected < MS)
}

fn selected_consent(a: &Agent) -> Instant {
    let (_, remote) = a.get_selected_candidate_pair().expect("a selected pair");
    remote.last_consent().expect("consent")
}

/// The defect this file was written for: the round trip of a connected path rises from
/// 20 ms to 600 ms and more (a queue filled up, a route changed), with no loss. Every consent
/// request is answered, each answer more than the RTO (500 ms) after its request: consent is
/// kept, for as long as the path is like that, and the agent is never `Disconnected`.
#[test]
fn test_consent_is_kept_when_the_round_trip_rises_above_the_rto() {
    for round_trip in [600 * MS, 800 * MS, 1000 * MS] {
        let (mut a, mut peer, now) = connected(config(true));
        let trace = peer.run(&mut a, now, now + 300 * S, |_, _, _| Some(round_trip));
        assert_eq!(
            trace.states,
            vec![],
            "{round_trip:?}: the state of an answered path changed"
        );
        assert_eq!(a.state(), ConnectionState::Connected);
        assert!(trace.requests.len() >= 45, "{}", trace.requests.len());
        // Every answer renewed consent (the last request may still be on its way).
        assert_eq!(trace.ignored, vec![], "{round_trip:?}");
        assert!(trace.renewed.len() + 1 >= trace.requests.len());
        assert!(now + 300 * S - selected_consent(&a) < 7 * S);
    }
}

/// The same path from the first check on. Its checks were all retransmitted (the RTO of a
/// check is 500 ms, RFC 8445 Section 14.3), so none of them gave a round-trip time (RFC 8489
/// Section 6.2.1: none "from STUN transactions that result in the retransmission of a
/// request"): the first consent requests wait on the initial RTO, and are answered within
/// their transaction. (Between two full agents a check cancelled before its retransmission
/// and answered later usually gives a round-trip time; nothing guarantees one.)
#[test]
fn test_a_pair_whose_round_trip_is_long_from_the_first_check_keeps_consent() {
    let start = Instant::now();
    let mut a = started_agent(start, config(true), &[REMOTE_A]);
    let mut peer = SlowPeer::default();
    let trace = peer.run(&mut a, start, start + 120 * S, |_, _, _| Some(800 * MS));
    assert_eq!(
        trace
            .states
            .iter()
            .map(|(_, s)| *s)
            .filter(|s| *s != ConnectionState::Checking)
            .collect::<Vec<_>>(),
        vec![ConnectionState::Connected],
        "connected, and nothing else"
    );
    assert!(start + 120 * S - selected_consent(&a) < 7 * S);
}

/// A round trip that grows by a quarter from one consent request to the next, up to 4.5 s:
/// consent is kept and the agent is never `Disconnected` (no request is unanswered for 5 s).
#[test]
fn test_consent_is_kept_while_the_round_trip_grows_gradually() {
    let (mut a, mut peer, now) = connected(config(true));
    let mut round_trip = 20 * MS;
    let trace = peer.run(&mut a, now, now + 400 * S, |_, _, _| {
        round_trip = (round_trip * 5 / 4).min(4500 * MS);
        Some(round_trip)
    });
    assert_eq!(round_trip, 4500 * MS);
    assert_eq!(trace.states, vec![]);
    assert_eq!(trace.ignored, vec![]);
    assert_eq!(a.state(), ConnectionState::Connected);
}

/// The wait follows the round-trip time (RFC 7675 Section 5.1: "The RTT value can be updated
/// as described in [RFC5389]"): a round trip that grows gradually to 12 s, longer than the
/// 8 s a request waits on the initial RTO, never costs the consent, because every answer
/// that takes long makes the next requests wait longer. (At 12 s each request is unanswered
/// for more than `disconnected_timeout`, so the agent may report `Disconnected` in between;
/// it never fails.)
#[test]
fn test_the_wait_grows_with_the_round_trip_the_responses_show() {
    let (mut a, mut peer, now) = connected(config(true));
    let mut round_trip = 20 * MS;
    let trace = peer.run(&mut a, now, now + 600 * S, |_, _, _| {
        round_trip = (round_trip * 5 / 4).min(12 * S);
        Some(round_trip)
    });
    assert_eq!(round_trip, 12 * S);
    assert!(!trace.saw(ConnectionState::Failed), "{:?}", trace.states);
    assert_eq!(trace.ignored, vec![], "every answer was within its wait");
    assert!(now + 600 * S - selected_consent(&a) < 7 * S);
    let pair = a.candidate_pairs[a.selected_pair.unwrap()];
    assert!(pair.rto.rto() >= 11 * S, "{:?}", pair.rto.rto());
}

/// A round trip that jumps from 20 ms to 6 s at once (more than the 4 s the wait used to be
/// capped at): the first late answer is within the 8 s of the initial RTO, and the wait
/// grows from there.
#[test]
fn test_consent_is_kept_when_the_round_trip_jumps_to_six_seconds() {
    let (mut a, mut peer, now) = connected(config(true));
    let trace = peer.run(&mut a, now, now + 300 * S, |_, _, _| Some(6 * S));
    assert!(!trace.saw(ConnectionState::Failed), "{:?}", trace.states);
    assert_eq!(trace.ignored, vec![]);
    assert!(now + 300 * S - selected_consent(&a) < 7 * S);
}

/// What the wait is: `Rm` (16) times the RTO (RFC 8489 Section 6.2.1: "If, after the last
/// request, a duration equal to Rm times the RTO has passed without a response [...], the
/// client SHOULD consider the transaction to have failed"), 8 s with the initial RTO of
/// 500 ms. A response that comes before that renews consent, whether or not the agent's timer
/// ran in between; one that comes at that instant or later is for a transaction that is no
/// longer in progress (RFC 8489 Section 6.3) and renews nothing.
#[test]
fn test_a_consent_request_waits_sixteen_times_the_rto_for_its_response() {
    for (after, renews, timer_runs) in [
        (7_999 * MS, true, false),
        (7_999 * MS, true, true),
        (8 * S, false, false),
        (8 * S, false, true),
    ] {
        let (mut a, mut peer, now) = connected(config(true));
        let before = selected_consent(&a);
        // Up to the first consent request, which the path holds.
        let mut sent = None;
        let mut at = now;
        while sent.is_none() {
            at = a.poll_timeout().unwrap().max(at + Duration::from_micros(1));
            let trace = peer.run(&mut a, at, at, |_, _, _| None);
            sent = trace.requests.first().map(|r| (r.0, r.1));
        }
        let (sent_at, id) = sent.unwrap();
        let arrival = sent_at + after;
        if timer_runs {
            // Up to the arrival; the consent requests that follow are lost.
            peer.run(&mut a, sent_at, arrival, |_, _, _| None);
        }
        let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
        let _ = deliver(&mut a, arrival, &response, REMOTE_A);
        let expected = if renews { arrival } else { before };
        assert_eq!(
            selected_consent(&a),
            expected,
            "a response {after:?} after its request (timer ran: {timer_runs})"
        );
    }
}

/// The limit of the RFC's wait, and libwebrtc's form. The round trip jumps from 20 ms to
/// 9 s: every answer comes after the 8 s its request waited (the RTO is still the initial
/// one, and an answer that is not taken teaches nothing), so no response renews consent and
/// it expires 30 s after the last one that did (RFC 7675 Section 5.1), with every open
/// transaction discarded. With a fixed wait of 60 s (`ConsentResponseWait::Fixed`,
/// libwebrtc's `kConnectionResponseTimeout`) the same answers are taken and the path stays.
#[test]
fn test_a_response_after_its_wait_renews_nothing_unless_the_wait_is_fixed() {
    let (mut a, mut peer, now) = connected(config(true));
    no_more_candidates(&mut a);
    let last = selected_consent(&a);
    let trace = peer.run(&mut a, now, now + 120 * S, |_, _, _| Some(9 * S));
    assert_eq!(trace.renewed, vec![], "an answer 9 s after its request");
    assert!(trace.ignored.len() >= 3);
    assert!(is_at(trace.lost, last + 30 * S), "{:?}", trace.states);
    assert!(trace.saw(ConnectionState::Failed), "{:?}", trace.states);
    assert!(a.pending_binding_requests.is_empty());

    let (mut a, mut peer, now) = connected(fixed(60 * S));
    let trace = peer.run(&mut a, now, now + 300 * S, |_, _, _| Some(9 * S));
    assert!(!trace.saw(ConnectionState::Failed), "{:?}", trace.states);
    assert_eq!(trace.ignored, vec![]);
    assert!(now + 300 * S - selected_consent(&a) < 7 * S);
}

/// Loss on top of the delay: two requests (or their answers) in three are lost and the third
/// is answered 800 ms later. Consent is renewed at least every 18 s: the agent never fails.
#[test]
fn test_consent_survives_loss_on_a_slow_path() {
    let (mut a, mut peer, now) = connected(config(true));
    let trace = peer.run(&mut a, now, now + 300 * S, |_, sent_before, _| {
        (sent_before % 3 == 2).then_some(800 * MS)
    });
    assert!(!trace.saw(ConnectionState::Failed), "{:?}", trace.states);
    assert_eq!(trace.ignored, vec![]);
    assert!(trace.renewed.len() >= 15);
    assert!(now + 300 * S - selected_consent(&a) < 19 * S);
    // A request that went 5 s without any answer was reported, and the answer that came
    // then took the report back.
    let states: Vec<ConnectionState> = trace.states.iter().map(|(_, s)| *s).collect();
    assert!(
        states
            .windows(2)
            .any(|w| w == [ConnectionState::Disconnected, ConnectionState::Connected]),
        "{states:?}"
    );
}

/// No transaction outlives the consent expiry. On a path with a round trip of 3 s the wait
/// would be 16 times an RTO of 3 s or more; it is 30 s. A response held for 31 s, while the
/// others keep the consent alive, renews nothing (its transaction is gone); with libwebrtc's
/// fixed 60 s it does. The open consent transactions stay few either way: the requests are
/// at least 4 s apart.
#[test]
fn test_no_consent_transaction_is_kept_past_the_consent_expiry() {
    for (cfg, held_renews, most) in [(config(true), false, 8), (fixed(60 * S), true, 15)] {
        let (mut a, mut peer, now) = connected(cfg);
        // Long enough for the RTO to follow the 3 s.
        peer.run(&mut a, now, now + 60 * S, |_, _, _| Some(3 * S));
        assert!(a.candidate_pairs[a.selected_pair.unwrap()].rto.rto() >= 2 * S);
        let trace = peer.run(&mut a, now + 60 * S, now + 160 * S, |_, sent_before, _| {
            Some(if sent_before == 2 { 31 * S } else { 3 * S })
        });
        assert!(!trace.saw(ConnectionState::Failed), "{:?}", trace.states);
        let held = trace.requests[2].1;
        assert_eq!(
            trace.renewed.iter().any(|(_, id)| *id == held),
            held_renews,
            "a response 31 s after its request"
        );
        assert_eq!(
            trace.ignored.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
            if held_renews { vec![] } else { vec![held] }
        );
        assert!(
            trace.most_open_consent_transactions <= most,
            "{} open consent transactions",
            trace.most_open_consent_transactions
        );
    }
}

/// A peer that stops answering: the agent is `Disconnected` when a consent request has gone
/// 5 s without any response, loses consent (its media path) 30 s after the last response and
/// is `Failed` then or as the PAC timer expires (W3C webrtc-pc 5.6.4), and then holds no
/// transaction (RFC 7675 Section 5.1: "All outstanding STUN consent transactions for a
/// candidate pair MUST be discarded when consent expires"). Until then the open consent
/// transactions are few: the requests are 4 to 6 s apart and each waits 8 s (the initial
/// RTO), or, once the path has shown a round trip of 3 s, the 30 s of the consent expiry, as
/// with a fixed wait of 60 s: eight at most.
#[test]
fn test_unanswered_consent_transactions_are_bounded_and_end_with_the_consent() {
    for (cfg, warm_up, open) in [
        (config(true), None, 2..=3),
        (config(true), Some(3 * S), 5..=8),
        (fixed(60 * S), None, 4..=8),
    ] {
        let (mut a, mut peer, mut now) = connected(cfg);
        no_more_candidates(&mut a);
        if let Some(round_trip) = warm_up {
            peer.run(&mut a, now, now + 60 * S, |_, _, _| Some(round_trip));
            now += 60 * S;
        }
        let before = selected_consent(&a);
        let trace = peer.run(&mut a, now, now + 70 * S, |_, _, _| None);
        // (The answers still on their way when the peer stopped arrive first.)
        let last = trace.renewed.last().map_or(before, |(at, _)| *at);
        assert!(
            is_at(trace.lost, last + 30 * S),
            "{:?} after the last response",
            trace.lost.map(|at| at - last)
        );
        assert!(trace.saw(ConnectionState::Failed), "{:?}", trace.states);
        if warm_up.is_none() {
            let first_unanswered = trace.requests[0].0;
            assert!(
                is_at(
                    trace.at(ConnectionState::Disconnected),
                    first_unanswered + 5 * S
                ),
                "{:?}",
                trace.states
            );
        }
        assert!(
            open.contains(&trace.most_open_consent_transactions),
            "{} open consent transactions, expected {open:?}",
            trace.most_open_consent_transactions
        );
        assert!(a.pending_binding_requests.is_empty());
    }
}

/// Responses that overtake each other: every other request is answered after 7 s, the
/// others after 200 ms, so the answer to a request arrives after the answer to the next one.
/// Each renews consent when it arrives (RFC 7675 Section 5.1: "a response might be for a
/// previous request (rather than for the most recently sent request)").
#[test]
fn test_responses_out_of_order_each_renew_consent() {
    let (mut a, mut peer, now) = connected(config(true));
    let trace = peer.run(&mut a, now, now + 120 * S, |_, sent_before, _| {
        Some(if sent_before % 2 == 0 {
            7 * S
        } else {
            200 * MS
        })
    });
    assert!(!trace.saw(ConnectionState::Failed), "{:?}", trace.states);
    assert_eq!(trace.ignored, vec![]);
    let overtaken = trace
        .renewed
        .windows(2)
        .filter(|w| trace.sent_at(w[1].1) < trace.sent_at(w[0].1))
        .count();
    assert!(
        overtaken >= 5,
        "{overtaken} answers arrived after a later one"
    );
    assert_eq!(selected_consent(&a), trace.renewed.last().unwrap().0);
}

/// Consent exists to stop sending to a peer that does not want the traffic, so only a
/// response that matches a request the agent sent, signed by the peer, renews it, however
/// long transactions wait: not a signed response to a transaction the agent never sent, not
/// a response to an open transaction with a wrong signature (which leaves the transaction
/// open for the genuine one), and not a second copy of a response already taken.
#[test]
fn test_only_a_matching_authenticated_response_renews_consent() {
    for cfg in [config(true), fixed(60 * S)] {
        let (mut a, mut peer, now) = connected(cfg);
        let before = selected_consent(&a);
        let mut sent = None;
        let mut at = now;
        while sent.is_none() {
            at = a.poll_timeout().unwrap().max(at + Duration::from_micros(1));
            let trace = peer.run(&mut a, at, at, |_, _, _| None);
            sent = trace.requests.first().map(|r| (r.0, r.1));
        }
        let (sent_at, id) = sent.unwrap();

        // Signed by the peer, for a transaction that was never sent.
        let unsolicited = peer_response(BINDING_SUCCESS, TransactionId::new(), addr(LOCAL), None);
        let _ = deliver(&mut a, sent_at + 100 * MS, &unsolicited, REMOTE_A);
        assert_eq!(selected_consent(&a), before, "an unsolicited response");

        // The open transaction, signed with another password.
        let mut forged = Message::new();
        forged
            .build(&[
                Box::new(BINDING_SUCCESS),
                Box::new(id),
                Box::new(XorMappedAddress {
                    ip: addr(LOCAL).ip(),
                    port: addr(LOCAL).port(),
                }),
                Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                    "notthepeerspassword".to_owned(),
                    provider().crypto(),
                )),
                Box::new(FINGERPRINT),
            ])
            .unwrap();
        let _ = deliver(&mut a, sent_at + 200 * MS, &forged, REMOTE_A);
        assert_eq!(selected_consent(&a), before, "a forged response");

        // The genuine response, late; and the same datagram once more.
        let genuine = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
        deliver(&mut a, sent_at + 900 * MS, &genuine, REMOTE_A).unwrap();
        assert_eq!(selected_consent(&a), sent_at + 900 * MS);
        let _ = deliver(&mut a, sent_at + 1500 * MS, &genuine, REMOTE_A);
        assert_eq!(
            selected_consent(&a),
            sent_at + 900 * MS,
            "a replayed response"
        );

        // The same response from another address than the request went to renews nothing.
        let mut next = None;
        at = sent_at + 1500 * MS;
        while next.is_none() {
            at = a.poll_timeout().unwrap().max(at + Duration::from_micros(1));
            let trace = peer.run(&mut a, at, at, |_, _, _| None);
            next = trace.requests.first().map(|r| (r.0, r.1));
        }
        let (next_at, next_id) = next.unwrap();
        let elsewhere = peer_response(BINDING_SUCCESS, next_id, addr(LOCAL), None);
        let _ = deliver(&mut a, next_at + 100 * MS, &elsewhere, REMOTE_B);
        assert_eq!(
            selected_consent(&a),
            sent_at + 900 * MS,
            "from another address"
        );
    }
}

/// The selected pair's consent is its own. A check on another pair that is answered late
/// (its transaction was cancelled at the nomination and waits out its time, RFC 8445 Section
/// 7.3.1.4) makes that pair valid and says nothing about the selected one, whose peer
/// address has stopped answering: consent is lost (no media path) 30 s after the selected
/// pair's last response, and the agent fails (then, or as the PAC timer expires).
#[test]
fn test_a_late_response_on_another_pair_does_not_renew_the_selected_pairs_consent() {
    let start = Instant::now();
    let mut a = bare_agent(start, config(true));
    // The other pair has the higher priority and a foundation of its own: it is checked
    // first, and is still unanswered when the selected one is nominated.
    for (remote, priority, foundation) in [(REMOTE_B, 500, "other"), (REMOTE_A, 400, "selected")] {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: addr(remote).ip().to_string(),
                port: addr(remote).port(),
                component: 1,
                priority,
                foundation: foundation.to_owned(),
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap();
        a.add_remote_candidate(candidate).unwrap();
    }
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    no_more_candidates(&mut a);
    let mut peer = SlowPeer::default();
    let trace = peer.run(&mut a, start, start + 120 * S, |at, _, to| {
        if to == addr(REMOTE_B) {
            // Its only check is answered after 10 s.
            Some(10 * S)
        } else if at < start + 3 * S {
            Some(20 * MS)
        } else {
            None
        }
    });
    let renewed_by = |remote: &str| -> Vec<Instant> {
        trace
            .renewed
            .iter()
            .filter(|(_, id)| {
                trace
                    .requests
                    .iter()
                    .any(|r| r.1 == *id && r.2 == addr(remote))
            })
            .map(|(at, _)| *at)
            .collect()
    };
    let selected_last = renewed_by(REMOTE_A).into_iter().max().unwrap();
    let other = renewed_by(REMOTE_B);
    assert_eq!(other.len(), 1, "the other pair's late response was taken");
    assert!(other[0] > selected_last);
    assert!(
        is_at(trace.lost, selected_last + 30 * S),
        "{:?}",
        trace.states
    );
    assert!(trace.saw(ConnectionState::Failed), "{:?}", trace.states);
}

/// Consent is per 5-tuple (RFC 7675 Section 1: "Consent to send applies to a single
/// 5-tuple"; Section 5.1: without a valid response "from the remote peer's transport
/// address in 30 seconds, the endpoint MUST cease transmission on that 5-tuple"). Two local
/// candidates with bases of their own, one remote candidate: (L1, R) is selected while the
/// check on (L2, R) is still open. From then on nothing sent from L1 is answered, and the
/// open (L2, R) check is answered 10 s later, from the same remote address. That response
/// is taken (it validates (L2, R)) but says nothing of the 5-tuple (L1, R): consent is lost
/// 30 s after the last response on (L1, R), and the agent fails.
#[test]
fn test_a_late_response_on_another_pair_to_the_same_remote_does_not_renew_consent() {
    const LOCAL_2: &str = "192.168.0.5:1001";
    let start = Instant::now();
    let mut a = Agent::new(start, Arc::new(config(true)), provider()).unwrap();
    a.add_local_candidate(host_with_priority(addr(LOCAL), 500))
        .unwrap();
    a.add_local_candidate(host_with_priority(addr(LOCAL_2), 400))
        .unwrap();
    a.add_remote_candidate(host(addr(REMOTE_A))).unwrap();
    a.start_connectivity_checks(start, true, REMOTE_UFRAG.to_owned(), REMOTE_PWD.to_owned())
        .unwrap();
    no_more_candidates(&mut a);

    let to_agent = |a: &mut Agent, now: Instant, m: &Message, local: &str| {
        a.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: addr(local),
                peer_addr: addr(REMOTE_A),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&m.raw[..]),
        })
    };

    // Responses on their way: arrival, the response, the local address it arrives at.
    let mut in_flight: Vec<(Instant, Message, &str)> = vec![];
    let mut seen = std::collections::HashSet::new();
    let mut open_on_l2: Option<TransactionId> = None;
    let mut selected_at: Option<Instant> = None;
    let mut last_on_l1: Option<Instant> = None;
    let mut l2_answered_at: Option<Instant> = None;
    let mut l2_taken = false;
    let mut selected_local: Option<SocketAddr> = None;
    let mut failed_at: Option<Instant> = None;
    // When the media path went away (consent expired): `Failed` then, or as the PAC timer
    // expires when that is later (W3C webrtc-pc 5.6.4).
    let mut lost_at: Option<Instant> = None;
    let mut now = start;
    let until = start + 120 * S;
    while now <= until && failed_at.is_none() {
        in_flight.sort_by_key(|(at, _, _)| *at);
        while in_flight.first().is_some_and(|(at, _, _)| *at <= now) {
            let (_, response, local) = in_flight.remove(0);
            let _ = to_agent(&mut a, now, &response, local);
            if local == LOCAL {
                last_on_l1 = Some(now);
            } else {
                l2_answered_at = Some(now);
                // The response was matched and taken: consent from the remote candidate,
                // on the other 5-tuple.
                let remote = a.find_remote_candidate(addr(REMOTE_A)).unwrap();
                l2_taken = a.remote_candidates[remote].last_consent() == Some(now);
            }
        }
        let had_path = a.media_path().is_some();
        a.handle_timeout(now).unwrap();
        if had_path && a.media_path().is_none() {
            lost_at.get_or_insert(now);
        }
        while let Some(t) = a.poll_write() {
            let mut m = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            m.decode().unwrap();
            if m.typ != BINDING_REQUEST || !seen.insert(m.transaction_id) {
                continue;
            }
            let response = peer_response(BINDING_SUCCESS, m.transaction_id, addr(LOCAL), None);
            if t.transport.local_addr == addr(LOCAL_2) {
                // The first check on (L2, R) is answered 10 s after the selection; nothing
                // else sent from L2 is.
                if open_on_l2.is_none() {
                    open_on_l2 = Some(m.transaction_id);
                }
            } else if selected_at.is_none() {
                // Until the selection (L1, R) answers after 100 ms, so that the check on
                // (L2, R) is sent and open when (L1, R) is nominated.
                in_flight.push((now + 100 * MS, response, LOCAL));
            }
        }
        while let Some(e) = a.poll_event() {
            match e.event {
                Event::ConnectionStateChange(ConnectionState::Connected)
                    if selected_at.is_none() =>
                {
                    selected_at = Some(e.now);
                    selected_local = a.get_selected_candidate_pair().map(|(l, _)| l.addr());
                }
                Event::ConnectionStateChange(ConnectionState::Failed) => failed_at = Some(e.now),
                _ => {}
            }
        }
        if let (Some(selected), Some(id), None) = (selected_at, open_on_l2, l2_answered_at)
            && !in_flight.iter().any(|(_, m, _)| m.transaction_id == id)
        {
            // The L2 check, answered from the remote's address 10 s after the selection.
            let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL_2), None);
            in_flight.push((selected + 10 * S, response, LOCAL_2));
        }
        let arrival = in_flight.iter().map(|(at, _, _)| *at).min();
        let next = match (a.poll_timeout(), arrival) {
            (Some(timer), Some(arrival)) => Some(timer.min(arrival)),
            (timer, arrival) => timer.or(arrival),
        };
        match next {
            Some(next) => now = next.max(now + Duration::from_micros(1)),
            None => break,
        }
    }

    let selected_at = selected_at.expect("(L1, R) was selected");
    assert_eq!(
        selected_local,
        Some(addr(LOCAL)),
        "the selected pair is (L1, R)"
    );
    let last_on_l1 = last_on_l1.unwrap();
    assert!(last_on_l1 + S >= selected_at && last_on_l1 <= selected_at + S);
    let l2_answered_at = l2_answered_at.expect("the open check on (L2, R) was answered");
    assert!(l2_answered_at > last_on_l1 + 5 * S);
    assert!(l2_taken, "the late response on (L2, R) was matched");
    assert!(failed_at.is_some(), "the agent fails");
    assert!(
        is_at(lost_at, last_on_l1 + 30 * S),
        "consent lost at {:?}, last response on (L1, R) at {:?}, on (L2, R) at {:?}",
        lost_at.map(|t| t - start),
        last_on_l1 - start,
        l2_answered_at - start,
    );
}

/// The pair ICE selects is not the pair that was checked, and the only consent response is
/// on the checked one. A controlled agent: 10 s after the start the peer nominates (L, R)
/// with a request carrying USE-CANDIDATE; the agent's triggered check on (L, R) is answered
/// with an XOR-MAPPED-ADDRESS that is not a local candidate, so the valid pair has a
/// peer-reflexive local candidate on L's base (RFC 8445 Section 7.2.5.3.1) and the
/// nomination is accepted on that valid pair (Section 7.2.5.3.4). The response was to a
/// request sent on the checked pair; it is the selected pair's consent because the two are
/// one 5-tuple (RFC 7675 Section 1). Nothing after it is answered: the agent fails 30 s
/// after that response, not 30 s after the start (which is what reading the selected pair's
/// own responses alone gives).
#[test]
fn test_the_response_that_validated_another_pair_is_the_selected_pairs_consent() {
    const MAPPED: &str = "203.0.113.7:4000";
    let start = Instant::now();
    let mut a = started_agent(start, config(false), &[REMOTE_A]);
    no_more_candidates(&mut a);

    let nominate_at = start + 10 * S;
    let mut nominated = false;
    let mut seen = std::collections::HashSet::new();
    let mut answered_at: Option<Instant> = None;
    let mut answers = 0;
    let mut selected: Option<(CandidateType, SocketAddr)> = None;
    let mut checked_consent_only = false;
    let mut failed_at: Option<Instant> = None;
    let mut now = start;
    while now <= start + 120 * S && failed_at.is_none() {
        if !nominated && now >= nominate_at {
            nominated = true;
            let request = peer_request(
                &a,
                vec![
                    Box::new(AttrControlling(1)),
                    Box::new(PriorityAttr(1000)),
                    Box::new(crate::attributes::use_candidate::UseCandidateAttr::new()),
                ],
            );
            deliver(&mut a, now, &request, REMOTE_A).unwrap();
        }
        a.handle_timeout(now).unwrap();
        while let Some(t) = a.poll_write() {
            let mut m = Message {
                raw: t.message.to_vec(),
                ..Message::default()
            };
            m.decode().unwrap();
            if m.typ != BINDING_REQUEST || !seen.insert(m.transaction_id) {
                continue;
            }
            // Only the check the nomination triggers is answered, at once.
            if nominated && selected.is_none() && answered_at.is_none() {
                let response = peer_response(BINDING_SUCCESS, m.transaction_id, addr(MAPPED), None);
                deliver(&mut a, now, &response, REMOTE_A).unwrap();
                answered_at = Some(now);
                answers += 1;
            }
        }
        while let Some(e) = a.poll_event() {
            match e.event {
                Event::ConnectionStateChange(ConnectionState::Connected) if selected.is_none() => {
                    let pair = a.selected_pair.expect("a selected pair");
                    selected = a
                        .get_selected_candidate_pair()
                        .map(|(l, _)| (l.candidate_type(), l.addr()));
                    // The consent is on the checked pair, not on the selected one.
                    checked_consent_only = a.candidate_pairs[pair].last_consent.is_none()
                        && a.candidate_pairs
                            .iter()
                            .any(|p| p.last_consent == answered_at);
                }
                Event::ConnectionStateChange(ConnectionState::Failed) => failed_at = Some(e.now),
                _ => {}
            }
        }
        let next = a.poll_timeout();
        let next = if nominated {
            next
        } else {
            Some(next.map_or(nominate_at, |n| n.min(nominate_at)))
        };
        match next {
            Some(next) => now = next.max(now + Duration::from_micros(1)),
            None => break,
        }
    }

    let answered_at = answered_at.expect("the triggered check was answered");
    assert_eq!(answers, 1);
    assert!(answered_at >= nominate_at);
    assert_eq!(
        selected,
        Some((CandidateType::PeerReflexive, addr(MAPPED))),
        "the selected pair is the valid pair, not the checked one"
    );
    assert!(
        checked_consent_only,
        "the only response is recorded on the checked pair"
    );
    assert!(
        is_at(failed_at, answered_at + 30 * S),
        "failed at {:?}, the one response at {:?}",
        failed_at.map(|t| t - start),
        answered_at - start,
    );
}

/// An ICE restart with a consent request on its way (RFC 7675 Section 5.1: "an endpoint that
/// continues to send traffic on the previously validated candidate pair during ICE restart
/// MUST continue to perform consent freshness on that candidate pair"): the request stays
/// open on the path the restart keeps, and its answer, which arrives after the restart,
/// renews the consent of that path.
#[test]
fn test_a_consent_request_open_at_an_ice_restart_is_still_answered() {
    let (mut a, mut peer, now) = connected(config(true));
    let mut sent = None;
    let mut at = now;
    while sent.is_none() {
        at = a.poll_timeout().unwrap().max(at + Duration::from_micros(1));
        let trace = peer.run(&mut a, at, at, |_, _, _| None);
        sent = trace.requests.first().map(|r| (r.0, r.1));
    }
    let (sent_at, id) = sent.unwrap();
    let path = a.media_path().unwrap();
    a.restart(sent_at + 100 * MS, String::new(), String::new(), true)
        .unwrap();
    assert_eq!(a.media_path(), Some(path));
    let before = a.previous_generation.as_ref().unwrap().last_consent;

    let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
    let _ = deliver(&mut a, sent_at + 800 * MS, &response, REMOTE_A);
    let previous = a.previous_generation.as_ref().unwrap();
    assert_ne!(previous.last_consent, before);
    assert_eq!(previous.last_consent, sent_at + 800 * MS);
    // And once only.
    let _ = deliver(&mut a, sent_at + 900 * MS, &response, REMOTE_A);
    let previous = a.previous_generation.as_ref().unwrap();
    assert_eq!(previous.last_consent, sent_at + 800 * MS);
}

/// The path an ICE restart keeps, when it is slow: its consent requests (the old
/// generation's) are answered 800 ms or 6 s later, and the path stays for as long as the
/// restart has no pair of its own.
#[test]
fn test_the_path_kept_across_a_restart_keeps_consent_when_it_is_slow() {
    for round_trip in [800 * MS, 6 * S] {
        let (mut a, mut peer, now) = connected(config(true));
        let path = a.media_path().unwrap();
        a.restart(now, String::new(), String::new(), true).unwrap();
        let trace = peer.run(&mut a, now, now + 120 * S, |_, _, _| Some(round_trip));
        assert_eq!(a.media_path(), Some(path), "{round_trip:?}");
        assert!(trace.requests.len() >= 15, "{}", trace.requests.len());
        let previous = a.previous_generation.as_ref().unwrap();
        assert!(now + 120 * S - previous.last_consent < 7 * S + round_trip);
        assert!(previous.pending.len() <= 3, "{}", previous.pending.len());
    }
}

/// On the path kept across a restart too, the wait follows the round trip the answers show: a
/// round trip that grows gradually to 12 s, past the 8 s of the initial RTO, keeps the path.
#[test]
fn test_the_wait_on_the_path_kept_across_a_restart_grows_with_the_round_trip() {
    let (mut a, mut peer, now) = connected(config(true));
    let path = a.media_path().unwrap();
    a.restart(now, String::new(), String::new(), true).unwrap();
    let mut round_trip = 20 * MS;
    peer.run(&mut a, now, now + 600 * S, |_, _, _| {
        round_trip = (round_trip * 5 / 4).min(12 * S);
        Some(round_trip)
    });
    assert_eq!(round_trip, 12 * S);
    assert_eq!(a.media_path(), Some(path));
    let previous = a.previous_generation.as_ref().unwrap();
    assert!(now + 600 * S - previous.last_consent < 7 * S);
}

/// The wait of a consent request on the path kept across a restart is the same `Rm` times
/// the RTO: an answer 8 s after its request, at the initial RTO, renews nothing, and one a
/// millisecond sooner does.
#[test]
fn test_a_previous_generation_consent_request_waits_sixteen_times_the_rto() {
    for (after, renews) in [(7_999 * MS, true), (8 * S, false)] {
        let (mut a, mut peer, now) = connected(config(true));
        a.restart(now, String::new(), String::new(), true).unwrap();
        let mut sent = None;
        let mut at = now;
        while sent.is_none() {
            at = a.poll_timeout().unwrap().max(at + Duration::from_micros(1));
            let trace = peer.run(&mut a, at, at, |_, _, _| None);
            sent = trace.requests.first().map(|r| (r.0, r.1));
        }
        let (sent_at, id) = sent.unwrap();
        let before = a.previous_generation.as_ref().unwrap().last_consent;
        let response = peer_response(BINDING_SUCCESS, id, addr(LOCAL), None);
        let _ = deliver(&mut a, sent_at + after, &response, REMOTE_A);
        let previous = a.previous_generation.as_ref().unwrap();
        assert_eq!(
            previous.last_consent,
            if renews { sent_at + after } else { before },
            "a response {after:?} after its request"
        );
    }
}
