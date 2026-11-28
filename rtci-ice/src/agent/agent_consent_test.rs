//! Consent freshness (RFC 7675 §5.1): only responses to our own checks grant consent.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio::Protocol;
use stun::attributes::ATTR_USERNAME;

use super::*;
use crate::attributes::control::AttrControlling;
use crate::attributes::priority::PriorityAttr;
use crate::candidate::candidate_host::CandidateHostConfig;

fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

const LOCAL: &str = "192.168.0.2:1000";
const REMOTE: &str = "192.168.0.3:2000";

fn host(addr: SocketAddr) -> Candidate {
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

/// A controlled agent whose one pair is selected at `base`.
fn connected_agent(base: Instant) -> Agent {
    let mut a = Agent::new(base, Arc::new(AgentConfig::default()), provider()).unwrap();
    a.add_local_candidate(host(LOCAL.parse().unwrap())).unwrap();
    a.add_remote_candidate(host(REMOTE.parse().unwrap()))
        .unwrap();
    a.set_remote_credentials("remoteufrag".to_owned(), "remotepwd".to_owned())
        .unwrap();
    assert_eq!(a.candidate_pairs.len(), 1);
    a.set_selected_pair(Some(base), Some(0));
    a
}

/// An authenticated Binding request from the peer.
fn peer_request(a: &Agent) -> Message {
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":remoteufrag";
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(1)),
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    msg
}

/// The peer's authenticated success response to our request `id`.
fn peer_response(id: TransactionId) -> Message {
    let local: SocketAddr = LOCAL.parse().unwrap();
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(id),
        Box::new(XorMappedAddress {
            ip: local.ip(),
            port: local.port(),
        }),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            "remotepwd".to_owned(),
            provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])
    .unwrap();
    msg
}

/// Transaction ids of the Binding requests the agent queued.
fn sent_requests(a: &mut Agent) -> Vec<TransactionId> {
    let mut ids = vec![];
    while let Some(out) = a.poll_write() {
        let mut m = Message {
            raw: out.message.to_vec(),
            ..Message::default()
        };
        if m.decode().is_ok() && m.typ == BINDING_REQUEST {
            ids.push(m.transaction_id);
        }
    }
    ids
}

#[test]
fn test_peer_requests_alone_do_not_keep_consent() {
    let base = Instant::now();
    let mut a = connected_agent(base);
    let remote: SocketAddr = REMOTE.parse().unwrap();
    for secs in 1..60 {
        let now = base + Duration::from_secs(secs);
        let mut req = peer_request(&a);
        let _ = a.handle_inbound(now, &mut req, 0, remote);
        let _ = sent_requests(&mut a); // our checks go unanswered
        a.validate_selected_pair(now);
        if a.get_selected_candidate_pair().is_none() {
            break;
        }
    }
    // Consent expired: the pair is no longer used (`Failed`, or `Disconnected` while the end
    // of the candidates or the PAC timer is awaited, W3C webrtc-pc 5.6.4).
    assert!(
        a.get_selected_candidate_pair().is_none() && a.media_path().is_none(),
        "the peer's own requests kept consent alive"
    );
    assert_ne!(a.connection_state, ConnectionState::Connected);
}

#[test]
fn test_responses_to_our_checks_keep_consent() {
    let base = Instant::now();
    let mut a = connected_agent(base);
    let remote: SocketAddr = REMOTE.parse().unwrap();
    for secs in 1..60 {
        let now = base + Duration::from_secs(secs);
        a.check_keepalive(now);
        for id in sent_requests(&mut a) {
            let mut resp = peer_response(id);
            a.handle_inbound(now, &mut resp, 0, remote).unwrap();
        }
        a.validate_selected_pair(now);
        assert_eq!(a.connection_state, ConnectionState::Connected, "at {secs}s");
    }
    assert!(a.remote_candidates[0].last_consent().is_some());
}

#[test]
fn test_unsolicited_response_does_not_grant_consent() {
    let base = Instant::now();
    let mut a = connected_agent(base);
    let remote: SocketAddr = REMOTE.parse().unwrap();
    let mut resp = peer_response(TransactionId::new());
    let _ = a.handle_inbound(base + Duration::from_secs(1), &mut resp, 0, remote);
    assert!(a.remote_candidates[0].last_consent().is_none());
}
