//! Entry points for stateful fuzz targets.
//!
//! [`agent_handle_inbound`] connects a target agent to an honest in-memory peer agent and lets
//! the fuzzer interleave its own traffic: raw datagrams, binding requests and responses that
//! carry valid credentials and MESSAGE-INTEGRITY (so they get past authentication), clock steps,
//! network partitions and ICE restarts. The agent is reachable in the Checking, Connected,
//! Disconnected and Failed states, and through a Failed → restart sequence, the path of
//! [upstream #88](https://github.com/webrtc-rs/rtc/issues/88).
//!
//! Randomness comes from seeded providers and the clock is `start` plus offsets the input
//! chooses. STUN transaction ids are still drawn by `rand` inside `rtc-stun`; the harness only
//! ever refers to the agent's requests by position, so behaviour does not depend on their value.
//! Gated behind `cfg(fuzzing)`; not part of the supported API.
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use stun::attributes::ATTR_USERNAME;
use stun::error_code::{CODE_ROLE_CONFLICT, ErrorCodeAttribute};
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{
    BINDING_ERROR, BINDING_REQUEST, BINDING_SUCCESS, CLASS_REQUEST, METHOD_BINDING, Message,
    Setter, TransactionId, is_stun_message,
};
use stun::textattrs::Username;
use stun::xoraddr::XorMappedAddress;

use crate::agent::Agent;
use crate::agent::agent_config::AgentConfig;
use crate::attributes::control::{AttrControlled, AttrControlling};
use crate::attributes::priority::PriorityAttr;
use crate::attributes::use_candidate::UseCandidateAttr;
use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::{CandidateConfig, unmarshal_candidate};
use crate::mdns::MulticastDnsMode;
use crate::state::ConnectionState;

/// How many of the target's outgoing binding requests the harness remembers.
const REQUESTS: usize = 16;

fn target_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 5000))
}

fn peer_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 6000))
}

fn host_candidate(addr: SocketAddr) -> Option<crate::candidate::Candidate> {
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
    .ok()
}

fn new_agent(
    start: Instant,
    name: &str,
    seed: u64,
    controlling: bool,
    timeouts: u8,
) -> Option<Agent> {
    let provider = crypto::fuzzing::deterministic_provider(seed, false).ok()?;
    let config = AgentConfig {
        local_ufrag: format!("{name}ufrag"),
        local_pwd: format!("{name}-password-for-fuzzing"),
        multicast_dns_mode: MulticastDnsMode::Disabled,
        multicast_dns_local_name: format!("{name}.local"),
        disconnected_timeout: Some(Duration::from_millis(
            500 * u64::from(timeouts & 0x0f) + 500,
        )),
        failed_timeout: Some(Duration::from_millis(500 * u64::from(timeouts >> 4) + 500)),
        keepalive_interval: Some(Duration::from_millis(300)),
        check_interval: Duration::from_millis(100),
        is_controlling: controlling,
        ..Default::default()
    };
    Agent::new(start, Arc::new(config), provider).ok()
}

struct Harness {
    target: Agent,
    peer: Agent,
    now: Instant,
    /// Datagrams in flight to the target and to the peer.
    to_target: VecDeque<TaggedBytesMut>,
    to_peer: VecDeque<TaggedBytesMut>,
    /// The target's recent binding requests: transaction id and the address it went to.
    requests: VecDeque<(TransactionId, SocketAddr)>,
    /// While set, nothing in flight is delivered, so the agents time out.
    partitioned: bool,
}

/// The same datagram as seen by its receiver.
fn reverse(msg: TaggedBytesMut, now: Instant) -> TaggedBytesMut {
    TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: msg.transport.peer_addr,
            peer_addr: msg.transport.local_addr,
            ecn: msg.transport.ecn,
            transport_protocol: msg.transport.transport_protocol,
        },
        message: msg.message,
    }
}

impl Harness {
    fn drain(&mut self) {
        while let Some(msg) = self.target.poll_write() {
            if is_stun_message(&msg.message) {
                let mut m = Message {
                    raw: msg.message.to_vec(),
                    ..Message::default()
                };
                if m.decode().is_ok()
                    && m.typ.method == METHOD_BINDING
                    && m.typ.class == CLASS_REQUEST
                {
                    if self.requests.len() == REQUESTS {
                        self.requests.pop_front();
                    }
                    self.requests
                        .push_back((m.transaction_id, msg.transport.peer_addr));
                }
            }
            self.to_peer.push_back(msg);
        }
        while self.target.poll_event().is_some() {}
        while let Some(msg) = self.peer.poll_write() {
            self.to_target.push_back(msg);
        }
        while self.peer.poll_event().is_some() {}
    }

    fn send_to_target(&mut self, from: SocketAddr, message: BytesMut) {
        let _ = self.target.handle_read(TaggedBytesMut {
            now: self.now,
            transport: TransportContext {
                local_addr: target_addr(),
                peer_addr: from,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message,
        });
        self.drain();
    }

    fn pump_once(&mut self) {
        self.drain();
        let to_target = std::mem::take(&mut self.to_target);
        let to_peer = std::mem::take(&mut self.to_peer);
        if self.partitioned {
            return;
        }
        for msg in to_target {
            let _ = self.target.handle_read(reverse(msg, self.now));
        }
        for msg in to_peer {
            let _ = self.peer.handle_read(reverse(msg, self.now));
        }
        self.drain();
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        let _ = self.target.handle_timeout(self.now);
        let _ = self.peer.handle_timeout(self.now);
        let _ = self.target.poll_timeout();
        let _ = self.peer.poll_timeout();
        self.drain();
    }

    /// Signals both agents' credentials and candidates to each other and starts their checks.
    fn signal(&mut self, target_controlling: bool) {
        let target = self.target.get_local_credentials().clone();
        let peer = self.peer.get_local_credentials().clone();
        if let Some(c) = host_candidate(peer_addr()) {
            let _ = self.target.add_remote_candidate(c);
        }
        if let Some(c) = host_candidate(target_addr()) {
            let _ = self.peer.add_remote_candidate(c);
        }
        let _ = self.target.start_connectivity_checks(
            self.now,
            target_controlling,
            peer.ufrag,
            peer.pwd,
        );
        let _ = self.peer.start_connectivity_checks(
            self.now,
            !target_controlling,
            target.ufrag,
            target.pwd,
        );
        self.drain();
    }

    fn build(setters: &[Box<dyn Setter + '_>]) -> Option<BytesMut> {
        let mut m = Message::new();
        m.build(setters).ok()?;
        Some(BytesMut::from(&m.raw[..]))
    }

    /// A binding request to the target with valid credentials and fuzzer-chosen attributes.
    fn binding_request(&mut self, arg: &[u8]) {
        let flags = byte(arg, 0);
        let tie_breaker = u64::from_be_bytes(bytes8(arg, 1));
        let priority =
            u32::from_be_bytes([byte(arg, 9), byte(arg, 10), byte(arg, 11), byte(arg, 12)]);
        let from = fuzzed_source(flags, byte(arg, 13), byte(arg, 14));

        let local = self.target.get_local_credentials().clone();
        let remote_ufrag = self
            .target
            .get_remote_credentials()
            .map(|c| c.ufrag.clone())
            .unwrap_or_default();
        let username = if flags & 0x40 != 0 {
            String::from_utf8_lossy(arg.get(15..).unwrap_or(&[])).into_owned()
        } else {
            format!("{}:{}", local.ufrag, remote_ufrag)
        };
        let provider = self.target.crypto_provider.clone();
        let integrity =
            MessageIntegrity::new_short_term_integrity_with_provider(local.pwd, provider.crypto());

        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId([byte(arg, 1); 12])),
            Box::new(Username::new(ATTR_USERNAME, username)),
        ];
        match flags & 0x03 {
            0 => setters.push(Box::new(AttrControlling(tie_breaker))),
            1 => setters.push(Box::new(AttrControlled(tie_breaker))),
            2 => {
                setters.push(Box::new(AttrControlling(tie_breaker)));
                setters.push(Box::new(AttrControlled(tie_breaker)));
            }
            _ => {}
        }
        if flags & 0x04 != 0 {
            setters.push(Box::new(UseCandidateAttr));
        }
        if flags & 0x08 != 0 {
            setters.push(Box::new(PriorityAttr(priority)));
        }
        setters.push(Box::new(integrity));
        setters.push(Box::new(FINGERPRINT));
        if let Some(raw) = Self::build(&setters) {
            self.send_to_target(from, raw);
        }
    }

    /// A response to one of the target's own requests, signed with the password the target
    /// expects, with a fuzzer-chosen mapped address, class and source.
    fn binding_response(&mut self, arg: &[u8]) {
        if self.requests.is_empty() {
            return;
        }
        let flags = byte(arg, 0);
        let (transaction_id, to) = self.requests[usize::from(byte(arg, 1)) % self.requests.len()];
        let mapped = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                byte(arg, 2),
                byte(arg, 3),
                byte(arg, 4),
                byte(arg, 5),
            )),
            u16::from_be_bytes([byte(arg, 6), byte(arg, 7)]),
        );
        let from = if flags & 0x10 != 0 {
            fuzzed_source(flags, byte(arg, 8), byte(arg, 9))
        } else {
            to
        };
        let pwd = self
            .target
            .get_remote_credentials()
            .map(|c| c.pwd.clone())
            .unwrap_or_default();
        let provider = self.target.crypto_provider.clone();
        let integrity =
            MessageIntegrity::new_short_term_integrity_with_provider(pwd, provider.crypto());
        let mut setters: Vec<Box<dyn Setter>> = vec![Box::new(transaction_id)];
        if flags & 0x01 != 0 {
            setters.push(Box::new(BINDING_ERROR));
            setters.push(Box::new(ErrorCodeAttribute {
                code: CODE_ROLE_CONFLICT,
                reason: b"Role Conflict".to_vec(),
            }));
        } else {
            setters.push(Box::new(BINDING_SUCCESS));
            setters.push(Box::new(XorMappedAddress {
                ip: mapped.ip(),
                port: mapped.port(),
            }));
        }
        if flags & 0x02 == 0 {
            setters.push(Box::new(integrity));
        }
        setters.push(Box::new(FINGERPRINT));
        if let Some(raw) = Self::build(&setters) {
            self.send_to_target(from, raw);
        }
    }

    /// The Failed → restart sequence: both sides (or only the target) restart, re-signal and
    /// start checking again.
    fn restart(&mut self, arg: &[u8]) {
        let flags = byte(arg, 0);
        let keep_local = flags & 0x01 != 0;
        let _ = self
            .target
            .restart(self.now, String::new(), String::new(), keep_local);
        if flags & 0x02 == 0 {
            let _ = self
                .peer
                .restart(self.now, String::new(), String::new(), true);
        }
        // Gather again: a restart without keeping them, or the move to Failed, dropped them.
        if self.target.get_local_candidates().is_empty()
            && let Some(c) = host_candidate(target_addr())
        {
            let _ = self.target.add_local_candidate(c);
        }
        if self.peer.get_local_candidates().is_empty()
            && let Some(c) = host_candidate(peer_addr())
        {
            let _ = self.peer.add_local_candidate(c);
        }
        self.requests.clear();
        if flags & 0x04 == 0 {
            self.signal(flags & 0x08 != 0);
        }
        self.drain();
    }
}

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

fn bytes8(arg: &[u8], at: usize) -> [u8; 8] {
    std::array::from_fn(|i| byte(arg, at + i))
}

/// The peer's address, or (with bit 0x20 of `flags`) another one, which the target learns as a
/// peer-reflexive candidate.
fn fuzzed_source(flags: u8, host: u8, port: u8) -> SocketAddr {
    if flags & 0x20 != 0 {
        SocketAddr::from(([10, 0, 1, host], 7000 + u16::from(port)))
    } else {
        peer_addr()
    }
}

/// Splits the next op argument off `data`: a one-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let len = usize::from(len).min(rest.len());
    let (arg, rest) = rest.split_at(len);
    *data = rest;
    arg
}

/// Stateful target: a target ICE agent against an in-memory peer, fed fuzzed STUN and non-STUN
/// traffic.
///
/// The first byte picks the target's role; the second its disconnected and failed timeouts.
/// The rest is a sequence of ops, each an op byte followed by a length-prefixed argument:
///
/// - pump until the target is connected (bounded), or deliver one round;
/// - a raw datagram to the target, from the peer or from another address;
/// - an authenticated binding request (role attributes, tie-breaker, USE-CANDIDATE, PRIORITY,
///   source address and optionally username chosen by the input);
/// - an authenticated response (success with a fuzzed XOR-MAPPED-ADDRESS, or a 487 error) to one
///   of the target's own requests, optionally from another address or without integrity;
/// - advancing the clock; partitioning the network; an ICE restart;
/// - a remote candidate parsed from the input; a non-STUN validity check.
pub fn agent_handle_inbound(mut data: &[u8], start: Instant) {
    let (Some(&config), Some(&timeouts)) = (data.first(), data.get(1)) else {
        return;
    };
    data = &data[2..];
    let target_controlling = config & 0x01 != 0;

    let (Some(mut target), Some(mut peer)) = (
        new_agent(start, "target", 21, target_controlling, timeouts),
        new_agent(start, "peer", 22, !target_controlling, timeouts),
    ) else {
        return;
    };
    if let (Some(t), Some(p)) = (host_candidate(target_addr()), host_candidate(peer_addr())) {
        let _ = target.add_local_candidate(t);
        let _ = peer.add_local_candidate(p);
    }
    let mut h = Harness {
        target,
        peer,
        now: start,
        to_target: VecDeque::new(),
        to_peer: VecDeque::new(),
        requests: VecDeque::new(),
        partitioned: false,
    };
    h.signal(target_controlling);

    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 11 {
            0 => {
                for _ in 0..64 {
                    if h.target.state() == ConnectionState::Connected {
                        break;
                    }
                    h.pump_once();
                    h.advance(Duration::from_millis(50));
                }
            }
            1 => h.pump_once(),
            2 => {
                let from = fuzzed_source(op & 0x20, byte(arg, 0), 0);
                h.send_to_target(from, BytesMut::from(arg));
            }
            3 => h.binding_request(arg),
            4 => h.binding_response(arg),
            5 => h.advance(Duration::from_millis(u64::from(byte(arg, 0)) * 100 + 10)),
            6 => h.partitioned = !h.partitioned,
            7 => h.restart(arg),
            8 => {
                if let Ok(c) = unmarshal_candidate(&String::from_utf8_lossy(arg)) {
                    let _ = h.target.add_remote_candidate(c);
                    h.drain();
                }
            }
            9 => {
                let peer = fuzzed_source(op & 0x20, byte(arg, 0), byte(arg, 1));
                let _ = h.target.is_valid_non_stun_traffic(
                    h.now,
                    TransportContext {
                        local_addr: target_addr(),
                        peer_addr: peer,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                );
            }
            _ => {
                let _ = h.target.close();
                h.drain();
            }
        }
        let _ = h.target.get_selected_candidate_pair();
        let _ = h.target.get_best_available_candidate_pair();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pumping alone connects the target in either role, so the ops reach the Connected state.
    #[test]
    fn pumping_connects_the_target() {
        for controlling in [false, true] {
            let start = Instant::now();
            let mut target = new_agent(start, "target", 21, controlling, 0x44).unwrap();
            let mut peer = new_agent(start, "peer", 22, !controlling, 0x44).unwrap();
            target
                .add_local_candidate(host_candidate(target_addr()).unwrap())
                .unwrap();
            peer.add_local_candidate(host_candidate(peer_addr()).unwrap())
                .unwrap();
            let mut h = Harness {
                target,
                peer,
                now: start,
                to_target: VecDeque::new(),
                to_peer: VecDeque::new(),
                requests: VecDeque::new(),
                partitioned: false,
            };
            h.signal(controlling);
            for _ in 0..64 {
                h.pump_once();
                h.advance(Duration::from_millis(50));
            }
            assert_eq!(
                h.target.state(),
                ConnectionState::Connected,
                "controlling={controlling}"
            );
            assert!(!h.requests.is_empty());

            // A partition takes it to Failed, and a restart brings it back.
            h.partitioned = true;
            for _ in 0..40 {
                h.pump_once();
                h.advance(Duration::from_millis(500));
            }
            assert_eq!(h.target.state(), ConnectionState::Failed);
            h.partitioned = false;
            h.restart(&[0x01]);
            for _ in 0..64 {
                h.pump_once();
                h.advance(Duration::from_millis(50));
            }
            assert_eq!(
                h.target.state(),
                ConnectionState::Connected,
                "after restart"
            );
        }
    }
}
