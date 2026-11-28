//! The checklist of RFC 8445: candidate pairs and their states, the ordinary and the triggered
//! checks paced by Ta, the STUN transaction behind each check, the valid list, nomination and
//! the conclusion of ICE.
//!
//! The engine has one data stream with one component (BUNDLE and rtcp-mux), so there is one
//! checklist. `Agent::candidate_pairs` holds it together with the valid pairs a check produces
//! that are not on it (Section 7.2.5.3.2); the order of the checklist is the pairs' priority,
//! read when a pair is picked (Section 6.1.2.3).
//!
//! Section 8.1.1 uses the nominated pair with the highest priority, and so does the controlled
//! agent here. libwebrtc moves a session to another pair after it connects, whatever that
//! pair's priority: following the controlling agent's *latest* nomination (or the highest
//! libwebrtc `NOMINATION` value) is `AgentConfig::nomination_acceptance`.
//!
//! One of the RFC's rules is not followed, on purpose: Sections 7.2.5.3.4 and 7.3.1.5 fail the
//! checklist when a nomination fails. Here the pair fails, and the checklist only when no
//! other pair can still be nominated.

use crate::agent::agent_config::*;
use crate::agent::{Agent, BindingRequest, Event, HeldFailure, TaggedEvent};
use crate::mdns::MulticastDnsMode;
use bytes::BytesMut;
use crc::{CRC_32_ISCSI, Crc};
use log::{debug, error, trace, warn};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::XorMappedAddress;

use crate::attributes::{control::*, nomination::nomination_of, priority::*, use_candidate::*};
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::{candidate_pair::*, *};
use crate::state::ConnectionState;

/// What a transport reports about the path of a connectivity check. See
/// [`Agent::handle_transport_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportError {
    /// A hard ICMP error (destination, port or protocol unreachable) for a datagram sent on
    /// the path.
    IcmpHardError,
    /// The TCP connection of the path could not be established.
    ConnectionFailed,
    /// What arrived on the path's TCP connection, in answer to the first check, is not STUN.
    NotStun,
}

/// RFC 6544 Section 12: "an ICE agent SHOULD NOT have more than 5 outstanding TCP connection
/// attempts with the same peer to the same IP address."
pub(crate) const MAX_TCP_CONNECTION_ATTEMPTS_PER_ADDRESS: usize = 5;

/// The state of the checklist (RFC 8445 Section 6.1.2.1). With one checklist it is also the
/// state of the ICE session (Section 6.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChecklistState {
    /// Checks are, or may still be, performed.
    Running,
    /// A pair has been nominated: no further ordinary checks.
    Completed,
    /// No valid pair could be produced, or consent was lost.
    Failed,
}

impl Agent {
    /// Whether `index` has been waiting long enough to be nominated, as of `now`.
    ///
    /// `now` is supplied by the caller rather than sampled here so that one nomination decision
    /// makes one time observation: both halves of a pair are tested against the same instant.
    fn is_nominatable(&self, now: Instant, index: usize, is_local: bool) -> bool {
        let c = if is_local {
            &self.local_candidates[index]
        } else {
            &self.remote_candidates[index]
        };
        let min_wait = match c.candidate_type() {
            CandidateType::Host => self.host_acceptance_min_wait,
            CandidateType::ServerReflexive => self.srflx_acceptance_min_wait,
            CandidateType::PeerReflexive => self.prflx_acceptance_min_wait,
            CandidateType::Relay => self.relay_acceptance_min_wait,
            CandidateType::Unspecified => {
                error!(
                    "is_nominatable invalid candidate type {}",
                    c.candidate_type()
                );
                return false;
            }
        };
        // RFC 8838 Section 14: the wait is for higher-priority candidates; once both sides
        // have said they have no more (end-of-candidates, and local gathering complete), there
        // is nothing left to wait for.
        if self.remote_end_of_candidates && self.local_gathering_complete {
            return true;
        }
        now.saturating_duration_since(self.start_time) > min_wait
    }

    /// The state of the checklist, in RFC 8445's terms: Running until a pair is nominated,
    /// Completed from then on, Failed when the agent is.
    ///
    /// [`Agent::state`] is the W3C transport state, which is `Connected` once a pair is
    /// nominated and `Completed` only when, in addition, both sides have said they have no
    /// more candidates.
    pub fn checklist_state(&self) -> ChecklistState {
        if self.connection_state == ConnectionState::Failed
            || self.failure_held == Some(HeldFailure::NominationFailed)
        {
            ChecklistState::Failed
        } else if self.selected_pair.is_some() {
            ChecklistState::Completed
        } else {
            ChecklistState::Running
        }
    }

    // ---------------------------------------------------------------------------------------
    // Pairs: forming, pruning, limiting, initial state (Sections 6.1.2.2 to 6.1.2.6)
    // ---------------------------------------------------------------------------------------

    /// Whether two local candidates send from the same socket: same base, same transport.
    pub(crate) fn same_base(&self, a: usize, b: usize) -> bool {
        let (a, b) = (&self.local_candidates[a], &self.local_candidates[b]);
        a.base_addr() == b.base_addr()
            && a.network_type() == b.network_type()
            && a.tcp_type() == b.tcp_type()
    }

    /// Whether two pairs send on the same 5-tuple: the same remote candidate, from local
    /// candidates with the same base (RFC 7675 Section 1).
    pub(crate) fn same_five_tuple(&self, a: usize, b: usize) -> bool {
        let (a, b) = (&self.candidate_pairs[a], &self.candidate_pairs[b]);
        a.remote_index == b.remote_index && self.same_base(a.local_index, b.local_index)
    }

    /// The last consent on a pair's 5-tuple (RFC 7675 Section 1): the latest success response
    /// to a Binding request sent on it or on another pair of the same 5-tuple (a valid pair
    /// whose local candidate is the mapped address shares its checked pair's base).
    pub(crate) fn pair_consent(&self, pair_index: usize) -> Option<Instant> {
        (0..self.candidate_pairs.len())
            .filter(|&other| self.same_five_tuple(pair_index, other))
            .filter_map(|other| self.candidate_pairs[other].last_consent)
            .max()
    }

    pub(crate) fn pair_foundation(&self, local_index: usize, remote_index: usize) -> u32 {
        let mut buf = self.local_candidates[local_index].foundation().into_bytes();
        buf.push(b':');
        buf.extend_from_slice(self.remote_candidates[remote_index].foundation().as_bytes());
        Crc::<u32>::new(&CRC_32_ISCSI).checksum(&buf)
    }

    /// Forms the pair (Section 6.1.2.2) and puts it on the checklist, unless it is redundant
    /// (6.1.2.4) or the checklist is full of better pairs (6.1.2.5).
    pub(crate) fn add_pair(&mut self, local_index: usize, remote_index: usize) {
        let local = &self.local_candidates[local_index];
        let remote = &self.remote_candidates[remote_index];
        // Every check goes out on a pair, so this is where the destination policy holds: a
        // loopback or link-local remote address is reached only from a local candidate in the
        // same scope (unless the configuration allows it). See `remote_policy`.
        let local_base = local.base_addr();
        let remote_addr = remote.addr();
        if !self.remote_policy.allows_pair(local_base, remote_addr) {
            debug!(
                "[{}]: not pairing local {} with remote {}: destination not allowed from this local candidate",
                self.get_name(),
                local_base,
                remote_addr
            );
            return;
        }
        // Section 6.1.2.2: "A local candidate is paired with a remote candidate if and only if
        // the two candidates have the same component ID and have the same IP address version."
        if local.component() != remote.component() {
            debug!(
                "[{}]: not pairing local {} with remote {}: components {} and {}",
                self.get_name(),
                local,
                remote,
                local.component(),
                remote.component()
            );
            return;
        }

        // draft-ietf-mmusic-mdns-ice-candidates Section 3.3.2: "an ICE agent MUST NOT form
        // candidate pairs between its own relay candidates and remote mDNS candidates": the
        // TURN server would learn the address the name hides.
        if local.candidate_type() == CandidateType::Relay && remote.address().ends_with(".local") {
            debug!(
                "[{}]: not pairing relay candidate {} with mDNS candidate {}",
                self.get_name(),
                local,
                remote.address()
            );
            return;
        }

        let mut pair = CandidatePair::new(
            local_index,
            remote_index,
            local.priority(),
            remote.priority(),
            self.is_controlling,
        );
        pair.foundation = self.pair_foundation(local_index, remote_index);

        // Section 6.1.2.4: a reflexive local candidate stands for its base, and of two pairs
        // with the same base and the same remote candidate the one with the higher priority
        // stays. RFC 8838 Section 11: only a pair that is still Waiting or Frozen gives way.
        let redundant = self.candidate_pairs.iter().position(|p| {
            p.remote_index == remote_index && self.same_base(p.local_index, local_index)
        });
        if let Some(existing) = redundant {
            let e = self.candidate_pairs[existing];
            let unchecked = matches!(
                e.state,
                CandidatePairState::Waiting | CandidatePairState::Frozen
            ) && !e.triggered
                && !e.nomination_pending;
            if unchecked && pair.priority() > e.priority() {
                pair.state = self.initial_pair_state(&pair, Some(existing));
                self.announce_pair(existing, false);
                self.candidate_pairs[existing] = pair;
                self.announce_pair(existing, true);
            }
            return;
        }

        // Section 6.1.2.5: the checklist holds a limited number of pairs.
        let slot = if self.checklist_len() < self.max_candidate_pairs {
            None
        } else {
            match self.pair_to_discard(pair.priority()) {
                Some(slot) => Some(slot),
                None => {
                    debug!(
                        "[{}]: checklist full ({} pairs): dropping pair {}",
                        self.get_name(),
                        self.max_candidate_pairs,
                        pair
                    );
                    return;
                }
            }
        };
        pair.state = self.initial_pair_state(&pair, slot);
        let index = match slot {
            Some(slot) => {
                self.announce_pair(slot, false);
                self.candidate_pairs[slot] = pair;
                slot
            }
            None => {
                self.candidate_pairs.push(pair);
                self.candidate_pairs.len() - 1
            }
        };
        self.announce_pair(index, true);
        // W3C webrtc-pc 5.6.4: a transport that is "disconnected" with its checks failed
        // while candidates may still come checks again when one comes ("disconnected", new
        // local candidates: "checking").
        if self.failure_held.is_some() {
            self.update_connection_state(Some(self.clock), ConnectionState::Checking);
            self.request_connectivity_check();
        }
    }

    /// Queues `CandidatePairAdded` (`added`) or `CandidatePairRemoved` for the pair at
    /// `index`. A pair the application removed was announced removed already.
    pub(crate) fn announce_pair(&mut self, index: usize, added: bool) {
        let p = self.candidate_pairs[index];
        if p.removed {
            return;
        }
        let (Some(local), Some(remote)) = (
            self.local_candidates.get(p.local_index),
            self.remote_candidates.get(p.remote_index),
        ) else {
            return;
        };
        let (local, remote) = (Box::new(local.clone()), Box::new(remote.clone()));
        self.event_outs.push_back(TaggedEvent {
            now: self.clock,
            event: if added {
                Event::CandidatePairAdded(local, remote)
            } else {
                Event::CandidatePairRemoved(local, remote)
            },
        });
    }

    /// Section 7.3.1.4: the pair of a request the peer sent is put on the checklist even when
    /// the checklist is full: it replaces the lowest-priority pair that has not been checked
    /// (or a Failed one), whatever the priorities. When every pair is in flight or done it is
    /// not added.
    pub(crate) fn add_triggered_pair(&mut self, local_index: usize, remote_index: usize) {
        let local = &self.local_candidates[local_index];
        let remote = &self.remote_candidates[remote_index];
        if !self
            .remote_policy
            .allows_pair(local.base_addr(), remote.addr())
            || local.component() != remote.component()
            || self.checklist_len() < self.max_candidate_pairs
        {
            return;
        }
        let Some(slot) = self.pair_to_discard(u64::MAX) else {
            return;
        };
        let mut pair = CandidatePair::new(
            local_index,
            remote_index,
            local.priority(),
            remote.priority(),
            self.is_controlling,
        );
        pair.foundation = self.pair_foundation(local_index, remote_index);
        self.announce_pair(slot, false);
        self.candidate_pairs[slot] = pair;
        self.announce_pair(slot, true);
    }

    /// The pairs that count against the limit: the checklist, not the valid pairs a response
    /// added beside it.
    fn checklist_len(&self) -> usize {
        self.candidate_pairs
            .iter()
            .filter(|p| !(p.valid && self.is_learned_local(p.local_index)))
            .count()
    }

    /// Whether the local candidate was learned from a response's mapped address.
    fn is_learned_local(&self, local_index: usize) -> bool {
        self.local_candidates[local_index].candidate_type() == CandidateType::PeerReflexive
    }

    /// RFC 8838 Section 11, step 5: when the checklist is full, "the agent SHOULD discard any
    /// pairs in the Failed state to make room for the new pair. If there are no such pairs,
    /// the agent SHOULD discard a pair with a lower priority than the new pair". A pair whose
    /// check is in flight or done is never discarded.
    fn pair_to_discard(&self, new_priority: u64) -> Option<usize> {
        let lowest = |wanted: &dyn Fn(&CandidatePair) -> bool| {
            self.candidate_pairs
                .iter()
                .enumerate()
                .filter(|(i, p)| {
                    wanted(p)
                        && !p.triggered
                        && !p.nomination_pending
                        && Some(*i) != self.selected_pair
                        && Some(*i) != self.nominated_pair
                })
                .min_by_key(|(_, p)| p.priority())
                .map(|(i, p)| (i, p.priority()))
        };
        if let Some((failed, _)) = lowest(&|p| p.state == CandidatePairState::Failed) {
            return Some(failed);
        }
        match lowest(&|p| {
            matches!(
                p.state,
                CandidatePairState::Waiting | CandidatePairState::Frozen
            )
        }) {
            Some((index, priority)) if priority < new_priority => Some(index),
            _ => None,
        }
    }

    /// The state a new pair starts in (RFC 8838 Section 12, which for a checklist that is
    /// complete from the start gives RFC 8445 Section 6.1.2.6): Waiting when it is the
    /// highest-priority pair of its foundation or a pair of that foundation has succeeded,
    /// Frozen otherwise. `replacing` is the slot it takes over, if any.
    fn initial_pair_state(
        &self,
        pair: &CandidatePair,
        replacing: Option<usize>,
    ) -> CandidatePairState {
        let mut topmost = true;
        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if Some(index) == replacing || p.foundation != pair.foundation {
                continue;
            }
            if p.state == CandidatePairState::Succeeded {
                return CandidatePairState::Waiting;
            }
            if p.priority() >= pair.priority() {
                topmost = false;
            }
        }
        if topmost {
            CandidatePairState::Waiting
        } else {
            CandidatePairState::Frozen
        }
    }

    /// RFC 8445 Section 6.1.2.6, when checks start: "For each foundation, the agent sets the
    /// state of exactly one candidate pair to the Waiting state", the one with the highest
    /// priority; the others are Frozen. Pairs added one by one before that each started
    /// Waiting when they were, at the time, the best of their foundation.
    pub(crate) fn compute_initial_pair_states(&mut self) {
        let untouched = self.candidate_pairs.iter().all(|p| {
            matches!(
                p.state,
                CandidatePairState::Waiting | CandidatePairState::Frozen
            ) && !p.triggered
        });
        if !untouched {
            return;
        }
        for index in 0..self.candidate_pairs.len() {
            let pair = self.candidate_pairs[index];
            let best = !self.candidate_pairs.iter().enumerate().any(|(other, p)| {
                p.foundation == pair.foundation
                    && (p.priority() > pair.priority()
                        || (p.priority() == pair.priority() && other < index))
            });
            self.candidate_pairs[index].state = if best {
                CandidatePairState::Waiting
            } else {
                CandidatePairState::Frozen
            };
        }
    }

    pub(crate) fn find_pair_exact(&self, local_index: usize, remote_index: usize) -> Option<usize> {
        self.candidate_pairs
            .iter()
            .position(|p| p.local_index == local_index && p.remote_index == remote_index)
    }

    /// The pair of these two candidates, or, when pruning kept another pair for the same
    /// socket and remote candidate (Section 6.1.2.4), that one.
    pub(crate) fn find_pair(&self, local_index: usize, remote_index: usize) -> Option<usize> {
        self.find_pair_exact(local_index, remote_index).or_else(|| {
            self.candidate_pairs.iter().position(|p| {
                p.remote_index == remote_index
                    && !(p.valid && self.is_learned_local(p.local_index))
                    && self.same_base(p.local_index, local_index)
            })
        })
    }

    // ---------------------------------------------------------------------------------------
    // Scheduling: the triggered-check queue and Ta (Sections 6.1.4.1 and 6.1.4.2)
    // ---------------------------------------------------------------------------------------

    /// Puts the pair on the triggered-check queue (FIFO, once).
    pub(crate) fn enqueue_triggered(&mut self, pair_index: usize) {
        let p = &mut self.candidate_pairs[pair_index];
        if p.removed {
            return;
        }
        if !p.triggered {
            p.triggered = true;
            self.triggered_queue
                .push_back((p.local_index, p.remote_index));
        }
        self.request_connectivity_check();
    }

    fn pop_triggered(&mut self) -> Option<usize> {
        while let Some((local_index, remote_index)) = self.triggered_queue.pop_front() {
            if let Some(pair_index) = self.find_pair_exact(local_index, remote_index)
                && self.candidate_pairs[pair_index].triggered
            {
                return Some(pair_index);
            }
        }
        None
    }

    /// Section 7.3.1.4, what a Binding request does to its pair unless the pair has succeeded:
    /// an In-Progress transaction is cancelled, the pair is Waiting and on the triggered-check
    /// queue.
    pub(crate) fn trigger_check(&mut self, pair_index: usize) {
        let p = self.candidate_pairs[pair_index];
        if p.removed {
            return;
        }
        if p.state == CandidatePairState::InProgress {
            self.cancel_transactions(p.local_index, p.remote_index);
        }
        self.candidate_pairs[pair_index].state = CandidatePairState::Waiting;
        self.enqueue_triggered(pair_index);
    }

    /// Whether ordinary checks are performed: the checklist is Running, and the agent is not a
    /// lite one answering a full agent (Section 6.2: no checks).
    fn ordinary_checks_allowed(&self) -> bool {
        self.selected_pair.is_none()
            // (Nor a lite one with a lite peer, Section 6.1.1: "no connectivity checks are
            // ever sent".)
            && !(self.lite && (!self.is_controlling || self.remote_lite))
            && !matches!(
                self.connection_state,
                ConnectionState::Failed | ConnectionState::Closed
            )
    }

    /// The Waiting pair with the highest priority (Section 6.1.4.2, step 3).
    fn next_waiting(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.state != CandidatePairState::Waiting || p.triggered {
                continue;
            }
            if self.tcp_attempts_exhausted(p) {
                continue;
            }
            if best.is_none_or(|b| self.candidate_pairs[b].priority() < p.priority()) {
                best = Some(index);
            }
        }
        best
    }

    /// Whether the pair is one this agent opens a TCP connection for (an active local
    /// candidate, RFC 6544 Section 7.1).
    fn opens_tcp_connection(&self, p: &CandidatePair) -> bool {
        let local = &self.local_candidates[p.local_index];
        local.network_type().is_tcp() && local.tcp_type() == crate::tcp_type::TcpType::Active
    }

    /// RFC 6544 Section 12: whether as many connection attempts as allowed are outstanding to
    /// the IP address of this pair's remote candidate, so that its check has to wait. An
    /// attempt is outstanding while its check is In-Progress: it ends with the response, or
    /// with the transaction (Ti, 39.5 s, or a failure the transport reports).
    fn tcp_attempts_exhausted(&self, p: &CandidatePair) -> bool {
        if !self.opens_tcp_connection(p) {
            return false;
        }
        let ip = self.remote_candidates[p.remote_index].addr().ip();
        self.candidate_pairs
            .iter()
            .filter(|q| {
                q.state == CandidatePairState::InProgress
                    && self.opens_tcp_connection(q)
                    && self.remote_candidates[q.remote_index].addr().ip() == ip
            })
            .count()
            >= MAX_TCP_CONNECTION_ATTEMPTS_PER_ADDRESS
    }

    /// The Frozen pairs step 2 of Section 6.1.4.2 would unfreeze: with no pair Waiting, for
    /// each foundation without a Waiting or In-Progress pair, its highest-priority Frozen pair.
    fn pairs_to_unfreeze(&self) -> Vec<usize> {
        let mut out: Vec<usize> = vec![];
        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.state != CandidatePairState::Frozen {
                continue;
            }
            let busy = self.candidate_pairs.iter().any(|q| {
                q.foundation == p.foundation
                    && matches!(
                        q.state,
                        CandidatePairState::Waiting | CandidatePairState::InProgress
                    )
            });
            if busy {
                continue;
            }
            match out
                .iter()
                .position(|&o| self.candidate_pairs[o].foundation == p.foundation)
            {
                Some(slot) if self.candidate_pairs[out[slot]].priority() < p.priority() => {
                    out[slot] = index
                }
                Some(_) => {}
                None => out.push(index),
            }
        }
        out
    }

    /// Whether `run_ta` would start a check now if Ta allowed it.
    pub(crate) fn has_check_to_start(&self) -> bool {
        if !self.triggered_queue.is_empty() {
            return true;
        }
        self.ordinary_checks_allowed()
            && (self.next_waiting().is_some() || !self.pairs_to_unfreeze().is_empty())
    }

    /// Timer Ta (Section 6.1.4.2): at most one check is started per Ta, a triggered one first,
    /// else the highest-priority Waiting pair, unfreezing pairs when none is Waiting.
    pub(crate) fn run_ta(&mut self, now: Instant) {
        if now < self.next_check_at || self.ufrag_pwd.remote_credentials.is_none() {
            return;
        }
        let pair_index = match self.pop_triggered() {
            Some(pair_index) => Some(pair_index),
            None if self.ordinary_checks_allowed() => {
                if self.next_waiting().is_none() {
                    for index in self.pairs_to_unfreeze() {
                        self.candidate_pairs[index].state = CandidatePairState::Waiting;
                    }
                }
                self.next_waiting()
            }
            None => None,
        };
        if let Some(pair_index) = pair_index {
            // Section 14.2: with other agents, one transaction per 5 ms for all of them.
            if let Some(group) = &self.pacing_group
                && let Err(at) = group.take(now)
            {
                // (A triggered check taken off the queue goes back at its head.)
                let p = self.candidate_pairs[pair_index];
                if p.triggered {
                    self.triggered_queue
                        .push_front((p.local_index, p.remote_index));
                }
                self.next_check_at = at;
                return;
            }
            self.start_check(now, pair_index);
            self.next_check_at = now + self.ta;
        }
    }

    fn start_check(&mut self, now: Instant, pair_index: usize) {
        let p = &mut self.candidate_pairs[pair_index];
        p.triggered = false;
        // Section 8.1.1: the controlling agent nominates with USE-CANDIDATE; the controlled
        // agent never sends it.
        let use_candidate = self.is_controlling && p.nominate;
        // A nomination is a check on a pair that is valid already; it stays Succeeded.
        if p.state != CandidatePairState::Succeeded {
            p.state = CandidatePairState::InProgress;
        }
        trace!(
            "[{}]: check on {} (nominating: {})",
            self.get_name(),
            self.candidate_pairs[pair_index],
            use_candidate
        );
        self.send_check(now, pair_index, use_candidate, false);
    }

    // ---------------------------------------------------------------------------------------
    // Transactions (Sections 7.2.2 to 7.2.5, 14.3; RFC 8489 Section 6.2)
    // ---------------------------------------------------------------------------------------

    /// Section 14.3: "RTO = MAX (500ms, Ta * N * (Num-Waiting + Num-In-Progress))", N being
    /// the number of checklists, one here.
    pub(crate) fn check_rto(&self) -> Duration {
        let active = self
            .candidate_pairs
            .iter()
            .filter(|p| {
                matches!(
                    p.state,
                    CandidatePairState::Waiting | CandidatePairState::InProgress
                )
            })
            .count();
        (self.ta * u32::try_from(active).unwrap_or(u32::MAX)).max(MIN_RTO)
    }

    /// How long the consent request sent now on the pair waits for its response (RFC 7675
    /// Section 5.1): by default `Rm` times the pair's RTO, the consent expiry at most. See
    /// [`ConsentResponseWait`].
    fn consent_wait(&mut self, now: Instant, pair_index: usize) -> Duration {
        let rto = self.candidate_pairs[pair_index].rto.start(now);
        super::consent_response_wait(self.consent_response_wait, rto, self.consent_expiry())
    }

    /// Builds and sends a Binding request on the pair and opens its transaction: a
    /// connectivity check (retransmitted over UDP, Section 14.3), with USE-CANDIDATE a
    /// nomination, or with `consent` a consent request, which is sent once (RFC 7675).
    pub(crate) fn send_check(
        &mut self,
        now: Instant,
        pair_index: usize,
        use_candidate: bool,
        consent: bool,
    ) {
        let Some(remote_credentials) = &self.ufrag_pwd.remote_credentials else {
            error!("ufrag_pwd.remote_credentials is none");
            return;
        };
        let pair = self.candidate_pairs[pair_index];
        let local = &self.local_candidates[pair.local_index];
        // Section 7.1.1: the priority the local candidate would have as a peer-reflexive one,
        // which is what the peer makes of an unknown source.
        let priority = local.peer_reflexive_priority();
        let is_tcp = local.network_type().is_tcp();

        // Section 7.2.2: USERNAME is the peer's fragment, a colon, ours; the key is the peer's
        // password.
        let username = remote_credentials.ufrag.clone()
            + ":"
            + self.ufrag_pwd.local_credentials.ufrag.as_str();
        let mut msg = Message::new();
        let built = {
            let mut setters: Vec<Box<dyn Setter + '_>> = vec![
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
            ];
            if use_candidate {
                setters.push(Box::<UseCandidateAttr>::default());
            }
            // Section 7.1.3.
            if self.is_controlling {
                setters.push(Box::new(AttrControlling(self.tie_breaker)));
            } else {
                setters.push(Box::new(AttrControlled(self.tie_breaker)));
            }
            setters.push(Box::new(PriorityAttr(priority)));
            // RFC 8489 Section 6.1: a request SHOULD carry SOFTWARE.
            if let Some(software) = &self.software {
                setters.push(Box::new(Software::new(ATTR_SOFTWARE, software.clone())));
            }
            setters.push(Box::new(
                MessageIntegrity::new_short_term_integrity_with_provider(
                    remote_credentials.pwd.clone(),
                    self.crypto_provider.crypto(),
                ),
            ));
            // Section 7.2.4.
            setters.push(Box::new(FINGERPRINT));
            msg.build(&setters)
        };
        if let Err(err) = built {
            // (A USERNAME of 509 bytes or more, say: the check can never be sent.)
            error!("{}", err);
            self.fail_pair(pair_index);
            return;
        }
        // RFC 8489 Section 6.1: over UDP a STUN message fits the path MTU (assumed 576 / 1280
        // bytes when not known): long ufrags can make a check that does not. It is not sent,
        // and the pair fails at once.
        if !is_tcp {
            let destination = self.remote_candidates[pair.remote_index].addr();
            if msg.raw.len() > self.max_udp_stun_size(destination) {
                warn!(
                    "[{}]: a check of {} bytes on {} exceeds the path MTU: the pair failed",
                    self.get_name(),
                    msg.raw.len(),
                    pair
                );
                self.fail_pair(pair_index);
                return;
            }
        }

        let rto = self.check_rto();
        let (retransmit, next_event) = if consent {
            // Sent once (RFC 7675 Section 5.1), over TCP as over UDP; its response is awaited
            // for a time based on the pair's round-trip time.
            (false, now + self.consent_wait(now, pair_index))
        } else if is_tcp {
            // RFC 6544 Section 7.1: no retransmissions over TCP.
            (false, now + STUN_TI)
        } else if self.max_binding_requests <= 1 {
            (false, now + rto * STUN_RM)
        } else {
            (true, now + rto)
        };
        trace!(
            "[{}]: ping STUN from {} to {}",
            self.get_name(),
            self.local_candidates[pair.local_index],
            self.remote_candidates[pair.remote_index],
        );
        self.track_transaction(BindingRequest {
            timestamp: now,
            transaction_id: msg.transaction_id,
            destination: self.remote_candidates[pair.remote_index].addr(),
            is_use_candidate: use_candidate,
            local_index: pair.local_index,
            remote_index: pair.remote_index,
            sent_as_controlling: self.is_controlling,
            raw: BytesMut::from(&msg.raw[..]),
            rto,
            interval: rto,
            transmissions: 1,
            next_event,
            retransmit,
            cancelled: false,
            consent,
            priority,
            unauthentic_response: false,
        });

        // Track request sent on the candidate pair
        self.candidate_pairs[pair_index].on_request_sent();
        self.send_stun(now, &msg, pair.local_index, pair.remote_index);
    }

    /// Remembers an open transaction. Checks are bounded by the checklist (one per pair);
    /// consent requests and cancelled transactions by `MAX_PENDING_BINDING_REQUESTS`, the
    /// oldest of them being forgotten first.
    pub(crate) fn track_transaction(&mut self, transaction: BindingRequest) {
        self.pending_binding_requests.push(transaction);
        self.trim_passive_transactions();
    }

    fn trim_passive_transactions(&mut self) {
        let passive = |r: &BindingRequest| r.consent || r.cancelled;
        let mut excess = self
            .pending_binding_requests
            .iter()
            .filter(|r| passive(r))
            .count()
            .saturating_sub(MAX_PENDING_BINDING_REQUESTS);
        if excess > 0 {
            self.pending_binding_requests.retain(|r| {
                if excess > 0 && passive(r) {
                    excess -= 1;
                    false
                } else {
                    true
                }
            });
        }
    }

    /// Cancels the pair's open check transactions (Section 7.3.1.4): "the agent will not
    /// retransmit the Binding requests associated with the connectivity-check transaction,
    /// will not treat the lack of response to be a failure, but will wait the duration of the
    /// transaction timeout for a response."
    /// Cancels the transactions on a pair the application removed.
    pub(crate) fn cancel_pair_checks(&mut self, local_index: usize, remote_index: usize) {
        self.cancel_transactions(local_index, remote_index);
    }

    fn cancel_transactions(&mut self, local_index: usize, remote_index: usize) {
        // How long a transaction lasts without a response (RFC 8489 Section 6.2.1): the `Rc`
        // requests are RTO, 2 RTO, 4 RTO, ... apart and the last one is given `Rm` times the
        // RTO: 39.5 s with the defaults.
        let rc = u32::from(self.max_binding_requests.clamp(1, 16));
        let duration = |rto: Duration| rto * ((1u32 << (rc - 1)) - 1 + STUN_RM);
        for r in &mut self.pending_binding_requests {
            if r.local_index == local_index
                && r.remote_index == remote_index
                && !r.consent
                && !r.is_use_candidate
            {
                r.cancelled = true;
                r.next_event = r.next_event.max(r.timestamp + duration(r.rto));
            }
        }
        self.trim_passive_transactions();
    }

    /// Retransmits the requests whose RTO ran out and ends the transactions that got no
    /// response (RFC 8489 Section 6.2.1: requests RTO, 2 RTO, 4 RTO, ... apart, `Rc` of them,
    /// then `Rm * RTO` of patience). A check that times out fails its pair (Section
    /// 7.2.5.2.3).
    pub(crate) fn run_transactions(&mut self, now: Instant) {
        let rc = self.max_binding_requests.max(1);
        let mut resend: Vec<(BytesMut, usize, SocketAddr)> = vec![];
        let mut timed_out: Vec<BindingRequest> = vec![];
        let mut index = 0;
        while index < self.pending_binding_requests.len() {
            let r = &mut self.pending_binding_requests[index];
            if r.next_event > now {
                index += 1;
                continue;
            }
            if r.retransmit && !r.cancelled && r.transmissions < rc {
                r.transmissions += 1;
                r.interval *= 2;
                r.next_event = now
                    + if r.transmissions >= rc {
                        r.rto * STUN_RM
                    } else {
                        r.interval
                    };
                resend.push((r.raw.clone(), r.local_index, r.destination));
                index += 1;
            } else {
                timed_out.push(self.pending_binding_requests.remove(index));
            }
        }

        for (raw, local_index, destination) in resend {
            if local_index < self.local_candidates.len() {
                self.send_raw_stun(now, raw, local_index, destination);
            }
        }

        let mut failed = false;
        for r in timed_out {
            if r.unauthentic_response && !r.cancelled {
                self.signal_integrity_violation(&r);
            }
            if r.cancelled || r.consent {
                continue;
            }
            let Some(pair_index) = self.find_pair_exact(r.local_index, r.remote_index) else {
                continue;
            };
            let pair = self.candidate_pairs[pair_index];
            // A nomination is a check on a valid pair: the pair has received a success
            // response and stays Succeeded (Section 7.2.5.3.3). When it times out, the pair
            // and the checklist fail (Section 7.2.5.3.4), or with `FailedNomination::Retry`
            // it is sent again for as long as the peer is heard from (see
            // `nomination_is_alive`).
            let nomination = self.is_open_nomination(&r, pair_index);
            if self.failed_nomination == FailedNomination::FailChecklist
                && (nomination || self.is_followed_nomination(&r, pair_index))
            {
                self.fail_nomination(now, pair_index, "no response");
                return;
            }
            if nomination && self.nomination_is_alive(now, pair_index) {
                debug!(
                    "[{}]: no response to the nomination of {} after {} requests: nominating it again",
                    self.get_name(),
                    pair,
                    r.transmissions
                );
                self.candidate_pairs[pair_index].nominate = true;
                self.enqueue_triggered(pair_index);
                continue;
            }
            // A check that timed out on a pair another transaction has validated since is
            // moot; a nomination that timed out is not.
            if pair.state == CandidatePairState::InProgress || r.is_use_candidate {
                warn!(
                    "[{}]: no response to {} requests on {}{}: the pair failed",
                    self.get_name(),
                    r.transmissions,
                    self.candidate_pairs[pair_index],
                    if r.is_use_candidate {
                        " (nomination)"
                    } else {
                        ""
                    }
                );
                self.fail_pair(pair_index);
                failed = true;
            }
        }
        if failed {
            self.maybe_nominate(now);
        }
    }

    /// A response with the transaction id `id` failed its integrity check and was discarded.
    ///
    /// Over UDP the transaction stays open: a genuine response may still come. Over a
    /// reliable transport (ICE-TCP, where a check is sent once) none will: RFC 8489 Section
    /// 9.1.4, "the transaction MUST be ended immediately and the layer MUST signal an
    /// integrity protection violation". The transaction is ended at the next timer pass, which
    /// is due at once: the pair fails and `Event::IntegrityViolation` is raised.
    pub(crate) fn note_unauthentic_response(&mut self, id: TransactionId) {
        let clock = self.clock;
        let tcp = |local_index: usize, candidates: &[Candidate]| {
            candidates
                .get(local_index)
                .is_some_and(|c| c.network_type().is_tcp())
        };
        if let Some(r) = self
            .pending_binding_requests
            .iter_mut()
            .find(|r| r.transaction_id == id)
        {
            r.unauthentic_response = true;
            if tcp(r.local_index, &self.local_candidates) {
                r.retransmit = false;
                r.next_event = r.next_event.min(clock);
            }
        }
    }

    /// RFC 8489 Section 9.1.4: "If all responses received are discarded, then instead of
    /// signaling a timeout after ending the transaction, the layer MUST signal an integrity
    /// protection violation."
    fn signal_integrity_violation(&mut self, r: &BindingRequest) {
        let (Some(local), Some(remote)) = (
            self.local_candidates.get(r.local_index),
            self.remote_candidates.get(r.remote_index),
        ) else {
            return;
        };
        warn!(
            "[{}]: every response to the request on {} -> {} failed its integrity check: integrity violation",
            self.get_name(),
            local,
            remote
        );
        let event = Event::IntegrityViolation(Box::new(local.clone()), Box::new(remote.clone()));
        self.event_outs.push_back(TaggedEvent {
            now: self.clock,
            event,
        });
    }

    /// The pair is Failed: out of the valid list, not nominated, not awaited. The selected
    /// pair is not failed this way; it ends when its consent expires.
    pub(crate) fn fail_pair(&mut self, pair_index: usize) {
        if self.selected_pair == Some(pair_index) {
            return;
        }
        let failed = |p: &mut CandidatePair| {
            p.state = CandidatePairState::Failed;
            p.valid = false;
            p.valid_pair = None;
            p.nominated = false;
            p.nomination_pending = false;
            p.nominate = false;
            p.triggered = false;
        };
        failed(&mut self.candidate_pairs[pair_index]);
        if self.nominated_pair == Some(pair_index) {
            self.nominated_pair = None;
        }
        // The pairs whose check produced this valid pair go with it.
        for index in 0..self.candidate_pairs.len() {
            if self.candidate_pairs[index].valid_pair == Some(pair_index)
                && self.selected_pair != Some(index)
            {
                failed(&mut self.candidate_pairs[index]);
            }
        }
    }

    /// Whether `request` is the controlling agent's nomination of `pair_index`, a valid pair,
    /// with no pair selected yet: the check Section 7.2.5.3.4 says the checklist fails with.
    fn is_open_nomination(&self, request: &BindingRequest, pair_index: usize) -> bool {
        let pair = &self.candidate_pairs[pair_index];
        request.is_use_candidate
            && request.sent_as_controlling
            && self.is_controlling
            && self.selected_pair.is_none()
            && pair.valid
            && pair.state == CandidatePairState::Succeeded
    }

    /// Whether `request` is the controlled agent's check of `pair_index` that a received
    /// USE-CANDIDATE triggered (Section 7.3.1.5: the nomination waits for it), with no pair
    /// selected yet: Section 7.2.5.3.4, "If the triggered request fails, the agent MUST remove
    /// the candidate pair from the valid list, set the candidate pair state to Failed, and set
    /// the checklist state to Failed." (Once a pair is selected the checklist is Completed and
    /// a later nomination's check failing only fails its pair.)
    fn is_followed_nomination(&self, request: &BindingRequest, pair_index: usize) -> bool {
        !request.sent_as_controlling
            && !self.is_controlling
            && !request.consent
            && self.selected_pair.is_none()
            && self.candidate_pairs[pair_index].nomination_pending
    }

    /// Section 7.2.5.3.4: "If the request fails (Section 7.2.5.2), the agent MUST remove the
    /// candidate pair from the valid list, set the candidate pair state to Failed, and set the
    /// checklist state to Failed." (`FailedNomination::FailChecklist`.)
    fn fail_nomination(&mut self, now: Instant, pair_index: usize, why: &str) {
        warn!(
            "[{}]: {} to the nomination of {}: the pair and the checklist failed",
            self.get_name(),
            why,
            self.candidate_pairs[pair_index]
        );
        self.fail_pair(pair_index);
        self.nomination_started = None;
        // The checklist is Failed; the transport is "failed" only once no candidate is to
        // come (W3C webrtc-pc 5.6.4), "disconnected" until then.
        self.fail_or_hold(now, HeldFailure::NominationFailed);
    }

    /// Takes the open transaction `id`, if there is one. A consent request's transaction
    /// that has reached its end is not one, whether or not the timer has run since (RFC 8489
    /// Section 6.3: the response of a transaction that is no longer in progress is
    /// discarded).
    pub(crate) fn handle_inbound_binding_success(
        &mut self,
        now: Instant,
        id: TransactionId,
    ) -> Option<BindingRequest> {
        let index = self
            .pending_binding_requests
            .iter()
            .position(|r| r.transaction_id == id)?;
        let request = self.pending_binding_requests.remove(index);
        (!request.consent || request.next_event > now).then_some(request)
    }

    // ---------------------------------------------------------------------------------------
    // Responses (Section 7.2.5)
    // ---------------------------------------------------------------------------------------

    /// An authenticated success response. `local_index` is the local candidate it arrived on,
    /// `remote_addr` its source.
    pub(crate) fn handle_success_response(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_addr: SocketAddr,
    ) {
        // RFC 8489 Section 6.3.3: "For the Binding method, the client checks that the
        // XOR-MAPPED-ADDRESS attribute is present in the response", and processes the success
        // response only "if all the checks succeed". Without it the response is discarded: the
        // transaction goes on (retransmissions, its timeout) as if it had not arrived, and it
        // refreshes no consent. (One whose address family cannot be decoded is processed; the
        // value is ignored, Section 6.3.3's SHOULD, and the pair is valid on the sent local
        // candidate.)
        if !m.contains(ATTR_XORMAPPED_ADDRESS) {
            debug!(
                "[{}]: discard Binding success response from {} without XOR-MAPPED-ADDRESS",
                self.get_name(),
                remote_addr
            );
            return;
        }

        // Section 7.2.5: the response belongs to the transaction with its id, and so to that
        // transaction's pair.
        let Some(request) = self.handle_inbound_binding_success(now, m.transaction_id) else {
            warn!(
                "[{}]: discard message from ({}), unknown TransactionID 0x{:?}",
                self.get_name(),
                remote_addr,
                m.transaction_id
            );
            return;
        };
        let checked = self.find_pair_exact(request.local_index, request.remote_index);

        // Section 7.2.5.2.1: "The ICE agent MUST check that the source and destination
        // transport addresses in the Binding request and response are symmetric. [...] If the
        // addresses are not symmetric, the agent MUST set the candidate pair state to Failed."
        let symmetric = request.destination == remote_addr
            && request.local_index < self.local_candidates.len()
            && self.same_base(request.local_index, local_index);
        if !symmetric {
            debug!(
                "[{}]: response from {} to a request sent to {}: not symmetric",
                self.get_name(),
                remote_addr,
                request.destination
            );
            if let Some(pair_index) = checked
                && !request.consent
            {
                if self.failed_nomination == FailedNomination::FailChecklist
                    && (self.is_open_nomination(&request, pair_index)
                        || self.is_followed_nomination(&request, pair_index))
                {
                    self.fail_nomination(now, pair_index, "a response from another address");
                    return;
                }
                self.fail_pair(pair_index);
                self.maybe_nominate(now);
            }
            return;
        }
        let Some(checked) = checked else {
            return;
        };
        // The application removed the pair: its checks stopped (webrtc-extensions 7).
        if self.candidate_pairs[checked].removed {
            return;
        }

        // Consent (RFC 7675 Section 5.1): a matching, authenticated success response from the
        // address the request went to. It is consent on the 5-tuple the request was sent on
        // (Section 1): the pair's, and that of any other pair with the same local base and
        // remote candidate (`pair_consent`), not the remote candidate's other pairs.
        if let Some(remote) = self.remote_candidates.get_mut(request.remote_index) {
            remote.last_consent = Some(now);
        }
        self.candidate_pairs[checked].last_consent = Some(now);
        if self
            .selected_pair
            .is_some_and(|selected| self.same_five_tuple(selected, checked))
        {
            self.consent_unanswered_since = None;
            // Consent is back: the state is looked at now, not at the next consent check.
            if self.connection_state == ConnectionState::Disconnected {
                self.request_connectivity_check();
            }
        }

        // Round-trip time, from a request that was sent once (a retransmitted one does not say
        // which transmission was answered: RFC 8489 Section 6.2.1, Karn's algorithm). It
        // also makes the pair's RTO (RFC 6298), which the wait of the next consent requests
        // is based on: a response that takes long teaches the agent to wait longer.
        let rtt = now.saturating_duration_since(request.timestamp);
        if request.transmissions == 1 {
            self.candidate_pairs[checked].on_response_received(rtt);
            self.candidate_pairs[checked].rto.sample(rtt, now);
        } else {
            self.candidate_pairs[checked].responses_received += 1;
        }
        if request.consent {
            return;
        }

        trace!(
            "[{}]: inbound STUN (SuccessResponse) from {} to {}",
            self.get_name(),
            self.remote_candidates[request.remote_index],
            self.local_candidates[local_index]
        );

        // Sections 7.2.5.3.1 and 7.2.5.3.2: the valid pair is (mapped address, the request's
        // destination).
        let valid_local = self.local_candidate_for_mapped_address(m, &request);
        let valid = if valid_local == request.local_index {
            checked
        } else {
            self.valid_pair_for(valid_local, request.remote_index)
        };

        // Section 7.2.5.3.3: the pair that generated the check and the valid pair are
        // Succeeded, and the Frozen pairs with the same foundation are unfrozen.
        let remote_nomination = self.candidate_pairs[checked].remote_nomination;
        {
            let c = &mut self.candidate_pairs[checked];
            c.state = CandidatePairState::Succeeded;
            c.valid_pair = Some(valid);
            // A triggered check still queued for the pair is not needed any more, but a
            // nomination queued for it is (Section 8.1.1): an answer to an earlier check
            // must not take it off the queue.
            c.triggered = c.triggered && c.nominate;
        }
        {
            let v = &mut self.candidate_pairs[valid];
            v.state = CandidatePairState::Succeeded;
            v.valid = true;
            v.valid_pair = Some(valid);
            v.remote_nomination = v.remote_nomination.max(remote_nomination);
        }
        let foundation = self.candidate_pairs[checked].foundation;
        for p in &mut self.candidate_pairs {
            if p.state == CandidatePairState::Frozen && p.foundation == foundation {
                p.state = CandidatePairState::Waiting;
            }
        }
        // The pair's other open checks have nothing left to decide.
        self.cancel_transactions(request.local_index, request.remote_index);

        trace!(
            "[{}]: valid pair {} from check on {}, use-candidate: {}, rtt: {:.3}ms",
            self.get_name(),
            self.candidate_pairs[valid],
            self.candidate_pairs[checked],
            request.is_use_candidate,
            rtt.as_millis()
        );

        // Section 7.2.5.3.4.
        if request.is_use_candidate && self.is_controlling {
            // "If the controlling agent sends a Binding request with the USE-CANDIDATE
            // attribute set, and if the ICE agent receives a successful response to the
            // request, the agent sets the nominated flag of the pair to true."
            self.candidate_pairs[valid].nominate = false;
            self.candidate_pairs[checked].nominate = false;
            if self.selected_pair.is_none() {
                self.set_selected_pair(Some(now), Some(valid));
                self.conclude();
            }
        } else if self.adopt_tcp_reconnection(now, valid) {
            // The selected pair's connection was opened again: see `adopt_tcp_reconnection`.
        } else if std::mem::take(&mut self.candidate_pairs[checked].nomination_pending) {
            // "If the controlled agent receives a successful response to a Binding request
            // sent by the agent, and that Binding request was triggered by a received Binding
            // request with the USE-CANDIDATE attribute set, the agent sets the nominated flag
            // of the pair to true."
            self.accept_nomination(now, valid);
        } else {
            self.maybe_nominate(now);
        }
    }

    /// RFC 6544 Section 11.1: when the selected pair's TCP connection is lost, the active side
    /// opens it again and the passive side waits for it. The new connection has another source
    /// port, so on the passive side it is a new peer-reflexive candidate and a new pair. Once
    /// that pair is valid it *is* the selected pair's connection, re-established: the session
    /// moves to it without a nomination (the active side still sees the pair it nominated).
    /// Returns whether `valid` was adopted.
    fn adopt_tcp_reconnection(&mut self, now: Instant, valid: usize) -> bool {
        let Some(selected) = self.selected_pair else {
            return false;
        };
        if selected == valid {
            return false;
        }
        let (old, new) = (self.candidate_pairs[selected], self.candidate_pairs[valid]);
        let local = &self.local_candidates[new.local_index];
        let (old_remote, new_remote) = (
            &self.remote_candidates[old.remote_index],
            &self.remote_candidates[new.remote_index],
        );
        let reconnection = local.network_type().is_tcp()
            && local.tcp_type() == crate::tcp_type::TcpType::Passive
            && self.same_base(old.local_index, new.local_index)
            && new_remote.candidate_type() == CandidateType::PeerReflexive
            && new_remote.tcp_type() == crate::tcp_type::TcpType::Active
            && old_remote.tcp_type() == crate::tcp_type::TcpType::Active
            && old_remote.addr().ip() == new_remote.addr().ip();
        if !reconnection {
            return false;
        }
        debug!(
            "[{}]: the selected TCP pair was reconnected: {} replaces {}",
            self.get_name(),
            new,
            old
        );
        self.candidate_pairs[valid].remote_nomination = old.remote_nomination;
        self.candidate_pairs[valid].nomination_pending = false;
        self.candidate_pairs[selected].nominated = false;
        self.set_selected_pair(Some(now), Some(valid));
        self.conclude();
        true
    }

    /// Section 7.2.5.3.1: "The ICE agent MUST check the mapped address from the STUN response.
    /// If the transport address does not match any of the local candidates that the agent
    /// knows about, the mapped address represents a new candidate: a peer-reflexive
    /// candidate", whose base is the local candidate the request was sent from and whose
    /// priority is the PRIORITY the request carried. Returns the local candidate of the valid
    /// pair.
    fn local_candidate_for_mapped_address(
        &mut self,
        m: &Message,
        request: &BindingRequest,
    ) -> usize {
        let sent_index = request.local_index;
        let mut mapped = XorMappedAddress::default();
        if mapped.get_from(m).is_err() {
            return sent_index;
        }
        let mapped = SocketAddr::new(mapped.ip, mapped.port);
        let has_address = |c: &Candidate| {
            c.addr() == mapped
                || (c.port() == mapped.port() && c.address().parse::<IpAddr>() == Ok(mapped.ip()))
        };
        let sent = &self.local_candidates[sent_index];
        if has_address(sent) {
            return sent_index;
        }
        // Over TCP the mapped port is the connection's (an active candidate is signalled on
        // port 9, RFC 6544 Section 4.5): the same IP address is the same candidate.
        if sent.network_type().is_tcp() && sent.base_addr().ip() == mapped.ip() {
            return sent_index;
        }
        let (base, network_type) = (sent.base_addr(), sent.network_type());
        if let Some(known) = self.local_candidates.iter().position(|c| {
            has_address(c) && c.network_type() == network_type && c.base_addr() == base
        }) {
            return known;
        }

        // Bounded: a peer can answer each check with another mapped address.
        let learned = self
            .local_candidates
            .iter()
            .filter(|c| c.candidate_type() == CandidateType::PeerReflexive)
            .count();
        if learned >= MAX_LOCAL_PEER_REFLEXIVE_CANDIDATES {
            return sent_index;
        }
        let (component, tcp_type) = (sent.component(), sent.tcp_type());
        match (CandidatePeerReflexiveConfig {
            base_config: CandidateConfig {
                network: network_type.to_string(),
                address: mapped.ip().to_string(),
                port: mapped.port(),
                component,
                priority: request.priority.min(MAX_CANDIDATE_PRIORITY),
                ..CandidateConfig::default()
            },
            rel_addr: base.ip().to_string(),
            rel_port: base.port(),
        })
        .new_candidate_peer_reflexive()
        {
            Ok(mut prflx) => {
                prflx.tcp_type = tcp_type;
                // draft-ietf-mmusic-mdns-ice-candidates section 3.3.1: "Statistics related to
                // ICE candidates that are accessible to the web application MUST NOT contain
                // the IP address of a local or remote mDNS candidate". With host addresses
                // hidden, the base is not given in the related address, and a mapped address
                // that is a hidden host address of this agent shows as its name.
                if self.mdns_mode == MulticastDnsMode::QueryAndGather {
                    prflx.hide_related_address = true;
                    if let Some(name) = self.mdns_name_of_hidden(mapped.ip()) {
                        prflx.address = name;
                    }
                }
                debug!(
                    "[{}]: new local peer-reflexive candidate {} (base {})",
                    self.get_name(),
                    mapped,
                    base
                );
                self.local_candidates.push(prflx);
                self.local_candidates.len() - 1
            }
            Err(err) => {
                warn!(
                    "[{}]: cannot make a local peer-reflexive candidate for {}: {}",
                    self.get_name(),
                    mapped,
                    err
                );
                sent_index
            }
        }
    }

    /// The valid pair with this local candidate, created beside the checklist when it is
    /// not there (Section 7.2.5.3.2, case 3).
    fn valid_pair_for(&mut self, local_index: usize, remote_index: usize) -> usize {
        if let Some(index) = self.find_pair_exact(local_index, remote_index) {
            return index;
        }
        let mut pair = CandidatePair::new(
            local_index,
            remote_index,
            self.local_candidates[local_index].priority(),
            self.remote_candidates[remote_index].priority(),
            self.is_controlling,
        );
        pair.foundation = self.pair_foundation(local_index, remote_index);
        pair.state = CandidatePairState::Succeeded;
        self.candidate_pairs.push(pair);
        let index = self.candidate_pairs.len() - 1;
        self.announce_pair(index, true);
        index
    }

    /// An error response to one of our Binding requests, already authenticated.
    ///
    /// RFC 8445 Section 7.2.5.1: a 487 (Role Conflict) switches the role away from the one the
    /// request claimed, changes the tiebreaker, and the pair goes back on the triggered-check
    /// queue. Section 7.2.5.2.4: any other error response is unrecoverable and fails the pair.
    pub(crate) fn handle_error_response(
        &mut self,
        now: Instant,
        m: &Message,
        remote_addr: SocketAddr,
    ) {
        use crate::rand::generate_tie_breaker;
        use stun::error_code::{CODE_ROLE_CONFLICT, ErrorCodeAttribute};

        let Some(pending) = self.handle_inbound_binding_success(now, m.transaction_id) else {
            warn!(
                "[{}]: discard error response from ({}), unknown TransactionID 0x{:?}",
                self.get_name(),
                remote_addr,
                m.transaction_id
            );
            return;
        };
        if pending.destination != remote_addr {
            return;
        }

        let mut error = ErrorCodeAttribute::default();
        let role_conflict = error.get_from(m).is_ok() && error.code == CODE_ROLE_CONFLICT;
        let pair_index = self.find_pair_exact(pending.local_index, pending.remote_index);
        let is_selected = pair_index.is_some() && pair_index == self.selected_pair;

        if role_conflict {
            if pending.sent_as_controlling == self.is_controlling {
                log::info!(
                    "[{}]: 487 (Role Conflict) from {}: switching role",
                    self.get_name(),
                    remote_addr
                );
                self.switch_role(now);
            }
            match generate_tie_breaker(self.crypto_provider.random()) {
                Ok(tie_breaker) => self.tie_breaker = tie_breaker,
                Err(err) => warn!(
                    "[{}]: cannot generate a new tiebreaker: {}",
                    self.get_name(),
                    err
                ),
            }
            // "the agent MUST add the candidate pair whose check generated the 487 error
            // response to the triggered-check queue [...] and set the candidate pair state to
            // Waiting." The selected pair keeps its state: its next consent check carries the
            // new role.
            if let Some(pair_index) = pair_index
                && !is_selected
                && !pending.cancelled
                && self.candidate_pairs[pair_index].state != CandidatePairState::Succeeded
            {
                self.candidate_pairs[pair_index].state = CandidatePairState::Waiting;
                self.enqueue_triggered(pair_index);
            }
            self.request_connectivity_check();
        } else if let Some(pair_index) = pair_index
            && !is_selected
            && !pending.cancelled
            && !pending.consent
        {
            // (An error answer to a consent check on the selected pair grants no consent, RFC
            // 7675 Section 5.1, and takes nothing away either.)
            if self.failed_nomination == FailedNomination::FailChecklist
                && (self.is_open_nomination(&pending, pair_index)
                    || self.is_followed_nomination(&pending, pair_index))
            {
                self.fail_nomination(now, pair_index, "an error response");
                return;
            }
            debug!(
                "[{}]: error response {} from {}: pair {} failed",
                self.get_name(),
                error,
                remote_addr,
                self.candidate_pairs[pair_index]
            );
            self.fail_pair(pair_index);
            self.maybe_nominate(now);
        }
    }

    /// The transaction `id` failed on an authenticated response the agent cannot use (RFC 8489
    /// Section 6.3.4: an error response with unknown comprehension-required attributes): its
    /// pair fails as on an error response (Section 7.2.5.2.4), its nomination with the
    /// checklist by default (Section 7.2.5.3.4).
    pub(crate) fn handle_failed_transaction(
        &mut self,
        now: Instant,
        id: TransactionId,
        remote_addr: SocketAddr,
    ) {
        let Some(pending) = self.handle_inbound_binding_success(now, id) else {
            return;
        };
        if pending.destination != remote_addr || pending.cancelled || pending.consent {
            return;
        }
        let Some(pair_index) = self.find_pair_exact(pending.local_index, pending.remote_index)
        else {
            return;
        };
        if self.selected_pair == Some(pair_index) {
            return;
        }
        if self.failed_nomination == FailedNomination::FailChecklist
            && (self.is_open_nomination(&pending, pair_index)
                || self.is_followed_nomination(&pending, pair_index))
        {
            self.fail_nomination(now, pair_index, "an unusable error response");
            return;
        }
        self.fail_pair(pair_index);
        self.maybe_nominate(now);
    }

    // ---------------------------------------------------------------------------------------
    // Requests (Sections 7.3.1.4, 7.3.1.5, 7.3.2)
    // ---------------------------------------------------------------------------------------

    /// What an authenticated Binding request does beyond being answered. The caller answered
    /// it and made sure the pair is on the checklist.
    pub(crate) fn handle_binding_request(
        &mut self,
        now: Instant,
        m: &Message,
        local_index: usize,
        remote_index: usize,
    ) {
        let Some(pair_index) = self.find_pair(local_index, remote_index) else {
            return;
        };

        // A nomination is `USE-CANDIDATE` (value 1) or libwebrtc's `NOMINATION` value, read
        // only from the part of the request MESSAGE-INTEGRITY covers. It has a meaning for
        // the controlled agent only (Section 7.3.1.5); like libwebrtc, a controlling agent
        // ignores it and answers the check.
        let nomination = if self.is_controlling {
            0
        } else {
            nomination_of(m)
        };
        if nomination > 0 {
            let p = &mut self.candidate_pairs[pair_index];
            p.remote_nomination = p.remote_nomination.max(nomination);
            let value = p.remote_nomination;
            if let Some(valid) = p.valid_pair {
                let v = &mut self.candidate_pairs[valid];
                v.remote_nomination = v.remote_nomination.max(value);
            }
        }

        if self.lite && !self.is_controlling {
            // Section 7.3.2: a lite agent sends no checks. A request with USE-CANDIDATE is all
            // it gets: "the agent constructs a candidate pair [...] This candidate pair is
            // then added to the valid list" and its nominated flag is set. Without
            // USE-CANDIDATE there is nothing more to do than answer.
            if nomination > 0 {
                let p = &mut self.candidate_pairs[pair_index];
                p.state = CandidatePairState::Succeeded;
                p.valid = true;
                p.valid_pair = Some(pair_index);
                self.accept_nomination(now, pair_index);
            }
            return;
        }

        let p = self.candidate_pairs[pair_index];
        if p.state == CandidatePairState::Succeeded {
            // Section 7.3.1.4: "If the state of that pair is Succeeded, nothing further is
            // done." Section 7.3.1.5: with USE-CANDIDATE, "the agent sets the nominated flag
            // value of the valid pair to true". Which nominated pair is then used is
            // `accept_nomination`'s business.
            if nomination > 0 {
                self.accept_nomination(now, p.valid_pair.unwrap_or(pair_index));
            } else {
                self.maybe_nominate(now);
            }
            return;
        }

        if nomination > 0 {
            // Section 7.3.1.5: the nomination takes effect once our triggered check on this
            // pair succeeds (see `handle_success_response`). If the check fails, the pair is
            // not used.
            self.candidate_pairs[pair_index].nomination_pending = true;
        }
        // Section 7.3.1.4: In-Progress, Waiting, Frozen or Failed: a triggered check.
        self.trigger_check(pair_index);
    }

    // ---------------------------------------------------------------------------------------
    // Nomination and conclusion (Section 8)
    // ---------------------------------------------------------------------------------------

    /// Controlled agent: `pair_index`, a valid pair, was nominated by the controlling agent.
    /// It becomes the selected pair when there is none. When there is one:
    ///
    /// - [`NominationAcceptance::HighestPriority`] (RFC 8445 Section 8.1.1: "the agents MUST
    ///   produce the selected pairs and use the pairs with the highest priority"): it takes
    ///   over when its priority is higher. A nominated pair of lower priority takes over only
    ///   when the selected pair has lost the peer's consent (the agent is `Disconnected`): that
    ///   pair is on its way out of the valid list, and the highest-priority nominated pair is
    ///   then this one.
    /// - [`NominationAcceptance::Latest`] (libwebrtc): it takes over unless the selected pair
    ///   carries a higher nomination (libwebrtc's renomination: the highest `NOMINATION` value
    ///   wins, so a delayed earlier one does not move the session back). Between regular
    ///   nominations, all value 1, the latest one wins.
    ///
    /// Switching emits `SelectedCandidatePairChange`, and `media_path` follows at once: DTLS,
    /// SRTP and SCTP go out on the new pair from the next datagram.
    pub(crate) fn accept_nomination(&mut self, now: Instant, pair_index: usize) {
        self.candidate_pairs[pair_index].nominated = true;
        match self.get_selected_pair() {
            Some(selected) if selected == pair_index => {}
            Some(selected) => {
                let (current, offered) = (
                    self.candidate_pairs[selected],
                    self.candidate_pairs[pair_index],
                );
                let takes_over = match self.nomination_acceptance {
                    NominationAcceptance::HighestPriority => {
                        offered.priority() > current.priority()
                            || self.connection_state == ConnectionState::Disconnected
                    }
                    NominationAcceptance::Latest => {
                        offered.remote_nomination >= current.remote_nomination
                    }
                };
                if takes_over {
                    debug!(
                        "[{}]: peer nominated another pair: switching selected pair from {} to {} (nomination {} -> {})",
                        self.get_name(),
                        current,
                        offered,
                        current.remote_nomination,
                        offered.remote_nomination
                    );
                    if self.nomination_acceptance == NominationAcceptance::Latest {
                        self.candidate_pairs[selected].nominated = false;
                    }
                    self.set_selected_pair(Some(now), Some(pair_index));
                    self.conclude();
                } else {
                    debug!(
                        "[{}]: nomination of {} accepted, selected pair {} kept (nomination {} / {})",
                        self.get_name(),
                        offered,
                        current,
                        offered.remote_nomination,
                        current.remote_nomination
                    );
                }
            }
            None => {
                self.set_selected_pair(Some(now), Some(pair_index));
                self.conclude();
            }
        }
    }

    /// Controlled agent, [`NominationAcceptance::HighestPriority`], when consent is lost on
    /// the selected pair: the session moves to the nominated valid pair with the highest
    /// priority the peer has been heard on since it last consented on the selected one, if
    /// there is one. (RFC 8445 Section 8.1.1 uses the nominated pairs "with the highest
    /// priority"; a pair without consent may not be sent on, RFC 7675 Section 5.1.)
    pub(crate) fn fall_back_to_another_nominated_pair(&mut self, now: Instant) {
        if self.is_controlling
            || self.nomination_acceptance != NominationAcceptance::HighestPriority
        {
            return;
        }
        let Some(selected) = self.selected_pair else {
            return;
        };
        let last_consent = self.pair_consent(selected).unwrap_or(self.start_time);
        let best = self
            .candidate_pairs
            .iter()
            .enumerate()
            .filter(|(index, p)| {
                *index != selected
                    && p.nominated
                    && p.valid
                    && p.state == CandidatePairState::Succeeded
                    && p.remote_index != self.candidate_pairs[selected].remote_index
                    && self.remote_candidates[p.remote_index]
                        .last_authenticated()
                        .is_some_and(|heard| heard > last_consent)
            })
            .max_by_key(|(_, p)| p.priority())
            .map(|(index, _)| index);
        if let Some(pair_index) = best {
            debug!(
                "[{}]: consent lost on {}: moving to the nominated pair {}",
                self.get_name(),
                self.candidate_pairs[selected],
                self.candidate_pairs[pair_index]
            );
            self.set_selected_pair(Some(now), Some(pair_index));
            self.conclude();
        }
    }

    /// What the transport learned about the path `transport` (its local address the base of
    /// a local candidate, its peer address a remote candidate):
    ///
    /// - [`TransportError::IcmpHardError`], RFC 8445 Section 7.2.5.2.2: "if a Binding request
    ///   generates a hard ICMP error, the agent SHOULD set the state of the candidate pair to
    ///   Failed". Only a pair whose check is in flight fails, and never a valid one: an ICMP
    ///   error is not authenticated ("ICMP errors can be used as a method for
    ///   Denial-of-Service attacks"), so it cannot take away a pair a check has validated.
    ///   Consent decides for those.
    /// - [`TransportError::ConnectionFailed`], RFC 6544 Section 7.1: "If the TCP connection
    ///   cannot be established, the check is considered to have failed, and a full-mode agent
    ///   MUST update the pair state to Failed". The pair fails whether or not its check has
    ///   started; a valid pair is left to consent, as above.
    /// - [`TransportError::NotStun`], RFC 6544 Section 7.1: "If the response to the first
    ///   connectivity check on the established TCP connection is something other than a STUN
    ///   message, the remote candidate address apparently was not one of the peer's addresses,
    ///   and the agent SHOULD close the connection and consider all pairs with that remote
    ///   candidate as failed." Every pair with that remote candidate that is not valid fails;
    ///   closing the connection is the caller's.
    ///
    /// Returns whether a pair failed.
    pub fn handle_transport_error(
        &mut self,
        now: Instant,
        transport: shared::TransportContext,
        error: TransportError,
    ) -> bool {
        let Some(local_index) =
            self.find_local_candidate(transport.local_addr, transport.transport_protocol)
        else {
            return false;
        };
        let Some(remote_index) = self.remote_candidates.iter().position(|c| {
            c.addr() == transport.peer_addr
                && c.network_type().to_protocol() == transport.transport_protocol
        }) else {
            return false;
        };
        let is_tcp = transport.transport_protocol == shared::TransportProtocol::TCP;
        let mut failed = vec![];
        for (index, p) in self.candidate_pairs.iter().enumerate() {
            if p.remote_index != remote_index
                || p.valid
                || p.state == CandidatePairState::Succeeded
                || p.state == CandidatePairState::Failed
                || Some(index) == self.selected_pair
            {
                continue;
            }
            let on_path = self.same_base(p.local_index, local_index);
            let fails = match error {
                TransportError::IcmpHardError => {
                    on_path && p.state == CandidatePairState::InProgress
                }
                TransportError::ConnectionFailed => is_tcp && on_path,
                TransportError::NotStun => is_tcp,
            };
            if fails {
                failed.push(index);
            }
        }
        if error == TransportError::NotStun
            && !failed.iter().any(|&index| {
                self.candidate_pairs[index].state == CandidatePairState::InProgress
                    && self.same_base(self.candidate_pairs[index].local_index, local_index)
            })
        {
            // Not the answer to a first check: nothing is concluded from it.
            return false;
        }
        for &index in &failed {
            let p = self.candidate_pairs[index];
            debug!(
                "[{}]: {:?} on {}: the pair failed",
                self.get_name(),
                error,
                p
            );
            self.pending_binding_requests
                .retain(|r| !(r.local_index == p.local_index && r.remote_index == p.remote_index));
            self.fail_pair(index);
        }
        if !failed.is_empty() {
            self.maybe_nominate(now);
            self.request_connectivity_check();
        }
        !failed.is_empty()
    }

    /// Something other than STUN arrived over TCP on `transport`, on no valid pair: what a
    /// driver that demultiplexes the connection itself (the peer connection does) calls
    /// instead of deciding on [`TransportError::NotStun`] on its own.
    ///
    /// RFC 6544 Section 7.1 concludes from "the response to the first connectivity check on
    /// the established TCP connection". Only on a connection this agent opened (its local
    /// candidate is active) are the peer's first bytes that response: the agent sends its
    /// check as soon as the connection is up, and the peer has nothing to send before it. On
    /// a connection the peer opened (a passive local candidate) the peer may send DTLS before
    /// it answers this agent's triggered check, so nothing is concluded there. Returns
    /// whether a pair failed; closing the connection is the caller's.
    pub fn handle_non_stun_before_validation(
        &mut self,
        now: Instant,
        transport: shared::TransportContext,
    ) -> bool {
        if transport.transport_protocol != shared::TransportProtocol::TCP {
            return false;
        }
        let opened_here = self
            .find_local_candidate(transport.local_addr, transport.transport_protocol)
            .is_some_and(|local| {
                self.local_candidates[local].tcp_type() == crate::tcp_type::TcpType::Active
            });
        opened_here && self.handle_transport_error(now, transport, TransportError::NotStun)
    }

    /// Two lite agents (RFC 8445 Sections 6.2 and 8.2): "the agent pairs local candidates
    /// with remote candidates that are of the same data stream and have the same component,
    /// transport protocol, and IP address family. [...] if there is only one candidate pair,
    /// that pair is added to the valid list. If there is more than one pair, it is
    /// RECOMMENDED that an agent follow the procedures of RFC 6724 to select a pair and add it
    /// to the valid list." The pair chosen is the selected pair: there is no nomination
    /// between two agents that send no checks.
    ///
    /// With more than one pair "the controlling agent MUST send an updated candidate list":
    /// it raises [`Event::LiteCandidateUpdate`], once, with the pair it chose; the peer takes
    /// the update with [`Agent::replace_remote_candidates`].
    pub(crate) fn conclude_lite_to_lite(&mut self, now: Instant) {
        if self.selected_pair.is_some()
            || self.ufrag_pwd.remote_credentials.is_none()
            || matches!(
                self.connection_state,
                ConnectionState::Failed | ConnectionState::Closed
            )
        {
            return;
        }
        let Some(chosen) =
            (0..self.candidate_pairs.len()).max_by_key(|&index| self.lite_pair_preference(index))
        else {
            return;
        };
        let several = self.candidate_pairs.len() > 1;
        {
            let p = &mut self.candidate_pairs[chosen];
            p.state = CandidatePairState::Succeeded;
            p.valid = true;
            p.valid_pair = Some(chosen);
        }
        self.set_selected_pair(Some(now), Some(chosen));
        if several && self.is_controlling && !self.lite_update_raised {
            self.lite_update_raised = true;
            let p = self.candidate_pairs[chosen];
            self.event_outs.push_back(crate::agent::TaggedEvent {
                now,
                event: crate::agent::Event::LiteCandidateUpdate(
                    Box::new(self.local_candidates[p.local_index].clone()),
                    Box::new(self.remote_candidates[p.remote_index].clone()),
                ),
            });
        }
    }

    /// How a pair ranks among the pairs of two lite agents, larger first: a pair whose local
    /// candidate an updated candidate exchange named (`pinned_local_addr`), then the destination
    /// address selection of RFC 6724 Section 6, as far as it applies to two transport
    /// addresses that are given: Rule 2, prefer matching scope (link-local with link-local,
    /// loopback with loopback, global with global); Rule 6, prefer higher precedence (the
    /// default policy table puts IPv6 above IPv4); Rule 9, the longest matching prefix
    /// between source and destination. What is left is decided by the pair priority, which
    /// both agents compute alike.
    fn lite_pair_preference(&self, index: usize) -> (bool, bool, bool, u32, u64) {
        use crate::agent::remote_policy::ip_scope;

        let p = &self.candidate_pairs[index];
        // RFC 8839 Section 4.4.2.2: the local candidate an updated exchange named wins.
        let pinned = self.pinned_local_addr.is_some_and(|pinned| {
            let candidate = &self.local_candidates[p.local_index];
            candidate.addr() == pinned || candidate.base_addr() == pinned
        });
        let local = self.local_candidates[p.local_index].base_addr().ip();
        let remote = self.remote_candidates[p.remote_index].addr().ip();
        let matching_scope = ip_scope(local) == ip_scope(remote);
        let is_v6 = matches!(remote.to_canonical(), IpAddr::V6(_));
        let common_prefix = match (local.to_canonical(), remote.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) ^ u32::from(b)).leading_zeros(),
            (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a) ^ u128::from(b)).leading_zeros(),
            _ => 0,
        };
        (pinned, matching_scope, is_v6, common_prefix, p.priority())
    }

    /// Controlling agent that has concluded: sends the nomination of its selected pair again
    /// (a check with USE-CANDIDATE, retransmitted like any check). Used when the peer has
    /// shown that it does not hold the nomination; no other pair is ever nominated.
    pub(crate) fn repeat_nomination(&mut self) {
        let Some(selected) = self.selected_pair else {
            return;
        };
        if !self.is_controlling || (self.lite && self.is_controlling) {
            return;
        }
        self.candidate_pairs[selected].nominate = true;
        self.enqueue_triggered(selected);
    }

    /// Controlling agent, regular nomination (Section 8.1.1): once its best valid pair has
    /// waited long enough for its type, that pair is put on the triggered-check queue for a
    /// check with USE-CANDIDATE. One nomination is in flight at a time; when it fails the
    /// next valid pair is nominated.
    pub(crate) fn maybe_nominate(&mut self, now: Instant) {
        if !self.is_controlling || self.selected_pair.is_some() || self.nominated_pair.is_some() {
            return;
        }
        // Checks that have failed (`Agent::fail_or_hold`, the agent `Disconnected` until no
        // candidate is to come) nominate nothing more until a new pair comes.
        if self.failure_held.is_some() {
            return;
        }
        let Some(pair_index) = self.get_best_valid_candidate_pair() else {
            return;
        };
        let p = self.candidate_pairs[pair_index];
        // The wait is that of the candidates the agent chose to check: when the valid pair's
        // local candidate is the mapped address of the response, the candidate its check was
        // sent from.
        let checked_local = self
            .candidate_pairs
            .iter()
            .enumerate()
            .find(|(index, c)| *index != pair_index && c.valid_pair == Some(pair_index))
            .map_or(p.local_index, |(_, c)| c.local_index);
        if !self.is_nominatable(now, checked_local, true)
            || !self.is_nominatable(now, p.remote_index, false)
        {
            return;
        }
        if self.candidate_pair_proposals {
            // webrtc-extensions 7: propose the pair, once; the application decides.
            if self.nomination_proposal.is_some() || self.declined_nominations.contains(&pair_index)
            {
                return;
            }
            self.nomination_proposal = Some(pair_index);
            self.event_outs.push_back(crate::agent::TaggedEvent {
                now,
                event: crate::agent::Event::CandidatePairNominationProposed(
                    Box::new(self.local_candidates[p.local_index].clone()),
                    Box::new(self.remote_candidates[p.remote_index].clone()),
                ),
            });
            return;
        }
        trace!(
            "Nominatable pair found, nominating ({}, {})",
            self.local_candidates[p.local_index], self.remote_candidates[p.remote_index],
        );
        self.candidate_pairs[pair_index].nominate = true;
        self.nominated_pair = Some(pair_index);
        self.nomination_started = Some(now);
        self.enqueue_triggered(pair_index);
    }

    /// Whether the controlling agent's nomination of `pair_index` may still be answered: the
    /// peer has been heard from on the pair's remote candidate (an authenticated request or
    /// response) or the nomination started, less than the consent expiry ago (30 seconds,
    /// the time RFC 7675 Section 5.1 gives a peer to answer before the path is given up).
    pub(crate) fn nomination_is_alive(&self, now: Instant, pair_index: usize) -> bool {
        let p = &self.candidate_pairs[pair_index];
        let heard = self
            .remote_candidates
            .get(p.remote_index)
            .and_then(|r| r.last_authenticated);
        let started = self
            .nomination_started
            .filter(|_| self.nominated_pair == Some(pair_index));
        heard
            .into_iter()
            .chain(started)
            .max()
            .is_some_and(|at| now.saturating_duration_since(at) < self.consent_expiry())
    }

    /// Controlling agent, checking, with `FailedNomination::Retry`: a nomination the peer has
    /// not been heard from on for the consent expiry is given up. The pair fails (its
    /// transactions with it), and the next valid pair, if there is one, is nominated.
    ///
    /// With `FailedNomination::FailChecklist` (RFC 8445 Section 7.2.5.3.4) a nomination fails
    /// only as a request does (Section 7.2.5.2): at the end of its transaction (Section 14.3),
    /// by an error response or by a response from another address; not by this.
    pub(crate) fn expire_unanswered_nomination(&mut self, now: Instant) {
        let Some(nominated) = self.nominated_pair else {
            return;
        };
        if self.failed_nomination != FailedNomination::Retry
            || !self.is_controlling
            || self.selected_pair.is_some()
            || self.nomination_is_alive(now, nominated)
        {
            return;
        }
        warn!(
            "[{}]: nomination of {} is unanswered and the peer is not heard from: the pair failed",
            self.get_name(),
            self.candidate_pairs[nominated]
        );
        let p = self.candidate_pairs[nominated];
        self.pending_binding_requests
            .retain(|r| !(r.local_index == p.local_index && r.remote_index == p.remote_index));
        self.fail_pair(nominated);
        self.nomination_started = None;
        self.maybe_nominate(now);
    }

    /// Whether something may still produce a selected pair: a pair Frozen, Waiting or In
    /// Progress, a triggered check queued, a valid pair the controlling agent nominates (or
    /// will), or a pair the peer has been heard from on within the consent expiry (the peer
    /// is checking it, and the controlled agent waits for its nomination). While this holds,
    /// the checklist has not failed (RFC 8445 Section 8.1.2) and the agent does not fail by
    /// its timer.
    pub(crate) fn checks_in_progress(&self, now: Instant) -> bool {
        if !self.triggered_queue.is_empty() {
            return true;
        }
        let expiry = self.consent_expiry();
        self.candidate_pairs.iter().any(|p| match p.state {
            CandidatePairState::Frozen
            | CandidatePairState::Waiting
            | CandidatePairState::InProgress => true,
            CandidatePairState::Failed | CandidatePairState::Unspecified => false,
            CandidatePairState::Succeeded => {
                (self.is_controlling && p.valid)
                    || self
                        .remote_candidates
                        .get(p.remote_index)
                        .and_then(|r| r.last_authenticated)
                        .is_some_and(|at| now.saturating_duration_since(at) < expiry)
            }
        })
    }

    /// Section 8.1.2, once a pair is nominated: "the ICE agent MUST remove all candidate pairs
    /// for the same component from the checklist and from the triggered-check queue. If the
    /// state of a pair is In-Progress, the agent cancels the In-Progress transaction". The
    /// other pairs leave the triggered-check queue, their In-Progress transactions are
    /// cancelled, and every pair still to be checked (Frozen, Waiting, or In-Progress until
    /// now) is Failed: that is how the agent represents a pair that is out of the checklist
    /// (as `remove_pair_at` does), so that no reader of pair states (Ta's next check, the
    /// pairs left to check when consent is lost, the checks in progress the checking timeout
    /// waits for, the checklist's failure) can take it for one still to come, also once the
    /// selected pair is gone (lost consent; Section 8.1.1: no other pair may be nominated in
    /// this ICE session). The pairs stay in the list (their statistics say `failed`), and
    /// because the peer may still nominate another one a request on one of them is answered
    /// and triggers a check as for any Failed pair (Section 7.3.1.4). Pairs formed later are
    /// checked as any other; an ICE restart replaces them all.
    pub(crate) fn conclude(&mut self) {
        let Some(selected) = self.selected_pair else {
            return;
        };
        let mut cancel: Vec<(usize, usize)> = vec![];
        for (index, p) in self.candidate_pairs.iter_mut().enumerate() {
            // (A pair the peer nominated keeps its place in the queue too.)
            p.triggered = p.triggered && p.nomination_pending;
            p.nominate = false;
            // A pair the peer nominated before its check finished keeps its transaction: its
            // answer decides whether the peer's (later) nomination is followed.
            if index != selected
                && p.state == CandidatePairState::InProgress
                && !p.nomination_pending
            {
                p.state = CandidatePairState::Waiting;
                cancel.push((p.local_index, p.remote_index));
            }
            if index != selected
                && !p.nomination_pending
                && matches!(
                    p.state,
                    CandidatePairState::Frozen | CandidatePairState::Waiting
                )
            {
                p.state = CandidatePairState::Failed;
            }
        }
        for (local_index, remote_index) in cancel {
            self.cancel_transactions(local_index, remote_index);
        }
        let pairs = &self.candidate_pairs;
        self.triggered_queue.retain(|(local_index, remote_index)| {
            pairs.iter().any(|p| {
                p.triggered && p.local_index == *local_index && p.remote_index == *remote_index
            })
        });
        // The state is looked at again at once: `Completed` when both sides are done
        // gathering.
        self.request_connectivity_check();
    }

    /// Sections 7.2.5.4 and 8.1.2 with RFC 8838 Section 8: the checklist is Failed when every
    /// pair has failed and none is valid, but only once no pair can be added any more: local
    /// gathering is complete and the peer has signalled end-of-candidates. Until then a
    /// checking agent fails by its timeout only.
    ///
    /// A pair can also be added by a check from the peer (Section 7.3.1.3: a peer-reflexive
    /// remote candidate and its pair), signalled candidates or not. While the peer has
    /// signalled a candidate the agent does not pair but whose checks can reach it (a
    /// `tcptype active` candidate dialling a local passive one, RFC 6544 Section 7.2; a `.local`
    /// name not resolved, mDNS draft Section 5.3), the agent expects such a pair: the
    /// checklist stays Running (RFC 8838 Section 8: "MUST keep each checklist in the Running
    /// state as long as it expects candidate pairs to be incrementally added") and the
    /// agent's timeout ends it if none comes.
    ///
    /// A lite agent has no checklist to fail: RFC 8445 Section 6.2, "Lite implementations
    /// skip most of the steps in Section 6 except for verifying the peer's ICE support and
    /// determining its role in the ICE processing" (the checklist and its Failed state,
    /// Section 6.1.2.1, are a full agent's), and it "do[es] not generate connectivity checks"
    /// (Section 2.5), so none of its pairs fails by a check. With no pair yet its pair comes
    /// from the peer: a full peer's check (a peer-reflexive pair, RFC 8838 Appendix B), or, a
    /// lite peer, a candidate it still sends (the engine trickles its TCP candidates once their
    /// listeners are bound; a peer's description without `trickle` does not stop it from
    /// sending one). Its checking timeout still ends
    /// it, with the indications that no candidate is to come.
    pub(crate) fn update_checklist_failure(&mut self, now: Instant) {
        if self.lite
            || self.connection_state != ConnectionState::Checking
            || self.selected_pair.is_some()
            || self.pac_running(now)
            || !self.no_more_remote_candidates()
            || !self.local_gathering_complete
            || !self.mdns_queries.is_empty()
            || !self.early_requests.is_empty()
            || !self.triggered_queue.is_empty()
            || self.pair_may_come_from_a_peer_check()
        {
            return;
        }
        if self
            .candidate_pairs
            .iter()
            .all(|p| p.state == CandidatePairState::Failed)
        {
            debug!(
                "[{}]: every pair failed and no candidate is to come: the checklist failed",
                self.get_name()
            );
            self.update_connection_state(Some(now), ConnectionState::Failed);
        }
    }

    /// Whether the PAC timer (RFC 8863 Section 4, "Patiently Awaiting Connectivity") of a full
    /// agent is running at `now`. It starts when ICE processing begins (`start`: the peer's
    /// credentials are in, candidates or not), and "while the timer is still running, the ICE
    /// agent MUST NOT update a checklist state from Running to Failed, even if there are no
    /// pairs left in the checklist to check": a check from the peer can still make a
    /// peer-reflexive pair (RFC 8445 Section 7.3.1.3) when the agent has no pair (the peer
    /// signalled no candidate, or none the agent can use; RFC 8863 Sections 3.1, 3.2) or only
    /// failed ones (Section 3.3), and Section 5 keeps it so after end-of-candidates. Its
    /// length is the RECOMMENDED one, "equal to the agent's connectivity check transaction
    /// timeout, including all retransmissions": `Rc` requests from the 500 ms RTO and `Rm`
    /// RTOs after the last, 39.5 s with the defaults.
    pub(crate) fn pac_running(&self, now: Instant) -> bool {
        if self.lite {
            return false;
        }
        let rc = u32::from(self.max_binding_requests.clamp(1, 16));
        let pac = MIN_RTO * ((1u32 << (rc - 1)) - 1 + STUN_RM);
        now < self.start_time + pac
    }

    /// A lite agent's keepalive (RFC 8445 Section 11): it sends no Binding requests, so when
    /// it has sent nothing on the selected pair for Tr (15 seconds) it sends a Binding
    /// indication: no authentication, FINGERPRINT only.
    pub(crate) fn lite_keepalive(&mut self, now: Instant) {
        let Some(pair_index) = self.selected_pair else {
            return;
        };
        if self.keepalive_interval == Duration::ZERO {
            return;
        }
        let p = self.candidate_pairs[pair_index];
        let last_sent = self.local_candidates[p.local_index]
            .last_sent()
            .unwrap_or(self.start_time);
        if now.saturating_duration_since(last_sent) < KEEPALIVE_TR {
            return;
        }
        let mut msg = Message::new();
        if let Err(err) = msg.build(&[
            Box::new(MessageType::new(METHOD_BINDING, CLASS_INDICATION)),
            Box::new(TransactionId::new()),
            Box::new(FINGERPRINT),
        ]) {
            error!("{}", err);
            return;
        }
        self.send_stun(now, &msg, p.local_index, p.remote_index);
    }

    /// Called when the session (re)starts.
    pub(crate) fn start(&mut self, now: Instant) {
        self.nominated_pair = None;
        self.start_time = now;
        self.next_check_at = now;
    }
}
