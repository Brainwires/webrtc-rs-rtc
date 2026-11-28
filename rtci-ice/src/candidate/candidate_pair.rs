//! Candidate pairs and their check state.
//!
//! ICE forms a pair from each compatible local/remote candidate combination and works through
//! them in priority order. A pair's combined priority is computed from both sides' priorities with
//! the controlling agent's dominating, so both agents derive the same ordering.
//!
//! [`CandidatePairState`](crate::candidate::candidate_pair::CandidatePairState) tracks how far a pair has got (RFC 8445 Section 6.1.2.6): frozen,
//! waiting, in progress, succeeded or failed. The controlling agent nominates one of the valid
//! pairs, and that pair carries the media.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};

/// Represent the ICE candidate pair state.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CandidatePairState {
    #[default]
    #[serde(rename = "unspecified")]
    /// No state was set.
    Unspecified = 0,

    /// Means a check has not been performed for this pair.
    #[serde(rename = "waiting")]
    Waiting = 1,

    /// Means a check has been sent for this pair, but the transaction is in progress.
    #[serde(rename = "in-progress")]
    InProgress = 2,

    /// Means a check for this pair was already done and failed, either never producing any response
    /// or producing an unrecoverable failure response.
    #[serde(rename = "failed")]
    Failed = 3,

    /// Means a check for this pair was already done and produced a successful result.
    #[serde(rename = "succeeded")]
    Succeeded = 4,

    /// Means a check for this pair has not been sent, and it cannot be sent until the pair is
    /// unfrozen: another pair with the same foundation is being checked first.
    #[serde(rename = "frozen")]
    Frozen = 5,
}

impl From<u8> for CandidatePairState {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Waiting,
            2 => Self::InProgress,
            3 => Self::Failed,
            4 => Self::Succeeded,
            5 => Self::Frozen,
            _ => Self::Unspecified,
        }
    }
}

impl fmt::Display for CandidatePairState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::Waiting => "waiting",
            Self::InProgress => "in-progress",
            Self::Failed => "failed",
            Self::Succeeded => "succeeded",
            Self::Frozen => "frozen",
            Self::Unspecified => "unspecified",
        };

        write!(f, "{s}")
    }
}

/// Represents a combination of a local and remote candidate.
#[derive(Clone, Copy)]
pub struct CandidatePair {
    /// Index of the local candidate in the agent's list.
    pub local_index: usize,
    /// Index of the remote candidate in the agent's list.
    pub remote_index: usize,
    /// The local candidate's priority.
    pub local_priority: u32,
    /// The remote candidate's priority.
    pub remote_priority: u32,
    pub(crate) ice_role_controlling: bool,
    pub(crate) state: CandidatePairState,
    /// The nominated flag of a valid pair (RFC 8445 Section 7.2.5.3.2).
    pub(crate) nominated: bool,
    /// The pair's foundation: its two candidates' foundations taken together (a hash of them).
    /// Pairs that share one are checked one at a time until one succeeds (Section 6.1.2.6).
    pub(crate) foundation: u32,
    /// The pair is in the valid list: a check produced it (Section 7.2.5.3.2).
    pub(crate) valid: bool,
    /// The valid pair this pair's successful check produced: the pair itself, or one whose
    /// local candidate is the mapped address the response reported.
    pub(crate) valid_pair: Option<usize>,
    /// The pair is in the triggered-check queue (Section 6.1.4.1).
    pub(crate) triggered: bool,
    /// Controlling agent: the next check on this pair carries USE-CANDIDATE (Section 8.1.1).
    pub(crate) nominate: bool,
    /// The highest nomination the controlling peer has sent on this pair (controlled agent):
    /// 1 for `USE-CANDIDATE`, or libwebrtc's `NOMINATION` value. 0 until it nominates the pair.
    pub(crate) remote_nomination: u32,
    /// The peer nominated this pair before its check succeeded here; the nomination takes
    /// effect when the triggered check does (RFC 8445 Section 7.3.1.5).
    pub(crate) nomination_pending: bool,
    /// The application removed the pair (`Agent::remove_candidate_pair`): it is Failed, no
    /// check is sent or answered on it, and it is not listed. It keeps its slot: pairs are
    /// referenced by index.
    pub(crate) removed: bool,
    /// Consent expired on this pair while it was selected and the agent went on (it was not
    /// failed: candidates may still come): it is removed, and the peer's requests on it are
    /// not answered either ("After consent is lost, the same ICE credentials MUST NOT be used
    /// on the affected 5-tuple again", RFC 7675 Section 5.1).
    pub(crate) consent_lost: bool,
    // STUN transaction stats
    /// Total number of STUN connectivity check requests sent (not including retransmissions).
    pub(crate) requests_sent: u64,
    /// Total number of STUN connectivity check requests received.
    pub(crate) requests_received: u64,
    /// Total number of STUN connectivity check responses sent.
    pub(crate) responses_sent: u64,
    /// Total number of STUN connectivity check responses received.
    pub(crate) responses_received: u64,
    /// Total number of consent freshness requests sent.
    pub(crate) consent_requests_sent: u64,

    // RTT tracking
    /// Sum of all round trip time measurements.
    pub(crate) total_round_trip_time: Duration,
    /// Latest round trip time measured.
    pub(crate) current_round_trip_time: Duration,
    /// The pair's RTO (RFC 8489 Section 6.2.1, RFC 6298): 500 ms until a round trip has been
    /// measured, then the smoothed round-trip time plus four times its variation, 500 ms at
    /// least. What a consent request's wait is based on (RFC 7675 Section 5.1).
    pub(crate) rto: stun::timer::RtoEstimator,
    /// When a success response to a Binding request sent on this pair last arrived: consent
    /// on the pair's 5-tuple (RFC 7675 Section 1, "Consent to send applies to a single
    /// 5-tuple"). Read through `Agent::pair_consent`, which takes the pairs of the same
    /// 5-tuple (the same local base and remote candidate) together.
    pub(crate) last_consent: Option<Instant>,
}

impl fmt::Debug for CandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prio {} (local, prio {}) {} <-> {} (remote, prio {})",
            self.priority(),
            self.local_priority,
            self.local_index,
            self.remote_index,
            self.remote_priority,
        )
    }
}

impl fmt::Display for CandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prio {} (local, prio {}) {} <-> {} (remote, prio {})",
            self.priority(),
            self.local_priority,
            self.local_index,
            self.remote_index,
            self.remote_priority,
        )
    }
}

impl PartialEq for CandidatePair {
    fn eq(&self, other: &Self) -> bool {
        self.local_index == other.local_index && self.remote_index == other.remote_index
    }
}

impl CandidatePair {
    #[must_use]
    /// Forms a pair from a local and a remote candidate.
    ///
    /// `controlling` selects which priority dominates in the pair's combined priority.
    pub fn new(
        local_index: usize,
        remote_index: usize,
        local_priority: u32,
        remote_priority: u32,
        ice_role_controlling: bool,
    ) -> Self {
        Self {
            local_index,
            remote_index,
            local_priority,
            remote_priority,
            ice_role_controlling,
            state: CandidatePairState::Waiting,
            nominated: false,
            foundation: 0,
            valid: false,
            valid_pair: None,
            triggered: false,
            nominate: false,
            remote_nomination: 0,
            nomination_pending: false,
            removed: false,
            consent_lost: false,
            // STUN transaction stats
            requests_sent: 0,
            requests_received: 0,
            responses_sent: 0,
            responses_received: 0,
            consent_requests_sent: 0,
            // RTT tracking
            total_round_trip_time: Duration::ZERO,
            current_round_trip_time: Duration::ZERO,
            rto: stun::timer::RtoEstimator::new(crate::agent::agent_config::MIN_RTO, true),
            last_consent: None,
        }
    }

    /// RFC 8445 Section 6.1.2.3, Computing Pair Priority and Ordering Pairs.
    /// Let G be the priority for the candidate provided by the controlling
    /// agent.  Let D be the priority for the candidate provided by the
    /// controlled agent.
    /// pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    pub fn priority(&self) -> u64 {
        let (g, d) = if self.ice_role_controlling {
            (self.local_priority, self.remote_priority)
        } else {
            (self.remote_priority, self.local_priority)
        };

        // Candidate priorities are at most 2^31 - 1 (Section 5.1.2), so the sum is under 2^63.
        // The arithmetic wraps rather than panics for a priority a raw `Candidate` was given
        // outside that range.
        (u64::from(std::cmp::min(g, d)) << 32)
            .wrapping_add(2 * u64::from(std::cmp::max(g, d)))
            .wrapping_add(u64::from(g > d))
    }

    /// Called when a STUN binding request is sent.
    pub fn on_request_sent(&mut self) {
        self.requests_sent += 1;
    }

    /// Called when a STUN binding request is received.
    pub fn on_request_received(&mut self) {
        self.requests_received += 1;
    }

    /// Called when a STUN binding success response is sent.
    pub fn on_response_sent(&mut self) {
        self.responses_sent += 1;
    }

    /// Called when a STUN binding success response is received.
    /// Also updates RTT measurements.
    pub fn on_response_received(&mut self, rtt: Duration) {
        self.responses_received += 1;
        self.current_round_trip_time = rtt;
        self.total_round_trip_time += rtt;
    }

    /// Called when a consent freshness request is sent (keepalive).
    pub fn on_consent_request_sent(&mut self) {
        self.consent_requests_sent += 1;
    }
}
