//! The RTCP session of an endpoint: who it is, when it speaks and what a packet looks like.
//!
//! See [`RtcpSessionInterceptor`].

mod ecn;
pub(crate) mod identity;
pub(crate) mod scheduler;

use crate::nack::{NackControl, older_than};
use crate::report::receiver_stream::ReceiverStream;
use crate::report::sender_stream::SenderStream;
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Interceptor, Packet, TaggedPacket};
use identity::{RtcpRandom, SharedRandom, ThreadRandom, choose_ssrc, generate_cname};
use rtcp::extended_report::{
    DLRRReport, DLRRReportBlock, EcnSummaryReport, EcnSummaryReportBlock, ExtendedReport,
    ReceiverReferenceTimeReportBlock,
};
use rtcp::goodbye::Goodbye;
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtcp::payload_feedbacks::slice_loss_indication::SliceLossIndication;
use rtcp::payload_feedbacks::temporal_spatial_tradeoff::{
    TemporalSpatialTradeoffNotification, TemporalSpatialTradeoffRequest,
};
use rtcp::receiver_report::ReceiverReport;
use rtcp::reception_report::ReceptionReport;
use rtcp::sender_report::SenderReport;
use rtcp::source_description::{
    SdesType, SourceDescription, SourceDescriptionChunk, SourceDescriptionItem,
};
use rtcp::transport_feedbacks::cc_feedback_report::CcFeedbackReport;
use rtcp::transport_feedbacks::ecn_feedback::EcnFeedback;
use rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest;
use rtcp::transport_feedbacks::tmmb::TemporaryMaximumBitrateRequest;
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use rtcp::transport_feedbacks::transport_layer_nack::{
    NackPair, TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use sansio::Protocol;
use scheduler::{
    BYE_BACKOFF_MEMBERS, IntervalInput, LOWER_LAYER_OVERHEAD, RTCP_BW_FRACTION, RTCP_MIN_TIME,
    RTCP_SENDER_BW_FRACTION, RegularDecision, TIMEOUT_MULTIPLIER, Timing, after,
    deterministic_interval, randomized_interval, reduced_minimum, regular_decision,
    seconds_between, update_avg_rtcp_size,
};
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::MarshalSize;
use shared::time::{SystemInstant, near_leap_second};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The session bandwidth assumed while none is configured and no media has been measured:
/// one audio stream.
pub const RTCP_SESSION_MIN_BANDWIDTH: u64 = 64_000;
/// The session bandwidth assumed for video at the start, while no `b=` line gave one and the
/// media has not yet had its two seconds to be measured: 1 Mbit/s, a camera stream at
/// standard definition.
///
/// RFC 3550 section 6.2 takes the RTCP bandwidth as a share of the session bandwidth, which
/// it lets "a session management application" supply; without one the session measures the
/// media, both ways, over the last two seconds (64 kbit/s at least). Before there is anything
/// to measure, this start-up value (with [`RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH`] for audio)
/// stands in, so the first reports are not held to an idle session's share. Congestion
/// control feedback does not depend on it: it follows the media it reports on
/// ([`RtcpSessionBuilder::with_immediate_congestion_feedback`]).
pub const RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH: u64 = 1_000_000;
/// The session bandwidth assumed for audio while none was signalled: 64 kbit/s, an Opus
/// stream at its high end for speech and the floor the session has always had.
pub const RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH: u64 = RTCP_SESSION_MIN_BANDWIDTH;

/// The nominal session bandwidth of a session that carries video and / or audio, bits per
/// second (see [`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH`]).
pub(crate) fn nominal_session_bandwidth(video: bool, audio: bool) -> f64 {
    let mut nominal = 0;
    if video {
        nominal += RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH;
    }
    if audio {
        nominal += RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH;
    }
    nominal.max(RTCP_SESSION_MIN_BANDWIDTH) as f64
}

/// The default of [`RtcpSessionBuilder::with_t_rr_interval`].
pub const RTCP_SESSION_DEFAULT_T_RR_INTERVAL: Duration = Duration::from_secs(1);
/// The default of [`RtcpSessionBuilder::with_mtu`]: the size a compound RTCP packet is kept
/// under, SRTCP and lower layers not counted.
pub const RTCP_SESSION_DEFAULT_MTU: usize = 1200;

/// The most sources the member table holds; RTCP from further unknown SSRCs is not counted.
const MAX_MEMBERS: usize = 1024;
/// The most feedback and other packets held for the next compound packet.
const MAX_PENDING: usize = 64;
/// The most receiver reference times held for answering at once.
const MAX_REFERENCE_TIMES: usize = 64;
/// The most timer expiries worked through in one call: a session left alone for long catches
/// up to here and starts over from the present.
const MAX_CATCH_UP: usize = 4096;
/// The window the media bitrate is measured over when no session bandwidth is configured.
const RATE_WINDOW: Duration = Duration::from_secs(2);
/// The size of one bucket of that window.
const RATE_BUCKET: Duration = Duration::from_millis(250);
/// RFC 5506 4.2.2: a feedback packet larger than this goes out compound, not reduced-size.
const REDUCED_SIZE_MAX: usize = 400;
/// RFC 5506 4.2.1: this many reduced-size NACK packets in a row with none of the packets
/// they asked for arriving, and the session falls back to compound packets.
const REDUCED_SIZE_UNANSWERED_LIMIT: u32 = 8;
/// The most report blocks one SR or RR carries (RFC 3550 6.4.1: RC is five bits).
const MAX_REPORT_BLOCKS: usize = 31;

/// The fraction lost (in 1/256: about 10%) from which a stream's report goes before the round
/// robin when not every report fits (RFC 8083 section 4.3).
const HIGH_LOSS_FRACTION: u8 = 26;
/// The longest `T_rr_interval` the RTCP bandwidth left over by congestion control feedback
/// stretches the regular reports to ([`RtcpSessionBuilder::with_congestion_feedback_in_budget`]),
/// seconds: RFC 4585 section 5 (interworking with AVP) has `T_rr_interval` "SHOULD NOT be larger
/// than five seconds" where RTP/AVP entities may take part.
const MAX_BUDGET_T_RR_INTERVAL: f64 = 5.0;

/// The least interval the session computes, in seconds. RTP/AVPF has no minimum for a
/// point-to-point session (RFC 4585 3.5.1), so with enough bandwidth the calculated interval
/// tends to nothing; a timer cannot.
const MIN_INTERVAL: f64 = 0.005;

/// The RTP profile whose RTCP timing rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RtcpProfile {
    /// RTP/AVP and RTP/SAVP (RFC 3551): a five second minimum interval, no early feedback.
    Avp,
    /// RTP/AVPF and RTP/SAVPF (RFC 4585): early feedback, `T_rr_interval`. What WebRTC uses.
    #[default]
    Avpf,
}

/// The bandwidth figures a session description gives for RTCP, all in bits per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtcpBandwidth {
    /// The session bandwidth (`b=TIAS`, or `b=AS` times 1000). RTCP gets 5% of it unless
    /// `rs` and `rr` say otherwise. `None`: the media bitrate measured over the last two
    /// seconds, with a start-up value before that ([`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH`]).
    pub session: Option<u64>,
    /// `b=RS` (RFC 3556): the RTCP bandwidth of the senders.
    pub rs: Option<u64>,
    /// `b=RR` (RFC 3556): the RTCP bandwidth of the receivers.
    pub rr: Option<u64>,
}

/// What an application (or the peer connection) tells the session while it runs.
///
/// It travels as an [`Attribute::Custom`] on an empty RTCP packet written into the chain
/// ([`RtcpSessionControl::into_packet`]); the session takes it off the belt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpSessionControl {
    /// The transport is up: the session joins now, without waiting for a first packet.
    Start,
    /// The CNAME of this endpoint, the one its session description announces.
    Cname(String),
    /// The negotiated bandwidth (`b=` lines).
    Bandwidth(RtcpBandwidth),
    /// Whether reduced-size RTCP (`a=rtcp-rsize`, RFC 5506) was negotiated.
    ReducedSize(bool),
    /// The octets SRTCP adds to every compound packet: the E flag and SRTCP index, the
    /// authentication tag and the MKI. RFC 3711 section 3.4: they are part of the packet size
    /// avg_rtcp_size is computed from, the initial estimate included. Give it before
    /// [`Self::Start`]; 0 (the default) for plain RTCP.
    SrtcpOverhead(usize),
    /// The negotiated `trr-int` (RFC 4585 4.2), the minimum interval between regular reports.
    TrrInt(Duration),
    /// The negotiation has no `trr-int` (any more): the interval the session was built with
    /// ([`RtcpSessionBuilder::with_t_rr_interval`]) applies again.
    TrrIntCleared,
    /// The endpoint leaves the session: every local SSRC says BYE.
    Leave,
    /// The rate the congestion controller of the same chain allows this endpoint to send at,
    /// bits per second. Used only with
    /// [`RtcpSessionBuilder::with_share_following_send_rate`]; the congestion control
    /// interceptor writes it wire-ward when told to
    /// ([`CongestionControlBuilder::with_send_rate_told_to_rtcp`](crate::CongestionControlBuilder::with_send_rate_told_to_rtcp)).
    SendRate(u64),
    /// What identifies the local stream `ssrc` beyond the CNAME: the identification-tag of
    /// its m= section (RFC 9143 section 15.1, SDES `MID`), its RtpStreamId (RFC 8852 section
    /// 3.1) and, for a redundancy stream (RTX, FEC), the RepairedRtpStreamId of the stream it
    /// repairs (section 3.2). Each given value is an item of the SSRC's SDES chunk in every
    /// compound packet: RFC 9143 section 15 wants the MID "in the first few RTCP packets after
    /// joining the session and ... regularly thereafter". All `None` forgets the SSRC's items;
    /// the items of an SSRC that is no longer bound go when the next ones are given.
    StreamIdentifiers {
        /// The local SSRC.
        ssrc: u32,
        /// The m= section's `a=mid`.
        mid: Option<String>,
        /// The RtpStreamId (the encoding's rid).
        rid: Option<String>,
        /// The RepairedRtpStreamId (the rid of the stream a redundancy stream repairs).
        repaired_rid: Option<String>,
    },
    /// RFC 7160 section 4.1: the local stream `current` took over from the streams `previous`
    /// because the sender switched to another clock rate (each clock rate has an SSRC of its
    /// own). The next compound packet "MUST contain multiple SR packets, the first one
    /// containing the mapping for the current clock rate and the subsequent SR packet(s)
    /// containing the mapping for the other clock rates seen during the last period": it
    /// leads with `current`'s report, followed by those of the `previous` streams that sent
    /// lately.
    ClockRateSwitch {
        /// The SSRC of the clock rate now in use.
        current: u32,
        /// The SSRCs of the other clock rates the stream was sent with, still in the session.
        previous: Vec<u32>,
    },
    /// Stops the repetitions of the packets written with the [`RepeatInRegularReports`] of
    /// this `key` that are still owed (RFC 7728 section 6.4: "stopping such repetition
    /// whenever leaving the state").
    StopRepeating {
        /// The key the packets were written with.
        key: u32,
    },
}

/// Attached as an [`Attribute::Custom`] to RTCP packets written into the chain: besides
/// sending them as it sends any feedback (in an Early packet when RFC 4585 3.5.2 allows one,
/// in the next Regular packet otherwise), the RTCP session puts a copy of them into each of
/// the next `count` **Regular** compound packets after the one that carried them.
///
/// RFC 7728 section 6.3 has a paused sender "repeat PAUSED in the next two regular RTCP
/// reports" (section 8.2: "PAUSED MUST also be included in (at least) the next two regular
/// RTCP reports"); the session is what knows when a regular report leaves. Packets written
/// again with the same `key` replace the repetitions still owed for it, and
/// [`RtcpSessionControl::StopRepeating`] ends them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepeatInRegularReports {
    /// Groups the repetitions, for replacing or stopping them (e.g. the media SSRC the
    /// packets are about).
    pub key: u32,
    /// In how many Regular compound packets after the first one they ride again.
    pub count: u8,
}

/// Attached as an [`Attribute::Custom`] to RTCP packets written into the chain that are to
/// leave in the RTCP session's next **Regular** compound packet, not in an Early one: RFC 5104
/// section 4.2.1.3, "Any repetition of a request message SHOULD use regular RTCP mode for its
/// transmission timing" (the TMMBR requester marks its repetitions so).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegularTiming;

/// Packets the RTCP session repeats in its Regular compound packets.
struct Repeat {
    key: u32,
    packets: Vec<Box<dyn rtcp::Packet>>,
    left: u8,
    /// Whether the compound packet that carried the original has left: only Regular packets
    /// after it carry a copy.
    armed: bool,
}

impl RtcpSessionControl {
    /// The packet that carries this to the session when written into the chain at `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// What the session tells the rest of the chain and the peer connection.
///
/// It travels application-ward as an [`Attribute::Custom`] on an empty RTCP packet; read it
/// with [`AttributedPacket::custom`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpSessionEvent {
    /// RFC 3550 8.2: a packet arrived from another source that uses `ssrc`, one of this
    /// endpoint's own. `replacement` is an SSRC no known source uses, for the stream to move
    /// to; a reporting SSRC the session chose itself has already moved.
    SsrcCollision {
        /// The local SSRC another source uses too.
        ssrc: u32,
        /// An unused SSRC to replace it with.
        replacement: u32,
    },
    /// RFC 3550 6.5.1: the remote source `ssrc` named its CNAME (or changed it).
    RemoteCname {
        /// The remote SSRC.
        ssrc: u32,
        /// Its canonical name.
        cname: String,
    },
    /// RFC 3550 6.3.5: nothing was heard from the remote source for five report intervals.
    SourceTimedOut {
        /// The remote SSRC.
        ssrc: u32,
    },
    /// The SSRC the session reports from while the endpoint has no media SSRC, which it drew
    /// itself; `None` once there is none (a stream took it over, it said BYE). RFC 8108
    /// section 6.1: "An endpoint that has never sent an RTP stream will have an SSRC that it
    /// uses for RTCP reporting. If that endpoint wants to start sending an RTP stream, it is
    /// RECOMMENDED that it use its existing SSRC for that stream". A local stream bound under
    /// this SSRC takes it over: the same participant, no BYE.
    ReportingSsrc {
        /// The reporting SSRC, or `None`.
        ssrc: Option<u32>,
    },
    /// RFC 3550 6.4.1: the round-trip time to the receiver that reported on the local `ssrc`.
    RoundTripTime {
        /// The local SSRC the report block was about.
        ssrc: u32,
        /// The round trip.
        rtt: Duration,
    },
}

/// The deterministic RTCP reporting interval Td (RFC 3550 section 6.3.1: the calculated
/// interval without its random variation) as this session calculates it now, for a member
/// that sends RTP and for one that does not.
///
/// The session attaches it to every RTCP packet it hands application-ward. It is what RFC
/// 8083 section 3 has a sender estimate its receiver's interval by ("Tdr ... can be estimated
/// by executing the algorithm in Section 6.2 of \[RFC3550\] using the average RTCP packet size
/// seen at the sender, the number of members ... and whether the receiver is sending SR or RR
/// packets"): the RTP circuit breaker application-ward of the session reads it. Both values
/// are computed with the session's own bandwidth, membership, average packet size and
/// minimum interval (none under RTP/AVPF); a `T_rr_interval` is not in them. Read with
/// [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RtcpReportingInterval {
    /// Td of a member that has sent RTP lately (it reports with sender reports).
    pub sender: Duration,
    /// Td of a member that has not (receiver reports).
    pub receiver: Duration,
}

/// This endpoint's share of the RTCP bandwidth as the session calculates it now: the RTCP
/// bandwidth (RFC 3550 section 6.2: 5% of the session bandwidth, or what `b=RS` / `b=RR`
/// give) divided equally among the members (section 6.3.1), times the number of this
/// endpoint's SSRCs that take part (RFC 8108 section 5: each is a member).
///
/// The session attaches it to every RTCP packet it hands application-ward, beside
/// [`RtcpReportingInterval`]. The congestion control feedback generators read it: with
/// [`CongestionFeedbackCadence::PerFrame`](crate::CongestionFeedbackCadence) their interval
/// grows towards 100 ms where this share does not hold a feedback packet per interval (RFC
/// 4585 section 3.2: feedback is "subject to the RTCP bandwidth constraints";
/// draft-ietf-rmcat-gcc-02 section 3: "If the feedback overhead needs to be limited this
/// interval can be increased to 100 ms"). Read with
/// [`AttributedPacket::custom`](crate::AttributedPacket::custom).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RtcpBandwidthShare {
    /// The share, bits per second.
    pub bits_per_second: f64,
}

/// Builder for [`RtcpSessionInterceptor`].
///
/// ```
/// use rtci_interceptor::{Registry, RtcpSessionBuilder, Slot};
///
/// let chain = Registry::new()
///     .with(Slot::RtcpSession, RtcpSessionBuilder::new().build())
///     .build();
/// # let _ = chain;
/// ```
pub struct RtcpSessionBuilder {
    profile: RtcpProfile,
    t_rr_interval: Duration,
    bandwidth: RtcpBandwidth,
    rtcp_fraction: f64,
    reduced_minimum: bool,
    reduced_size: bool,
    mtu: usize,
    cname: Option<String>,
    point_to_point: Option<bool>,
    report_from_every_ssrc: bool,
    immediate_congestion_feedback: bool,
    congestion_feedback_in_budget: bool,
    minimum_session_bandwidth: u64,
    share_follows_send_rate: bool,
    joins_on_start: bool,
    first_report_at_join: bool,
    random: Box<dyn RtcpRandom>,
    wall_clock: Option<SystemInstant>,
}

impl Default for RtcpSessionBuilder {
    fn default() -> Self {
        Self {
            profile: RtcpProfile::default(),
            t_rr_interval: RTCP_SESSION_DEFAULT_T_RR_INTERVAL,
            bandwidth: RtcpBandwidth::default(),
            rtcp_fraction: RTCP_BW_FRACTION,
            reduced_minimum: false,
            reduced_size: false,
            mtu: RTCP_SESSION_DEFAULT_MTU,
            cname: None,
            point_to_point: None,
            report_from_every_ssrc: false,
            immediate_congestion_feedback: true,
            congestion_feedback_in_budget: false,
            minimum_session_bandwidth: RTCP_SESSION_MIN_BANDWIDTH,
            share_follows_send_rate: false,
            joins_on_start: false,
            first_report_at_join: false,
            random: Box::new(ThreadRandom),
            wall_clock: None,
        }
    }
}

impl RtcpSessionBuilder {
    /// A builder with the defaults: RTP/AVPF timing, a `T_rr_interval` of one second, RTCP at
    /// 5% of the measured media bitrate (a start-up value before it is measured), compound
    /// packets only, congestion control feedback sent as it is built.
    pub fn new() -> Self {
        Self::default()
    }

    /// The profile whose timing rules apply. Default: [`RtcpProfile::Avpf`].
    pub fn with_profile(mut self, profile: RtcpProfile) -> Self {
        self.profile = profile;
        self
    }

    /// `T_rr_interval` (RFC 4585 3.4): the minimum interval between regular (full compound)
    /// reports under RTP/AVPF. Feedback is not held by it.
    ///
    /// RFC 4585 4.2 makes the value zero when `trr-int` is not negotiated, which lets regular
    /// reports use the whole RTCP bandwidth: a report every few tens of milliseconds beside a
    /// video stream. The default here is one second (what this engine sent before, and what
    /// browsers send); a negotiated `trr-int` ([`RtcpSessionControl::TrrInt`]) replaces it,
    /// and zero gives the RFC's default.
    pub fn with_t_rr_interval(mut self, t_rr_interval: Duration) -> Self {
        self.t_rr_interval = t_rr_interval;
        self
    }

    /// The bandwidth the session description gives (`b=AS` / `b=TIAS`, `b=RS`, `b=RR`).
    /// Default: none, so the media bitrate is measured and RTCP gets 5% of it.
    pub fn with_bandwidth(mut self, bandwidth: RtcpBandwidth) -> Self {
        self.bandwidth = bandwidth;
        self
    }

    /// The share of the session bandwidth RTCP uses when `b=RS` / `b=RR` do not say. Default:
    /// 0.05, the value RFC 3550 6.2 recommends.
    pub fn with_rtcp_fraction(mut self, fraction: f64) -> Self {
        self.rtcp_fraction = fraction.clamp(0.0, 1.0);
        self
    }

    /// Under RTP/AVP, use the reduced minimum interval of RFC 3550 6.2 (360 divided by the
    /// session bandwidth in kbit/s) instead of five seconds.
    pub fn with_reduced_minimum(mut self, reduced_minimum: bool) -> Self {
        self.reduced_minimum = reduced_minimum;
        self
    }

    /// Whether reduced-size RTCP (RFC 5506) was negotiated. Default: no, every packet is a
    /// compound packet.
    pub fn with_reduced_size(mut self, reduced_size: bool) -> Self {
        self.reduced_size = reduced_size;
        self
    }

    /// The size compound packets are kept under (RFC 3550 6.1). Default:
    /// [`RTCP_SESSION_DEFAULT_MTU`].
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu.max(128);
        self
    }

    /// The CNAME to use. Default: one generated as RFC 7022 section 4.2 describes.
    pub fn with_cname(mut self, cname: impl Into<String>) -> Self {
        self.cname = Some(cname.into());
        self
    }

    /// Says whether the session is point to point instead of leaving it to the count of
    /// remote CNAMEs (RFC 8108 5.4.2: "unless signaling indicates").
    pub fn with_point_to_point(mut self, point_to_point: bool) -> Self {
        self.point_to_point = Some(point_to_point);
        self
    }

    /// RFC 8108 5.1: "each SSRC will send RTCP reports for all other SSRCs, including those
    /// co-located at the same endpoint": every local SSRC carries a report block for every
    /// remote SSRC and for each of the endpoint's other SSRCs that has sent (`true`, the
    /// `StrictRfc` behaviour profile). Default `false`: the blocks are carried once, by the
    /// first local media SSRC, and none about the co-located SSRCs, as libwebrtc does and as
    /// RFC 8861 reporting groups allow where they are signalled.
    ///
    /// The default is a measured choice. The RFC form's compound packets are about twice the
    /// size, and RFC 3550 section 6.3's interval does not make up for all of it (the average
    /// packet size it is computed from counts the small congestion control feedback packets
    /// too): an endpoint of a 2.5 Mbit/s audio and video call sent 149 instead of 122 kbit/s
    /// of RTCP, and 93 instead of 80 kbit/s on a link that had collapsed to 300 kbit/s. In
    /// the capacity instrument (`tests/capacity_instrument.rs`, chain `every` against `paced`,
    /// the same seeds) the picture through the collapse was 0.5 s older, the send target
    /// under the cap 24 kbit/s lower and three times as many calls took over 20 s to recover.
    pub fn with_report_from_every_ssrc(mut self, every: bool) -> Self {
        self.report_from_every_ssrc = every;
        self
    }

    /// Whether congestion control feedback (transport-wide feedback, RFC 8888 reports) leaves
    /// as soon as its generator writes it (the default), or waits its turn under RFC 4585
    /// section 3.5.2 like other feedback: at most one Early packet per regular interval.
    ///
    /// The generators size their own cadence to 5% of the media they report on, between 50
    /// and 250 ms (`TwccReceiverBuilder::with_adaptive_interval`): congestion control feedback
    /// is the sender's congestion signal and is not held to the RTCP bandwidth the regular
    /// reports share, as libwebrtc and the browsers send it. It goes as a reduced-size packet
    /// where `a=rtcp-rsize` was negotiated, else in a minimal compound packet, and counts in
    /// the average RTCP packet size (RFC 4585 3.5.4: "avg_rtcp_size ... MUST be updated
    /// accordingly", Early or Regular), sent as received. `false` is RFC 4585 as written: at low media rates
    /// the session then sends feedback a few times a second, with gaps a sender's estimator
    /// does not climb through.
    pub fn with_immediate_congestion_feedback(mut self, immediate: bool) -> Self {
        self.immediate_congestion_feedback = immediate;
        self
    }

    /// Whether the congestion control feedback that leaves at once
    /// ([`Self::with_immediate_congestion_feedback`]) counts against the RTCP bandwidth the
    /// regular reports share (`true`), or comes on top of it (`false`, the default).
    ///
    /// With `true` the session measures the congestion control feedback it sends and receives
    /// over the last two seconds, and spaces its regular reports so that they and the
    /// feedback together stay inside the RTCP bandwidth (RFC 3550 section 6.2: 5% of the
    /// session bandwidth): the regular interval computed with what the feedback leaves becomes
    /// a `T_rr_interval` (RFC 4585 section 3.5.3, which suppresses regular reports inside it
    /// and lets feedback through), no longer than five seconds. Regular reports become rarer
    /// at low media rates and nothing else changes. Part of the `Performance` behaviour
    /// profile.
    pub fn with_congestion_feedback_in_budget(mut self, in_budget: bool) -> Self {
        self.congestion_feedback_in_budget = in_budget;
        self
    }

    /// The least session bandwidth the RTCP bandwidth is computed from when no `b=` line gives
    /// one and the media is measured, bits per second. Default
    /// [`RTCP_SESSION_MIN_BANDWIDTH`] (64 kbit/s). Below it the measured media rate is not
    /// used, so a 24 kbit/s audio call reports as a 64 kbit/s one would (RFC 3550 section 6.2
    /// lets the session bandwidth be the expected one). The `Performance` behaviour profile
    /// takes 16 kbit/s, so the RTCP bandwidth follows the media down to there. Held to at
    /// least 8 kbit/s, so a session with no media still reports.
    pub fn with_minimum_session_bandwidth(mut self, bits_per_second: u64) -> Self {
        self.minimum_session_bandwidth = bits_per_second.max(8_000);
        self
    }

    /// Tuning with no specification behind it, off by default: whether this endpoint's own
    /// share of the RTCP bandwidth follows the rate its congestion controller allows it to
    /// send at.
    ///
    /// RFC 3550 section 6.2 sizes the RTCP bandwidth from the session bandwidth, here the
    /// media measured in both directions, and section 6.3.1 shares it equally among the
    /// members; nothing in it, in RFC 4585 or in RFC 8108 ties one endpoint's share to the
    /// rate of its own direction. So when one direction of a call collapses and the other
    /// does not, the endpoint behind the collapsed link keeps reporting at the rate the
    /// whole session gives it: a fifth of a 300 kbit/s link, measured. With `true`, the RTCP
    /// bandwidth this endpoint's own SSRCs schedule their regular reports with is at most the
    /// session's RTCP fraction (5%) of the session there would be if every endpoint sent at
    /// this endpoint's rate: `fraction x send rate x members / local SSRCs`, no less than the
    /// fraction of the minimum session bandwidth. The send rate is the congestion
    /// controller's ([`RtcpSessionControl::SendRate`]); until one is told, and when the
    /// session's own figure is lower, nothing changes. The intervals calculated for the
    /// other members ([`RtcpReportingInterval`]) are not touched: the peer shares the
    /// bandwidth as RFC 3550 says. Congestion control feedback is not slowed by it (it is
    /// sent at once unless [`Self::with_immediate_congestion_feedback`] is off); early
    /// feedback (NACK, PLI) keeps its rules, on the longer regular interval.
    pub fn with_share_following_send_rate(mut self, follows: bool) -> Self {
        self.share_follows_send_rate = follows;
        self
    }

    /// Whether the session joins only when told [`RtcpSessionControl::Start`] (`true`), or at
    /// the first control, packet or stream it is given (`false`, the default).
    ///
    /// RFC 3550 section 6: RTCP is the control protocol of an RTP session, and there is none
    /// until an RTP m= section is negotiated (RFC 8834 section 4.1). A peer connection knows
    /// when that is, per transport, and joins the session then; with `true` nothing else makes
    /// it join: until `Start` it sends nothing (no report, no SDES, no SSRC of its own), and
    /// what is written to it as RTCP is dropped. After [`RtcpSessionControl::Leave`], a
    /// `Start` joins it again (RTCP resumes from a new reporting SSRC).
    pub fn with_joins_on_start(mut self, joins_on_start: bool) -> Self {
        self.joins_on_start = joins_on_start;
        self
    }

    /// Whether the first compound packet goes out when the session joins (`true`), or after
    /// the initial interval of RFC 3550 section 6.2 (`false`, the default).
    ///
    /// RFC 8834 section 4.1, with RFC 3550 section 6.2 as RFC 8108 updates it: "The delay
    /// before sending the initial compound RTCP packet can be set to zero." A peer connection
    /// joins a transport's session when its keys exist, and reporting then tells the peer the
    /// endpoint's SSRCs at once (RFC 3550 section 8.2: an SSRC collision is found from the
    /// first packet that shows it) and starts the round-trip and loss reports congestion
    /// control reads.
    pub fn with_first_report_at_join(mut self, at_join: bool) -> Self {
        self.first_report_at_join = at_join;
        self
    }

    /// The source of the session's random numbers; a test supplies one that repeats.
    pub fn with_random(mut self, random: impl RtcpRandom + 'static) -> Self {
        self.random = Box::new(random);
        self
    }

    /// The wall-clock anchor the session's NTP times (sender reports, XR receiver reference
    /// times) derive from. Default: the process-wide [`SystemInstant::shared`]. Give one per
    /// peer connection for reproducible virtual-time runs: two runs in one process otherwise
    /// map the same instants to NTP times as far apart as the real time between them.
    pub fn with_wall_clock(mut self, anchor: SystemInstant) -> Self {
        self.wall_clock = Some(anchor);
        self
    }

    /// Builds an RTCP session per RTP session ([`crate::PerRtpSession`]): a peer connection
    /// with sections on several transports runs an RTCP session on each (RFC 3550 section 6,
    /// RFC 8834 section 4.4), every one with these settings, the same CNAME (RFC 7022
    /// section 4.2: one per endpoint) and its own members, bandwidth and timers.
    pub fn build_per_rtp_session(mut self) -> crate::PerRtpSession<RtcpSessionInterceptor> {
        let cname = self
            .cname
            .take()
            .unwrap_or_else(|| generate_cname(self.random.as_mut()));
        let random = SharedRandom(Arc::new(std::sync::Mutex::new(std::mem::replace(
            &mut self.random,
            Box::new(ThreadRandom),
        ))));
        let template = RtcpSessionBuilder {
            cname: Some(cname),
            random: Box::new(random.clone()),
            ..self
        };
        let make = move |template: &RtcpSessionBuilder| RtcpSessionBuilder {
            profile: template.profile,
            t_rr_interval: template.t_rr_interval,
            bandwidth: template.bandwidth,
            rtcp_fraction: template.rtcp_fraction,
            reduced_minimum: template.reduced_minimum,
            reduced_size: template.reduced_size,
            mtu: template.mtu,
            cname: template.cname.clone(),
            point_to_point: template.point_to_point,
            report_from_every_ssrc: template.report_from_every_ssrc,
            immediate_congestion_feedback: template.immediate_congestion_feedback,
            congestion_feedback_in_budget: template.congestion_feedback_in_budget,
            minimum_session_bandwidth: template.minimum_session_bandwidth,
            share_follows_send_rate: template.share_follows_send_rate,
            joins_on_start: template.joins_on_start,
            first_report_at_join: template.first_report_at_join,
            random: Box::new(random.clone()),
            wall_clock: template.wall_clock,
        };
        let first = make(&template).build();
        crate::PerRtpSession::with_first(first, move || make(&template).build())
    }

    /// Builds the interceptor.
    pub fn build(mut self) -> RtcpSessionInterceptor {
        let cname = self
            .cname
            .take()
            .unwrap_or_else(|| generate_cname(self.random.as_mut()));
        RtcpSessionInterceptor {
            profile: self.profile,
            t_rr_interval: self.t_rr_interval.as_secs_f64(),
            configured_t_rr_interval: self.t_rr_interval.as_secs_f64(),
            bandwidth: self.bandwidth,
            rtcp_fraction: self.rtcp_fraction,
            reduced_minimum: self.reduced_minimum,
            reduced_size: self.reduced_size,
            mtu: self.mtu,
            cname,
            point_to_point: self.point_to_point,
            report_from_every_ssrc: self.report_from_every_ssrc,
            random: self.random,

            joins_on_start: self.joins_on_start,
            first_report_at_join: self.first_report_at_join,
            start_given: false,
            announced_reporter: None,
            started: false,
            left: false,
            locals: Vec::new(),
            departing: Vec::new(),
            remotes: HashMap::new(),
            remote_order: Vec::new(),
            ecn_summary_next: 0,
            report_cursor: 0,
            members: HashMap::new(),
            pmembers: 0,
            avg_rtcp_size: 0.0,
            srtcp_overhead: 0,
            rate: RateWindow::default(),
            immediate_congestion_feedback: self.immediate_congestion_feedback,
            congestion_feedback_in_budget: self.congestion_feedback_in_budget,
            minimum_session_bandwidth: self.minimum_session_bandwidth,
            share_follows_send_rate: self.share_follows_send_rate,
            send_rate: None,
            congestion_feedback_rate: RateWindow::default(),
            regular_size: 0.0,
            sending_regular: false,
            outside_budget: false,
            pending: Vec::new(),
            repeats: Vec::new(),
            held_for_regular: Vec::new(),
            early_at: None,
            sender_report_requested: None,
            clock_rate_switch: None,
            compound_sent: false,
            reference_times: HashMap::new(),
            dlrr_limits: HashMap::new(),
            wall_clock: self.wall_clock,
            reduced_size_failed: false,
            unanswered_reduced_nacks: 0,
            awaited: None,
            collided: HashSet::new(),
            said_bye: HashMap::new(),
            identifiers: HashMap::new(),
            bye: None,
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Audio,
    Video,
    Other,
}

impl Kind {
    fn of(mime_type: &str) -> Self {
        let mime_type = mime_type.to_ascii_lowercase();
        if mime_type.starts_with("audio/") {
            Kind::Audio
        } else if mime_type.starts_with("video/") {
            Kind::Video
        } else {
            Kind::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The SSRC of a media stream this endpoint is set up to send.
    Media,
    /// An RTX or FEC SSRC: a participant once it has sent.
    Repair,
    /// The SSRC the session chose to report from while the endpoint has no media SSRC.
    Reporter,
}

/// One of this endpoint's SSRCs.
struct Local {
    ssrc: u32,
    kind: Kind,
    role: Role,
    stream: SenderStream,
    /// `None` until the SSRC takes part and the session has started.
    timing: Option<Timing>,
    last_rtp: Option<Instant>,
    rtp_sent: bool,
    rtcp_sent: bool,
    /// The compact NTP timestamps of the last sender reports and when each was sent, for the
    /// round-trip time (RFC 3550 6.4.1).
    sent_reports: VecDeque<(u32, Instant)>,
}

impl Local {
    fn new(
        ssrc: u32,
        kind: Kind,
        role: Role,
        clock_rate: u32,
        wall_clock: Option<SystemInstant>,
    ) -> Self {
        Self {
            ssrc,
            kind,
            role,
            stream: SenderStream::new(ssrc, clock_rate, false).with_wall_clock(wall_clock),
            timing: None,
            last_rtp: None,
            rtp_sent: false,
            rtcp_sent: false,
            sent_reports: VecDeque::new(),
        }
    }

    /// Whether the SSRC is a participant of the session: a repair SSRC is one from its first
    /// packet on.
    fn participates(&self) -> bool {
        self.role != Role::Repair || self.rtp_sent
    }
}

/// A remote stream bound for reception.
struct Remote {
    stream: ReceiverStream,
    kind: Kind,
    /// Whether receiver reference times (RFC 3611 4.4) were negotiated for it.
    rrtr: bool,
    /// The RTCP ECN Feedback packet (`nack ecn`, RFC 6679 6.2) was negotiated for it.
    ecn_feedback: bool,
    /// The XR ECN Summary Report (`xr ecn-sum`, RFC 6679 6.3) was negotiated for it.
    ecn_summary: bool,
    /// Its ECN counts (RFC 6679 5.1), kept while either is negotiated.
    ecn: Option<Box<ecn::EcnTally>>,
    /// The source said BYE or timed out: it is not reported on until it is heard again.
    gone: bool,
}

/// A source in the member table (RFC 3550 6.2.1).
struct Member {
    last_heard: Instant,
    last_rtp: Option<Instant>,
    cname: Option<String>,
}

/// RFC 3550 6.3.7: a BYE waiting its turn in a session of more than fifty members.
struct ByeBackoff {
    packets: Vec<Box<dyn rtcp::Packet>>,
    size: f64,
    tp: Instant,
    tn: Instant,
    /// The BYE packets counted so far, this one included.
    members: usize,
}

/// The media bitrate of the last seconds, for a session whose bandwidth nobody stated.
#[derive(Default)]
struct RateWindow {
    buckets: VecDeque<(Instant, u64)>,
    first: Option<Instant>,
}

impl RateWindow {
    fn add(&mut self, now: Instant, octets: usize) {
        self.first.get_or_insert(now);
        match self.buckets.back_mut() {
            Some((start, sum)) if now.saturating_duration_since(*start) < RATE_BUCKET => {
                *sum += octets as u64;
            }
            _ => self.buckets.push_back((now, octets as u64)),
        }
        while self
            .buckets
            .front()
            .is_some_and(|(start, _)| now.saturating_duration_since(*start) > RATE_WINDOW)
        {
            self.buckets.pop_front();
        }
    }

    fn bits_per_second(&self, now: Instant) -> f64 {
        let Some(first) = self.first else {
            return 0.0;
        };
        let octets: u64 = self
            .buckets
            .iter()
            .filter(|(start, _)| now.saturating_duration_since(*start) <= RATE_WINDOW)
            .map(|(_, sum)| *sum)
            .sum();
        let span = now
            .saturating_duration_since(first)
            .clamp(RATE_BUCKET, RATE_WINDOW);
        octets as f64 * 8.0 / span.as_secs_f64()
    }
}

/// How a compound packet is put together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A regular report: every due SSRC's SR or RR with the report blocks, SDES, XR.
    Full,
    /// RFC 4585 3.1: the minimal compound packet that carries feedback: one SR or RR without
    /// report blocks, SDES, the feedback.
    Minimal,
}

/// The RTCP session of an endpoint (RFC 3550 section 6, RFC 4585 section 3, RFC 8108).
///
/// One interceptor, closest to the wire, is the endpoint's whole RTCP voice:
///
/// - **Identity.** One CNAME for every local SSRC (RFC 7022: 96 random bits, Base64), given
///   or generated. Reports and feedback come from the local media SSRCs; an endpoint with
///   none reports from one SSRC the session chooses (never zero, never one in use). Every
///   feedback packet the interceptors above or the application write leaves with the packet
///   sender SSRC of this endpoint (RFC 8108 5.4.1), whatever they filled in.
/// - **Reports.** A sender report for every SSRC that sent RTP in the last two intervals, RTX
///   and FEC SSRCs included; a receiver report otherwise (RFC 3550 6.4). Reception report
///   blocks for the remote streams (RFC 3550 Appendix A.3), an SDES CNAME for every reporting
///   SSRC, XR receiver reference time and DLRR blocks (RFC 3611).
/// - **Timing.** The interval of RFC 3550 6.3 from the member and sender counts, the average
///   packet size and the RTCP bandwidth, randomised, with timer reconsideration and reverse
///   reconsideration; the early feedback rules of RFC 4585 3.5 and `T_rr_interval`; one timer
///   per local SSRC, aggregated into one compound packet (RFC 8108 5.3).
/// - **Packets.** Everything leaves as a compound packet (SR or RR first, then SDES) unless
///   reduced-size RTCP was negotiated (RFC 5506), kept under the MTU.
/// - **Membership.** Sources heard in RTP and RTCP, their CNAMEs, BYE, the timeout after five
///   intervals, sender status over two; BYE for a local SSRC that stops and for all of them
///   when the endpoint leaves; a collision with one of the endpoint's own SSRCs.
///
/// It replaces [`SenderReportInterceptor`](crate::SenderReportInterceptor) and
/// [`ReceiverReportInterceptor`](crate::ReceiverReportInterceptor), which report on fixed
/// timers: a sender or receiver report those (or the application) write is dropped here, the
/// session's own stand for it.
///
/// # Where it goes
///
/// [`Slot::RtcpSession`](crate::Slot::RtcpSession), wire-ward of everything: it counts what
/// leaves (retransmissions and FEC included) and what arrives, and every RTCP packet the
/// chain writes passes it last.
///
/// # Inputs and outputs
///
/// What a session description negotiates is handed in with the builder or, while running,
/// as an [`RtcpSessionControl`]. What the session learns leaves as an [`RtcpSessionEvent`].
pub struct RtcpSessionInterceptor {
    profile: RtcpProfile,
    /// Seconds.
    t_rr_interval: f64,
    /// Seconds: the builder's, which [`RtcpSessionControl::TrrIntCleared`] goes back to.
    configured_t_rr_interval: f64,
    bandwidth: RtcpBandwidth,
    rtcp_fraction: f64,
    reduced_minimum: bool,
    reduced_size: bool,
    mtu: usize,
    cname: String,
    point_to_point: Option<bool>,
    report_from_every_ssrc: bool,
    random: Box<dyn RtcpRandom>,

    /// [`RtcpSessionBuilder::with_share_following_send_rate`].
    share_follows_send_rate: bool,
    /// The rate the congestion controller allows this endpoint to send at
    /// ([`RtcpSessionControl::SendRate`]), bits per second.
    send_rate: Option<f64>,
    /// [`RtcpSessionBuilder::with_joins_on_start`].
    joins_on_start: bool,
    /// [`RtcpSessionBuilder::with_first_report_at_join`].
    first_report_at_join: bool,
    /// [`RtcpSessionControl::Start`] was given since the session was built or last left.
    start_given: bool,
    /// The reporting SSRC last announced ([`RtcpSessionEvent::ReportingSsrc`]).
    announced_reporter: Option<u32>,
    started: bool,
    left: bool,
    /// In the order they were bound.
    locals: Vec<Local>,
    /// Local SSRCs unbound since the chain was last driven: each says BYE unless bound again.
    departing: Vec<Local>,
    /// The SDES items of a local SSRC after its CNAME ([`RtcpSessionControl::StreamIdentifiers`]).
    identifiers: HashMap<u32, Vec<SourceDescriptionItem>>,
    remotes: HashMap<u32, Remote>,
    /// The bound remote SSRCs in the order they were bound, for the round robin of report
    /// blocks.
    remote_order: Vec<u32>,
    /// Where the next ECN summary starts in `remote_order` when not every sender fits (RFC
    /// 6679 section 5.2: a subset, round-robin).
    ecn_summary_next: usize,
    report_cursor: usize,
    /// The remote members of the session.
    members: HashMap<u32, Member>,
    pmembers: usize,
    avg_rtcp_size: f64,
    /// What SRTCP adds to each compound packet ([`RtcpSessionControl::SrtcpOverhead`]).
    srtcp_overhead: usize,
    rate: RateWindow,
    /// Whether congestion control feedback leaves as soon as it is written.
    immediate_congestion_feedback: bool,
    /// [`RtcpSessionBuilder::with_congestion_feedback_in_budget`].
    congestion_feedback_in_budget: bool,
    /// [`RtcpSessionBuilder::with_minimum_session_bandwidth`], bits per second.
    minimum_session_bandwidth: u64,
    /// The congestion control feedback sent and received, with SRTCP, over the last seconds.
    congestion_feedback_rate: RateWindow,
    /// The average size of this endpoint's regular compound packets per reporting SSRC.
    regular_size: f64,
    /// Set while a regular packet is sent.
    sending_regular: bool,
    /// Set while a packet is sent outside the RTCP bandwidth's timing (immediate congestion
    /// feedback): it is measured as congestion control feedback, and counts in
    /// `avg_rtcp_size` as every packet does (RFC 4585 3.5.4).
    outside_budget: bool,
    /// Feedback and other packets waiting for a compound packet.
    pending: Vec<Box<dyn rtcp::Packet>>,
    /// Packets each of the next Regular compound packets carries again
    /// ([`RepeatInRegularReports`]).
    repeats: Vec<Repeat>,
    /// Packets written with [`RegularTiming`], for the next Regular compound packet.
    held_for_regular: Vec<Box<dyn rtcp::Packet>>,
    /// RFC 4585 3.5.2: when the scheduled Early packet goes.
    early_at: Option<Instant>,
    /// RFC 6051 section 3.2: the local SSRC an RTCP-SR-REQ asked for an SR of, until an
    /// Early packet carries it.
    sender_report_requested: Option<usize>,
    /// RFC 7160 section 4.1: the clock rate switch the next compound packet reports
    /// ([`RtcpSessionControl::ClockRateSwitch`]): the current SSRC, then the previous ones.
    clock_rate_switch: Option<(u32, Vec<u32>)>,
    /// Whether a compound packet has been sent (RFC 5506 4: none reduced-size before).
    compound_sent: bool,
    /// The receiver reference times received and not yet answered, by sender SSRC.
    reference_times: HashMap<u32, (u32, Instant)>,
    /// The largest DLRR block each bound stream's `rcvr-rtt=<mode>:<max>` allows, in octets
    /// (RFC 3611 section 5.1), by SSRC.
    dlrr_limits: HashMap<u32, usize>,
    wall_clock: Option<SystemInstant>,
    reduced_size_failed: bool,
    unanswered_reduced_nacks: u32,
    /// The packets the last reduced-size NACK asked for.
    awaited: Option<(u32, Vec<u16>)>,
    /// Local media SSRCs a collision was reported for.
    collided: HashSet<u32>,
    /// Sources that said BYE and when (RFC 3550 6.2.1: the entry is kept, marked, for a
    /// while, so that a packet that was overtaken by the BYE does not bring the source back).
    said_bye: HashMap<u32, Instant>,
    bye: Option<ByeBackoff>,

    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

fn boxed<P: rtcp::Packet + 'static>(packet: P) -> Box<dyn rtcp::Packet> {
    Box::new(packet)
}

/// Splits `nack` (RFC 3550 6.1, RFC 4585 6.2.1): a first NACK of the pairs that fit in `budget`
/// octets (it may ask for none) and NACKs of the rest, each of at most `room` octets. `None`
/// when `room` holds no pair.
fn split_nack(
    nack: &TransportLayerNack,
    budget: usize,
    room: usize,
) -> Option<(TransportLayerNack, Vec<TransportLayerNack>)> {
    /// The common header, the packet sender's and the media source's SSRC.
    const HEADER: usize = 12;
    /// One PID and BLP.
    const PAIR: usize = 4;
    let per_packet = room.saturating_sub(HEADER) / PAIR;
    if per_packet == 0 {
        return None;
    }
    let with = |nacks: &[NackPair]| TransportLayerNack {
        sender_ssrc: nack.sender_ssrc,
        media_ssrc: nack.media_ssrc,
        nacks: nacks.to_vec(),
    };
    let in_first = (budget.saturating_sub(HEADER) / PAIR).min(nack.nacks.len());
    let (first, rest) = nack.nacks.split_at(in_first);
    Some((with(first), rest.chunks(per_packet).map(with).collect()))
}

/// The size of `packets` on the wire, lower layers included.
fn wire_size(packets: &[Box<dyn rtcp::Packet>]) -> usize {
    LOWER_LAYER_OVERHEAD + packets.iter().map(|p| p.marshal_size()).sum::<usize>()
}

/// The number of SSRCs reporting in a compound packet (RFC 8108 5.3.1): the distinct sources
/// of its SR and RR packets, one for a packet without any.
fn reporting_ssrcs(packets: &[Box<dyn rtcp::Packet>]) -> usize {
    let mut sources: Vec<u32> = packets
        .iter()
        .filter_map(|packet| {
            let any = packet.as_any();
            any.downcast_ref::<SenderReport>()
                .map(|sr| sr.ssrc)
                .or_else(|| any.downcast_ref::<ReceiverReport>().map(|rr| rr.ssrc))
        })
        .collect();
    sources.sort_unstable();
    sources.dedup();
    sources.len().max(1)
}

/// The packet sender SSRC of a feedback or report packet, and the media SSRC a feedback
/// message is about.
fn sender_and_media(packet: &dyn rtcp::Packet) -> (Option<u32>, Option<u32>) {
    let any = packet.as_any();
    if let Some(p) = any.downcast_ref::<TransportLayerNack>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<PictureLossIndication>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<FullIntraRequest>() {
        (Some(p.sender_ssrc), p.fir.first().map(|entry| entry.ssrc))
    } else if let Some(p) = any.downcast_ref::<SliceLossIndication>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<ReceiverEstimatedMaximumBitrate>() {
        (Some(p.sender_ssrc), p.ssrcs.first().copied())
    } else if let Some(p) = any.downcast_ref::<TransportLayerCc>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<CcFeedbackReport>() {
        (Some(p.sender_ssrc), None)
    } else if let Some(p) = any.downcast_ref::<RapidResynchronizationRequest>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<EcnFeedback>() {
        (Some(p.sender_ssrc), Some(p.media_ssrc))
    } else if let Some(p) = any.downcast_ref::<ExtendedReport>() {
        (Some(p.sender_ssrc), None)
    } else if let Some(p) = any.downcast_ref::<SenderReport>() {
        (Some(p.ssrc), None)
    } else if let Some(p) = any.downcast_ref::<ReceiverReport>() {
        (Some(p.ssrc), None)
    } else {
        (None, None)
    }
}

/// Whether a remote stream negotiated the RFC 6679 ECN Feedback packet (`a=rtcp-fb:<pt> nack
/// ecn`, section 6.2) and the XR ECN Summary Report (`a=rtcp-xr:ecn-sum`, section 6.3, which
/// reaches a stream as an `xr` feedback entry).
fn negotiated_ecn_feedback(info: &StreamInfo) -> (bool, bool) {
    let feedback = info
        .rtcp_feedback
        .iter()
        .any(|f| f.typ == "nack" && f.parameter == crate::RTCP_FB_NACK_ECN);
    let summary = info
        .rtcp_feedback
        .iter()
        .any(|f| f.typ == crate::RTCP_FB_XR && f.parameter == crate::RTCP_XR_ECN_SUMMARY);
    (feedback, summary)
}

/// `packet` with `ssrc` as its packet sender, for the types that name one.
fn with_sender(packet: Box<dyn rtcp::Packet>, ssrc: u32) -> Box<dyn rtcp::Packet> {
    macro_rules! rewrite {
        ($($ty:ty),*) => {
            $(if let Some(p) = packet.as_any().downcast_ref::<$ty>() {
                let mut p = p.clone();
                p.sender_ssrc = ssrc;
                return Box::new(p);
            })*
        };
    }
    rewrite!(
        TransportLayerNack,
        PictureLossIndication,
        FullIntraRequest,
        SliceLossIndication,
        ReceiverEstimatedMaximumBitrate,
        TransportLayerCc,
        CcFeedbackReport,
        RapidResynchronizationRequest,
        EcnFeedback,
        ExtendedReport
    );
    packet
}

/// RFC 5506 4.2.1: whether the delivery of `packet` shows in what the peer does next (a
/// retransmission, a key frame, a sender that goes on raising its rate), so it may travel
/// reduced-size on its own.
///
/// Congestion control feedback is of that kind: RFC 8888 section 3.1 has it sent "in a
/// non-compound RTCP packet if supported by the session participants", and a sender whose
/// feedback does not arrive cuts its rate (RFC 8888 section 5), which the receiver sees.
/// Without the report and SDES around it the feedback is half the size, and at low media
/// rates twice as many fit the RTCP bandwidth.
fn delivery_shows(packet: &dyn rtcp::Packet) -> bool {
    let any = packet.as_any();
    any.is::<TransportLayerNack>()
        || any.is::<PictureLossIndication>()
        || any.is::<FullIntraRequest>()
        || any.is::<TransportLayerCc>()
        || any.is::<CcFeedbackReport>()
        || any.is::<EcnFeedback>()
}

/// The maximum DLRR size in `rcvr-rtt=<mode>:<max>` (RFC 3611 section 5.1), `None` without
/// one.
fn dlrr_limit(format: &str) -> Option<usize> {
    let (name, value) = format.split_once('=')?;
    if name != "rcvr-rtt" {
        return None;
    }
    value.split_once(':')?.1.parse().ok()
}

impl RtcpSessionInterceptor {
    /// The CNAME this endpoint's SSRCs are described with.
    pub fn cname(&self) -> &str {
        &self.cname
    }

    fn unit(&mut self) -> f64 {
        self.random.unit()
    }

    fn emit(&mut self, now: Instant, event: RtcpSessionEvent) {
        self.read_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(event))),
        });
    }

    fn send(&mut self, now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) {
        if packets.is_empty() {
            return;
        }
        if self.outside_budget {
            self.congestion_feedback_rate
                .add(now, wire_size(&packets) + self.srtcp_overhead);
        }
        if self.sending_regular {
            let size = (wire_size(&packets) + self.srtcp_overhead) as f64
                / reporting_ssrcs(&packets) as f64;
            self.regular_size = if self.regular_size > 0.0 {
                update_avg_rtcp_size(self.regular_size, size)
            } else {
                size
            };
        }
        // RFC 3550 6.3.6 with RFC 8108 5.3.1: the average takes the size per reporting SSRC.
        // RFC 4585 3.5.4: of every packet sent, Early or Regular, congestion control feedback
        // that leaves at once included, as the peer's is counted when it arrives.
        let size =
            (wire_size(&packets) + self.srtcp_overhead) as f64 / reporting_ssrcs(&packets) as f64;
        self.avg_rtcp_size = update_avg_rtcp_size(self.avg_rtcp_size, size);
        self.write_queue.push_back(TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(packets)),
        });
    }

    // ---- who is in the session -------------------------------------------------------

    fn local_index(&self, ssrc: u32) -> Option<usize> {
        self.locals.iter().position(|local| local.ssrc == ssrc)
    }

    fn ssrc_in_use(&self, ssrc: u32) -> bool {
        self.local_index(ssrc).is_some()
            || self.departing.iter().any(|local| local.ssrc == ssrc)
            || self.members.contains_key(&ssrc)
            || self.remotes.contains_key(&ssrc)
    }

    /// The local SSRC that carries the reception report blocks: the first media SSRC, or the
    /// session's own reporting SSRC.
    fn reporter(&self) -> Option<usize> {
        self.locals
            .iter()
            .position(|local| local.role == Role::Media)
            .or_else(|| {
                self.locals
                    .iter()
                    .position(|local| local.role == Role::Reporter)
            })
    }

    /// The local SSRC feedback about `media_ssrc` is sent from (RFC 8108 5.4.1): a media SSRC
    /// of the same kind as the stream when there is one, the reporter otherwise.
    fn feedback_source(&self, media_ssrc: Option<u32>) -> Option<usize> {
        let kind = media_ssrc
            .and_then(|ssrc| self.remotes.get(&ssrc))
            .map(|remote| remote.kind);
        kind.and_then(|kind| {
            self.locals
                .iter()
                .position(|local| local.role == Role::Media && local.kind == kind)
        })
        .or_else(|| self.reporter())
    }

    /// Keeps the session's own reporting SSRC while the endpoint has no media SSRC, and
    /// retires it when it has one (RFC 8108 6.2: with a BYE).
    fn sync_reporter(&mut self) {
        let has_media = self.locals.iter().any(|local| local.role == Role::Media);
        let reporter = self
            .locals
            .iter()
            .position(|local| local.role == Role::Reporter);
        match (has_media, reporter) {
            (true, Some(index)) => {
                let local = self.locals.remove(index);
                self.departing.push(local);
            }
            (false, None) if !self.left => {
                let mut random = std::mem::replace(&mut self.random, Box::new(ThreadRandom));
                let ssrc = choose_ssrc(random.as_mut(), |ssrc| self.ssrc_in_use(ssrc));
                self.random = random;
                self.locals.push(Local::new(
                    ssrc,
                    Kind::Other,
                    Role::Reporter,
                    90_000,
                    self.wall_clock,
                ));
            }
            _ => {}
        }
    }

    fn member_count(&self) -> usize {
        self.members.len() + self.locals.iter().filter(|l| l.participates()).count()
    }

    /// RFC 8108 5.4.2: point to point unless the remote sources name more than one CNAME.
    fn is_point_to_point(&self) -> bool {
        if let Some(point_to_point) = self.point_to_point {
            return point_to_point;
        }
        let mut cnames = self.members.values().filter_map(|m| m.cname.as_deref());
        match cnames.next() {
            Some(first) => cnames.all(|cname| cname == first),
            None => true,
        }
    }

    // ---- bandwidth and intervals -----------------------------------------------------

    fn session_bandwidth(&self, now: Instant) -> f64 {
        match self.bandwidth.session {
            Some(session) => session as f64,
            None => {
                // RFC 3550 6.2 lets the session bandwidth be "supplied by a session
                // management application"; without one it is the media measured both ways
                // over the last seconds. (A congestion controller's target is not used: an
                // application-limited sender's target is many times what it sends.)
                let measured = self.rate.bits_per_second(now);
                // The nominal figure stands only until the media has had its window to be
                // measured: a start-up value, not the session bandwidth.
                let starting = self
                    .rate
                    .first
                    .is_none_or(|first| now.saturating_duration_since(first) < RATE_WINDOW);
                let measured = if starting {
                    measured.max(self.nominal_bandwidth())
                } else {
                    measured
                };
                measured.max(self.minimum_session_bandwidth as f64)
            }
        }
    }

    /// The nominal session bandwidth of the media bound, when no `b=` line gave one.
    fn nominal_bandwidth(&self) -> f64 {
        let kinds = self
            .locals
            .iter()
            .filter(|local| local.role == Role::Media)
            .map(|local| local.kind)
            .chain(self.remotes.values().map(|remote| remote.kind));
        let (mut video, mut audio) = (false, false);
        for kind in kinds {
            match kind {
                Kind::Video => video = true,
                Kind::Audio => audio = true,
                Kind::Other => {}
            }
        }
        nominal_session_bandwidth(video, audio)
    }

    /// The RTCP bandwidth in octets per second and the senders' share of it.
    fn rtcp_bandwidth(&self, now: Instant) -> (f64, f64) {
        let session = self.session_bandwidth(now);
        // RFC 3556: a modifier that is absent keeps its default share of the 5%.
        let default_rs = session * self.rtcp_fraction * RTCP_SENDER_BW_FRACTION;
        let default_rr = session * self.rtcp_fraction * (1.0 - RTCP_SENDER_BW_FRACTION);
        match (self.bandwidth.rs, self.bandwidth.rr) {
            (None, None) => (session * self.rtcp_fraction / 8.0, RTCP_SENDER_BW_FRACTION),
            (rs, rr) => {
                let rs = rs.map_or(default_rs, |rs| rs as f64);
                let rr = rr.map_or(default_rr, |rr| rr as f64);
                let total = rs + rr;
                if total <= 0.0 {
                    (0.0, RTCP_SENDER_BW_FRACTION)
                } else {
                    (total / 8.0, rs / total)
                }
            }
        }
    }

    /// The RTCP bandwidth this endpoint's own SSRCs schedule with, octets per second, and the
    /// senders' share of it: [`Self::rtcp_bandwidth`], held with
    /// [`RtcpSessionBuilder::with_share_following_send_rate`] to the RTCP fraction of a
    /// session in which every endpoint sends at this endpoint's congestion-controlled rate.
    fn own_rtcp_bandwidth(&self, now: Instant) -> (f64, f64) {
        let (rtcp_bw, sender_fraction) = self.rtcp_bandwidth(now);
        let (true, Some(send_rate)) = (self.share_follows_send_rate, self.send_rate) else {
            return (rtcp_bw, sender_fraction);
        };
        let locals = self
            .locals
            .iter()
            .filter(|local| local.participates())
            .count()
            .max(1) as f64;
        let members = self.member_count().max(1) as f64;
        let session = (send_rate * members / locals).max(self.minimum_session_bandwidth as f64);
        (
            rtcp_bw.min(session * self.rtcp_fraction / 8.0),
            sender_fraction,
        )
    }

    /// The minimum interval in force for a local SSRC.
    fn t_min(&self, now: Instant, initial: bool) -> f64 {
        match self.profile {
            RtcpProfile::Avp => {
                if self.reduced_minimum {
                    reduced_minimum(self.session_bandwidth(now))
                } else {
                    RTCP_MIN_TIME
                }
            }
            // RFC 4585 3.5.1 and 3.5.3: zero for a point-to-point session, one second for the
            // first packet of a multiparty one, zero after it.
            RtcpProfile::Avpf => {
                if initial && !self.is_point_to_point() {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    /// RFC 3550 6.3.8: whether the local SSRC sent RTP within the last two report intervals.
    fn we_sent(&self, index: usize, now: Instant) -> bool {
        let horizon = 2.0 * self.report_interval(now);
        self.locals[index]
            .last_rtp
            .is_some_and(|last| now.saturating_duration_since(last).as_secs_f64() <= horizon)
    }

    /// The interval reports are made at, for the sender status of RFC 3550 6.3.5 and 6.3.8
    /// ("within the last two RTCP report intervals"): the interval at which the members
    /// share the RTCP bandwidth, no less than the profile's minimum, and under RTP/AVPF no
    /// less than `T_rr_interval`, inside which regular reports are suppressed.
    fn report_interval(&self, now: Instant) -> f64 {
        let (rtcp_bw, _) = self.rtcp_bandwidth(now);
        let shared = if rtcp_bw > 0.0 {
            self.avg_rtcp_size * self.member_count().max(1) as f64 / rtcp_bw
        } else {
            RTCP_MIN_TIME
        };
        let floor = match self.profile {
            RtcpProfile::Avp => self.t_min(now, false),
            RtcpProfile::Avpf => self.t_rr_interval,
        };
        shared.max(floor).max(MIN_INTERVAL)
    }

    fn sender_count(&self, now: Instant) -> usize {
        let horizon = 2.0 * self.report_interval(now);
        let sent_lately = |last_rtp: Option<Instant>| {
            last_rtp
                .is_some_and(|last| now.saturating_duration_since(last).as_secs_f64() <= horizon)
        };
        self.members
            .values()
            .filter(|member| sent_lately(member.last_rtp))
            .count()
            + self
                .locals
                .iter()
                .filter(|local| local.participates() && sent_lately(local.last_rtp))
                .count()
    }

    /// The input of the interval computation of RFC 3550 6.3.1.
    fn interval_input(
        &self,
        now: Instant,
        we_sent: bool,
        initial: bool,
        senders: usize,
        own: bool,
    ) -> IntervalInput {
        let (rtcp_bw, sender_fraction) = if own {
            self.own_rtcp_bandwidth(now)
        } else {
            self.rtcp_bandwidth(now)
        };
        IntervalInput {
            members: self.member_count().max(1),
            senders,
            rtcp_bw,
            sender_fraction,
            we_sent,
            avg_rtcp_size: self.avg_rtcp_size,
            t_min: self.t_min(now, initial),
            initial,
        }
    }

    /// The calculated interval T of a local SSRC, randomised (RFC 3550 6.3.1).
    fn interval(&mut self, index: usize, now: Instant) -> f64 {
        let we_sent = self.we_sent(index, now);
        let initial = self.locals[index]
            .timing
            .is_none_or(|timing| timing.initial);
        let senders = self.sender_count(now);
        let td = deterministic_interval(&self.interval_input(now, we_sent, initial, senders, true));
        let random = self.unit();
        randomized_interval(td, random).max(MIN_INTERVAL)
    }

    /// Td as the session calculates it now for a member that sends and for one that does not
    /// ([`RtcpReportingInterval`]).
    fn reporting_interval(&self, now: Instant) -> RtcpReportingInterval {
        let senders = self.sender_count(now);
        let td = |we_sent: bool| {
            // A member that sends is one of the senders, whether or not it has been heard to.
            let senders = if we_sent { senders.max(1) } else { senders };
            let td =
                deterministic_interval(&self.interval_input(now, we_sent, false, senders, false));
            // A member with no share of the RTCP bandwidth sends no regular report: an hour
            // stands for never.
            let td = if td.is_finite() {
                td.min(3600.0)
            } else {
                3600.0
            };
            Duration::from_secs_f64(td.max(MIN_INTERVAL))
        };
        RtcpReportingInterval {
            sender: td(true),
            receiver: td(false),
        }
    }

    /// This endpoint's share of the RTCP bandwidth ([`RtcpBandwidthShare`]).
    fn bandwidth_share(&self, now: Instant) -> RtcpBandwidthShare {
        let (rtcp_bw, _) = self.rtcp_bandwidth(now);
        let local = self.locals.iter().filter(|l| l.participates()).count();
        RtcpBandwidthShare {
            bits_per_second: rtcp_bw * 8.0 * local as f64 / self.member_count().max(1) as f64,
        }
    }

    /// The `T_rr_interval` regular reports keep (RFC 4585 3.5.3), seconds: the configured or
    /// negotiated one, or with [`RtcpSessionBuilder::with_congestion_feedback_in_budget`] the
    /// regular interval in what the RTCP bandwidth leaves after the congestion control
    /// feedback, whichever is longer (at most [`MAX_BUDGET_T_RR_INTERVAL`]).
    fn effective_t_rr_interval(&self, index: usize, now: Instant) -> f64 {
        if !self.congestion_feedback_in_budget {
            return self.t_rr_interval;
        }
        let (rtcp_bw, sender_fraction) = self.own_rtcp_bandwidth(now);
        let feedback = self.congestion_feedback_rate.bits_per_second(now) / 8.0;
        let left = rtcp_bw - feedback;
        let size = if self.regular_size > 0.0 {
            self.regular_size
        } else {
            self.avg_rtcp_size
        };
        let budget = if left <= 0.0 {
            MAX_BUDGET_T_RR_INTERVAL
        } else {
            let input = IntervalInput {
                members: self.member_count().max(1),
                senders: self.sender_count(now),
                rtcp_bw: left,
                sender_fraction,
                we_sent: self.we_sent(index, now),
                avg_rtcp_size: size,
                t_min: 0.0,
                initial: false,
            };
            deterministic_interval(&input).min(MAX_BUDGET_T_RR_INTERVAL)
        };
        self.t_rr_interval.max(budget)
    }

    // ---- joining ---------------------------------------------------------------------

    /// Whether anything may make the session join: always, unless it joins on
    /// [`RtcpSessionControl::Start`] only and has not been given it.
    fn may_join(&self) -> bool {
        !self.joins_on_start || self.start_given
    }

    /// [`RtcpSessionControl::Start`] after [`RtcpSessionControl::Leave`]: the session is
    /// joined afresh (RFC 3550 section 6.3.2's initial state), with no members, nothing
    /// pending and the next local SSRC it reports from a new one.
    fn rejoin(&mut self) {
        self.left = false;
        self.started = false;
        self.departing.clear();
        self.pending.clear();
        self.early_at = None;
        self.bye = None;
        self.members.clear();
        self.pmembers = 0;
        self.avg_rtcp_size = 0.0;
        self.compound_sent = false;
        self.reference_times.clear();
        self.awaited = None;
        self.unanswered_reduced_nacks = 0;
    }

    /// Joins the session if it has not, and gives every participating SSRC its timer.
    fn sync(&mut self, now: Instant) {
        if self.left || !self.may_join() {
            return;
        }
        self.sync_reporter();
        let joining = !self.started;
        if !self.started {
            self.started = true;
            // RFC 3550 6.3.2: avg_rtcp_size starts at the probable size of the first packet:
            // a report, an SDES with the CNAME, and a block for each stream bound so far.
            // RFC 3711 section 3.4: with the SRTCP fields.
            self.avg_rtcp_size = (LOWER_LAYER_OVERHEAD
                + 8
                + 12
                + self.cname.len()
                + 24 * self.remotes.len().min(MAX_REPORT_BLOCKS)
                + self.srtcp_overhead) as f64;
            self.pmembers = self.member_count().max(1);
        }
        for index in 0..self.locals.len() {
            if self.locals[index].timing.is_none() && self.locals[index].participates() {
                self.locals[index].timing = Some(if joining && self.first_report_at_join {
                    Timing::immediate(now)
                } else {
                    let t = self.interval(index, now);
                    Timing::new(now, t)
                });
            }
        }
        self.flush_departing(now);
        self.announce_reporter(now);
    }

    /// Tells the application of a change of the session's own reporting SSRC
    /// ([`RtcpSessionEvent::ReportingSsrc`]).
    fn announce_reporter(&mut self, now: Instant) {
        let reporter = self
            .locals
            .iter()
            .find(|local| local.role == Role::Reporter)
            .map(|local| local.ssrc);
        if reporter != self.announced_reporter {
            self.announced_reporter = reporter;
            self.emit(now, RtcpSessionEvent::ReportingSsrc { ssrc: reporter });
        }
    }

    // ---- the member table ------------------------------------------------------------

    fn heard(&mut self, now: Instant, ssrc: u32, rtp: bool) {
        if let Some(&left_at) = self.said_bye.get(&ssrc) {
            // RFC 3550 6.2.1: a straggler behind the BYE; the source stays gone for two
            // report intervals.
            if now.saturating_duration_since(left_at).as_secs_f64()
                <= 2.0 * self.report_interval(now)
            {
                return;
            }
            self.said_bye.remove(&ssrc);
        }
        if let Some(member) = self.members.get_mut(&ssrc) {
            member.last_heard = now;
            if rtp {
                member.last_rtp = Some(now);
            }
        } else if self.members.len() < MAX_MEMBERS {
            self.members.insert(
                ssrc,
                Member {
                    last_heard: now,
                    last_rtp: rtp.then_some(now),
                    cname: None,
                },
            );
        }
        if let Some(remote) = self.remotes.get_mut(&ssrc) {
            remote.gone = false;
        }
    }

    /// RFC 3550 6.3.4: the membership fell; the timers shrink with it.
    fn reverse_reconsider(&mut self, now: Instant) {
        let members = self.member_count().max(1);
        if members < self.pmembers {
            let pmembers = self.pmembers;
            for local in &mut self.locals {
                if let Some(timing) = local.timing.as_mut() {
                    timing.reverse_reconsider(now, members, pmembers);
                }
            }
            self.pmembers = members;
        }
    }

    fn remove_member(&mut self, ssrc: u32) -> bool {
        if let Some(remote) = self.remotes.get_mut(&ssrc) {
            remote.gone = true;
        }
        self.reference_times.remove(&ssrc);
        self.members.remove(&ssrc).is_some()
    }

    /// RFC 3550 6.3.5 with RFC 8108 7.1.4: a member not heard for five deterministic
    /// intervals (computed for a receiver, with a minimum of five seconds) is timed out.
    fn time_out_members(&mut self, now: Instant) {
        let mut input = self.interval_input(now, false, false, self.sender_count(now), false);
        input.t_min = RTCP_MIN_TIME;
        let timeout = TIMEOUT_MULTIPLIER * deterministic_interval(&input);
        if !timeout.is_finite() {
            return;
        }
        let silent: Vec<u32> = self
            .members
            .iter()
            .filter(|(_, member)| {
                now.saturating_duration_since(member.last_heard)
                    .as_secs_f64()
                    > timeout
            })
            .map(|(ssrc, _)| *ssrc)
            .collect();
        let linger = 2.0 * self.report_interval(now);
        self.said_bye
            .retain(|_, left_at| now.saturating_duration_since(*left_at).as_secs_f64() <= linger);
        if silent.is_empty() {
            return;
        }
        for ssrc in silent {
            self.remove_member(ssrc);
            self.emit(now, RtcpSessionEvent::SourceTimedOut { ssrc });
        }
        self.reverse_reconsider(now);
    }

    /// RFC 3550 8.2: a packet from another source carries one of this endpoint's SSRCs.
    fn collision(&mut self, now: Instant, ssrc: u32) {
        let Some(index) = self.local_index(ssrc) else {
            return;
        };
        let mut random = std::mem::replace(&mut self.random, Box::new(ThreadRandom));
        let replacement = choose_ssrc(random.as_mut(), |candidate| self.ssrc_in_use(candidate));
        self.random = random;

        if self.locals[index].role == Role::Reporter {
            // The session's own SSRC: say BYE with the old identifier and take the new one.
            let old = self.locals.remove(index);
            self.departing.push(old);
            self.locals.push(Local::new(
                replacement,
                Kind::Other,
                Role::Reporter,
                90_000,
                self.wall_clock,
            ));
            self.emit(now, RtcpSessionEvent::SsrcCollision { ssrc, replacement });
            self.sync(now);
        } else if self.collided.insert(ssrc) {
            // A stream's SSRC is the sender's to change: it is told, and the BYE for the old
            // SSRC leaves when the stream is unbound.
            self.emit(now, RtcpSessionEvent::SsrcCollision { ssrc, replacement });
        }
    }

    // ---- what arrives ----------------------------------------------------------------

    /// Whether the packet goes on to the rest of the chain.
    fn observe_rtp(
        &mut self,
        now: Instant,
        message: &AttributedPacket,
        ecn: Option<shared::EcnCodepoint>,
    ) -> bool {
        let Packet::Rtp(packet) = &message.packet else {
            return true;
        };
        let header = &packet.header;
        // The stream the packet arrived on: the RTX stream for a retransmission that was
        // de-encapsulated before the chain.
        let (arrival_ssrc, arrival_sequence_number) = message
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Retransmitted {
                    ssrc,
                    sequence_number,
                } => Some((*ssrc, *sequence_number)),
                _ => None,
            })
            .unwrap_or((header.ssrc, header.sequence_number));

        // RFC 3550 8.2: our own SSRC from the network is a collision, or our own packet
        // looped back; either way it is not a remote stream's.
        if self.local_index(arrival_ssrc).is_some() {
            self.collision(now, arrival_ssrc);
            return false;
        }

        // RFC 3550 6.2: "Bandwidth calculations for control and data traffic include lower-
        // layer transport and network protocols (e.g., UDP and IP)".
        self.rate.add(
            now,
            LOWER_LAYER_OVERHEAD + header.marshal_size() + packet.payload.len(),
        );
        self.heard(now, arrival_ssrc, true);
        for &csrc in &header.csrc {
            self.heard(now, csrc, false);
        }

        self.observe_ecn(now, arrival_ssrc, arrival_sequence_number, ecn);
        if let Some(remote) = self.remotes.get_mut(&arrival_ssrc) {
            if arrival_ssrc == header.ssrc {
                remote.stream.process_rtp(now, packet);
            } else {
                let mut arrived = rtp::Packet {
                    header: rtp::header::Header {
                        ssrc: arrival_ssrc,
                        sequence_number: arrival_sequence_number,
                        timestamp: header.timestamp,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                arrived.header.version = 2;
                remote.stream.process_rtp(now, &arrived);
            }
        } else if arrival_ssrc != header.ssrc
            && let Some(remote) = self.remotes.get_mut(&header.ssrc)
        {
            // A retransmission whose RTX stream is not bound counts where it is delivered.
            remote.stream.process_rtp(now, packet);
        }

        // RFC 5506 4.2.1: a packet a reduced-size NACK asked for arrived, so they get through.
        if let Some((ssrc, sequence_numbers)) = &self.awaited
            && *ssrc == header.ssrc
            && sequence_numbers.contains(&header.sequence_number)
        {
            self.awaited = None;
            self.unanswered_reduced_nacks = 0;
        }
        true
    }

    /// RFC 6679 5.1, 7.2.1 and 7.3.2: counts the ECN field of an RTP packet from a source
    /// that negotiated ECN feedback, and asks for an early ECN Feedback packet on the first
    /// ECT or CE packet of the source, on every CE mark and on a detected loss, where the
    /// feedback packet (`nack ecn`) was negotiated.
    fn observe_ecn(
        &mut self,
        now: Instant,
        ssrc: u32,
        sequence_number: u16,
        ecn: Option<shared::EcnCodepoint>,
    ) {
        let Some(remote) = self.remotes.get_mut(&ssrc) else {
            return;
        };
        let Some(tally) = remote.ecn.as_deref_mut() else {
            return;
        };
        let events = tally.on_packet(sequence_number, ecn);
        if !(events.any() && remote.ecn_feedback) {
            return;
        }
        let feedback = EcnFeedback {
            sender_ssrc: 0,
            media_ssrc: ssrc,
            extended_highest_sequence_number: tally.extended_highest(),
            counters: tally.counters(),
        };
        self.adopt(boxed(feedback));
        self.schedule_feedback(now);
    }

    fn observe_report_blocks(&mut self, now: Instant, reports: &[ReceptionReport]) {
        for report in reports {
            if report.last_sender_report == 0 {
                continue;
            }
            let Some(index) = self.local_index(report.ssrc) else {
                continue;
            };
            let Some(&(_, sent)) = self.locals[index]
                .sent_reports
                .iter()
                .find(|(compact_ntp, _)| *compact_ntp == report.last_sender_report)
            else {
                continue;
            };
            // RFC 3550 6.4.1: the round trip is the time since the report was sent less the
            // delay the receiver held it for (DLSR, in 1/65536 s).
            let elapsed = now.saturating_duration_since(sent).as_secs_f64();
            let rtt = (elapsed - f64::from(report.delay) / 65536.0).max(0.0);
            self.emit(
                now,
                RtcpSessionEvent::RoundTripTime {
                    ssrc: report.ssrc,
                    rtt: Duration::from_secs_f64(rtt),
                },
            );
        }
    }

    fn observe_rtcp(&mut self, now: Instant, packets: &[Box<dyn rtcp::Packet>]) {
        if packets.is_empty() {
            return;
        }
        // RFC 3711 section 3.4: the SRTCP fields count, though they are gone by now.
        let size =
            (wire_size(packets) + self.srtcp_overhead) as f64 / reporting_ssrcs(packets) as f64;
        let mut goodbyes = 0;
        let feedback: usize = packets
            .iter()
            .filter(|packet| {
                let any = packet.as_any();
                any.is::<TransportLayerCc>() || any.is::<CcFeedbackReport>()
            })
            .map(|packet| packet.marshal_size())
            .sum();
        if feedback > 0 {
            // A reduced-size packet's SRTCP fields are the feedback's own.
            let reduced = !packets.iter().any(|packet| {
                let any = packet.as_any();
                any.is::<SenderReport>() || any.is::<ReceiverReport>()
            });
            let overhead = if reduced { self.srtcp_overhead } else { 0 };
            self.congestion_feedback_rate.add(now, feedback + overhead);
        }

        for packet in packets {
            let any = packet.as_any();
            if let Some(goodbye) = any.downcast_ref::<Goodbye>() {
                goodbyes += 1;
                for &source in &goodbye.sources {
                    self.remove_member(source);
                    if self.said_bye.len() < MAX_MEMBERS {
                        self.said_bye.insert(source, now);
                    }
                }
                continue;
            }
            if let Some(sdes) = any.downcast_ref::<SourceDescription>() {
                for chunk in &sdes.chunks {
                    if self.local_index(chunk.source).is_some() {
                        continue;
                    }
                    self.heard(now, chunk.source, false);
                    let cname = chunk
                        .items
                        .iter()
                        .find(|item| item.sdes_type == SdesType::SdesCname)
                        .map(|item| String::from_utf8_lossy(&item.text).into_owned());
                    if let Some(cname) = cname
                        && let Some(member) = self.members.get_mut(&chunk.source)
                        && member.cname.as_deref() != Some(cname.as_str())
                    {
                        member.cname = Some(cname.clone());
                        self.emit(
                            now,
                            RtcpSessionEvent::RemoteCname {
                                ssrc: chunk.source,
                                cname,
                            },
                        );
                    }
                }
                continue;
            }

            let (sender, _) = sender_and_media(packet.as_ref());
            if let Some(sender) = sender {
                if self.local_index(sender).is_some() {
                    // RFC 3550 8.2: RTCP from another source under one of our SSRCs.
                    self.collision(now, sender);
                    continue;
                }
                self.heard(now, sender, false);
            }

            // RFC 6051 section 3.2: "a media source that understands the RTCP-SR-REQ packet
            // SHOULD generate an RTCP SR packet as soon as possible while complying with the
            // RTCP early feedback rules".
            if let Some(request) = any.downcast_ref::<RapidResynchronizationRequest>()
                && let Some(index) = self.local_index(request.media_ssrc)
            {
                self.request_sender_report(now, index);
            }

            if let Some(sr) = any.downcast_ref::<SenderReport>() {
                // RFC 7164 section 5.1: the timestamps of a sender report from near a leap
                // second are ignored; the last one before it stays the one reported on (LSR).
                if let Some(remote) = self.remotes.get_mut(&sr.ssrc)
                    && !near_leap_second(sr.ntp_time)
                {
                    remote.stream.process_sender_report(now, sr);
                }
                self.observe_report_blocks(now, &sr.reports);
            } else if let Some(rr) = any.downcast_ref::<ReceiverReport>() {
                self.observe_report_blocks(now, &rr.reports);
            } else if let Some(xr) = any.downcast_ref::<ExtendedReport>() {
                for block in &xr.reports {
                    if let Some(rrtr) = block
                        .as_any()
                        .downcast_ref::<ReceiverReferenceTimeReportBlock>()
                        && (self.reference_times.len() < MAX_REFERENCE_TIMES
                            || self.reference_times.contains_key(&xr.sender_ssrc))
                    {
                        self.reference_times
                            .insert(xr.sender_ssrc, ((rrtr.ntp_timestamp >> 16) as u32, now));
                    }
                }
            }
        }

        if let Some(bye) = self.bye.as_mut() {
            // RFC 3550 6.3.7: while a BYE waits, only BYE packets are counted and sized.
            if goodbyes > 0 {
                bye.members += goodbyes;
                bye.size = update_avg_rtcp_size(bye.size, size);
            }
        } else {
            self.avg_rtcp_size = update_avg_rtcp_size(self.avg_rtcp_size, size);
            if goodbyes > 0 {
                self.reverse_reconsider(now);
            }
        }
    }

    // ---- what the chain and the application write ------------------------------------

    /// Takes an RTCP packet written from above into the session's hands.
    fn adopt(&mut self, packet: Box<dyn rtcp::Packet>) {
        let any = packet.as_any();
        // The session's own reports and CNAME stand for these.
        if any.is::<SenderReport>() || any.is::<ReceiverReport>() || any.is::<SourceDescription>() {
            return;
        }
        let (sender, media) = sender_and_media(packet.as_ref());
        let packet = match (sender, self.feedback_source(media)) {
            (Some(_), Some(index)) => with_sender(packet, self.locals[index].ssrc),
            _ => packet,
        };

        if let Some(request) = packet
            .as_any()
            .downcast_ref::<TemporaryMaximumBitrateRequest>()
        {
            self.supersede_held_requests(request);
        }

        // RFC 4585 3.5.2: feedback for one compound packet is merged into as few messages
        // as possible.
        let any = packet.as_any();
        if let Some(nack) = any.downcast_ref::<TransportLayerNack>() {
            for held in &mut self.pending {
                if let Some(other) = held.as_any().downcast_ref::<TransportLayerNack>()
                    && other.media_ssrc == nack.media_ssrc
                {
                    let mut sequence_numbers: Vec<u16> = other
                        .nacks
                        .iter()
                        .chain(&nack.nacks)
                        .flat_map(|pair| pair.packet_list())
                        .collect();
                    sequence_numbers.sort_unstable();
                    sequence_numbers.dedup();
                    *held = boxed(TransportLayerNack {
                        sender_ssrc: nack.sender_ssrc,
                        media_ssrc: nack.media_ssrc,
                        nacks: nack_pairs_from_sequence_numbers(&sequence_numbers),
                    });
                    return;
                }
            }
        } else if let Some(feedback) = any.downcast_ref::<EcnFeedback>() {
            // RFC 6679 5.1: the counters are cumulative, so the newest report says all an
            // older one waiting beside it would.
            let media = feedback.media_ssrc;
            self.pending.retain(|held| {
                held.as_any()
                    .downcast_ref::<EcnFeedback>()
                    .is_none_or(|other| other.media_ssrc != media)
            });
        } else if let Some(pli) = any.downcast_ref::<PictureLossIndication>()
            && self.pending.iter().any(|held| {
                held.as_any()
                    .downcast_ref::<PictureLossIndication>()
                    .is_some_and(|other| other.media_ssrc == pli.media_ssrc)
            })
        {
            return;
        }

        if self.pending.len() >= MAX_PENDING {
            self.pending.remove(0);
        }
        self.pending.push(packet);
    }

    /// Holds a packet written with [`RegularTiming`] for the next Regular compound packet.
    fn hold_for_regular(&mut self, packet: Box<dyn rtcp::Packet>) {
        let any = packet.as_any();
        if any.is::<SenderReport>() || any.is::<ReceiverReport>() || any.is::<SourceDescription>() {
            return;
        }
        if let Some(request) = any.downcast_ref::<TemporaryMaximumBitrateRequest>() {
            self.supersede_held_requests(request);
        }
        if self.held_for_regular.len() >= MAX_PENDING {
            self.held_for_regular.remove(0);
        }
        self.held_for_regular.push(packet);
    }

    /// A newer TMMBR replaces the entries a held repetition has for the same media senders
    /// (RFC 5104 section 4.2.1.2: the entry is sent with its current values).
    fn supersede_held_requests(&mut self, newer: &TemporaryMaximumBitrateRequest) {
        let asked: HashSet<u32> = newer.entries.iter().map(|entry| entry.ssrc).collect();
        self.held_for_regular.retain_mut(|held| {
            let Some(request) = held
                .as_any()
                .downcast_ref::<TemporaryMaximumBitrateRequest>()
            else {
                return true;
            };
            if !request
                .entries
                .iter()
                .any(|entry| asked.contains(&entry.ssrc))
            {
                return true;
            }
            let mut request = request.clone();
            request.entries.retain(|entry| !asked.contains(&entry.ssrc));
            if request.entries.is_empty() {
                return false;
            }
            *held = boxed(request);
            true
        });
    }

    /// Moves the packets held for a Regular compound packet into `packets`, as far as
    /// `budget` goes; the others wait for the next one.
    fn take_held_for_regular(
        &mut self,
        packets: &mut Vec<Box<dyn rtcp::Packet>>,
        budget: &mut usize,
    ) {
        let mut kept = vec![];
        for packet in std::mem::take(&mut self.held_for_regular) {
            let size = packet.marshal_size();
            if size <= *budget {
                *budget -= size;
                packets.push(packet);
            } else {
                kept.push(packet);
            }
        }
        self.held_for_regular = kept;
    }

    /// RFC 4585 3.5.2, step 4a: feedback that could not leave in an Early packet is stored
    /// for the next regular one and sent with it "if it is still useful then". The receiving
    /// application's NACK horizon ([`NackControl::Horizon`], RFC 4588 6.3) says which packets
    /// of `media_ssrc` no longer are: the ones before `oldest_useful` leave a NACK that is
    /// still held, and a NACK left with none is not sent.
    fn forget_nacks_behind(&mut self, media_ssrc: u32, oldest_useful: u16) {
        self.pending.retain_mut(|held| {
            let Some(nack) = held.as_any().downcast_ref::<TransportLayerNack>() else {
                return true;
            };
            if nack.media_ssrc != media_ssrc {
                return true;
            }
            let requested: Vec<u16> = nack
                .nacks
                .iter()
                .flat_map(|pair| pair.packet_list())
                .collect();
            let useful: Vec<u16> = requested
                .iter()
                .copied()
                .filter(|&sequence_number| !older_than(sequence_number, oldest_useful))
                .collect();
            if useful.len() == requested.len() {
                return true;
            }
            if useful.is_empty() {
                return false;
            }
            let sender_ssrc = nack.sender_ssrc;
            *held = boxed(TransportLayerNack {
                sender_ssrc,
                media_ssrc,
                nacks: nack_pairs_from_sequence_numbers(&useful),
            });
            true
        });
    }

    fn has_feedback(&self) -> bool {
        self.pending.iter().any(|packet| {
            let any = packet.as_any();
            // RFC 5104 sections 4.3.2.3 and 4.3.3.3: a TSTR "is not time critical and SHOULD
            // be sent using regular RTCP timing", and so is the TSTN that answers it. They
            // wait for the next regular packet and ask for no Early one (another feedback
            // message that does takes them along).
            !any.is::<ExtendedReport>()
                && !any.is::<Goodbye>()
                && !any.is::<TemporalSpatialTradeoffRequest>()
                && !any.is::<TemporalSpatialTradeoffNotification>()
        })
    }

    /// RFC 4585 3.5.2: feedback was detected at `now`.
    fn schedule_feedback(&mut self, now: Instant) {
        if !self.has_feedback() || self.profile == RtcpProfile::Avp {
            // Without AVPF, feedback rides the next regular packet.
            return;
        }
        // Step 2: a packet with feedback is already scheduled; this joins it.
        if self.early_at.is_some() {
            return;
        }
        let media = self
            .pending
            .iter()
            .find_map(|packet| sender_and_media(packet.as_ref()).1);
        let Some(index) = self.feedback_source(media) else {
            return;
        };
        let Some(timing) = self.locals[index].timing else {
            return;
        };
        // Step 2b: no dither between two parties, half the regular interval among more.
        let t_dither_max = if self.is_point_to_point() {
            0.0
        } else {
            0.5 * seconds_between(timing.tp, timing.tn).max(0.0)
        };
        // Step 3: the regular packet is due within the dither; step 4a: no early packet is
        // allowed. Either way the feedback is stored for the regular packet at tn.
        if after(now, t_dither_max) > timing.tn || !timing.allow_early {
            return;
        }
        // Step 4b.
        let te = after(now, self.unit() * t_dither_max);
        if te <= now {
            self.send_early(now, index);
        } else {
            self.early_at = Some(te);
        }
    }

    /// RFC 6051 section 3.2: an SR from the local SSRC `index` as soon as RFC 4585 3.5.2
    /// allows, in an Early packet (a regular one due within the dither carries it anyway,
    /// as does the next regular one when no Early packet is allowed now). Under RTP/AVP
    /// there is no Early packet; nor is there an SR to give for an SSRC that has not sent.
    fn request_sender_report(&mut self, now: Instant, index: usize) {
        if self.profile == RtcpProfile::Avp || !self.we_sent(index, now) {
            return;
        }
        let Some(timing) = self.locals[index].timing else {
            return;
        };
        self.sender_report_requested = Some(index);
        if self.early_at.is_some() {
            return;
        }
        let t_dither_max = if self.is_point_to_point() {
            0.0
        } else {
            0.5 * seconds_between(timing.tp, timing.tn).max(0.0)
        };
        if after(now, t_dither_max) > timing.tn || !timing.allow_early {
            self.sender_report_requested = None;
            return;
        }
        let te = after(now, self.unit() * t_dither_max);
        if te <= now {
            self.sender_report_requested = None;
            self.send_early(now, index);
        } else {
            self.early_at = Some(te);
        }
    }

    // ---- building packets ------------------------------------------------------------

    fn sdes_chunk(&self, ssrc: u32) -> SourceDescriptionChunk {
        let mut items = vec![SourceDescriptionItem {
            sdes_type: SdesType::SdesCname,
            text: self.cname.clone().into(),
        }];
        if let Some(identifiers) = self.identifiers.get(&ssrc) {
            items.extend(identifiers.iter().cloned());
        }
        SourceDescriptionChunk {
            source: ssrc,
            items,
        }
    }

    /// The SR of a local SSRC that sent lately, its RR otherwise (RFC 3550 6.4).
    fn report(
        &mut self,
        index: usize,
        now: Instant,
        blocks: Vec<ReceptionReport>,
    ) -> Box<dyn rtcp::Packet> {
        let we_sent = self.we_sent(index, now);
        let local = &mut self.locals[index];
        local.rtcp_sent = true;
        // RFC 7164 section 5.1: no sender report "containing an originating NTP timestamp in
        // the vicinity of a positive leap second"; a receiver report in its place keeps the
        // schedule.
        if we_sent
            && let Some(mut report) = local.stream.generate_report(now)
            && !near_leap_second(report.ntp_time)
        {
            local
                .sent_reports
                .push_back(((report.ntp_time >> 16) as u32, now));
            while local.sent_reports.len() > 8 {
                local.sent_reports.pop_front();
            }
            report.reports = blocks;
            boxed(report)
        } else {
            boxed(ReceiverReport {
                ssrc: local.ssrc,
                reports: blocks,
                ..Default::default()
            })
        }
    }

    /// The report blocks of this interval: up to `max` remote streams, taken round robin so
    /// that each is reported in turn when they do not all fit (RFC 3550 6.1).
    ///
    /// When they do not all fit, streams losing [`HIGH_LOSS_FRACTION`] or more since their
    /// last report go first, the worst first, in up to half of the blocks (RFC 8083 section
    /// 4.3: "priority SHOULD be given to reports on sources that have high packet loss
    /// rates"); the other half stays round robin, so every stream is still reported in turn.
    fn report_blocks(&mut self, now: Instant, max: usize) -> Vec<ReceptionReport> {
        let candidates: Vec<u32> = self
            .remote_order
            .iter()
            .copied()
            .filter(|ssrc| {
                self.remotes
                    .get(ssrc)
                    .is_some_and(|remote| !remote.gone && remote.stream.has_received())
            })
            .collect();
        if candidates.is_empty() || max == 0 {
            return vec![];
        }
        let mut chosen: Vec<u32> = Vec::new();
        if candidates.len() > max {
            let mut lossy: Vec<(u8, u32)> = candidates
                .iter()
                .filter_map(|ssrc| {
                    let loss = self.remotes.get(ssrc)?.stream.pending_fraction_lost();
                    (loss >= HIGH_LOSS_FRACTION).then_some((loss, *ssrc))
                })
                .collect();
            lossy.sort_by_key(|(loss, _)| std::cmp::Reverse(*loss));
            chosen.extend(lossy.iter().take(max / 2).map(|(_, ssrc)| *ssrc));
        }
        let rest: Vec<u32> = candidates
            .iter()
            .copied()
            .filter(|ssrc| !chosen.contains(ssrc))
            .collect();
        if !rest.is_empty() {
            let count = rest.len().min(max - chosen.len());
            let start = self.report_cursor % rest.len();
            self.report_cursor = (start + count) % rest.len();
            chosen.extend((0..count).map(|offset| rest[(start + offset) % rest.len()]));
        }
        chosen
            .into_iter()
            .filter_map(|ssrc| {
                self.remotes
                    .get_mut(&ssrc)
                    .map(|remote| remote.stream.generate_reception_report(now))
            })
            .collect()
    }

    /// RFC 8108 5.1: the report blocks about this endpoint's own SSRCs that have sent, for
    /// the other local SSRCs to carry ("each SSRC will send RTCP reports for all other SSRCs,
    /// including those co-located at the same endpoint"). What a co-located receiver measures
    /// over a path with no loss and no delay: nothing lost, no jitter, the highest sequence
    /// number sent, and the last sender report of the source with the time since it.
    fn colocated_blocks(&self, now: Instant) -> Vec<ReceptionReport> {
        self.locals
            .iter()
            .filter(|local| local.participates())
            .filter_map(|local| {
                let last_sequence_number = local.stream.extended_highest_sequence()?;
                let (last_sender_report, delay) = local
                    .sent_reports
                    .back()
                    .map(|&(lsr, at)| {
                        let delay = now.saturating_duration_since(at).as_secs_f64() * 65536.0;
                        (lsr, delay.min(f64::from(u32::MAX)) as u32)
                    })
                    .unwrap_or((0, 0));
                Some(ReceptionReport {
                    ssrc: local.ssrc,
                    last_sequence_number,
                    last_sender_report,
                    delay,
                    ..Default::default()
                })
            })
            .collect()
    }

    /// RFC 3611 section 5.1: the maximum DLRR size a stream's `rcvr-rtt=<mode>:<max>` names
    /// (an `rrtr` feedback whose parameter is the `xr-format` as signalled).
    fn record_dlrr_limit(&mut self, info: &StreamInfo) {
        let limit = info
            .rtcp_feedback
            .iter()
            .filter(|feedback| feedback.typ == crate::RTCP_FB_RRTR)
            .filter_map(|feedback| dlrr_limit(&feedback.parameter))
            .min();
        match limit {
            Some(limit) => self.dlrr_limits.insert(info.ssrc, limit),
            None => self.dlrr_limits.remove(&info.ssrc),
        };
    }

    /// The XR packet of a regular report: a receiver reference time when a bound stream
    /// negotiated it, and a DLRR block answering the reference times received (RFC 3611 4.4,
    /// 4.5) when a local SSRC sends.
    fn extended_report(
        &mut self,
        now: Instant,
        ssrc: u32,
        any_sender: bool,
        budget: usize,
    ) -> Option<ExtendedReport> {
        let mut blocks: Vec<Box<dyn rtcp::Packet>> = vec![];
        if self
            .remotes
            .values()
            .any(|remote| remote.rrtr && !remote.gone)
        {
            let wall_clock = *self
                .wall_clock
                .get_or_insert_with(|| SystemInstant::shared(now));
            let ntp_timestamp = wall_clock.ntp(now);
            // RFC 7164 section 5: no NTP timestamp generated near a leap second.
            if !near_leap_second(ntp_timestamp) {
                blocks.push(Box::new(ReceiverReferenceTimeReportBlock { ntp_timestamp }));
            }
        }
        // RFC 3611 section 5.1: "non RTP senders SHALL NOT send DLRR blocks" under
        // `rcvr-rtt=sender`; under `all` they MAY, and this endpoint does not. A DLRR block is
        // no larger than the signalled maximum: the reference times that do not fit wait for
        // the next report, oldest first ("in a round robin fashion across several report
        // intervals").
        if any_sender && !self.reference_times.is_empty() {
            let fit = self
                .dlrr_limits
                .values()
                .min()
                .map_or(usize::MAX, |octets| octets.saturating_sub(4) / 12)
                .max(1);
            let mut waiting: Vec<(u32, (u32, Instant))> =
                self.reference_times.iter().map(|(k, v)| (*k, *v)).collect();
            waiting.sort_by_key(|(ssrc, (_, arrived))| (*arrived, *ssrc));
            let reports = waiting
                .into_iter()
                .take(fit)
                .map(|(ssrc, (last_rr, arrived))| {
                    self.reference_times.remove(&ssrc);
                    DLRRReport {
                        ssrc,
                        last_rr,
                        dlrr: (now.saturating_duration_since(arrived).as_secs_f64() * 65536.0)
                            as u64 as u32,
                    }
                })
                .collect();
            blocks.push(Box::new(DLRRReportBlock { reports }));
        }
        // RFC 6679 7.3.2: "Every time a regular compound RTCP packet is to be transmitted, an
        // ECN-capable RTP receiver MUST include an RTCP XR ECN Summary Report"; section 5.2:
        // the SSRCs reported as senders are in it, and with none the block "SHALL still be
        // sent with no report block entry and a zero report block length".
        if self
            .remotes
            .values()
            .any(|remote| remote.ecn_summary && !remote.gone)
        {
            let mut reports: Vec<EcnSummaryReport> = self
                .remote_order
                .iter()
                .filter_map(|ssrc| {
                    let remote = self.remotes.get(ssrc)?;
                    let tally = remote.ecn.as_deref()?;
                    (remote.ecn_summary && !remote.gone && tally.heard()).then(|| {
                        EcnSummaryReport {
                            ssrc: *ssrc,
                            counters: tally.counters(),
                        }
                    })
                })
                .collect();
            // RFC 6679 section 5.2: "If the RTCP SR or RR packet and the XR ECN summary
            // report together exceed the MTU, a subset of the senders is reported, chosen in a
            // round-robin fashion" across the compound packets. Room is what the compound
            // packet has left after the XR header and the blocks before this one; one entry
            // goes at least. One XR block's length field counts at most 65535 words.
            let used = 8 + blocks.iter().map(|b| b.marshal_size()).sum::<usize>() + 4;
            let fit = (budget.saturating_sub(used) / 20)
                .max(1)
                .min(usize::from(u16::MAX) / 5);
            if reports.len() > fit {
                let start = self.ecn_summary_next % reports.len();
                reports.rotate_left(start);
                reports.truncate(fit);
                self.ecn_summary_next = start + fit;
            } else {
                self.ecn_summary_next = 0;
            }
            blocks.push(Box::new(EcnSummaryReportBlock { reports }));
        }
        (!blocks.is_empty()).then_some(ExtendedReport {
            sender_ssrc: ssrc,
            reports: blocks,
        })
    }

    /// The octets an XR ECN Summary Report about the senders heard takes, at most `limit`
    /// (one entry at least): 0 when no remote negotiated the summary.
    fn ecn_summary_reserve(&self, limit: usize) -> usize {
        let wanted = self
            .remotes
            .values()
            .any(|remote| remote.ecn_summary && !remote.gone);
        if !wanted {
            return 0;
        }
        let senders = self
            .remotes
            .values()
            .filter(|remote| {
                remote.ecn_summary
                    && !remote.gone
                    && remote.ecn.as_deref().is_some_and(|t| t.heard())
            })
            .count();
        // XR header, block header, 20 octets an entry.
        let entries = senders.min(limit.saturating_sub(12) / 20).max(1);
        12 + 20 * entries
    }

    /// RFC 7728 sections 6.3, 8.2 ([`RepeatInRegularReports`]): a copy of each armed
    /// repetition into this Regular compound packet, as far as `budget` goes; a repetition
    /// that does not fit waits for the next Regular packet.
    fn take_repeats(&mut self, packets: &mut Vec<Box<dyn rtcp::Packet>>, budget: &mut usize) {
        for repeat in self.repeats.iter_mut().filter(|repeat| repeat.armed) {
            let size: usize = repeat.packets.iter().map(|p| p.marshal_size()).sum();
            if size > *budget {
                continue;
            }
            *budget -= size;
            packets.extend(repeat.packets.iter().map(|p| p.cloned()));
            repeat.left = repeat.left.saturating_sub(1);
        }
        self.repeats.retain(|repeat| repeat.left > 0);
    }

    /// Moves what is waiting into `packets`, as far as `budget` octets go. What does not fit
    /// waits for the next packet. A NACK too large for any compound packet is split (RFC 3550
    /// 6.1): its first pairs go in `packets` as far as `budget` goes, and the NACKs of the rest
    /// are returned, to leave at once in compound packets of their own. Any other packet too
    /// large for a compound packet goes as it is (it cannot be split).
    fn take_pending(
        &mut self,
        packets: &mut Vec<Box<dyn rtcp::Packet>>,
        budget: &mut usize,
        overhead: usize,
    ) -> Vec<TransportLayerNack> {
        /// A report without blocks and an SDES with one CNAME: what a minimal compound
        /// packet spends before its feedback.
        const MINIMAL_OVERHEAD: usize = 64;
        let mut kept = vec![];
        let mut rest = vec![];
        for packet in std::mem::take(&mut self.pending) {
            let size = packet.marshal_size();
            if size <= *budget {
                *budget -= size;
                packets.push(packet);
            } else if size + MINIMAL_OVERHEAD > self.mtu {
                if let Some(nack) = packet.as_any().downcast_ref::<TransportLayerNack>()
                    && let Some((first, more)) =
                        split_nack(nack, *budget, self.mtu.saturating_sub(overhead))
                {
                    *budget = budget.saturating_sub(first.marshal_size());
                    if !first.nacks.is_empty() {
                        packets.push(boxed(first));
                    }
                    rest.extend(more);
                } else {
                    *budget = budget.saturating_sub(size);
                    packets.push(packet);
                }
            } else {
                kept.push(packet);
            }
        }
        self.pending = kept;
        rest
    }

    /// Builds and sends a compound packet led by the local SSRC `first`.
    ///
    /// `Shape::Full` aggregates the other local SSRCs (RFC 8108 5.3.2) and returns the
    /// indices of those that reported; `Shape::Minimal` carries the leading report alone.
    fn send_compound(&mut self, now: Instant, first: usize, shape: Shape) -> Vec<usize> {
        let mut budget = self.mtu;
        // RFC 7160 section 4.1: after a clock rate switch the packet leads with the report of
        // the SSRC now in use, and the SRs of the other clock rates' SSRCs follow it. The SSRC
        // whose timer brought the packet is in it as well.
        let switch = self
            .clock_rate_switch
            .take()
            .and_then(|(current, previous)| {
                let lead = self.local_index(current)?;
                let previous: Vec<usize> = previous
                    .iter()
                    .filter_map(|ssrc| self.local_index(*ssrc))
                    .filter(|&index| index != lead && self.we_sent(index, now))
                    .collect();
                Some((lead, previous))
            });
        let (first, switched): (usize, Vec<usize>) = match switch {
            Some((lead, mut previous)) => {
                if first != lead && !previous.contains(&first) {
                    previous.push(first);
                }
                (lead, previous)
            }
            None => (first, vec![]),
        };
        let mut included = vec![first];
        let mut reports: Vec<Box<dyn rtcp::Packet>> = vec![];

        // The SDES chunk of an SSRC is 12 octets and its CNAME, padded, and its stream
        // identifiers: the largest one is counted for each.
        let chunk = self
            .locals
            .iter()
            .map(|local| self.sdes_chunk(local.ssrc).marshal_size())
            .max()
            .unwrap_or_else(|| self.sdes_chunk(0).marshal_size());
        let block = 24;

        let reporter = self.reporter();
        let mut blocks = vec![];
        if shape == Shape::Full {
            // What is left for report blocks once every participant's report and CNAME are
            // in: the streams that do not fit are reported next time (RFC 3550 6.1).
            let participants = self.locals.iter().filter(|l| l.participates()).count();
            // RFC 6679 section 5.2: the reports and the ECN summary share the MTU; the summary
            // is given room for its senders, up to half the packet, before the blocks are sized.
            let summary_reserve = self.ecn_summary_reserve(budget / 2);
            let room =
                budget.saturating_sub(participants * (28 + chunk) + 4 + summary_reserve) / block;
            blocks = self.report_blocks(now, room.max(1));
        }
        // RFC 3550 6.1: a report carries 31 blocks; further ones follow in additional RR
        // packets from the same SSRC.
        let overflow: Vec<ReceptionReport> = if blocks.len() > MAX_REPORT_BLOCKS {
            blocks.split_off(MAX_REPORT_BLOCKS)
        } else {
            vec![]
        };
        let every = self.report_from_every_ssrc;
        let carries_blocks =
            move |index: usize| every || Some(index) == reporter || reporter.is_none();
        // RFC 8108 5.1: with every SSRC reporting, each reports on the co-located SSRCs too.
        let colocated = if every {
            self.colocated_blocks(now)
        } else {
            vec![]
        };
        let blocks_of = |index: usize, ssrc: u32| -> Vec<ReceptionReport> {
            if !carries_blocks(index) {
                return vec![];
            }
            let mut own = blocks.clone();
            let room = MAX_REPORT_BLOCKS.saturating_sub(own.len());
            own.extend(
                colocated
                    .iter()
                    .filter(|block| block.ssrc != ssrc)
                    .take(room)
                    .cloned(),
            );
            own
        };
        let first_blocks = blocks_of(first, self.locals[first].ssrc);
        let report = self.report(first, now, first_blocks);
        budget = budget.saturating_sub(report.marshal_size() + 4 + chunk);
        reports.push(report);
        // The other clock rates' reports (and the SSRC whose timer this is) right behind the
        // leader, whatever the shape.
        for &index in &switched {
            let own_blocks = blocks_of(index, self.locals[index].ssrc);
            let report = self.report(index, now, own_blocks);
            budget = budget.saturating_sub(report.marshal_size() + chunk);
            reports.push(report);
            included.push(index);
        }

        if shape == Shape::Full {
            // RFC 8108 5.3.2: the other SSRCs, in the order their timers would expire, as
            // long as their reports fit; RFC 8108 5.2: the senders first, the reports "most
            // useful" to the peers when not every one fits.
            let mut others: Vec<usize> = (0..self.locals.len())
                .filter(|&index| {
                    !included.contains(&index)
                        && self.locals[index].participates()
                        && self.locals[index].timing.is_some()
                })
                .collect();
            others.sort_by_key(|&index| {
                (
                    !self.we_sent(index, now),
                    self.locals[index].timing.map(|timing| timing.tn),
                )
            });
            // The SSRC that carries the blocks reports right behind the leader.
            if let Some(reporter) = reporter
                && let Some(position) = others.iter().position(|&index| index == reporter)
            {
                let reporter = others.remove(position);
                others.insert(0, reporter);
            }
            for index in others {
                let own_blocks = blocks_of(index, self.locals[index].ssrc);
                let size = 28 + block * own_blocks.len() + chunk;
                if size > budget && Some(index) != reporter {
                    // It keeps its own timer and reports when that expires.
                    continue;
                }
                let report = self.report(index, now, own_blocks);
                budget = budget.saturating_sub(report.marshal_size() + chunk);
                reports.push(report);
                included.push(index);
            }
        }

        let mut packets = reports;
        if !overflow.is_empty() {
            let ssrc = self.locals[reporter.filter(|r| included.contains(r)).unwrap_or(first)].ssrc;
            // Behind the report of the SSRC they continue.
            let position = packets
                .iter()
                .position(|packet| sender_and_media(packet.as_ref()).0 == Some(ssrc))
                .map_or(packets.len(), |position| position + 1);
            for (offset, chunk) in overflow.chunks(MAX_REPORT_BLOCKS).enumerate() {
                let more = boxed(ReceiverReport {
                    ssrc,
                    reports: chunk.to_vec(),
                    ..Default::default()
                });
                budget = budget.saturating_sub(more.marshal_size());
                packets.insert(position + offset, more);
            }
        }
        packets.push(boxed(SourceDescription {
            chunks: included
                .iter()
                .map(|&index| self.sdes_chunk(self.locals[index].ssrc))
                .collect(),
        }));

        if shape == Shape::Full {
            let any_sender = included.iter().any(|&index| self.we_sent(index, now));
            let ssrc = self.locals[reporter.filter(|r| included.contains(r)).unwrap_or(first)].ssrc;
            if let Some(xr) = self.extended_report(now, ssrc, any_sender, budget) {
                budget = budget.saturating_sub(xr.marshal_size());
                packets.push(boxed(xr));
            }
        }

        if shape == Shape::Full {
            self.take_repeats(&mut packets, &mut budget);
            self.take_held_for_regular(&mut packets, &mut budget);
        }
        // A follow-up compound packet: the leader's report without blocks, its CNAME, then
        // the rest of a split NACK.
        let follow_up_overhead = 28 + 4 + chunk;
        let rest = self.take_pending(&mut packets, &mut budget, follow_up_overhead);
        // The originals of the repetitions not yet armed left with this packet (everything
        // pending is taken): the Regular packets after it carry the copies.
        for repeat in &mut self.repeats {
            repeat.armed = true;
        }
        self.early_at = None;
        self.compound_sent = true;
        self.send(now, packets);
        // RFC 3550 6.1: what a NACK too large for one compound packet asks for more is
        // "segmented into multiple shorter compound packets to be transmitted in separate
        // packets", each beginning with a report.
        for nack in rest {
            let report = self.report(first, now, vec![]);
            let sdes = boxed(SourceDescription {
                chunks: vec![self.sdes_chunk(self.locals[first].ssrc)],
            });
            self.send(now, vec![report, sdes, boxed(nack)]);
        }
        included
    }

    /// Congestion control feedback leaves now, outside RFC 4585's Early allowance and the
    /// regular timing (see [`RtcpSessionBuilder::with_immediate_congestion_feedback`]):
    /// reduced-size where negotiated, else in a minimal compound packet; whatever other
    /// feedback is waiting goes with it.
    fn send_congestion_feedback(&mut self, now: Instant) {
        let media = self
            .pending
            .iter()
            .find_map(|packet| sender_and_media(packet.as_ref()).1);
        let Some(index) = self.feedback_source(media) else {
            return;
        };
        if self.locals[index].timing.is_none() {
            return;
        }
        let reduced = self.reduced_size
            && self.compound_sent
            && !self.reduced_size_failed
            && self
                .pending
                .iter()
                .all(|packet| delivery_shows(packet.as_ref()))
            && self.pending.iter().map(|p| p.marshal_size()).sum::<usize>() <= REDUCED_SIZE_MAX;
        self.outside_budget = true;
        if reduced {
            self.note_reduced_nack();
            let packets = std::mem::take(&mut self.pending);
            self.send(now, packets);
        } else {
            self.send_compound(now, index, Shape::Minimal);
        }
        self.outside_budget = false;
        if self.pending.is_empty() {
            self.early_at = None;
        }
    }

    /// RFC 4585 3.5.2 step 6: the Early packet goes, from the local SSRC `index`.
    fn send_early(&mut self, now: Instant, index: usize) {
        let reduced = self.reduced_size
            && self.compound_sent
            && !self.reduced_size_failed
            && self
                .pending
                .iter()
                .all(|packet| delivery_shows(packet.as_ref()))
            && self.pending.iter().map(|p| p.marshal_size()).sum::<usize>() <= REDUCED_SIZE_MAX;

        if reduced {
            self.note_reduced_nack();
            let packets = std::mem::take(&mut self.pending);
            self.early_at = None;
            self.send(now, packets);
        } else {
            self.send_compound(now, index, Shape::Minimal);
        }
        if let Some(timing) = self.locals[index].timing.as_mut() {
            timing.early_sent();
        }
    }

    /// RFC 5506 4.2.1: watches whether reduced-size NACKs get an answer. A run of them with
    /// none of the requested packets arriving means they do not get through, and the session
    /// goes back to compound packets.
    fn note_reduced_nack(&mut self) {
        let Some(nack) = self
            .pending
            .iter()
            .find_map(|packet| packet.as_any().downcast_ref::<TransportLayerNack>())
        else {
            return;
        };
        if self.awaited.is_some() {
            self.unanswered_reduced_nacks += 1;
            if self.unanswered_reduced_nacks >= REDUCED_SIZE_UNANSWERED_LIMIT {
                self.reduced_size_failed = true;
            }
        }
        self.awaited = Some((
            nack.media_ssrc,
            nack.nacks
                .iter()
                .flat_map(|pair| pair.packet_list())
                .collect(),
        ));
    }

    /// RFC 3550 6.6 and 6.3.7: the local SSRCs that were unbound say BYE, each behind its
    /// last report, unless they never sent anything.
    fn flush_departing(&mut self, now: Instant) {
        if self.departing.is_empty() {
            return;
        }
        let departing = std::mem::take(&mut self.departing);
        let mut reports: Vec<Box<dyn rtcp::Packet>> = vec![];
        let mut chunks = vec![];
        let mut sources = vec![];
        for mut local in departing {
            self.collided.remove(&local.ssrc);
            // "A participant which never sent an RTP or RTCP packet MUST NOT send a BYE."
            if !local.rtp_sent && !local.rtcp_sent {
                continue;
            }
            let horizon = 2.0 * self.report_interval(now);
            let was_sender = local
                .last_rtp
                .is_some_and(|last| now.saturating_duration_since(last).as_secs_f64() <= horizon);
            match local.stream.generate_report(now).filter(|_| was_sender) {
                Some(report) => reports.push(boxed(report)),
                None => reports.push(boxed(ReceiverReport {
                    ssrc: local.ssrc,
                    ..Default::default()
                })),
            }
            chunks.push(self.sdes_chunk(local.ssrc));
            sources.push(local.ssrc);
        }
        if sources.is_empty() {
            return;
        }
        let mut packets = reports;
        packets.push(boxed(SourceDescription { chunks }));
        packets.push(boxed(Goodbye {
            sources,
            reason: Default::default(),
        }));

        if self.member_count() >= BYE_BACKOFF_MEMBERS && !self.left {
            // RFC 3550 6.3.7: in a large session the BYE takes its turn.
            let size = (wire_size(&packets) + self.srtcp_overhead) as f64;
            let mut input = self.interval_input(now, false, true, 0, false);
            input.members = 1;
            input.avg_rtcp_size = size;
            let t = randomized_interval(deterministic_interval(&input), self.unit());
            self.bye = Some(ByeBackoff {
                packets,
                size,
                tp: now,
                tn: after(now, t),
                members: 1,
            });
        } else if self.member_count() < BYE_BACKOFF_MEMBERS {
            self.compound_sent = true;
            self.send(now, packets);
        }
        // Leaving a session of more than fifty members at once: without a BYE (6.3.7 allows
        // it), since the transport does not outlive the back-off.
    }

    // ---- the timers ------------------------------------------------------------------

    /// RFC 3550 6.3.6 (with RFC 4585 3.5.3 and RFC 8108 5.3.2): works through every timer
    /// that expired by `now`.
    fn run_timers(&mut self, now: Instant) {
        if !self.started {
            return;
        }
        self.time_out_members(now);

        if let Some(te) = self.early_at
            && te <= now
        {
            let media = self
                .pending
                .iter()
                .find_map(|packet| sender_and_media(packet.as_ref()).1);
            match (
                self.feedback_source(media),
                self.sender_report_requested.take(),
            ) {
                (Some(index), _) if self.has_feedback() => self.send_early(now, index),
                (_, Some(index)) if index < self.locals.len() => self.send_early(now, index),
                _ => self.early_at = None,
            }
        }

        self.run_bye_timer(now);

        for _ in 0..MAX_CATCH_UP {
            let Some(index) = (0..self.locals.len())
                .filter(|&index| {
                    self.locals[index]
                        .timing
                        .is_some_and(|timing| timing.tn <= now)
                })
                .min_by_key(|&index| self.locals[index].timing.map(|timing| timing.tn))
            else {
                return;
            };
            let Some(mut timing) = self.locals[index].timing else {
                return;
            };
            // The timer expired at tn, which may be a while ago: a session nobody woke
            // catches up with the expiries it would have suppressed.
            let tc = timing.tn;
            let t = self.interval(index, tc);
            if !timing.immediate && !timing.reconsider(tc, t) {
                self.locals[index].timing = Some(timing);
                self.pmembers = self.member_count().max(1);
                continue;
            }

            let decision = match self.profile {
                RtcpProfile::Avp => RegularDecision::Send,
                RtcpProfile::Avpf => {
                    let random = self.unit();
                    let t_rr_interval = self.effective_t_rr_interval(index, tc);
                    regular_decision(
                        t_rr_interval,
                        timing.t_rr_last,
                        tc,
                        random,
                        !self.pending.is_empty(),
                    )
                }
            };
            match decision {
                RegularDecision::Send => self.send_regular(now, index),
                RegularDecision::SendFeedbackOnly => {
                    self.send_compound(now, index, Shape::Minimal);
                    let t = self.interval(index, now);
                    if let Some(timing) = self.locals[index].timing.as_mut() {
                        timing.rescheduled(now, t);
                    }
                }
                RegularDecision::Suppress => {
                    // RFC 8108 5.3.2: "tp is updated to tc as aggregation has not taken place".
                    let t = self.interval(index, tc);
                    if let Some(timing) = self.locals[index].timing.as_mut() {
                        timing.rescheduled(tc, t);
                    }
                }
            }
            self.pmembers = self.member_count().max(1);
        }

        // Too far behind to replay: every timer starts over from now.
        for index in 0..self.locals.len() {
            if self.locals[index].timing.is_some() {
                let t = self.interval(index, now);
                if let Some(timing) = self.locals[index].timing.as_mut() {
                    timing.rescheduled(now, t);
                }
            }
        }
    }

    /// A Regular RTCP packet led by the local SSRC `first`, and the timers of every SSRC it
    /// carried (RFC 8108 5.3.2, steps a to d).
    fn send_regular(&mut self, now: Instant, first: usize) {
        self.sending_regular = true;
        let included = self.send_compound(now, first, Shape::Full);
        self.sending_regular = false;

        // a. The SSRC whose timer expired transmitted at tc. b. Each SSRC aggregated with it
        // would have transmitted when its own timer passed reconsideration.
        let mut offsets = vec![0.0];
        for &index in included.iter().skip(1) {
            let Some(mut timing) = self.locals[index].timing else {
                continue;
            };
            for _ in 0..64 {
                let t = self.interval(index, now);
                if after(timing.tp, t) <= timing.tn {
                    break;
                }
                timing.tn = after(timing.tp, t);
            }
            offsets.push(seconds_between(now, timing.tn).max(0.0));
        }
        // c. tp (and T_rr_last) of all of them is the average of those times.
        let tt_avg = after(now, offsets.iter().sum::<f64>() / offsets.len() as f64);
        // d. New timers from there.
        for &index in &included {
            if let Some(timing) = self.locals[index].timing.as_mut() {
                timing.initial = false;
                timing.t_rr_last = Some(tt_avg);
            }
            let t = self.interval(index, now);
            if let Some(timing) = self.locals[index].timing.as_mut() {
                timing.rescheduled(tt_avg, t);
            }
        }
    }

    /// RFC 3550 6.3.7: the BYE of a large session, sent when its own timer passes
    /// reconsideration against the number of BYE packets seen.
    fn run_bye_timer(&mut self, now: Instant) {
        let Some(bye) = self.bye.as_ref() else {
            return;
        };
        if bye.tn > now {
            return;
        }
        let mut input = self.interval_input(now, false, true, 0, false);
        input.members = bye.members;
        input.avg_rtcp_size = bye.size;
        let t = randomized_interval(deterministic_interval(&input), self.unit());
        let Some(bye) = self.bye.as_mut() else {
            return;
        };
        if after(bye.tp, t) <= now {
            let packets = std::mem::take(&mut bye.packets);
            self.bye = None;
            self.send(now, packets);
        } else {
            bye.tn = after(bye.tp, t);
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        if !self.started {
            return None;
        }
        let feedback_waits = !self.pending.is_empty();
        let regular = self.locals.iter().filter_map(|local| {
            let timing = local.timing?;
            // Until T_rr_interval has passed since the last regular packet, an expiring
            // timer only suppresses it; there is nothing to wake up for before half of it
            // (the least its dither allows) unless feedback is waiting.
            match (self.profile, timing.t_rr_last) {
                (RtcpProfile::Avpf, Some(t_rr_last))
                    if self.t_rr_interval > 0.0 && !feedback_waits =>
                {
                    Some(timing.tn.max(after(t_rr_last, 0.5 * self.t_rr_interval)))
                }
                _ => Some(timing.tn),
            }
        });
        regular
            .chain(self.early_at)
            .chain(self.bye.as_ref().map(|bye| bye.tn))
            .min()
    }

    fn control(&mut self, now: Instant, control: &RtcpSessionControl) {
        match control {
            RtcpSessionControl::Start => {
                if self.left {
                    self.rejoin();
                }
                self.start_given = true;
            }
            RtcpSessionControl::Cname(cname) => self.cname = cname.clone(),
            RtcpSessionControl::Bandwidth(bandwidth) => self.bandwidth = *bandwidth,
            RtcpSessionControl::SendRate(bits_per_second) => {
                self.send_rate = Some(*bits_per_second as f64);
            }
            RtcpSessionControl::ReducedSize(reduced_size) => self.reduced_size = *reduced_size,
            RtcpSessionControl::SrtcpOverhead(overhead) => {
                // Given after the session started (any control starts it), the average moves
                // by the difference: an average of sizes that each carry the overhead is the
                // average of the sizes plus the overhead.
                if self.started {
                    self.avg_rtcp_size += *overhead as f64 - self.srtcp_overhead as f64;
                }
                self.srtcp_overhead = *overhead;
            }
            RtcpSessionControl::TrrInt(t_rr_interval) => {
                self.t_rr_interval = t_rr_interval.as_secs_f64();
            }
            RtcpSessionControl::TrrIntCleared => {
                self.t_rr_interval = self.configured_t_rr_interval;
            }
            RtcpSessionControl::StreamIdentifiers {
                ssrc,
                mid,
                rid,
                repaired_rid,
            } => {
                let items: Vec<SourceDescriptionItem> = [
                    (SdesType::SdesMid, mid),
                    (SdesType::SdesRtpStreamId, rid),
                    (SdesType::SdesRepairedRtpStreamId, repaired_rid),
                ]
                .into_iter()
                // An SDES item holds at most 255 octets (RFC 3550 section 6.5).
                .filter_map(|(sdes_type, value)| {
                    value
                        .as_ref()
                        .filter(|value| !value.is_empty() && value.len() <= 255)
                        .map(|value| SourceDescriptionItem {
                            sdes_type,
                            text: value.clone().into(),
                        })
                })
                .collect();
                // Only the streams the session still has keep theirs.
                let (locals, departing) = (&self.locals, &self.departing);
                self.identifiers.retain(|kept, _| {
                    locals
                        .iter()
                        .chain(departing)
                        .any(|local| local.ssrc == *kept)
                });
                if items.is_empty() {
                    self.identifiers.remove(ssrc);
                } else {
                    self.identifiers.insert(*ssrc, items);
                }
            }
            RtcpSessionControl::ClockRateSwitch { current, previous } => {
                self.clock_rate_switch = Some((*current, previous.clone()));
            }
            RtcpSessionControl::StopRepeating { key } => {
                self.repeats.retain(|repeat| repeat.key != *key);
            }
            RtcpSessionControl::Leave => {
                // A session that joins on `Start` and was not given it has not joined: there
                // is nothing to leave.
                if !self.may_join() || self.left {
                    return;
                }
                self.start_given = false;
                // RFC 3550 6.6: every SSRC of an endpoint that leaves says BYE.
                self.sync(now);
                self.left = true;
                self.departing.append(&mut self.locals);
                self.pending.clear();
                self.repeats.clear();
                self.early_at = None;
                self.flush_departing(now);
                self.announce_reporter(now);
                return;
            }
        }
        self.sync(now);
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for RtcpSessionInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;
        self.sync(now);
        let pass = match &msg.message.packet {
            Packet::Rtp(_) => self.observe_rtp(now, &msg.message, msg.transport.ecn),
            Packet::Rtcp(packets) => {
                self.observe_rtcp(now, packets);
                true
            }
        };
        if pass
            && self.started
            && matches!(&msg.message.packet, Packet::Rtcp(packets) if !packets.is_empty())
        {
            // What this session calculates as the reporting interval, for the circuit breaker
            // application-ward (RFC 8083 section 3, Tdr).
            let interval = self.reporting_interval(now);
            msg.message.add(Attribute::Custom(Arc::new(interval)));
            // And what the RTCP bandwidth gives this endpoint, for the congestion control
            // feedback generators' cadence.
            let share = self.bandwidth_share(now);
            msg.message.add(Attribute::Custom(Arc::new(share)));
        }
        if pass {
            self.read_queue.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;

        // The NACK horizon on its way down from the generator: what it passed is of no use
        // any more, in a NACK held here as well. (The carrier goes on as any other.)
        if let Some(NackControl::Horizon {
            media_ssrc,
            oldest_useful: Some(oldest_useful),
        }) = msg.message.custom::<NackControl>().copied()
        {
            self.forget_nacks_behind(media_ssrc, oldest_useful);
        }

        if let Some(control) = msg.message.custom::<RtcpSessionControl>().cloned() {
            self.control(now, &control);
            msg.message.attributes.retain(|attribute| {
                !matches!(attribute, Attribute::Custom(value) if value.is::<RtcpSessionControl>())
            });
            if msg.message.attributes.is_empty()
                && matches!(&msg.message.packet, Packet::Rtcp(packets) if packets.is_empty())
            {
                return Ok(());
            }
        }
        if self.left || !self.may_join() {
            // After the BYE nothing more is said (RFC 3550 6.1: BYE is the last packet), and
            // before the session joins there is no RTP session to say it in.
            if matches!(msg.message.packet, Packet::Rtp(_)) {
                self.write_queue.push_back(msg);
            }
            return Ok(());
        }
        self.sync(now);

        let repeat = msg.message.custom::<RepeatInRegularReports>().copied();
        let regular = msg.message.custom::<RegularTiming>().is_some();
        match msg.message.packet {
            Packet::Rtp(ref packet) => {
                if let Some(index) = self.local_index(packet.header.ssrc) {
                    let local = &mut self.locals[index];
                    local.stream.process_rtp(now, packet);
                    local.last_rtp = Some(now);
                    local.rtp_sent = true;
                    self.rate.add(
                        now,
                        LOWER_LAYER_OVERHEAD + packet.header.marshal_size() + packet.payload.len(),
                    );
                    // A repair SSRC joins with its first packet.
                    self.sync(now);
                }
                self.write_queue.push_back(msg);
            }
            // An attribute carrier (see `Packet::Rtcp`): not the session's.
            Packet::Rtcp(ref packets) if packets.is_empty() => {
                self.write_queue.push_back(msg);
            }
            Packet::Rtcp(packets) => {
                let congestion_feedback = !packets.is_empty()
                    && packets.iter().all(|packet| {
                        let any = packet.as_any();
                        any.is::<TransportLayerCc>() || any.is::<CcFeedbackReport>()
                    });
                if let Some(repeat) = repeat {
                    self.repeats.retain(|held| held.key != repeat.key);
                    if repeat.count > 0 {
                        self.repeats.push(Repeat {
                            key: repeat.key,
                            packets: packets.iter().map(|packet| packet.cloned()).collect(),
                            left: repeat.count,
                            armed: false,
                        });
                    }
                }
                for packet in packets {
                    if regular {
                        self.hold_for_regular(packet);
                    } else {
                        self.adopt(packet);
                    }
                }
                self.run_timers(now);
                if congestion_feedback && self.immediate_congestion_feedback {
                    self.send_congestion_feedback(now);
                }
                self.schedule_feedback(now);
            }
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        if !self.started || self.left {
            return Ok(());
        }
        self.sync(now);
        self.run_timers(now);
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.next_timeout()
    }
}

impl Interceptor for RtcpSessionInterceptor {
    /// A stream this endpoint sends: its SSRC reports from now on, and its RTX and FEC SSRCs
    /// from their first packet. A stream unbound a moment ago and bound again with the same
    /// SSRC (a renegotiation) carries on: no BYE, and its counts are kept. A stream bound under
    /// the session's reporting SSRC takes it over (RFC 8108 6.1, see
    /// [`RtcpSessionEvent::ReportingSsrc`]).
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        self.record_dlrr_limit(info);
        let kind = Kind::of(&info.mime_type);
        let sources = std::iter::once((info.ssrc, Role::Media))
            .chain(info.ssrc_rtx.map(|ssrc| (ssrc, Role::Repair)))
            .chain(info.ssrc_fec.map(|ssrc| (ssrc, Role::Repair)));
        for (ssrc, role) in sources {
            // The media SSRC may carry the section's other formats (RFC 7160, one SSRC).
            let rates: &[(u8, u32)] = if role == Role::Media {
                &info.payload_clock_rates
            } else {
                &[]
            };
            if let Some(index) = self.local_index(ssrc) {
                let local = &mut self.locals[index];
                if local.role == Role::Reporter {
                    // RFC 8108 6.1: the endpoint starts sending on the SSRC it reports from;
                    // the SSRC stays the same participant (its timer and SRTCP context carry
                    // on), now with a media type and the stream's clock rate.
                    local.kind = kind;
                    local.role = role;
                }
                local.stream.set_clock_rate(info.clock_rate);
                local.stream.set_payload_clock_rates(rates);
                continue;
            }
            let mut local = match self.departing.iter().position(|local| local.ssrc == ssrc) {
                Some(position) => {
                    let mut local = self.departing.remove(position);
                    local.stream.set_clock_rate(info.clock_rate);
                    local.kind = kind;
                    local.role = role;
                    local
                }
                None => Local::new(ssrc, kind, role, info.clock_rate, self.wall_clock),
            };
            local.stream.set_payload_clock_rates(rates);
            self.locals.push(local);
        }
        self.sync_reporter();
    }

    /// The stream stopped: its SSRCs say BYE the next time the chain is driven, unless they
    /// are bound again first.
    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        self.dlrr_limits.remove(&info.ssrc);
        for ssrc in std::iter::once(info.ssrc)
            .chain(info.ssrc_rtx)
            .chain(info.ssrc_fec)
        {
            if let Some(index) = self.local_index(ssrc) {
                let local = self.locals.remove(index);
                self.departing.push(local);
            }
        }
    }

    /// A stream moving to another RTP session is not leaving: its SSRCs go from this
    /// session's members without the BYE `unbind_local_stream` sends (RFC 3550 6.6 is for a
    /// source that leaves the session; this one carries on in the other session, and this
    /// session's transport is going away or no longer carries it).
    fn move_local_stream_out(&mut self, info: &StreamInfo) {
        self.dlrr_limits.remove(&info.ssrc);
        for ssrc in std::iter::once(info.ssrc)
            .chain(info.ssrc_rtx)
            .chain(info.ssrc_fec)
        {
            if let Some(index) = self.local_index(ssrc) {
                self.locals.remove(index);
            }
        }
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        self.record_dlrr_limit(info);
        let rrtr = info
            .rtcp_feedback
            .iter()
            .any(|feedback| feedback.typ == crate::RTCP_FB_RRTR);
        let (ecn_feedback, ecn_summary) = negotiated_ecn_feedback(info);
        match self.remotes.get_mut(&info.ssrc) {
            Some(remote) => {
                remote.ecn_feedback = ecn_feedback;
                remote.ecn_summary = ecn_summary;
                if !(ecn_feedback || ecn_summary) {
                    remote.ecn = None;
                } else if remote.ecn.is_none() {
                    remote.ecn = Some(Box::default());
                }
                remote.stream.set_clock_rate(info.clock_rate);
                remote
                    .stream
                    .set_payload_clock_rates(&info.payload_clock_rates);
                remote.rrtr = rrtr;
                remote.kind = Kind::of(&info.mime_type);
            }
            None => {
                self.remotes.insert(
                    info.ssrc,
                    Remote {
                        stream: {
                            let mut stream = ReceiverStream::new(info.ssrc, info.clock_rate);
                            stream.set_payload_clock_rates(&info.payload_clock_rates);
                            stream
                        },
                        kind: Kind::of(&info.mime_type),
                        rrtr,
                        ecn_feedback,
                        ecn_summary,
                        ecn: (ecn_feedback || ecn_summary).then(Box::default),
                        gone: false,
                    },
                );
                self.remote_order.push(info.ssrc);
            }
        }
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.dlrr_limits.remove(&info.ssrc);
        self.remotes.remove(&info.ssrc);
        self.remote_order.retain(|ssrc| *ssrc != info.ssrc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(ssrc: u32) -> Box<dyn rtcp::Packet> {
        boxed(ReceiverReport {
            ssrc,
            ..Default::default()
        })
    }

    /// RFC 8108 5.3.1: the size that goes into avg_rtcp_size is the packet's divided by "the
    /// number of different SSRCs that are the source of SR or RR RTCP packets" in it; a
    /// packet without any reports for one.
    #[test]
    fn a_compound_packet_counts_per_reporting_ssrc() {
        let sr = boxed(SenderReport {
            ssrc: 3,
            ..Default::default()
        });
        assert_eq!(3, reporting_ssrcs(&[rr(1), rr(2), sr]));
        // A second RR from the same SSRC (more than 31 report blocks) is the same reporter.
        assert_eq!(1, reporting_ssrcs(&[rr(1), rr(1)]));
        let pli = boxed(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        });
        assert_eq!(1, reporting_ssrcs(&[pli]));

        // An empty RR is 8 octets; with UDP and IPv4 under it, 36.
        assert_eq!(36, wire_size(&[rr(1)]));
        let mut session = RtcpSessionBuilder::new().build();
        session.avg_rtcp_size = 100.0;
        session.send(Instant::now(), vec![rr(1), rr(2)]);
        // (28 + 16) / 2 = 22: 100 * 15/16 + 22 / 16.
        assert!((session.avg_rtcp_size - (93.75 + 1.375)).abs() < 1e-9);
    }

    /// RFC 8083 section 3 has a sender estimate its receiver's reporting interval "by
    /// executing the algorithm in Section 6.2 of \[RFC3550\]". The session executes it and
    /// attaches what it gives to the RTCP it hands application-ward: Td for a member that
    /// sends and for one that does not, from the session's bandwidth, members and average
    /// packet size, with the profile's minimum (five seconds under RTP/AVP, none under
    /// RTP/AVPF).
    #[test]
    fn the_calculated_reporting_interval_rides_on_the_rtcp_handed_application_ward() {
        let now = Instant::now();
        let read = |profile: RtcpProfile| {
            let mut session = RtcpSessionBuilder::new()
                .with_profile(profile)
                .with_bandwidth(RtcpBandwidth {
                    session: Some(1_000_000),
                    ..Default::default()
                })
                .build();
            session.control(now, &RtcpSessionControl::Cname("cname".to_owned()));
            assert!(session.started);
            session
                .handle_read(TaggedPacket {
                    now,
                    transport: TransportContext::default(),
                    message: AttributedPacket::new(Packet::Rtcp(vec![rr(7)])),
                })
                .unwrap();
            // What the session says of itself application-ward comes first; then the packet.
            let packet = std::iter::from_fn(|| session.poll_read())
                .find(|packet| matches!(&packet.message.packet, Packet::Rtcp(p) if !p.is_empty()))
                .expect("the packet is passed on");
            let interval = *packet
                .message
                .custom::<RtcpReportingInterval>()
                .expect("the calculated interval rides on it");
            // The remote reporter is a member now; nobody has sent RTP.
            let input = session.interval_input(now, false, false, 0, false);
            (interval, input)
        };

        let (interval, input) = read(RtcpProfile::Avpf);
        // 5 % of 1 Mbit/s is 6250 octets a second. Nobody is a sender yet, so the receivers
        // (both members) share three quarters of it. A member that sends is one sender of
        // two members, more than a quarter of them: then everyone shares all of it alike.
        assert!((input.rtcp_bw - 6250.0).abs() < 1e-9);
        assert_eq!(2, input.members);
        let receiver = input.avg_rtcp_size * 2.0 / (6250.0 * 0.75);
        let sender = input.avg_rtcp_size * 2.0 / 6250.0;
        assert!(receiver > MIN_INTERVAL && receiver < 0.1, "{receiver}");
        assert!((interval.receiver.as_secs_f64() - receiver).abs() < 1e-6);
        assert!((interval.sender.as_secs_f64() - sender).abs() < 1e-6);

        // RTP/AVP: the same calculation is held to the five second minimum.
        let (interval, _) = read(RtcpProfile::Avp);
        assert_eq!(Duration::from_secs(5), interval.receiver);
        assert_eq!(Duration::from_secs(5), interval.sender);
    }

    /// RFC 3711 section 3.4: the SRTCP index, E flag and authentication tag are part of the
    /// packet size: in the initial avg_rtcp_size and in every packet sent or received.
    #[test]
    fn the_srtcp_fields_count_in_the_average_packet_size() {
        let now = Instant::now();
        let started = |overhead: Option<usize>| {
            let mut session = RtcpSessionBuilder::new().build();
            session.control(now, &RtcpSessionControl::Cname("cname".to_owned()));
            if let Some(overhead) = overhead {
                session.control(now, &RtcpSessionControl::SrtcpOverhead(overhead));
            }
            session
        };
        let (plain, mut protected) = (started(None), started(Some(14)));
        assert!(plain.started && protected.started);
        assert!((protected.avg_rtcp_size - plain.avg_rtcp_size - 14.0).abs() < 1e-9);
        // Given before the session starts, the initial estimate has it.
        let mut early = RtcpSessionBuilder::new().build();
        early.srtcp_overhead = 14;
        early.cname = "cname".to_owned();
        early.sync(now);
        assert!((early.avg_rtcp_size - plain.avg_rtcp_size - 14.0).abs() < 1e-9);

        // A packet sent: 36 octets of RR, UDP and IPv4, and 14 of SRTCP.
        protected.avg_rtcp_size = 100.0;
        protected.send(now, vec![rr(1)]);
        assert!((protected.avg_rtcp_size - (93.75 + 50.0 / 16.0)).abs() < 1e-9);
        // One received: the same.
        protected.avg_rtcp_size = 100.0;
        protected.observe_rtcp(now, &[rr(2)]);
        assert!((protected.avg_rtcp_size - (93.75 + 50.0 / 16.0)).abs() < 1e-9);
    }

    /// RFC 4585 3.5.4: "the avg_rtcp_size ... MUST be updated accordingly" for every
    /// compound RTCP packet sent, Early or Regular. Congestion control feedback that leaves
    /// at once (the default, `with_immediate_congestion_feedback`) moves the average a
    /// sixteenth towards its size, as the same packet does when it arrives from the peer.
    #[test]
    fn congestion_feedback_sent_at_once_counts_in_the_average_packet_size() {
        let now = Instant::now();
        let mut session = RtcpSessionBuilder::new().build();
        session.bind_remote_stream(&StreamInfo {
            ssrc: 200,
            clock_rate: 90_000,
            mime_type: "video/VP8".to_owned(),
            ..Default::default()
        });
        session.control(now, &RtcpSessionControl::Cname("cname".to_owned()));
        session.control(now, &RtcpSessionControl::Start);
        while session.poll_write().is_some() {}
        let feedback = || {
            boxed(TransportLayerCc {
                sender_ssrc: 0,
                media_ssrc: 200,
                fb_pkt_count: 1,
                ..Default::default()
            })
        };
        session.avg_rtcp_size = 1000.0;
        session
            .handle_write(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![feedback()])),
            })
            .unwrap();
        let mut sent = vec![];
        while let Some(packet) = session.poll_write() {
            if let Packet::Rtcp(packets) = packet.message.packet {
                sent.push(packets);
            }
        }
        assert_eq!(1, sent.len(), "the feedback leaves at once");
        let size = wire_size(&sent[0]) as f64 / reporting_ssrcs(&sent[0]) as f64;
        let expected = 1000.0 * 15.0 / 16.0 + size / 16.0;
        assert!(
            (session.avg_rtcp_size - expected).abs() < 1e-9,
            "{} against {expected}",
            session.avg_rtcp_size
        );

        // The same packet received moves the average the same way.
        let mut peer = RtcpSessionBuilder::new().build();
        peer.avg_rtcp_size = 1000.0;
        peer.observe_rtcp(now, &sent[0]);
        assert!((peer.avg_rtcp_size - expected).abs() < 1e-9);
    }

    /// RFC 4585 6.1: the packet sender of a feedback message is rewritten, whatever its type.
    #[test]
    fn every_feedback_type_takes_the_endpoints_ssrc() {
        let packets: Vec<Box<dyn rtcp::Packet>> = vec![
            boxed(TransportLayerNack::default()),
            boxed(PictureLossIndication::default()),
            boxed(FullIntraRequest::default()),
            boxed(SliceLossIndication::default()),
            boxed(ReceiverEstimatedMaximumBitrate::default()),
            boxed(TransportLayerCc::default()),
            boxed(RapidResynchronizationRequest::default()),
        ];
        for packet in packets {
            let rewritten = with_sender(packet, 0xABCD);
            assert_eq!(
                Some(0xABCD),
                sender_and_media(rewritten.as_ref()).0,
                "{rewritten:?}"
            );
        }
    }

    /// RFC 8834 section 13 (with RFC 8108): the effect of RTCP from SSRCs this endpoint does
    /// not know is bounded. Reports and reference times from 5000 different unknown sources
    /// leave the member table at its bound, so the RTCP interval (which grows with the
    /// membership, RFC 3550 6.3.1) stays that of 1024 members, and the reference times kept
    /// for DLRR answers at 64.
    #[test]
    fn rtcp_from_many_unknown_ssrcs_has_a_bounded_effect() {
        let now = Instant::now();
        let mut session = RtcpSessionBuilder::new().build();
        session.control(now, &RtcpSessionControl::Cname("cname".to_owned()));
        let before = session.report_interval(now);
        for ssrc in 1..=5000u32 {
            let xr = boxed(ExtendedReport {
                sender_ssrc: ssrc,
                reports: vec![Box::new(ReceiverReferenceTimeReportBlock {
                    ntp_timestamp: u64::from(ssrc) << 16,
                })],
            });
            session.observe_rtcp(now, &[rr(ssrc), xr]);
        }
        assert_eq!(MAX_MEMBERS, session.members.len());
        assert_eq!(MAX_REFERENCE_TIMES, session.reference_times.len());
        let flooded = session.report_interval(now);
        assert!(flooded >= before, "{flooded} {before}");
        // One more member's worth of interval per member at most: what 1024 members give.
        let mut bounded = RtcpSessionBuilder::new().build();
        bounded.control(now, &RtcpSessionControl::Cname("cname".to_owned()));
        for ssrc in 1..=MAX_MEMBERS as u32 {
            bounded.observe_rtcp(now, &[rr(ssrc)]);
        }
        bounded.avg_rtcp_size = session.avg_rtcp_size;
        assert!(
            (flooded - bounded.report_interval(now)).abs() < 1e-6,
            "{flooded} against {}",
            bounded.report_interval(now)
        );
    }

    #[test]
    fn the_media_bitrate_is_measured_over_the_last_seconds() {
        let mut rate = RateWindow::default();
        let base = Instant::now();
        assert_eq!(0.0, rate.bits_per_second(base));
        // 50 packets a second of 1250 octets for three seconds: 500 kbit/s.
        for n in 0..150u32 {
            rate.add(base + Duration::from_millis(20) * n, 1250);
        }
        let measured = rate.bits_per_second(base + Duration::from_secs(3));
        assert!((measured - 500_000.0).abs() < 75_000.0, "{measured}");
        // Long after the last packet: nothing.
        assert_eq!(0.0, rate.bits_per_second(base + Duration::from_secs(30)));
    }

    /// RFC 3550 6.2: "Bandwidth calculations for control and data traffic include lower-layer
    /// transport and network protocols (e.g., UDP and IP)". The media a session measures for
    /// its session bandwidth is each RTP packet with its 28 octets of UDP and IPv4, sent and
    /// received alike: 100 packets a second of 12 + 160 octets are 160 kbit/s, not 137.6.
    #[test]
    fn the_measured_session_bandwidth_counts_udp_and_ip() {
        let media = |now: Instant, ssrc: u32, sequence_number: u16| TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc,
                    payload_type: 96,
                    sequence_number,
                    ..Default::default()
                },
                payload: vec![0u8; 160].into(),
            })),
        };
        let stream = |ssrc: u32| StreamInfo {
            ssrc,
            clock_rate: 90_000,
            mime_type: "video/VP8".to_owned(),
            ..Default::default()
        };
        let base = Instant::now();
        let end = base + Duration::from_secs(3);
        // What the window reads for these packets at 200 octets each.
        let mut expected = RateWindow::default();
        for n in 0..300u32 {
            expected.add(base + Duration::from_millis(10) * n, 28 + 12 + 160);
        }
        let expected = expected.bits_per_second(end);
        assert!((expected - 160_000.0).abs() < 16_000.0, "{expected}");

        for sending in [true, false] {
            let mut session = RtcpSessionBuilder::new().build();
            session.bind_local_stream(&stream(100));
            session.bind_remote_stream(&stream(200));
            session.control(base, &RtcpSessionControl::Start);
            for n in 0..300u32 {
                let now = base + Duration::from_millis(10) * n;
                if sending {
                    session.handle_write(media(now, 100, n as u16)).unwrap();
                } else {
                    session.handle_read(media(now, 200, n as u16)).unwrap();
                }
            }
            assert_eq!(
                expected,
                session.session_bandwidth(end),
                "sending {sending}"
            );
        }
    }
}
