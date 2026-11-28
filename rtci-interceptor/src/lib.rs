//! RTC Interceptor - Sans-IO interceptor framework for RTP/RTCP processing.
//!
//! This crate provides a composable interceptor framework built on top of the
//! [`sansio::Protocol`] trait. Interceptors can process, modify, or generate
//! RTP/RTCP packets as they flow through the pipeline.
//!
//! # Available Interceptors
//!
//! ## RTCP
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`RtcpSessionInterceptor`] | The endpoint's RTCP session: one CNAME and reporting identity, SR / RR / SDES / BYE, the timing of RFC 3550 6.3 and RFC 4585 3.5, every outbound RTCP packet in a compound packet (RFC 8108, RFC 5506) |
//! | [`SenderReportInterceptor`] | Sender Reports (SR) for local streams on a fixed timer, for a chain built without the session |
//! | [`ReceiverReportInterceptor`] | Receiver Reports (RR) on a fixed timer, for a chain built without the session |
//! | [`KeyFrameRequestInterceptor`] | Delivers inbound PLI and FIR (each FIR command once) to the application |
//!
//! ## NACK (Negative Acknowledgement)
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`NackGeneratorInterceptor`] | Detects missing RTP packets and generates NACK requests (RFC 4585) |
//! | [`NackResponderInterceptor`] | Buffers sent packets and retransmits on NACK, with optional RTX support (RFC 4588) |
//!
//! ## TWCC (Transport Wide Congestion Control)
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`TwccSenderInterceptor`] | Adds transport-wide sequence numbers to outgoing RTP packets |
//! | [`TwccReceiverInterceptor`] | Tracks incoming packets and generates TransportLayerCC feedback |
//!
//! ## Congestion control
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`PacerInterceptor`] | Releases outgoing packets at a target rate rather than in bursts |
//! | [`Rfc8888Interceptor`] | Reports per-packet arrival times back to the sender (RFC 8888) |
//!
//! ## Utility
//!
//! | Interceptor | Description |
//! |-------------|-------------|
//! | [`NoopInterceptor`] | Ends the inbound RTCP path; the last interceptor in a chain |
//!
//! # Design
//!
//! A chain is a flat list of interceptors driven over a shared belt. Each one can:
//! - transform a packet passing through, or swallow it to drop or delay it
//! - emit packets it generated or was holding, which rejoin the belt and carry on
//! - act on timeouts, for periodic work like report generation
//! - track stream statistics and state
//!
//! All interceptors work with [`TaggedPacket`] — an RTP or RTCP packet with transport metadata,
//! carrying [`Attribute`]s that say what happened to it on the way. No interceptor holds a
//! reference to another; [`Registry`] assembles the list and walks it. [`Registry::build`] appends
//! [`NoopInterceptor`] last, so inbound RTCP stops before the application — control traffic the
//! interceptors act on is not media the caller asked for. An interceptor that wants a particular
//! packet delivered anyway attaches [`Attribute::DeliverToApplication`] to it.
//!
//! # Direction
//!
//! A chain is a flat list ordered by **distance from the wire**: the first interceptor is closest to the
//! network, the last closest to the application. Direction is a property of the walk, not of the
//! structure:
//!
//! ```text
//! read   (network → application)   forward:  first → … → last
//! write  (application → network)   reverse:  last  → … → first
//! ```
//!
//! Each interceptor is fed from a shared belt and its output is collected back onto it, so **what a
//! interceptor emits is seen by every interceptor still ahead of it in the walk**. A retransmission emitted
//! mid-chain still gets paced, numbered and recorded, because there is no way out of the chain
//! except through the interceptors that follow.
//!
//! One list serves both directions, so "closest to the wire" means one thing rather than opposite
//! things per direction — which is why the send history and the FEC decoder sit next to each
//! other, one being the last thing on the way out and the other the first on the way in.
//!
//! # Quick Start
//!
//! ```
//! use rtci_interceptor::{
//!     NackGeneratorBuilder, NackResponderBuilder, ReceiverReportBuilder,
//!     Registry, SenderReportBuilder, Slot, TwccReceiverBuilder, TwccSenderBuilder,
//! };
//! use std::time::Duration;
//!
//! // The slot decides the position, not the order of these calls; they are listed
//! // wire-to-application here only because that reads the way the chain runs — forwards on the
//! // read path, and in reverse on the write path.
//! let chain = Registry::new()
//!     .with(Slot::TwccSender, TwccSenderBuilder::new().build())
//!     .with(Slot::NackResponder, NackResponderBuilder::new().build())
//!     .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
//!     .with(Slot::TwccReceiver, TwccReceiverBuilder::new().build())
//!     .with(Slot::ReceiverReport, ReceiverReportBuilder::new().build())
//!     .with(Slot::SenderReport, SenderReportBuilder::new().with_interval(Duration::from_secs(1)).build())
//!     .build();
//!
//! // `build` appends [`NoopInterceptor`] last, so inbound RTCP — control traffic the interceptors
//! // above act on — stops there rather than arriving mixed in with the application's media. To
//! // receive some of it, add an interceptor that marks those packets `DeliverToApplication`.
//! # let _ = chain;
//! ```
//!
//! # One chain type
//!
//! [`Registry::build`] returns a single concrete type whatever it was built from, so a struct can
//! hold one without a type parameter and two connections with different chains share a collection:
//!
//! ```
//! use rtci_interceptor::{Slot, NackGeneratorBuilder, Registry, SenderReportBuilder};
//!
//! # let nack_enabled = true; // e.g. from configuration, negotiated SDP, …
//! let chain = if nack_enabled {
//!     Registry::new().with(Slot::NackGenerator, NackGeneratorBuilder::new().build()).build()
//! } else {
//!     Registry::new().with(Slot::SenderReport, SenderReportBuilder::new().build()).build()
//! };
//! ```
//!
//! The cost is one virtual call per interceptor per packet, which is nothing beside SRTP.
//!
//! # Stream Binding
//!
//! Before interceptors can process packets for a stream, the stream must be bound:
//!
//! ```
//! use rtci_interceptor::{Slot, Interceptor, RTCPFeedback, RTPHeaderExtension, Registry, StreamInfo};
//!
//! let mut chain = Registry::new().build();
//!
//! // Create stream info with NACK and TWCC support
//! let stream_info = StreamInfo {
//!     ssrc: 0x12345678,
//!     clock_rate: 90000,
//!     mime_type: "video/VP8".to_string(),
//!     payload_type: 96,
//!     rtcp_feedback: vec![RTCPFeedback {
//!         typ: "nack".to_string(),
//!         parameter: String::new(),
//!     }],
//!     rtp_header_extensions: vec![RTPHeaderExtension {
//!         uri: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01".to_string(),
//!         id: 5,
//!     }],
//!     ..Default::default()
//! };
//!
//! // Bind for outgoing streams (sender side)
//! chain.bind_local_stream(&stream_info);
//!
//! // Bind for incoming streams (receiver side)
//! chain.bind_remote_stream(&stream_info);
//! ```
//!
//! # Writing your own
//!
//! Implement [`sansio::Protocol`] and [`Interceptor`], then add it wherever it belongs in the
//! list. What `handle_*` takes in, `poll_*` gives back — so even a pass-through needs a queue,
//! because the queue is what the next interceptor is fed from:
//!
//! ```
//! use rtci_interceptor::{Slot, Interceptor, Registry, StreamInfo, TaggedPacket};
//! use sansio::Protocol;
//! use std::collections::VecDeque;
//! use std::time::Instant;
//!
//! /// Counts packets on their way out.
//! #[derive(Default)]
//! struct Counter {
//!     sent: u64,
//!     read_queue: VecDeque<TaggedPacket>,
//!     write_queue: VecDeque<TaggedPacket>,
//! }
//!
//! impl Protocol<TaggedPacket, TaggedPacket, ()> for Counter {
//!     type Rout = TaggedPacket;
//!     type Wout = TaggedPacket;
//!     type Eout = ();
//!     type Error = shared::error::Error;
//!     type Time = Instant;
//!
//!     fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
//!         self.read_queue.push_back(msg);
//!         Ok(())
//!     }
//!
//!     fn poll_read(&mut self) -> Option<Self::Rout> {
//!         self.read_queue.pop_front()
//!     }
//!
//!     fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
//!         self.sent += 1;
//!         self.write_queue.push_back(msg); // queueing nothing would swallow it
//!         Ok(())
//!     }
//!
//!     fn poll_write(&mut self) -> Option<Self::Wout> {
//!         self.write_queue.pop_front()
//!     }
//! }
//!
//! impl Interceptor for Counter {
//!     fn bind_local_stream(&mut self, _info: &StreamInfo) {}
//!     fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
//!     fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
//!     fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
//! }
//!
//! let chain = Registry::new().with(Slot::NackGenerator, Counter::default()).build();
//! # let _ = chain;
//! ```
//!
//! Queue nothing to drop or delay a packet, and queue delayed or generated ones whenever they are
//! ready — from [`handle_timeout`](sansio::Protocol::handle_timeout), say. They leave through
//! `poll_*` and continue through every interceptor ahead.

#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

use std::time::Instant;

pub(crate) mod chain;
pub(crate) mod noop;
pub(crate) mod pass_through;
pub(crate) mod registry;

pub(crate) mod adaptive_jitter_buffer;
pub(crate) mod audio_red;
pub(crate) mod cc;
pub(crate) mod circuit_breaker;
pub(crate) mod fec_sent;
pub(crate) mod fec_session;
pub(crate) mod first_transmission;
pub(crate) mod flexfec;
pub(crate) mod gcc;
pub(crate) mod intervalpli;
pub(crate) mod jitterbuffer;
pub(crate) mod keyframe;
pub(crate) mod nack;
pub(crate) mod never_sent;
pub(crate) mod ntp_timestamp;
pub(crate) mod pacing;
pub(crate) mod packet;
pub(crate) mod pause_resume;
pub(crate) mod report;
pub(crate) mod rfc8888;
pub(crate) mod rtcp_session;
pub(crate) mod rtp_session;
pub(crate) mod rtpfb;
pub(crate) mod stream_info;
pub(crate) mod tst;
pub(crate) mod twcc;
pub(crate) mod ulpfec;
pub(crate) mod wire_image;
pub(crate) mod xr;

// Fork additions kept over upstream (see FORK.md): the TWCC-driven GCC interceptor with its
// shared bitrate handle, and the adaptive (RFC 3550 jitter + playout-delay extension) jitter buffer.
pub use adaptive_jitter_buffer::{
    JitterBufferBuilder as AdaptiveJitterBufferBuilder, JitterBufferControl,
    JitterBufferInterceptor as AdaptiveJitterBufferInterceptor,
};
pub use audio_red::{
    AudioRedundancy, RED_AUDIO_DEFAULT_MAX_PAYLOAD_SIZE, RED_AUDIO_DEFAULT_REDUNDANCY,
    RedAudioBuilder, RedAudioInterceptor,
};
pub use cc::estimator::{BandwidthEstimator, ConstantBitrate, EstimatorStats};
pub use cc::fec_rate::{FecRate, MIN_LOSS as FEC_MIN_LOSS};
pub use cc::feedback::{CongestionFeedbackFormat, negotiated_congestion_feedback};
pub use cc::feedback_cadence::{
    CongestionFeedbackCadence, PER_FRAME_INTERVAL, PER_FRAME_MAX_INTERVAL,
};
pub use cc::interceptor::{
    CongestionControlBuilder, CongestionControlHandle, CongestionControlInterceptor,
    DEFAULT_PRUNE_HORIZON as CONGESTION_CONTROL_DEFAULT_PRUNE_HORIZON, REMB_TIMEOUT, SendEstimate,
};
pub use cc::probe::{
    AfterDropProbe, PROBE_AFTER_DROP_TIMEOUT, PROBE_APPLICATION_LIMITED_INTERVAL,
    PROBE_DROP_MEMORY, PROBE_MAX_OCTETS, PROBE_MIN_DURATION, PROBE_MIN_PACKETS,
    PROBE_RECOVERY_INTERVAL, PROBE_RESULT_TIMEOUT, ProbeController, ProbeFill, ProbePacket,
    ProbeRequest, burst_estimate, probe_estimate,
};
pub use cc::tmmbr::{TMMBR_OWNER_TIMEOUT, TmmbEntry};
pub use cc::tmmbr_request::{TMMBR_REPEAT_INTERVAL, TmmbrControl};
pub use circuit_breaker::{
    CircuitBreakerBuilder, CircuitBreakerHandle, CircuitBreakerInterceptor, CircuitBreakerNotice,
    CircuitBreakerReason, CircuitBreakerState,
    DEFAULT_NON_REPORTING_THRESHOLD as CIRCUIT_BREAKER_NON_REPORTING_THRESHOLD,
    DEFAULT_RTCP_INTERVAL as CIRCUIT_BREAKER_RTCP_INTERVAL, MediaUsability,
    PacketSize as CircuitBreakerPacketSize,
};
pub use fec_sent::FecSent;
pub use fec_session::FecSessionSsrcMap;
pub use flexfec::bit_array::BitArray;
pub use flexfec::coverage::{MAX_FEC_PACKETS, MAX_MEDIA_PACKETS, ProtectionCoverage};
pub use flexfec::draft03::decoder::{FlexFec03Decoder, ParseError as FlexFecParseError};
pub use flexfec::draft03::encoder::FlexFec03Encoder;
pub use flexfec::draft03::encoder::{
    DRAFT03_MAX_MEDIA_PACKETS as FLEXFEC03_MAX_MEDIA_PACKETS,
    DRAFT03_MAX_REPAIR_PACKET_SIZE as FLEXFEC03_MAX_REPAIR_PACKET_SIZE,
};
pub use flexfec::draft03::receiver::{FlexFec03ReceiveBuilder, FlexFec03ReceiveInterceptor};
pub use flexfec::draft03::sender::{
    DEFAULT_NUM_FEC_PACKETS, DEFAULT_NUM_MEDIA_PACKETS, FlexFec03SendBuilder,
    FlexFec03SendInterceptor,
};
pub use flexfec::rfc8627::decoder::{
    FLEXFEC_DEFAULT_REPAIR_WINDOW, FlexFecDecoder, FlexFecDecoderConfig, FlexFecDecoderStats,
};
pub use flexfec::rfc8627::encoder::{
    FlexFecEncodeError, FlexFecEncoder, FlexFecLayout, FlexFecProtection,
};
pub use flexfec::rfc8627::header::{
    FLEXFEC_MAX_MASK_BITS, FLEXFEC_MAX_PROTECTED_SSRCS, FLEXFEC_RECOVERY_SIZE, FlexFecBlock,
    FlexFecHeader, FlexFecHeaderError, FlexFecProtected,
};
pub use flexfec::rfc8627::params::FlexFecParameters;
pub use flexfec::rfc8627::receiver::{
    FLEXFEC_MAX_REPAIR_WINDOW, FlexFecReceiveBuilder, FlexFecReceiveInterceptor,
};
pub use flexfec::rfc8627::sender::{
    FLEXFEC_DEFAULT_PROTECTION, FlexFecSendBuilder, FlexFecSendInterceptor,
};
pub use gcc::arrival_group::{
    ArrivalGroup, ArrivalGroupAccumulator, DEFAULT_BURST_INTERVAL as GCC_DEFAULT_BURST_INTERVAL,
    InterGroupDelay,
};
pub use gcc::estimator::{
    DEFAULT_INITIAL_BITRATE as GCC_INITIAL_BITRATE, DEFAULT_MAX_BITRATE as GCC_MAX_BITRATE,
    DEFAULT_MIN_BITRATE as GCC_MIN_BITRATE, Gcc,
};
pub use gcc::kalman::Kalman;
pub use gcc::loss::{
    DEFAULT_HIGH_LOSS as GCC_HIGH_LOSS, DEFAULT_LOSS_INTERVAL as GCC_LOSS_INTERVAL,
    DEFAULT_LOW_LOSS as GCC_LOW_LOSS, LossController,
};
pub use gcc::overuse::{DEFAULT_OVERUSE_TIME as GCC_DEFAULT_OVERUSE_TIME, OveruseDetector, Usage};
pub use gcc::queue_limit::{
    QUEUE_AT_LIMIT_MIN_DELAY, QUEUE_AT_LIMIT_SHARE, QUEUE_BASE_WINDOW, QUEUE_HIGH_WINDOW,
    QueueLimitDetector,
};
pub use gcc::rate_calc::{DEFAULT_WINDOW as GCC_RATE_WINDOW, RateCalculator};
pub use gcc::rate_control::{
    DEFAULT_DECREASE_FACTOR as GCC_DECREASE_FACTOR, DEFAULT_INCREASE_FACTOR as GCC_INCREASE_FACTOR,
    DEFAULT_RATE_CONTROL_INTERVAL as GCC_RATE_CONTROL_INTERVAL, RateController, ReceivedRateBound,
};
pub use gcc::remb::{
    ABS_SEND_TIME_SLOT, ABS_SEND_TIME_URI, AbsSendTimeInterceptor, GOOG_REMB,
    REMB_DECREASE_TRIGGER, REMB_GENERATOR_SLOT, REMB_INITIALIZATION_TIME, REMB_MAX_INTERVAL,
    REMB_UPDATE_INTERVAL, RembGeneratorBuilder, RembGeneratorInterceptor,
};
pub use gcc::slope::{DelayTrend, SlopeEstimator};
pub use gcc::state::RateControlState;
pub use gcc::threshold::{
    AdaptiveThreshold, DEFAULT_INITIAL_MS as GCC_THRESHOLD_INITIAL_MS, ThresholdTimeBase,
};
pub use gcc::twcc_gcc::{GccHandle, GccInterceptor, GccInterceptorBuilder, GccShared};
/// Derive macros for nested (`#[next]`-field) interceptors.
pub use interceptor_derive::{Interceptor, interceptor};
pub use intervalpli::generator::{
    DEFAULT_INTERVAL as INTERVAL_PLI_DEFAULT_INTERVAL, IntervalPliInterceptor,
};
pub use jitterbuffer::buffer::{
    JitterBuffer, JitterBufferStats, Rejected, State as JitterBufferState,
};
pub use jitterbuffer::receiver::{
    DEFAULT_CAPACITY as JITTER_BUFFER_DEFAULT_CAPACITY,
    DEFAULT_DEPTH as JITTER_BUFFER_DEFAULT_DEPTH, JitterBufferBuilder, JitterBufferInterceptor,
};
pub use keyframe::{FirCommands, KeyFrameRequestInterceptor, LocalKeyFrameRequest};
pub use nack::NackControl;
pub use nack::generator::{
    NackGeneratorBuilder, NackGeneratorInterceptor,
    SUGGESTED_MAX_NACKS_PER_PACKET as NACK_SUGGESTED_MAX_NACKS_PER_PACKET,
    SUGGESTED_MAX_PACKET_AGE as NACK_SUGGESTED_MAX_PACKET_AGE,
};
pub use nack::responder::{
    MAX_REPAIR_AGE as NACK_MAX_REPAIR_AGE, MAX_RETRANSMISSION_RESERVE, MinimumTarget,
    NackResponderBuilder, NackResponderInterceptor, PENDING_REQUEST_LIFETIME, PROBE_PADDING_OCTETS,
    REPAIR_BACKLOG_BOUND as NACK_REPAIR_BACKLOG_BOUND, RETRANSMISSION_RATE_WINDOW,
    RetransmissionRateLimit, RetransmissionReserve,
};
pub use noop::NoopInterceptor;
pub use ntp_timestamp::{
    NTP_TIMESTAMP_INITIAL_WINDOW, NTP_TIMESTAMP_INTERVAL, NTP_TIMESTAMP_SLOT, NtpTimestampBuilder,
    NtpTimestampInterceptor,
};
pub use pacing::pacer::{
    BURST_TIME as PACER_BURST_TIME, MIN_BURST_BITS as PACER_MIN_BURST_BITS, Pacer,
};
pub use pacing::sender::{
    Backlog as PacerBacklog, DEFAULT_BITRATE as PACER_DEFAULT_BITRATE,
    DEFAULT_QUEUE_LIMIT as PACER_DEFAULT_QUEUE_LIMIT,
    DEFAULT_QUEUE_TIME_LIMIT as PACER_DEFAULT_QUEUE_TIME_LIMIT, PacerBuilder, PacerDiscard,
    PacerFlush, PacerInterceptor, PacerPause, QueueOverflow as PacerQueueOverflow,
    RetransmissionsLeft, StreamsNotSending,
};
pub use packet::{Attribute, AttributedPacket, Packet, TaggedPacket};
pub use pass_through::PassThroughInterceptor;
pub use pause_resume::{
    PAUSE_DEFAULT_REPORT_INTERVAL, PAUSE_DEFAULT_ROUND_TRIP_TIME, PAUSED_REPETITIONS,
    PauseCapability, PauseResumeBuilder, PauseResumeControl, PauseResumeHandle,
    PauseResumeInterceptor, PauseState, RTCP_FB_CCM_PAUSE, RemotePauseState, pause_config_answer,
};
pub use registry::{Registry, Slot};
pub use report::receiver::{RTCP_FB_RRTR, ReceiverReportBuilder, ReceiverReportInterceptor};
pub use report::sender::{SenderReportBuilder, SenderReportInterceptor};
pub use rfc8888::ecn::{
    CONFIRMATIONS as ECN_CONFIRMATIONS, DEFAULT_RETRY_AFTER as ECN_DEFAULT_RETRY_AFTER, EcnFailure,
    EcnInitiation, EcnMarking, EcnState, EcnValidation, EctPreference,
    PROBE_INTERVAL as ECN_PROBE_INTERVAL, PROBE_SPACING as ECN_PROBE_SPACING,
};
pub use rfc8888::recorder::CcFeedbackRecorder;
pub use rfc8888::sender::{
    DEFAULT_INTERVAL as RFC8888_DEFAULT_INTERVAL,
    DEFAULT_MAX_REPORT_SIZE as RFC8888_DEFAULT_MAX_REPORT_SIZE, Rfc8888Builder, Rfc8888Interceptor,
};
pub use rtcp_session::identity::{RtcpRandom, generate_rtcp_cname};
pub use rtcp_session::{
    RTCP_SESSION_DEFAULT_MTU, RTCP_SESSION_DEFAULT_T_RR_INTERVAL, RTCP_SESSION_MIN_BANDWIDTH,
    RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH, RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH,
    RepeatInRegularReports, RtcpBandwidth, RtcpBandwidthShare, RtcpProfile, RtcpReportingInterval,
    RtcpSessionBuilder, RtcpSessionControl, RtcpSessionEvent, RtcpSessionInterceptor,
};
pub use rtp_session::{PathChanged, PerRtpSession, RtpSession, RtpSessionAssignment};
pub use rtpfb::acknowledgement::{Acknowledgement, PacketReport, Report};
pub use rtpfb::convert::{FeedbackTimeline, convert_ccfb, convert_twcc};
pub use rtpfb::history::History;
pub use stream_info::{FecSessionStream, RTCPFeedback, RTPHeaderExtension, StreamInfo};
pub use tst::{TstnResponderBuilder, TstnResponderInterceptor, TstrCommands, VbcmCommands};
pub use twcc::receiver::{TwccReceiverBuilder, TwccReceiverInterceptor};
pub use twcc::sender::{
    RETRANSMISSION_REPORT_HORIZON, ReportedRetransmission, RetransmissionsReported,
    TwccSenderBuilder, TwccSenderInterceptor,
};
pub use ulpfec::decoder::{ULPFEC_MAX_HELD_FEC, ULPFEC_MEDIA_WINDOW};
pub use ulpfec::sender::{
    ULPFEC_DEFAULT_NUM_FEC_PACKETS, ULPFEC_DEFAULT_NUM_MEDIA_PACKETS, ULPFEC_MAX_HELD_FEC_PACKETS,
};
pub use ulpfec::{
    FEC_HEADER_LENGTH as ULPFEC_HEADER_LENGTH, FecSessionPacket,
    LONG_MASK_BITS as ULPFEC_LONG_MASK_BITS, MAX_LEVELS as ULPFEC_MAX_LEVELS,
    ProtectionLevel as UlpfecProtectionLevel, RedFecPayload, RedPlacement,
    SHORT_MASK_BITS as ULPFEC_SHORT_MASK_BITS, UlpfecDecoder, UlpfecDecoderStats, UlpfecEncoder,
    UlpfecError, UlpfecLevel, UlpfecPacket, UlpfecReceiveBuilder, UlpfecReceiveInterceptor,
    UlpfecReceiveStats, UlpfecRepair, UlpfecSendBuilder, UlpfecSendInterceptor,
    UlpfecStreamPacketizer, depacketize_red as depacketize_red_for_ulpfec,
    one_level_only_from_fmtp as ulpfec_one_level_only_from_fmtp,
    validate_scheme as validate_ulpfec_scheme,
};
pub use wire_image::{MAX_HELD_WIRE_IMAGES, WireImageTap, WireImages, wire_image_tap};
pub use xr::{
    DEFAULT_GMIN as XR_DEFAULT_GMIN, DEFAULT_INTERVAL as XR_DEFAULT_INTERVAL, JitterBufferMetrics,
    RTCP_FB_NACK_ECN, RTCP_FB_XR, RTCP_XR_ECN_SUMMARY, XrReportBuilder, XrReportInterceptor,
};

/// One interceptor of packet processing.
///
/// An interceptor is a [`sansio::Protocol`] like everything else in this stack: packets arrive
/// through `handle_read`/`handle_write` and leave through `poll_read`/`poll_write`. What is
/// different is that nothing is wired to anything — an interceptor does not know what is on either
/// side of it. [`Registry`] builds a flat list and the chain it returns moves packets along it.
///
/// # The contract
///
/// **What `handle_*` takes in, `poll_*` gives back.** The chain hands you a packet, then asks what
/// you have ready; whatever you return is what the next interceptor receives. So an interceptor
/// that passes packets through still needs a queue — take the packet in `handle_read`, hand it
/// back from `poll_read`.
///
/// | To | Do |
/// |---|---|
/// | pass a packet through | queue it in `handle_*`, return it from `poll_*` |
/// | transform it | queue the modified packet |
/// | drop or delay it | queue nothing; a delayed one is queued later, from `handle_timeout` |
/// | generate one | queue it whenever you like; it joins the walk from `poll_*` |
/// | act on a timer | `handle_timeout`, and report the deadline from `poll_timeout` |
///
/// # What you emit continues
///
/// A packet returned from `poll_write` is handed to the next interceptor in the walk and passes
/// through every one still ahead of it. Nothing can bypass an interceptor by being generated past
/// it — which is the class of bug the previous, nested design allowed, and why a retransmission
/// used to escape the pacer, the transport-wide numbering and the send history.
///
/// The same is true in reverse: it also means **nothing reaches the wire or the application except
/// by passing through the interceptors that follow it**. An interceptor that keeps a packet to
/// itself keeps it from everything downstream, deliberately.
///
/// # Direction
///
/// Read walks the list forwards, write walks it in reverse, so one ordering serves both: the first
/// interceptor is closest to the network in both directions.
///
pub trait Interceptor:
    sansio::Protocol<
        TaggedPacket,
        TaggedPacket,
        (),
        Rout = TaggedPacket,
        Wout = TaggedPacket,
        Eout = (),
        Time = Instant,
        Error = shared::error::Error,
    > + Send
    + Sync
{
    /// Wraps this interceptor in an outer one built by `f`, for nested (`#[next]`-field)
    /// interceptors written with the [`Interceptor`](derive@Interceptor) derive. The result is an
    /// ordinary interceptor and can be placed in a [`Registry`] slot.
    ///
    /// Kept by the Brainwires fork: upstream removed it with the list-based chain.
    fn with<O, F>(self, f: F) -> O
    where
        Self: Sized,
        F: FnOnce(Self) -> O,
        O: Interceptor,
    {
        f(self)
    }

    /// bind_local_stream lets you modify any outgoing RTP packets. It is called once for per LocalStream. The returned method
    /// will be called once per rtp packet.
    fn bind_local_stream(&mut self, info: &StreamInfo);

    /// unbind_local_stream is called when the Stream is removed. It can be used to clean up any data related to that track.
    fn unbind_local_stream(&mut self, info: &StreamInfo);

    /// The local stream `info` moves to another RTP session (its m= section moved to another
    /// transport, as a bundling answer does): it leaves this one without ending, so nothing
    /// says it left (no RTCP BYE, RFC 3550 section 6.6). Unbinds it by default.
    fn move_local_stream_out(&mut self, info: &StreamInfo) {
        self.unbind_local_stream(info);
    }

    /// bind_remote_stream lets you modify any incoming RTP packets. It is called once for per RemoteStream. The returned method
    /// will be called once per rtp packet.
    fn bind_remote_stream(&mut self, info: &StreamInfo);

    /// unbind_remote_stream is called when the Stream is removed. It can be used to clean up any data related to that track.
    fn unbind_remote_stream(&mut self, info: &StreamInfo);
}

/// An interceptor whose concrete type has been erased.
///
/// `Interceptor` is object safe, which is what lets a chain be a flat list of these rather than a
/// tower of nested types.
pub type BoxedInterceptor = Box<dyn Interceptor>;

impl<P: Interceptor + ?Sized> Interceptor for Box<P> {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        (**self).bind_local_stream(info)
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_local_stream(info)
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).bind_remote_stream(info)
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_remote_stream(info)
    }
}

/// Blanket implementation for mutable references.
///
/// This lets a borrowed chain satisfy an `Interceptor` bound, so a function taking
/// `I: Interceptor` by value can be called with `&mut chain` and leave ownership with the
/// caller. It mirrors [`sansio::Protocol`]'s own `&mut P` implementation, and the same idiom
/// in `std` (`impl Read for &mut R`, `impl Iterator for &mut I`).
///
/// This is only expressible because [`Interceptor`] does not require `'static`: `&'a mut P`
/// outlives only `'a`. [`Registry::with`] is where the `'static` bound is asked for instead —
/// locally, by the one method that has to box what it is given.
impl<P: Interceptor + ?Sized> Interceptor for &mut P {
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        (**self).bind_local_stream(info)
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_local_stream(info)
    }

    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).bind_remote_stream(info)
    }

    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        (**self).unbind_remote_stream(info)
    }
}
