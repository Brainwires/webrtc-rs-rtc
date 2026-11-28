//! Interceptor Registry - Configuration helpers for RTP/RTCP interceptor chains.
//!
//! This module provides convenience functions for configuring common interceptor
//! combinations used in WebRTC applications. Interceptors process RTP/RTCP packets
//! as they flow through the media pipeline, enabling features like:
//!
//! - **NACK** - Negative acknowledgement for packet loss recovery (RFC 4585)
//! - **RTCP Reports** - Sender/Receiver reports for quality monitoring (RFC 3550)
//! - **TWCC** - Transport-wide congestion control for bandwidth estimation
//! - **Simulcast** - Multi-resolution video streaming support
//!
//! # Interceptor Chain Architecture
//!
//! A chain is a flat list of interceptors ordered by **distance from the wire**: the first is
//! closest to the network, the last closest to the application. Each interceptor declares that
//! distance as a [`Slot`], so the position is a property of the
//! interceptor rather than of the order the helpers below happened to be called in — which is what
//! lets them be called in any order. Direction is a property of the walk rather than of the list:
//!
//! ```text
//! read   (network → application)   forward:  first → … → last
//! write  (application → network)   reverse:  last  → … → first
//! ```
//!
//! One list serves both directions, so "closest to the wire" means one thing rather than opposite
//! things per direction.
//!
//! [`register_default_interceptors`] composes this chain, listed wire-to-application:
//!
//! ```text
//!   wire-most   [NACK Responder]    buffers sent RTP, retransmits on NACK
//!               [NACK Generator]    detects gaps in inbound RTP, emits NACK
//!               [TWCC Receiver]     records arrivals, emits TransportLayerCC
//!               [Receiver Report]   emits RR from inbound RTP statistics
//!    app-most   [Sender Report]     emits SR, filters hop-by-hop RTCP
//!                     ↓
//!               [Noop]              ends the inbound RTCP path
//! ```
//!
//! The NACK responder is wire-most because its retransmissions must still pass everything between
//! it and the network; the generator is above it because loss has to be detected from arrivals.
//! The arrival recorders come before the report generators, and before anything that delays or
//! re-stamps a packet.
//!
//! When adding an interceptor that **delays** a packet (jitter buffer, pacer) or **generates**
//! one (FEC repair, a recovered packet), its position stops being a preference and becomes a
//! correctness property. The named slots carry those rules; one of your own goes at
//! `Slot::from(n)`, and they are spaced so there is room between any two. The
//! rules are documented on [`Slot`],
//! [`Registry`] and on the interceptor trait itself.
//!
//! # Quick Start
//!
//! For most applications, use [`register_default_interceptors`] to enable
//! standard WebRTC functionality:
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtci::interceptor::Registry;
//! use rtci::peer_connection::RTCPeerConnectionBuilder;
//! use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
//! use rtci::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Register NACK, RTCP reports, simulcast headers, and TWCC receiver.
//! // Note this takes `&mut media_engine`: it registers the RTCP feedback types and
//! // header extensions the interceptors need, so pass that same engine to the registry.
//! let registry = register_default_interceptors(registry, &mut media_engine)?;
//!
//! let pc = RTCPeerConnectionBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Custom Configuration
//!
//! For fine-grained control, configure individual interceptors:
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtci::interceptor::Registry;
//! use rtci::peer_connection::RTCPeerConnectionBuilder;
//! use rtci::peer_connection::configuration::interceptor_registry::{configure_nack, configure_twcc};
//! use rtci::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Only enable NACK (no TWCC, no reports)
//! let registry = configure_nack(registry, &mut media_engine);
//!
//! // Or enable full TWCC for bandwidth estimation
//! let registry = configure_twcc(registry, &mut media_engine)?;
//!
//! // Handed over unbuilt: the peer connection builds the chain, and `build` composes by slot
//! // rather than by the order the helpers ran in.
//! let registry = registry;
//!
//! let pc = RTCPeerConnectionBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Available Configurations
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`register_default_interceptors`] | Standard WebRTC setup (NACK + Reports + TWCC Receiver) |
//! | [`configure_nack`] | NACK generator and responder for loss recovery |
//! | [`configure_rtcp_reports`] | The RTCP session: reports, CNAME, BYE, RFC 3550 / RFC 4585 timing |
//! | [`configure_twcc`] | Full TWCC (sender + receiver) |
//! | [`configure_twcc_sender_only`] | TWCC sender only (remote generates feedback) |
//! | [`configure_twcc_receiver_only`] | TWCC receiver only (generates feedback for remote) |
//! | [`configure_simulcast_extension_headers`] | RTP extensions for simulcast |
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - RTP/AVPF (NACK)
//! - [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP (SR/RR)
//! - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01) - TWCC

use crate::peer_connection::configuration::behaviour_profile::BehaviourProfile;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::configuration::remote_bitrate_limit::{
    REMOTE_BITRATE_LIMIT_SLOT, RemoteBitrateLimitInterceptor,
};
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::{
    RTCP_FB_ACK_CCFB, TYPE_RTCP_FB_ACK, TYPE_RTCP_FB_CCM, TYPE_RTCP_FB_NACK,
    TYPE_RTCP_FB_TRANSPORT_CC,
};
use crate::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpCodecParameters, RTCRtpHeaderExtensionCapability,
    RTCRtpHeaderExtensionEncryption, RTCRtpHeaderExtensionParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{PayloadType, RTCRtpTransceiverDirection, SSRC};
use interceptor::{
    BandwidthEstimator, CircuitBreakerBuilder, CircuitBreakerHandle, CongestionControlBuilder,
    CongestionControlHandle, Gcc, KeyFrameRequestInterceptor, NackGeneratorBuilder,
    NackResponderBuilder, PacerBuilder, PerRtpSession, Rfc8888Builder, RtcpSessionBuilder,
    TstnResponderBuilder, TwccReceiverBuilder, TwccSenderBuilder, XrReportBuilder,
};
use std::time::Duration;

/// The chain registry these helpers take and return, and the positions they place interceptors at.
///
/// Re-exported so the helpers and the type they operate on can be named from one path — every
/// example here reaches for both, and the definitions live in `rtci-interceptor` because the chain
/// does.
pub use interceptor::{Registry, Slot};
use shared::error::{Error, Result};

/// Registers a standard set of interceptors for typical WebRTC usage.
///
/// This function configures the following interceptors:
/// - **NACK**: Detects packet loss and requests retransmissions (video only)
/// - **RTCP Reports**: Generates Sender Reports (SR) and Receiver Reports (RR)
/// - **Simulcast Headers**: Enables RTP extensions for multi-resolution streaming
/// - **Congestion control feedback**: RFC 8888 (`ack ccfb`) and transport-wide congestion
///   control (`transport-cc`) are both offered, and each stream runs on one of them: RFC 8888
///   when the peer accepted it, TWCC otherwise (RFC 8888 section 6)
/// - **Congestion control**: Google Congestion Control ([`Gcc`]) over that feedback, with a
///   pacer that releases media at its target (RFC 8834 section 7)
/// - **TMMBR**: offered (`ccm tmmbr`), and honoured for the streams that negotiated it
///   (RFC 8834 section 5.1.6, RFC 5104)
/// - **RTP circuit breaker**: stops a flow whose receiver has gone or that persistently
///   overloads the path (RFC 8083; RFC 8834 section 7.1)
/// - **Key-frame requests**: Delivers inbound PLI and FIR to the application, the encoder that
///   has to answer them (fork addition; see [`configure_key_frame_requests`])
///
/// # Congestion control is on
///
/// RFC 8834 section 7 requires a WebRTC endpoint to adapt its RTP traffic to the capacity of
/// the path and to implement the RTP circuit breaker, so the standard set does both. The
/// estimate is what the application's encoder should produce. **The supported way to read
/// it** is [`register_default_interceptors_with_handles`] (or
/// [`register_default_interceptors_with_options`]) in place of this function:
/// [`DefaultInterceptorHandles::congestion_control`]
/// ([`CongestionControlHandle::target_bitrate`], the first transport's target; every
/// transport's in [`DefaultInterceptorHandles::transports`]), and per encoding, with the
/// pacer's pause as 0, `RTCRtpSender::target_bitrates`. The statistics report has it too
/// (`availableOutgoingBitrate`, `targetBitrate`).
///
/// The fork's pull-style [`GccHandle`](interceptor::GccHandle) is for a chain assembled by
/// hand. A [`GccInterceptor`](interceptor::GccInterceptor) placed in
/// [`Slot::CongestionControl`] of this registry replaces the controller registered here (a
/// slot holds one interceptor; the pacer follows the replacement): it is then one estimator
/// for every transport instead of one per transport, without the circuit breaker link or
/// [`DefaultInterceptorOptions`]' congestion settings, and
/// [`DefaultInterceptorHandles::congestion_control`] no longer reads a controller in the chain.
/// Media written faster than the target is queued by the pacer, not sent.
///
/// An application that brings its own congestion control, or runs where none is wanted (a
/// loopback test, a closed network with reserved capacity), opts out explicitly with
/// [`register_default_interceptors_without_congestion_control`].
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register RTCP feedback and header extensions
///
/// # Returns
///
/// A new registry with the configured interceptor chain.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// If you need to customize which interceptors are loaded, copy the code from
/// this function and remove or modify the unwanted interceptors.
///
/// # Errors
///
/// Returns an error if a header extension an interceptor requires cannot be registered on the
/// media engine — see [`MediaEngine::register_header_extension`].
pub fn register_default_interceptors(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    register_default_interceptors_with_handles(registry, media_engine)
        .map(|(registry, _handles)| registry)
}

/// What an application holds on to from the standard interceptor set.
#[derive(Clone)]
pub struct DefaultInterceptorHandles {
    /// The congestion controller of the first transport (the only one while every m= section
    /// is bundled): the target bit rate for the encoder, and where the limits from signalling
    /// go (`b=AS` / `b=TIAS`, a path change). Every transport's: [`Self::transports`].
    pub congestion_control: CongestionControlHandle,
    /// The RTP circuit breaker of the first transport: which flows have ceased transmission
    /// and why, and how one is restarted. Every transport's: [`Self::transports`].
    pub circuit_breaker: CircuitBreakerHandle,
    /// The congestion controller and circuit breaker of each transport (each RTP session,
    /// RFC 8834 section 4.4), by its RTP session number
    /// ([`RTCDtlsTransport::rtp_session`](crate::peer_connection::transport::RTCDtlsTransport::rtp_session)).
    pub transports: TransportHandles,
}

/// The congestion controller and circuit breaker handles of each transport of a peer
/// connection, by RTP session number (0 is the first transport). A transport's appear when
/// its first stream is bound; they stay while the transport has streams.
#[derive(Clone, Default)]
pub struct TransportHandles {
    shared: std::sync::Arc<std::sync::Mutex<TransportHandleTable>>,
}

#[derive(Default)]
struct TransportHandleTable {
    congestion_control: std::collections::BTreeMap<usize, CongestionControlHandle>,
    circuit_breakers: std::collections::BTreeMap<usize, CircuitBreakerHandle>,
}

impl TransportHandles {
    fn table(&self) -> std::sync::MutexGuard<'_, TransportHandleTable> {
        self.shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The RTP session numbers that have a congestion controller.
    pub fn sessions(&self) -> Vec<usize> {
        self.table().congestion_control.keys().copied().collect()
    }

    /// The congestion controller of the transport of RTP session `session`.
    pub fn congestion_control(&self, session: usize) -> Option<CongestionControlHandle> {
        self.table().congestion_control.get(&session).cloned()
    }

    /// The circuit breaker of the transport of RTP session `session`.
    pub fn circuit_breaker(&self, session: usize) -> Option<CircuitBreakerHandle> {
        self.table().circuit_breakers.get(&session).cloned()
    }

    /// The connection's target: the sum of the transports' targets, in bits per second.
    pub fn target_bitrate(&self) -> f64 {
        self.table()
            .congestion_control
            .values()
            .map(CongestionControlHandle::target_bitrate)
            .sum()
    }

    /// The circuit breaker handle of `session`, made the first time it is asked for.
    fn breaker_for(&self, session: usize) -> CircuitBreakerHandle {
        self.table()
            .circuit_breakers
            .entry(session)
            .or_default()
            .clone()
    }

    fn insert_congestion_control(&self, session: usize, handle: CongestionControlHandle) {
        self.table().congestion_control.insert(session, handle);
    }
}

/// The settings of the standard interceptor set. The default of each is what the RFCs say;
/// the other value is the behaviour of a browser or of an earlier version of this crate.
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::{
///     CongestionFeedback, DefaultInterceptorOptions, register_default_interceptors_with_options,
/// };
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let mut options = DefaultInterceptorOptions::default();
/// // Offer transport-wide congestion control only, as browsers do.
/// options.congestion_feedback = CongestionFeedback::Twcc;
/// let (registry, handles) =
///     register_default_interceptors_with_options(Registry::new(), &mut media_engine, &options)?;
/// # let _ = (registry, handles);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct DefaultInterceptorOptions {
    /// Which congestion control feedback is offered and accepted. The default,
    /// [`CongestionFeedback::Negotiated`], offers RFC 8888 and transport-wide congestion
    /// control together and runs each stream on the one the peer accepted.
    pub congestion_feedback: CongestionFeedback,
    /// Whether a TMMBR limits a stream that did not negotiate `a=rtcp-fb:<pt> ccm tmmbr`
    /// (RFC 5104 sections 7.1 and 7.2). `false` by default: only a negotiated TMMBR is
    /// honoured. See
    /// [`CongestionControlBuilder::with_unnegotiated_tmmbr`](interceptor::CongestionControlBuilder::with_unnegotiated_tmmbr).
    pub unnegotiated_tmmbr: bool,
    /// Whether the pacer lets a packet inside its budget leave as it is written (`true`, the
    /// default) or holds every packet for its next timeout. See
    /// [`PacerBuilder::with_immediate_release`](interceptor::PacerBuilder::with_immediate_release).
    pub pacer_immediate_release: bool,
    /// What the pacer does with media the congestion controller's target has no room for
    /// (the application writing above the target for longer than the pacer's 2 s queue time
    /// limit): dropped by default, so nothing leaves above the target;
    /// [`PacerQueueOverflow::Drain`](interceptor::PacerQueueOverflow::Drain) sends it above
    /// the target as libwebrtc's pacer does. See
    /// [`PacerBuilder::with_queue_overflow`](interceptor::PacerBuilder::with_queue_overflow).
    pub pacer_queue_overflow: interceptor::PacerQueueOverflow,
    /// What the pacer does with its queue when the path's capacity collapses (the target
    /// falls to half or less of what the queued media was written for and the queue would
    /// take a second or more to leave): flushed by default, with a key-frame request
    /// (`RTCPeerConnectionEvent::OnKeyFrameRequest`), so the receiver's next picture is a
    /// current one; [`PacerBacklog::Keep`](interceptor::PacerBacklog::Keep) pauses the source
    /// and delivers the queue and every retransmission in order, for a receiver that cannot
    /// resume at a key frame. See
    /// [`PacerBuilder::with_backlog`](interceptor::PacerBuilder::with_backlog) and
    /// `docs/capacity-collapse.md`.
    ///
    /// `Keep` means "keep and repair everything" for the whole chain: it also switches off
    /// the NACK responder's two rules that decline repairs
    /// ([`nack_max_repair_age`](Self::nack_max_repair_age),
    /// [`nack_repair_backlog_bound`](Self::nack_repair_backlog_bound)), whatever those are
    /// set to, so nothing sent is ever given up for a key frame.
    pub pacer_backlog: interceptor::PacerBacklog,
    /// Whether the path is probed for capacity above the target with short clusters of
    /// packets, as libwebrtc does. `true` by default: RFC 8836 section 2 asks that a
    /// congestion controller "adapt as quickly as possible to initial network conditions"
    /// (requirement 4, a SHOULD) and names probing during setup as one way, and with it a
    /// path of 2.5 Mbit/s is found in under a second from a 300 kbit/s start, against about
    /// 26 seconds without. A cluster the application's own media does not fill is filled with
    /// padding-only packets on the RTX stream, which carry no media and which receivers drop
    /// (none without RTX negotiated). `false` sends only what the application writes. See
    /// [`CongestionControlBuilder::with_bandwidth_probing`](interceptor::CongestionControlBuilder::with_bandwidth_probing).
    pub bandwidth_probing: bool,
    /// With [`Self::bandwidth_probing`], what is probed for after a large drop of the target
    /// ([`AfterDropProbe`](interceptor::AfterDropProbe)): the engine's repeated probe, or
    /// libwebrtc's single one (the `Chrome` profile). See
    /// [`CongestionControlBuilder::with_after_drop_probe`](interceptor::CongestionControlBuilder::with_after_drop_probe).
    pub probe_after_drop: interceptor::AfterDropProbe,
    /// Whether, with [`Self::bandwidth_probing`], the path is probed back towards the rate it
    /// carried before a large drop of the target for a minute after it (a cluster at twice
    /// the target every five seconds while the target is below 85% of that rate and the
    /// estimator does not read over-use). Off by default and in every behaviour profile: it
    /// is tuning, no specification asks for it and Chrome does not do it. See
    /// [`CongestionControlBuilder::with_recovery_probing`](interceptor::CongestionControlBuilder::with_recovery_probing).
    pub recovery_probing: bool,
    /// Whether RFC 6051's rapid synchronisation is offered: the 64-bit NTP timestamp header
    /// extension on audio and video, stamped on a stream's first packets and a frame a
    /// second ([`configure_rapid_synchronisation`]). `true` by default: RFC 8834 section
    /// 5.2.1 recommends the extensions. RTCP-SR-REQ is answered with an Early SR either way.
    pub rapid_synchronisation: bool,
    /// How the audio level header extensions (RFC 6464 client-to-mixer, RFC 6465
    /// mixer-to-client) are offered with respect to RFC 6904 header extension encryption.
    /// [`BestEffort`](RTCRtpHeaderExtensionEncryption::BestEffort) by default: RFC 8834
    /// sections 5.2.2 and 5.2.3 make the encryption RECOMMENDED "unless ... explicitly
    /// disabled through API or signaling", and RFC 6904 section 4.1 offers both forms when
    /// lack of confidentiality is acceptable. The `Chrome` profile offers them in the clear
    /// ([`Clear`](RTCRtpHeaderExtensionEncryption::Clear)), as Chromium does unless the
    /// application asks for encryption. Answering, the engine takes the encrypted form an
    /// offer has whatever this says (RFC 6904 section 4.1).
    pub audio_level_encryption: RTCRtpHeaderExtensionEncryption,
    /// `T_rr_interval` of the RTCP session (RFC 4585 section 3.4): the least time between two
    /// regular reports. Zero by default, RFC 4585 section 4.2's value when `trr-int` is not
    /// negotiated; a negotiated `trr-int` replaces it. See
    /// [`RtcpSessionBuilder::with_t_rr_interval`](interceptor::RtcpSessionBuilder::with_t_rr_interval).
    pub rtcp_t_rr_interval: Duration,
    /// Whether congestion control feedback leaves as soon as it is built (`true`, the default)
    /// or waits its turn under RFC 4585 section 3.5.2 like other feedback. See
    /// [`RtcpSessionBuilder::with_immediate_congestion_feedback`](interceptor::RtcpSessionBuilder::with_immediate_congestion_feedback).
    pub rtcp_immediate_congestion_feedback: bool,
    /// Whether every local SSRC carries a report block for every remote SSRC and for the
    /// endpoint's other SSRCs (RFC 8108 section 5.1: "each SSRC will send RTCP reports for all
    /// other SSRCs, including those co-located at the same endpoint"). `false` by default:
    /// the blocks are carried once, as libwebrtc does; the RFC form was measured worse through
    /// a capacity collapse (see the setting). `true` in the `StrictRfc` behaviour profile. See
    /// [`RtcpSessionBuilder::with_report_from_every_ssrc`](interceptor::RtcpSessionBuilder::with_report_from_every_ssrc).
    pub rtcp_report_from_every_ssrc: bool,
    /// Whether transport-wide feedback reports a packet received again when the base sequence
    /// number moves back over it, as libwebrtc does. `false` by default. See
    /// [`TwccReceiverBuilder::with_rereport_received`](interceptor::TwccReceiverBuilder::with_rereport_received).
    pub twcc_rereport_received: bool,
    /// The time step of the congestion controller's adaptive threshold
    /// (draft-ietf-rmcat-gcc-02 section 5.4). See
    /// [`Gcc::with_threshold_time_base`](interceptor::Gcc::with_threshold_time_base).
    pub gcc_threshold_time_base: interceptor::ThresholdTimeBase,
    /// Whether over-use lowers the estimate at most once per round trip (`true`, libwebrtc's
    /// form) or on every update (`false`, the default: draft-ietf-rmcat-gcc-02 section 5.5).
    /// See
    /// [`Gcc::with_one_decrease_per_round_trip`](interceptor::Gcc::with_one_decrease_per_round_trip).
    pub gcc_one_decrease_per_round_trip: bool,
    /// What the bound of the congestion controller's estimate by the received rate
    /// (draft-ietf-rmcat-gcc-02 section 5.5, `A_hat(i) < 1.5 * R_hat(i)`) does to an estimate
    /// above it: stop its increase (the default: an application that sends less than the
    /// estimate keeps it) or bring it down to the bound. See
    /// [`Gcc::with_received_rate_bound`](interceptor::Gcc::with_received_rate_bound).
    pub gcc_received_rate_bound: interceptor::ReceivedRateBound,
    /// The congestion controller's start, in bits per second: its target before any
    /// congestion feedback, what the pacer first releases media at and what the start-up
    /// probes are a multiple of (three and six times), on every transport and again from a
    /// new path. Default [`GCC_INITIAL_BITRATE`](interceptor::GCC_INITIAL_BITRATE), 300 kbit/s
    /// (libwebrtc's `start` too, `pc/peer_connection_factory.cc` at a222406d).
    ///
    /// No specification names a value: RFC 8836 section 2, requirement 4, asks the algorithm
    /// to "adapt as quickly as possible to initial network conditions" and allows
    /// "history-based startup (start at a point expected to be at or below channel bandwidth
    /// from historical information [...])", warning that "Starting too low and/or adapting up
    /// too slowly can cause a critical point in a personal communication to be poor" and
    /// "Starting too high above the available bandwidth causes other problems";
    /// draft-ietf-rmcat-gcc-02 gives no start value. An application that knows the path (a
    /// previous call's estimate) sets it here. Must lie within
    /// [`congestion_min_bitrate`](Self::congestion_min_bitrate)..=[`congestion_max_bitrate`](Self::congestion_max_bitrate):
    /// `register_default_interceptors_with_options` refuses other values
    /// (`Error::InvalidBitrate`).
    pub congestion_start_bitrate: f64,
    /// The congestion controller's floor, bits per second: the target never goes below it
    /// (it is lowered by a smaller REMB, TMMBR or `b=AS` / `b=TIAS` limit, or by
    /// `CongestionControlHandle::set_session_bitrate_limit`). Default
    /// [`GCC_MIN_BITRATE`](interceptor::GCC_MIN_BITRATE), 100 kbit/s.
    /// `CongestionControlHandle::set_min_bitrate` changes it during the call.
    pub congestion_min_bitrate: f64,
    /// The congestion controller's ceiling, bits per second. Default
    /// [`GCC_MAX_BITRATE`](interceptor::GCC_MAX_BITRATE), 100 Mbit/s.
    pub congestion_max_bitrate: f64,
    /// Whether the abs-send-time header extension is offered on audio as well as on video
    /// ([`configure_abs_send_time`]). `false` by default: it serves the receive-side estimate
    /// (REMB), which runs on video; Chromium offers it on audio too.
    pub abs_send_time_on_audio: bool,
    /// Whether receiver reference times (`a=rtcp-fb:<pt> rrtr`, written as
    /// `a=rtcp-xr:rcvr-rtt=all`, RFC 3611 section 4.4) are negotiated on audio as well as on
    /// video ([`configure_receiver_reference_time`]). `false` by default; Chromium offers them
    /// on audio too.
    pub receiver_reference_time_on_audio: bool,
    /// Whether video offers `red` and `ulpfec` (RFC 2198, RFC 5109 section 14.2) and the
    /// chain sends and recovers ULPFEC in RED ([`configure_video_red_ulpfec`]). `false` by
    /// default: RFC 8854 section 7, "Implementations MAY support additional FEC mechanisms if
    /// desired, e.g., [RFC5109]", and FlexFEC is the mechanism it names for video; Chromium
    /// offers both for every video section.
    pub video_red_ulpfec: bool,
    /// Whether the ULPFEC of [`Self::video_red_ulpfec`] covers the transport-wide sequence
    /// number, abs-send-time and toffset extensions as zeros in both directions, as libwebrtc
    /// does ([`configure_video_red_ulpfec_with`]). `false` by default: RFC 5109 section 8, the
    /// FEC covers the packet as sent; `true` in the `Chrome` profile, so a packet a browser
    /// rebuilds from this engine's FEC, and one this engine rebuilds from a browser's, is
    /// exact (those values zero) instead of carrying XOR noise in them.
    pub ulpfec_zero_mutable_extensions: bool,
    /// Whether video offers RFC 8627 FlexFEC (`video/flexfec`) and the chain sends and
    /// recovers it ([`configure_video_flexfec`]). `false` by default; `true` in the
    /// `StrictRfc` profile.
    ///
    /// RFC 8854 section 5.2: support for an SSRC-multiplexed FlexFEC stream "SHOULD be
    /// indicated by including video/flexfec ... in the SDP offer". RFC 8627 section 1.1.7: an
    /// answerer that supports FlexFEC and RTX and is offered both "MUST respond with an Answer
    /// containing only FLEX FEC", so with this on at both ends RTX is not negotiated for video
    /// (repair of what FEC cannot rebuild is then by retransmission on the media SSRC). The
    /// default keeps RTX: it is not offered.
    pub video_flexfec: bool,
    /// How the RTP circuit breaker takes s, the packet size of RFC 8083 section 4.3's TCP
    /// throughput equation: by default the mean size of the packets sent over the reporting
    /// intervals the sending rate is measured over;
    /// [`CircuitBreakerPacketSize::LastFrames`](interceptor::CircuitBreakerPacketSize::LastFrames)
    /// is section 3's "last 4 * G frames". See
    /// [`CircuitBreakerBuilder::with_packet_size`](interceptor::CircuitBreakerBuilder::with_packet_size).
    pub circuit_breaker_packet_size: interceptor::CircuitBreakerPacketSize,
    /// Whether the chain carries the RTP circuit breaker (RFC 8083). `true` by default: RFC
    /// 8834 section 7.1, "WebRTC Endpoints MUST implement the RTP circuit breaker algorithm".
    /// `false` in the `Chrome` behaviour profile: libwebrtc has none. Without it
    /// [`DefaultInterceptorHandles::circuit_breaker`] watches nothing and no
    /// `OnCircuitBreaker` event is raised.
    pub circuit_breaker: bool,
    /// Whether the circuit breaker restarts a ceased flow itself when the receiver's reports
    /// on the transport's other flows show what stopped it has gone (RFC 8083 section 4.5:
    /// "unless the sender has received information that the congestion has dissipated").
    /// `true` by default; with `false` every restart is the application's
    /// (`CircuitBreakerHandle::restart` after `OnCircuitBreaker`). See
    /// [`CircuitBreakerBuilder::with_automatic_restart`](interceptor::CircuitBreakerBuilder::with_automatic_restart).
    pub circuit_breaker_automatic_restart: bool,
    /// Whether congestion control feedback that leaves at once counts against the RTCP
    /// bandwidth of the regular reports, which then space out to keep both inside it. `false`
    /// by default. See
    /// [`RtcpSessionBuilder::with_congestion_feedback_in_budget`](interceptor::RtcpSessionBuilder::with_congestion_feedback_in_budget).
    pub rtcp_congestion_feedback_in_budget: bool,
    /// The least session bandwidth, bits per second, the RTCP bandwidth is computed from when
    /// the media is measured. 64 kbit/s by default. See
    /// [`RtcpSessionBuilder::with_minimum_session_bandwidth`](interceptor::RtcpSessionBuilder::with_minimum_session_bandwidth).
    pub rtcp_minimum_session_bandwidth: u64,
    /// Tuning with no specification behind it: whether this endpoint's own share of the RTCP
    /// bandwidth follows the rate its congestion controller allows it to send at, so that an
    /// endpoint behind a collapsed link reports less while the other direction still flows.
    /// `false` by default and in every behaviour profile: an option to turn on. See
    /// [`RtcpSessionBuilder::with_share_following_send_rate`](interceptor::RtcpSessionBuilder::with_share_following_send_rate).
    pub rtcp_share_follows_send_rate: bool,
    /// When congestion control feedback (transport-wide and RFC 8888) is built. By default
    /// [`CongestionFeedbackCadence::ReceivedMedia`](interceptor::CongestionFeedbackCadence::ReceivedMedia):
    /// every 50 to 250 ms, sized to 5% of the media received, an engine choice no
    /// specification has (measured: see the type). The `StrictRfc` behaviour profile takes the
    /// drafts' cadence (`PerFrame`: "once per received video frame or at least once every 30 ms
    /// if audio-only or multi-stream", up to 100 ms, draft-ietf-rmcat-gcc-02 section 3), the
    /// `Chrome` profile libwebrtc's (`SendEstimate`: 50 to 250 ms from 5% of the endpoint's
    /// own send estimate). See
    /// [`TwccReceiverBuilder::with_cadence`](interceptor::TwccReceiverBuilder::with_cadence).
    pub congestion_feedback_cadence: interceptor::CongestionFeedbackCadence,
    /// The share of the rate it is sized to that congestion control feedback takes with the
    /// `ReceivedMedia` and `SendEstimate` cadences. 0.05 by default. See
    /// [`TwccReceiverBuilder::with_feedback_share`](interceptor::TwccReceiverBuilder::with_feedback_share).
    pub congestion_feedback_share: f64,
    /// The longest interval between two congestion control feedback packets with the
    /// `ReceivedMedia` and `SendEstimate` cadences. 250 ms by default. See
    /// [`TwccReceiverBuilder::with_max_adaptive_interval`](interceptor::TwccReceiverBuilder::with_max_adaptive_interval).
    pub congestion_feedback_max_interval: Duration,
    /// Where the RTCP sessions draw their random numbers from (the report interval's
    /// variation, RFC 3550 section 6.3.1; the dither of early feedback, RFC 4585 section
    /// 3.5.2; their SSRC and CNAME): the provider's `random()` when one is given, as ICE, DTLS
    /// and SCTP do with the setting engine's provider; `rand` otherwise. Give the same provider
    /// as [`SettingEngineBuilder::with_crypto_provider`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_crypto_provider)
    /// for a run that a seeded provider makes the same every time (without it the report
    /// times, and with them everything the reports drive, differ from run to run).
    pub rtcp_random: Option<std::sync::Arc<dyn crate::crypto::RTCCryptoProvider>>,
    /// How many times the NACK generator asks for one missing packet. 0 by default:
    /// unlimited, a packet is asked for again a round trip after each request for as long as
    /// it is missing (RFC 4588 section 6.3, Appendix A gives no number). See
    /// [`NackGeneratorBuilder::with_max_nacks_per_packet`](interceptor::NackGeneratorBuilder::with_max_nacks_per_packet).
    pub nack_max_nacks_per_packet: u16,
    /// How the NACK responder's retransmissions are held to the congestion controller's
    /// target (RFC 4588 section 7). See
    /// [`NackResponderBuilder::with_rate_limit`](interceptor::NackResponderBuilder::with_rate_limit).
    pub nack_retransmission_rate_limit: interceptor::RetransmissionRateLimit,
    /// How old a packet may be and still be retransmitted: a NACK for a packet sent longer
    /// ago is declined, and for a video stream everything sent so far is given up and a key
    /// frame asked for (`RTCPeerConnectionEvent::OnKeyFrameRequest`). Two seconds by default
    /// (RFC 8834 section 6.1: the likelihood of a retransmission "arriving in time to be
    /// useful need[s] to be considered"); `None`: no bound, also what
    /// [`pacer_backlog`](Self::pacer_backlog) `Keep` and the `Chrome` profile give. See
    /// [`NackResponderBuilder::with_max_repair_age`](interceptor::NackResponderBuilder::with_max_repair_age)
    /// and `docs/capacity-collapse.md`.
    pub nack_max_repair_age: Option<Duration>,
    /// The backlog of retransmissions given up, with a key-frame request, when the target has
    /// fallen to half or less within two seconds: what would take this long or more to send
    /// at the target. Two seconds by default (RFC 4588 section 7: "If congestion is not kept
    /// under control, then retransmission SHOULD NOT be used"); `None`: every request is
    /// served in order, also what [`pacer_backlog`](Self::pacer_backlog) `Keep` and the
    /// `Chrome` profile give. See
    /// [`NackResponderBuilder::with_repair_backlog_bound`](interceptor::NackResponderBuilder::with_repair_backlog_bound).
    pub nack_repair_backlog_bound: Option<Duration>,
    /// The wall-clock anchor the NTP times of the interceptors derive from (the RTCP sessions'
    /// sender reports and receiver reference times, the RFC 8888 report timestamps, the RFC
    /// 6051 NTP timestamp header extension): the process-wide
    /// [`SystemInstant::shared`](shared::time::SystemInstant::shared) when none is given,
    /// which is right for a process with one clock. Give one per peer connection for a run
    /// under virtual time that is the same every time: two runs in one process otherwise map
    /// the same instants to NTP times as far apart as the real time between the runs, and the
    /// fractions of a second that differ reach the wire and what the reports drive.
    pub wall_clock: Option<shared::time::SystemInstant>,
}

impl std::fmt::Debug for DefaultInterceptorOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultInterceptorOptions")
            .field("congestion_feedback", &self.congestion_feedback)
            .field("unnegotiated_tmmbr", &self.unnegotiated_tmmbr)
            .field("pacer_immediate_release", &self.pacer_immediate_release)
            .field("pacer_queue_overflow", &self.pacer_queue_overflow)
            .field("pacer_backlog", &self.pacer_backlog)
            .field("bandwidth_probing", &self.bandwidth_probing)
            .field("probe_after_drop", &self.probe_after_drop)
            .field("recovery_probing", &self.recovery_probing)
            .field("rapid_synchronisation", &self.rapid_synchronisation)
            .field("audio_level_encryption", &self.audio_level_encryption)
            .field("rtcp_t_rr_interval", &self.rtcp_t_rr_interval)
            .field(
                "rtcp_immediate_congestion_feedback",
                &self.rtcp_immediate_congestion_feedback,
            )
            .field(
                "rtcp_report_from_every_ssrc",
                &self.rtcp_report_from_every_ssrc,
            )
            .field("twcc_rereport_received", &self.twcc_rereport_received)
            .field("gcc_threshold_time_base", &self.gcc_threshold_time_base)
            .field(
                "gcc_one_decrease_per_round_trip",
                &self.gcc_one_decrease_per_round_trip,
            )
            .field("gcc_received_rate_bound", &self.gcc_received_rate_bound)
            .field("congestion_start_bitrate", &self.congestion_start_bitrate)
            .field("congestion_min_bitrate", &self.congestion_min_bitrate)
            .field("congestion_max_bitrate", &self.congestion_max_bitrate)
            .field("abs_send_time_on_audio", &self.abs_send_time_on_audio)
            .field(
                "receiver_reference_time_on_audio",
                &self.receiver_reference_time_on_audio,
            )
            .field("video_red_ulpfec", &self.video_red_ulpfec)
            .field(
                "ulpfec_zero_mutable_extensions",
                &self.ulpfec_zero_mutable_extensions,
            )
            .field("video_flexfec", &self.video_flexfec)
            .field(
                "circuit_breaker_packet_size",
                &self.circuit_breaker_packet_size,
            )
            .field("circuit_breaker", &self.circuit_breaker)
            .field(
                "circuit_breaker_automatic_restart",
                &self.circuit_breaker_automatic_restart,
            )
            .field(
                "rtcp_congestion_feedback_in_budget",
                &self.rtcp_congestion_feedback_in_budget,
            )
            .field(
                "rtcp_minimum_session_bandwidth",
                &self.rtcp_minimum_session_bandwidth,
            )
            .field(
                "rtcp_share_follows_send_rate",
                &self.rtcp_share_follows_send_rate,
            )
            .field(
                "congestion_feedback_cadence",
                &self.congestion_feedback_cadence,
            )
            .field("congestion_feedback_share", &self.congestion_feedback_share)
            .field(
                "congestion_feedback_max_interval",
                &self.congestion_feedback_max_interval,
            )
            .field("nack_max_nacks_per_packet", &self.nack_max_nacks_per_packet)
            .field(
                "nack_retransmission_rate_limit",
                &self.nack_retransmission_rate_limit,
            )
            .field("nack_max_repair_age", &self.nack_max_repair_age)
            .field("nack_repair_backlog_bound", &self.nack_repair_backlog_bound)
            .field(
                "rtcp_random",
                &self.rtcp_random.as_ref().map(|provider| provider.name()),
            )
            .field("wall_clock", &self.wall_clock)
            .finish()
    }
}

impl DefaultInterceptorOptions {
    /// The engine's own defaults, whatever the build's default profile.
    pub(crate) fn rfc_base() -> Self {
        Self {
            congestion_feedback: CongestionFeedback::default(),
            unnegotiated_tmmbr: false,
            pacer_immediate_release: true,
            pacer_queue_overflow: interceptor::PacerQueueOverflow::default(),
            pacer_backlog: interceptor::PacerBacklog::default(),
            bandwidth_probing: true,
            probe_after_drop: interceptor::AfterDropProbe::Repeated,
            recovery_probing: false,
            rapid_synchronisation: true,
            audio_level_encryption: RTCRtpHeaderExtensionEncryption::BestEffort,
            rtcp_t_rr_interval: Duration::ZERO,
            rtcp_immediate_congestion_feedback: true,
            rtcp_report_from_every_ssrc: false,
            twcc_rereport_received: false,
            gcc_threshold_time_base: interceptor::ThresholdTimeBase::Arrival,
            gcc_one_decrease_per_round_trip: false,
            gcc_received_rate_bound: interceptor::ReceivedRateBound::LimitsIncrease,
            congestion_start_bitrate: interceptor::GCC_INITIAL_BITRATE,
            congestion_min_bitrate: interceptor::GCC_MIN_BITRATE,
            congestion_max_bitrate: interceptor::GCC_MAX_BITRATE,
            abs_send_time_on_audio: false,
            receiver_reference_time_on_audio: false,
            video_red_ulpfec: false,
            ulpfec_zero_mutable_extensions: false,
            video_flexfec: false,
            circuit_breaker_packet_size: interceptor::CircuitBreakerPacketSize::default(),
            circuit_breaker: true,
            circuit_breaker_automatic_restart: true,
            rtcp_congestion_feedback_in_budget: false,
            rtcp_minimum_session_bandwidth: interceptor::RTCP_SESSION_MIN_BANDWIDTH,
            rtcp_share_follows_send_rate: false,
            congestion_feedback_cadence: interceptor::CongestionFeedbackCadence::ReceivedMedia,
            congestion_feedback_share: 0.05,
            congestion_feedback_max_interval: Duration::from_millis(250),
            rtcp_random: None,
            nack_max_nacks_per_packet: 0,
            nack_retransmission_rate_limit: interceptor::RetransmissionRateLimit::default(),
            nack_max_repair_age: Some(interceptor::NACK_MAX_REPAIR_AGE),
            nack_repair_backlog_bound: Some(interceptor::NACK_REPAIR_BACKLOG_BOUND),
            wall_clock: None,
        }
    }

    /// The congestion controller's start, floor and ceiling, checked: finite, the floor not
    /// negative, the start above zero, and `min <= start <= max` (libwebrtc's
    /// `PeerConnection::SetBitrate` refuses the same, `pc/peer_connection.cc` at a222406d).
    fn congestion_bitrates(&self) -> Result<(f64, f64, f64)> {
        let (start, min, max) = (
            self.congestion_start_bitrate,
            self.congestion_min_bitrate,
            self.congestion_max_bitrate,
        );
        if [start, min, max].iter().all(|v| v.is_finite())
            && min >= 0.0
            && start > 0.0
            && min <= start
            && start <= max
        {
            Ok((start, min, max))
        } else {
            Err(Error::InvalidBitrate)
        }
    }

    /// What these options register on the media engine beyond the video defaults.
    fn register_audio_extras(&self, media_engine: &mut MediaEngine) -> Result<()> {
        // After `configure_default_header_extensions`, which offers them best-effort.
        for uri in [
            ::sdp::extmap::AUDIO_LEVEL_URI,
            rtp::extension::CSRC_AUDIO_LEVEL_URI,
        ] {
            media_engine.set_header_extension_encryption(uri, self.audio_level_encryption)?;
        }
        if self.receiver_reference_time_on_audio {
            media_engine.register_feedback(
                RTCPFeedback {
                    typ: interceptor::RTCP_FB_RRTR.to_owned(),
                    parameter: "".to_owned(),
                },
                RtpCodecKind::Audio,
            );
        }
        if self.abs_send_time_on_audio {
            media_engine.register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: sdp::extmap::ABS_SEND_TIME_URI.to_owned(),
                },
                RtpCodecKind::Audio,
                None,
            )?;
        }
        Ok(())
    }

    /// The options a [`BehaviourProfile`] gives (`docs/behaviour-profiles.md`); those it does
    /// not govern at their defaults.
    pub fn for_profile(profile: BehaviourProfile) -> Self {
        let mut options = Self::rfc_base();
        crate::peer_connection::configuration::behaviour_profile::apply_to_interceptor_options(
            &mut options,
            profile,
        );
        options
    }

    /// The RTCP session these options describe, drawing its random numbers from
    /// [`Self::rtcp_random`] and its NTP times from [`Self::wall_clock`] when they are given.
    fn rtcp_session(&self) -> RtcpSessionBuilder {
        let session = RtcpSessionBuilder::new()
            .with_t_rr_interval(self.rtcp_t_rr_interval)
            .with_immediate_congestion_feedback(self.rtcp_immediate_congestion_feedback)
            .with_report_from_every_ssrc(self.rtcp_report_from_every_ssrc)
            .with_congestion_feedback_in_budget(self.rtcp_congestion_feedback_in_budget)
            .with_minimum_session_bandwidth(self.rtcp_minimum_session_bandwidth)
            .with_share_following_send_rate(self.rtcp_share_follows_send_rate);
        let session = match self.wall_clock {
            Some(anchor) => session.with_wall_clock(anchor),
            None => session,
        };
        match &self.rtcp_random {
            Some(provider) => session.with_random(ProviderRtcpRandom(provider.clone())),
            None => session,
        }
    }
}

/// The options of [`BehaviourProfile::default()`]: the RFC defaults, or Chrome's with the
/// `chrome-defaults` cargo feature.
impl Default for DefaultInterceptorOptions {
    fn default() -> Self {
        Self::for_profile(BehaviourProfile::default())
    }
}

/// [`register_default_interceptors`], returning the handles of the congestion controller and
/// the circuit breaker it installs: the supported way for an application to read the
/// congestion controller's target.
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::RTCPeerConnectionBuilder;
/// use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors_with_handles;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
/// use std::time::Instant;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// media_engine.register_default_codecs()?;
/// let (registry, handles) =
///     register_default_interceptors_with_handles(Registry::new(), &mut media_engine)?;
/// let pc = RTCPeerConnectionBuilder::new()
///     .with_media_engine(media_engine)
///     .with_interceptor_registry(registry)
///     .build(Instant::now())?;
///
/// // On each tick of the application: the first transport's target, bits per second.
/// // (`RTCRtpSender::target_bitrates` gives each encoding its share, 0 while the pacer
/// // asks the source to pause.)
/// let target: f64 = handles.congestion_control.target_bitrate();
/// # let _ = (pc, target);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// As [`register_default_interceptors`].
pub fn register_default_interceptors_with_handles(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<(Registry, DefaultInterceptorHandles)> {
    let options = DefaultInterceptorOptions::for_profile(media_engine.behaviour_profile());
    register_default_interceptors_with_options(registry, media_engine, &options)
}

/// [`register_default_interceptors_with_handles`] with settings other than the defaults.
///
/// # Errors
///
/// As [`register_default_interceptors`].
pub fn register_default_interceptors_with_options(
    registry: Registry,
    media_engine: &mut MediaEngine,
    options: &DefaultInterceptorOptions,
) -> Result<(Registry, DefaultInterceptorHandles)> {
    // Order is not decided here — `Registry::build` decides it. These may be called in
    // any sequence.
    let registry = configure_nack_with(registry, media_engine, options);

    configure_simulcast_extension_headers(media_engine)?;

    // The per-packet feedback of both directions: what this endpoint's packets are numbered
    // with and reported in, and the reports about the remote's.
    register_congestion_feedback(media_engine, options.congestion_feedback)?;
    // Per transport, with the congestion controller below: each transport numbers its
    // packets and is estimated on its own (the remote reports each transport's sequence).
    let registry = with_congestion_feedback_senders(registry, options.congestion_feedback, true);
    let registry =
        with_congestion_feedback_recorders(registry, options.congestion_feedback, options);

    // A media sender implements TMMBR (RFC 8834 section 5.1.6), and it is in use where the
    // session names it (RFC 5104 section 7.1).
    configure_tmmbr(media_engine);

    // One circuit breaker per transport (RFC 8083 judges each RTP session's flows on its own
    // RTCP), given to that transport's congestion controller.
    let transports = TransportHandles::default();
    let circuit_breaker = transports.breaker_for(0);
    let registry = if options.circuit_breaker {
        let transports = transports.clone();
        let packet_size = options.circuit_breaker_packet_size;
        let automatic_restart = options.circuit_breaker_automatic_restart;
        let breaker = move || {
            CircuitBreakerBuilder::new()
                .with_packet_size(packet_size)
                .with_automatic_restart(automatic_restart)
        };
        registry.with_per_rtp_session(
            Slot::CircuitBreaker,
            PerRtpSession::with_first_for_sessions(
                breaker().build_with_handle(&circuit_breaker),
                move |session| breaker().build_with_handle(&transports.breaker_for(session)),
            ),
        )
    } else {
        registry
    };

    // The estimator runs on whichever per-packet feedback each stream negotiated: RFC 8888
    // when the peer accepted `ack ccfb`, transport-wide congestion control otherwise.
    //
    // One controller, bound and pacer per transport: each transport is a path of its own
    // (RFC 8836 section 2; an RTP session each, RFC 8834 section 4.4). The handle reads the
    // first transport's controller.
    // The start, floor and ceiling: one value seeds the controller of every transport, the
    // remote-limit interceptor and the pacer, so the first target is the same in all three.
    let (start, min, max) = options.congestion_bitrates()?;
    let initial_target = Gcc::new(start, min, max).target_bitrate();
    let congestion_control_builder = {
        let transports = transports.clone();
        let unnegotiated_tmmbr = options.unnegotiated_tmmbr;
        let bandwidth_probing = options.bandwidth_probing;
        let probe_after_drop = options.probe_after_drop;
        let recovery_probing = options.recovery_probing;
        let threshold_time_base = options.gcc_threshold_time_base;
        let one_decrease_per_round_trip = options.gcc_one_decrease_per_round_trip;
        let received_rate_bound = options.gcc_received_rate_bound;
        let send_rate_told_to_rtcp = options.rtcp_share_follows_send_rate;
        move |session: usize| {
            let estimator = Gcc::new(start, min, max)
                .with_threshold_time_base(threshold_time_base)
                .with_one_decrease_per_round_trip(one_decrease_per_round_trip)
                .with_received_rate_bound(received_rate_bound);
            CongestionControlBuilder::new(estimator)
                .with_circuit_breaker(transports.breaker_for(session))
                .with_unnegotiated_tmmbr(unnegotiated_tmmbr)
                .with_bandwidth_probing(bandwidth_probing)
                .with_after_drop_probe(probe_after_drop)
                .with_recovery_probing(recovery_probing)
                .with_send_rate_told_to_rtcp(send_rate_told_to_rtcp)
        }
    };
    let (congestion_control, handle) = congestion_control_builder(0).build_with_handle();
    transports.insert_congestion_control(0, handle.clone());
    let pacer_immediate_release = options.pacer_immediate_release;
    let pacer_queue_overflow = options.pacer_queue_overflow;
    let pacer_backlog = options.pacer_backlog;
    let registry = registry
        .with_per_rtp_session(
            Slot::CongestionControl,
            PerRtpSession::with_first_for_sessions(congestion_control, {
                let transports = transports.clone();
                move |session| {
                    let (controller, handle) =
                        congestion_control_builder(session).build_with_handle();
                    transports.insert_congestion_control(session, handle);
                    controller
                }
            }),
        )
        // The remote description's `b=TIAS` / `b=AS` bounds the estimate on its way to the
        // pacer (RFC 9429 section 5.10); the peer connection feeds it when an answer is
        // applied.
        .with_per_rtp_session(
            Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
            PerRtpSession::new(move || RemoteBitrateLimitInterceptor::new(initial_target)),
        )
        .with_per_rtp_session(
            Slot::Pacer,
            PerRtpSession::new(move || {
                PacerBuilder::new()
                    .with_target_bitrate(initial_target)
                    .with_immediate_release(pacer_immediate_release)
                    .with_queue_overflow(pacer_queue_overflow)
                    .with_backlog(pacer_backlog)
                    .build()
            }),
        );

    let registry = configure_rtcp_reports_with(registry, options.rtcp_session());
    let registry = configure_extended_reports(registry);
    let registry = configure_tradeoff_notifications(registry);
    configure_receiver_reference_time(media_engine);

    let registry = configure_key_frame_requests(registry);
    let registry = configure_remb(registry);

    // Last, so the ids of the extensions registered above stay what they were.
    configure_default_header_extensions(media_engine)?;
    configure_abs_send_time(media_engine)?;
    options.register_audio_extras(media_engine)?;
    let registry = if options.video_red_ulpfec {
        configure_video_red_ulpfec_with(
            registry,
            media_engine,
            options.ulpfec_zero_mutable_extensions,
        )?
    } else {
        registry
    };
    let registry = if options.video_flexfec {
        configure_video_flexfec(registry, media_engine)?
    } else {
        registry
    };
    let registry = if options.rapid_synchronisation {
        configure_rapid_synchronisation_with(registry, media_engine, options.wall_clock)?
    } else {
        registry
    };

    Ok((
        registry,
        DefaultInterceptorHandles {
            congestion_control: handle,
            circuit_breaker,
            transports,
        },
    ))
}

/// The standard set without congestion control: no estimator, no pacer, no transport-wide
/// sequence numbers on outgoing packets, no circuit breaker. NACK, RTCP reports, congestion
/// control feedback for the remote (RFC 8888 or transport-wide, as negotiated), and key-frame
/// requests are as in [`register_default_interceptors`].
///
/// This is the explicit opt-out. RFC 8834 section 7 requires congestion control and the RTP
/// circuit breaker of a WebRTC endpoint: use this only when the application provides them
/// itself (its own interceptors, [`configure_congestion_control`] with its own estimator) or
/// when the traffic never leaves a network where they are not needed.
///
/// # Errors
///
/// As [`register_default_interceptors`].
pub fn register_default_interceptors_without_congestion_control(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    let options = DefaultInterceptorOptions::for_profile(media_engine.behaviour_profile());
    let registry = configure_nack_with(registry, media_engine, &options);

    configure_simulcast_extension_headers(media_engine)?;

    let feedback = options.congestion_feedback;
    register_congestion_feedback(media_engine, feedback)?;
    let registry = with_congestion_feedback_recorders(registry, feedback, &options);

    let registry = configure_rtcp_reports_with(registry, options.rtcp_session());
    let registry = configure_extended_reports(registry);
    let registry = configure_tradeoff_notifications(registry);
    configure_receiver_reference_time(media_engine);

    let registry = configure_key_frame_requests(registry);

    // Last, so the ids of the extensions registered above stay what they were.
    configure_default_header_extensions(media_engine)?;
    options.register_audio_extras(media_engine)?;

    Ok(registry)
}

/// Registers the header extensions every WebRTC endpoint is expected to offer, beside the
/// ones the interceptors above need:
///
/// - **MID** (`urn:ietf:params:rtp-hdrext:sdes:mid`) for audio as well as video: RFC 9143
///   section 15 has an endpoint that offers a BUNDLE group offer it in every bundled RTP
///   section, and RFC 9429 section 5.2.1 lists it among the extensions of any m= section.
///   The sender stamps it (`RTCRtpSender::write_rtp`), and a receiver finds the m= section of
///   an SSRC no description declared by it.
/// - **Client-to-mixer audio level** (`urn:ietf:params:rtp-hdrext:ssrc-audio-level`, RFC
///   6464) for audio: RFC 8834 section 5.2.2 ("RECOMMENDED"). The application writes the
///   level into the packets it sends; a receiver reports the level it reads as the audio
///   level of its synchronization sources.
/// - **Mixer-to-client audio level** (`urn:ietf:params:rtp-hdrext:csrc-audio-level`, RFC
///   6465) for audio, receive only: RFC 8834 section 5.2.3 makes it optional; an endpoint
///   that implements it and does not mix states `recvonly` (RFC 6465 section 5). A receiver
///   reports the levels as the audio level of its contributing sources.
/// - **Coordination of video orientation** (`urn:3gpp:video-orientation`) for video: the
///   application writes and reads it.
/// - **Dependency Descriptor** (the AV1 RTP specification, appendix A) for video: the layer
///   structure a forwarder that cannot parse the payload routes by (W3C webrtc-svc section 4,
///   SFrame). The application writes it (`rtp::codec::dependency_descriptor`).
///
/// The two audio level extensions are offered encrypted as well as in the clear (RFC 6904
/// section 4.1 best-effort encryption): RFC 8834 sections 5.2.2 and 5.2.3 require that an
/// implementation can encrypt them and RECOMMEND that it does. A peer that implements RFC
/// 6904 takes the encrypted form, one that does not (browsers) the clear one.
/// [`MediaEngine::set_header_extension_encryption`] with
/// [`RTCRtpHeaderExtensionEncryption::Clear`] offers them in the clear only.
///
/// Part of [`register_default_interceptors`].
///
/// # Errors
///
/// Returns an error if a header extension cannot be registered (no free id).
pub fn configure_default_header_extensions(media_engine: &mut MediaEngine) -> Result<()> {
    for (uri, kind, direction) in [
        (::sdp::extmap::SDES_MID_URI, RtpCodecKind::Audio, None),
        (::sdp::extmap::AUDIO_LEVEL_URI, RtpCodecKind::Audio, None),
        (
            rtp::extension::CSRC_AUDIO_LEVEL_URI,
            RtpCodecKind::Audio,
            Some(RTCRtpTransceiverDirection::Recvonly),
        ),
        (
            ::sdp::extmap::VIDEO_ORIENTATION_URI,
            RtpCodecKind::Video,
            None,
        ),
        // The AV1 RTP specification's Dependency Descriptor (appendix A): what a forwarder
        // that cannot read the payload (SFrame, W3C webrtc-svc section 4) routes layers by.
        (
            ::rtp::codec::dependency_descriptor::DEPENDENCY_DESCRIPTOR_URI,
            RtpCodecKind::Video,
            None,
        ),
    ] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: uri.to_owned(),
            },
            kind,
            direction,
        )?;
    }
    for uri in [
        ::sdp::extmap::AUDIO_LEVEL_URI,
        rtp::extension::CSRC_AUDIO_LEVEL_URI,
    ] {
        media_engine
            .set_header_extension_encryption(uri, RTCRtpHeaderExtensionEncryption::BestEffort)?;
    }
    Ok(())
}

/// The receive-side variant of congestion control (draft-ietf-rmcat-gcc-02 section 3): a
/// REMB for every remote stream that negotiated `goog-remb` and neither transport-wide
/// congestion control nor RFC 8888, so a sender that only understands REMB still hears what
/// the path carries; and the abs-send-time header extension stamped on the packets of every
/// local stream that negotiated it, as they leave the pacer. Part of
/// [`register_default_interceptors`], which also registers abs-send-time on video
/// ([`configure_abs_send_time`]).
pub fn configure_remb(registry: Registry) -> Registry {
    registry
        .with(
            Slot::Custom(interceptor::REMB_GENERATOR_SLOT),
            interceptor::RembGeneratorBuilder::new().build(),
        )
        .with(
            Slot::Custom(interceptor::ABS_SEND_TIME_SLOT),
            interceptor::AbsSendTimeInterceptor::new(),
        )
}

/// Registers the abs-send-time header extension
/// (`http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time`) on video, so that it is
/// offered beside transport-wide congestion control and `ack ccfb`, and answered when a peer
/// offers it: a peer that runs neither (REMB with abs-send-time, the receive-side variant of
/// draft-ietf-rmcat-gcc-02 section 3) gets its send times, stamped by the
/// [`configure_remb`] interceptor, and REMB from this side. Part of
/// [`register_default_interceptors`]; registered after the other extensions, so their ids
/// stay as they were.
pub fn configure_abs_send_time(media_engine: &mut MediaEngine) -> Result<()> {
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::ABS_SEND_TIME_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    Ok(())
}

/// RFC 6051 rapid synchronisation, as RFC 8834 section 5.2.1 recommends: registers the
/// 64-bit NTP timestamp header extension (`urn:ietf:params:rtp-hdrext:ntp-64`, section 3.3)
/// on audio and video, so it is offered and answered, and adds the interceptor that stamps it
/// on a local stream that negotiated it (or `ntp-56`): every packet of the stream's first five
/// seconds, then a frame a second ([`NtpTimestampInterceptor`](interceptor::NtpTimestampInterceptor)).
/// A receiving stream that carries either extension is synchronised from it as from a sender
/// report (the capture times of its frames, before the first SR has arrived). Part of
/// [`register_default_interceptors`]; registered after the other extensions, so their ids
/// stay as they were.
///
/// # Errors
///
/// As [`MediaEngine::register_header_extension`].
pub fn configure_rapid_synchronisation(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    configure_rapid_synchronisation_with(registry, media_engine, None)
}

/// [`configure_rapid_synchronisation`] with the timestamps on `wall_clock` when one is given
/// ([`DefaultInterceptorOptions::wall_clock`]).
pub(crate) fn configure_rapid_synchronisation_with(
    registry: Registry,
    media_engine: &mut MediaEngine,
    wall_clock: Option<shared::time::SystemInstant>,
) -> Result<Registry> {
    for kind in [RtpCodecKind::Audio, RtpCodecKind::Video] {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: rtp::extension::NTP_64_URI.to_owned(),
            },
            kind,
            None,
        )?;
    }
    let builder = interceptor::NtpTimestampBuilder::new();
    let builder = match wall_clock {
        Some(anchor) => builder.with_wall_clock(anchor),
        None => builder,
    };
    Ok(registry.with(
        Slot::Custom(interceptor::NTP_TIMESTAMP_SLOT),
        builder.build(),
    ))
}

/// Offers TMMBR for audio and video: `a=rtcp-fb:<pt> ccm tmmbr` (RFC 5104 section 7.1).
///
/// A WebRTC endpoint that sends media implements TMMBR (RFC 8834 section 5.1.6): the
/// congestion controller keeps its target under the limit a TMMBR sets and answers with a
/// TMMBN. It does so for the streams that negotiated the message, which is what this
/// registers; a peer that does not answer `ccm tmmbr` (browsers do not) negotiates without it.
/// Part of [`register_default_interceptors`].
pub fn configure_tmmbr(media_engine: &mut MediaEngine) {
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        media_engine.register_feedback(
            RTCPFeedback {
                typ: TYPE_RTCP_FB_CCM.to_owned(),
                parameter: "tmmbr".to_owned(),
            },
            kind,
        );
    }
}

/// Registers what `feedback` needs negotiated, on audio and video codecs.
fn register_congestion_feedback(
    media_engine: &mut MediaEngine,
    feedback: CongestionFeedback,
) -> Result<()> {
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        if feedback.offers_twcc() {
            media_engine.register_feedback(
                RTCPFeedback {
                    typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
                    parameter: "".to_owned(),
                },
                kind,
            );
            media_engine.register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
                },
                kind,
                None,
            )?;
        }
        if feedback.offers_rfc8888() {
            // `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 6). No header extension: RFC 8888
            // reports against the RTP sequence number, which is in every packet already.
            register_ccfb_feedback(media_engine, kind);
        }
    }
    Ok(())
}

/// What numbers this endpoint's packets for the feedback about them. Only transport-wide
/// congestion control needs anything: RFC 8888 reports against the RTP sequence number.
///
/// `per_transport`: a numbering per transport (an RTP session each, RFC 8834 section 4.4),
/// for a congestion controller that runs per transport too.
fn with_congestion_feedback_senders(
    registry: Registry,
    feedback: CongestionFeedback,
    per_transport: bool,
) -> Registry {
    match (feedback.offers_twcc(), per_transport) {
        (false, _) => registry,
        (true, false) => registry.with(Slot::TwccSender, TwccSenderBuilder::new().build()),
        (true, true) => registry.with_per_rtp_session(
            Slot::TwccSender,
            PerRtpSession::new(|| TwccSenderBuilder::new().build()),
        ),
    }
}

/// What records the remote's packets and reports them. With both formats on offer both
/// recorders are in the chain, and each stream is reported by exactly one of them: the one
/// [`negotiated_congestion_feedback`](interceptor::negotiated_congestion_feedback) names.
///
/// The RFC 8888 report timestamps are on [`DefaultInterceptorOptions::wall_clock`] when it is
/// given; on the process-wide anchor otherwise.
fn with_congestion_feedback_recorders(
    registry: Registry,
    feedback: CongestionFeedback,
    options: &DefaultInterceptorOptions,
) -> Registry {
    let rereport_received = options.twcc_rereport_received;
    let cadence = options.congestion_feedback_cadence;
    let share = options.congestion_feedback_share;
    let max_interval = options.congestion_feedback_max_interval;
    let wall_clock = options.wall_clock;
    // Each transport's arrivals are reported on that transport (the remote numbers each
    // transport on its own).
    let registry = if feedback.offers_twcc() {
        registry.with_per_rtp_session(
            Slot::TwccReceiver,
            PerRtpSession::new(move || {
                TwccReceiverBuilder::new()
                    .with_rereport_received(rereport_received)
                    .with_cadence(cadence)
                    .with_feedback_share(share)
                    .with_max_adaptive_interval(max_interval)
                    .build()
            }),
        )
    } else {
        registry
    };
    if feedback.offers_rfc8888() {
        registry.with_per_rtp_session(
            Slot::Rfc8888,
            PerRtpSession::new(move || {
                let builder = Rfc8888Builder::new()
                    .with_cadence(cadence)
                    .with_feedback_share(share)
                    .with_max_adaptive_interval(max_interval);
                match wall_clock {
                    Some(anchor) => builder.with_wall_clock(anchor),
                    None => builder,
                }
                .build()
            }),
        )
    } else {
        registry
    }
}

/// Installs the RTP circuit breaker (RFC 8083) at [`Slot::CircuitBreaker`] with the RFC's
/// recommended parameters, and returns the handle that reports what it stopped.
///
/// It needs nothing negotiated: it reads the report blocks of the RTCP sender and receiver
/// reports every RTP endpoint sends. A flow it stops is restarted only by the application,
/// through the handle.
pub fn configure_circuit_breaker(registry: Registry) -> (Registry, CircuitBreakerHandle) {
    let (breaker, handle) = CircuitBreakerBuilder::new().build();
    (registry.with(Slot::CircuitBreaker, breaker), handle)
}

/// Delivers inbound key-frame requests (RTCP PLI and FIR) to the application.
///
/// The chain's terminus ends every inbound RTCP packet no interceptor vouches for, and no
/// interceptor can answer a key-frame request: only the encoder can, and the encoder is the
/// application. This registers [`KeyFrameRequestInterceptor`] at
/// [`Slot::KeyFrameRequests`], which marks them for delivery, so the application reads them as
/// `RTCMessage::RtcpPacket` and can send a key frame. Part of
/// [`register_default_interceptors`] (a fork addition: upstream swallows them).
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_key_frame_requests;
///
/// let registry = configure_key_frame_requests(Registry::new());
/// ```
pub fn configure_key_frame_requests(registry: Registry) -> Registry {
    registry.with(Slot::KeyFrameRequests, KeyFrameRequestInterceptor::new())
}

/// Configures NACK (Negative Acknowledgement) interceptors for packet loss recovery.
///
/// This function registers the following:
/// - **NACK Generator**: Monitors incoming RTP packets and generates NACK requests for missing packets
/// - **NACK Responder**: Buffers outgoing RTP packets and retransmits them when NACK requests arrive
/// - **RTCP Feedback**: Registers "nack" and "nack pli" feedback types for video codecs
///
/// # How NACK Works
///
/// 1. Receiver detects missing packets by tracking sequence numbers
/// 2. Receiver sends RTCP NACK listing missing sequence numbers
/// 3. Sender retransmits the requested packets from its buffer
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register NACK feedback capability
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_nack;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_nack(registry, &mut media_engine);
/// ```
///
/// # References
///
/// - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback
pub fn configure_nack(registry: Registry, media_engine: &mut MediaEngine) -> Registry {
    configure_nack_with(
        registry,
        media_engine,
        &DefaultInterceptorOptions::rfc_base(),
    )
}

/// The NACK responder's bounds on the repairs it makes (the age of a packet, the backlog after
/// a collapse) under `options`: its own two settings, or none at all with
/// [`PacerBacklog::Keep`](interceptor::PacerBacklog::Keep), which keeps and repairs
/// everything.
fn nack_repair_bounds(options: &DefaultInterceptorOptions) -> (Option<Duration>, Option<Duration>) {
    match options.pacer_backlog {
        interceptor::PacerBacklog::Keep => (None, None),
        _ => (
            options.nack_max_repair_age,
            options.nack_repair_backlog_bound,
        ),
    }
}

/// [`configure_nack`] with the NACK limits of `options`.
fn configure_nack_with(
    registry: Registry,
    media_engine: &mut MediaEngine,
    options: &DefaultInterceptorOptions,
) -> Registry {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: "pli".to_owned(),
        },
        RtpCodecKind::Video,
    );

    registry
        .with(Slot::NackResponder, {
            let (max_repair_age, repair_backlog_bound) = nack_repair_bounds(options);
            NackResponderBuilder::new()
                .with_rate_limit(options.nack_retransmission_rate_limit)
                .with_max_repair_age(max_repair_age)
                .with_repair_backlog_bound(repair_backlog_bound)
                .build()
        })
        .with(
            Slot::NackGenerator,
            NackGeneratorBuilder::new()
                .with_max_nacks_per_packet(options.nack_max_nacks_per_packet)
                .build(),
        )
}

/// Configures RTCP: the RTCP session of the connection.
///
/// Registers [`RtcpSessionInterceptor`](interceptor::RtcpSessionInterceptor) at
/// [`Slot::RtcpSession`], closest to the wire. It is the connection's whole RTCP voice:
///
/// - **Sender reports (SR)** for every SSRC that sent RTP in the last two report intervals
///   (RTX and FEC SSRCs included): NTP and RTP timestamps, packet and octet counts.
/// - **Receiver reports (RR)** otherwise, and reception report blocks for every remote stream:
///   fraction lost, cumulative loss, extended highest sequence number, interarrival jitter,
///   last SR and the delay since (RFC 3550 6.4, Appendix A.3).
/// - **One CNAME** (RFC 7022) in an SDES for every reporting SSRC, and a BYE for an SSRC that
///   stops and for all of them when the connection closes.
/// - **`T_rr_interval` of zero**, the RFC 4585 section 4.2 default when no `trr-int` is
///   signalled: see [`configure_rtcp_reports_with`] for the browsers' one second.
/// - **Timing** by RFC 3550 6.3 (interval from the member count, the average packet size and
///   the RTCP bandwidth, randomised, with timer reconsideration) and the RTP/AVPF rules of
///   RFC 4585 3.5: feedback the other interceptors and the application write (NACK, PLI, FIR,
///   TWCC, REMB, ...) leaves as early RTCP inside the same bandwidth, in compound packets
///   (reduced-size only when negotiated), from this connection's SSRC.
///
/// The peer connection starts the session when DTLS is up and gives it the connection's
/// CNAME. What a session description negotiates beyond that reaches it as an
/// [`RtcpSessionControl`](interceptor::RtcpSessionControl) (bandwidth from `b=` lines,
/// `a=rtcp-rsize`, `trr-int`) or through
/// [`RtcpSessionBuilder`] when the chain is built by hand:
///
/// ```
/// use rtci::interceptor::{Registry, RtcpBandwidth, RtcpSessionBuilder, Slot};
/// use std::time::Duration;
///
/// let registry = Registry::new().with(
///     Slot::RtcpSession,
///     RtcpSessionBuilder::new()
///         .with_bandwidth(RtcpBandwidth {
///             session: Some(1_500_000),
///             ..Default::default()
///         })
///         .with_t_rr_interval(Duration::from_millis(500))
///         .build(),
/// );
/// ```
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_rtcp_reports;
///
/// let registry = Registry::new();
/// let registry = configure_rtcp_reports(registry);
/// ```
///
/// # References
///
/// - [RFC 3550 Section 6](https://datatracker.ietf.org/doc/html/rfc3550#section-6) - RTCP
/// - [RFC 4585 Section 3](https://datatracker.ietf.org/doc/html/rfc4585#section-3) - RTP/AVPF timing
/// - [RFC 8108](https://datatracker.ietf.org/doc/html/rfc8108) - several SSRCs in one session
pub fn configure_rtcp_reports(registry: Registry) -> Registry {
    configure_rtcp_reports_with(
        registry,
        RtcpSessionBuilder::new().with_t_rr_interval(Duration::ZERO),
    )
}

/// [`configure_rtcp_reports`] for a peer connection whose registry brings no RTCP session:
/// the session draws its random numbers (the report interval's variation, RFC 3550 section
/// 6.3.1; the dither of early feedback, RFC 4585 section 3.5.2; its SSRC and CNAME) from
/// `provider`'s `random()`, as ICE, DTLS and SCTP do, so a seeded provider fixes when the
/// reports go out. Without a provider, from `rand`. Its NTP times derive from `wall_clock`
/// when one is given ([`DefaultInterceptorOptions::wall_clock`]).
pub(crate) fn configure_rtcp_reports_from(
    registry: Registry,
    provider: Option<&std::sync::Arc<dyn crate::crypto::RTCCryptoProvider>>,
    profile: BehaviourProfile,
    wall_clock: Option<shared::time::SystemInstant>,
) -> Registry {
    let mut options = DefaultInterceptorOptions::for_profile(profile);
    options.rtcp_random = provider.cloned();
    options.wall_clock = wall_clock;
    configure_rtcp_reports_with(registry, options.rtcp_session())
}

/// [`interceptor::RtcpRandom`] from a crypto provider's `random()`; from `rand` should the
/// provider fail (the values need unpredictability, not a particular source).
struct ProviderRtcpRandom(std::sync::Arc<dyn crate::crypto::RTCCryptoProvider>);

impl interceptor::RtcpRandom for ProviderRtcpRandom {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        match self.0.random().fill(&mut bytes) {
            Ok(()) => u32::from_be_bytes(bytes),
            Err(_) => rand::random(),
        }
    }
}

/// [`configure_rtcp_reports`] with the RTCP session built from `session`, for the settings a
/// session description does not carry.
///
/// The one [`configure_rtcp_reports`] itself sets is `T_rr_interval`, the minimum interval
/// between regular RTCP packets under RTP/AVPF: zero, as RFC 4585 section 4.2 has it when
/// `trr-int` is not signalled ("If trr-int is not specified, a default of 0 is assumed"), so
/// regular reports are spaced by the RTCP bandwidth alone (RFC 3550 section 6.2: 5% of the
/// session bandwidth). Browsers space them about a second apart whatever the bandwidth; that
/// is `RtcpSessionBuilder::new()` as it comes
/// ([`RTCP_SESSION_DEFAULT_T_RR_INTERVAL`](interceptor::RTCP_SESSION_DEFAULT_T_RR_INTERVAL)):
///
/// ```
/// use rtci::interceptor::{Registry, RtcpSessionBuilder};
/// use rtci::peer_connection::configuration::interceptor_registry::configure_rtcp_reports_with;
///
/// // Regular reports at most once a second, as browsers send them.
/// let registry = configure_rtcp_reports_with(Registry::new(), RtcpSessionBuilder::new());
/// ```
///
/// A `trr-int` this endpoint announces in its description replaces either value when the
/// answer is applied.
pub fn configure_rtcp_reports_with(registry: Registry, session: RtcpSessionBuilder) -> Registry {
    // An RTCP session per RTP session: one per transport when sections are not bundled
    // (RFC 3550 section 6, RFC 8834 section 4.4). Each joins when the peer connection says
    // its transport carries a negotiated RTP m= section and has SRTP keys, and leaves when the
    // last such section goes: a data-channel-only connection sends no RTCP.
    registry.with_per_rtp_session(
        Slot::RtcpSession,
        session
            .with_joins_on_start(true)
            .with_first_report_at_join(true)
            .build_per_rtp_session(),
    )
}

/// Adds the RTCP XR report blocks a receiver writes about each source (RFC 3611 section 4:
/// Loss RLE, Duplicate RLE, Packet Receipt Times, Statistics Summary, VoIP Metrics) for the
/// remote streams that negotiated them with `a=rtcp-xr` (section 5.1). A stream that did not
/// gets none. Part of [`register_default_interceptors`].
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_extended_reports;
///
/// let registry = configure_extended_reports(Registry::new());
/// # let _ = registry;
/// ```
pub fn configure_extended_reports(registry: Registry) -> Registry {
    registry.with(Slot::ExtendedReports, XrReportBuilder::new().build())
}

/// Adds the temporal-spatial trade-off notifications (RFC 5104 section 4.3.3): a local media
/// sender whose stream negotiated `ccm tstr` answers each request it receives with a TSTN
/// carrying the index it will use. The request itself still reaches the application, which
/// owns the encoder. Part of [`register_default_interceptors`].
pub fn configure_tradeoff_notifications(registry: Registry) -> Registry {
    registry.with(
        Slot::TradeoffNotifications,
        TstnResponderBuilder::new().build(),
    )
}

/// Adds RTP stream pause and resume (RFC 7728) and offers it for audio and video:
/// `a=rtcp-fb:<pt> ccm pause` (section 9; the full implementation, `config=1`, without
/// `nowait`). Returns the handle through which the application asks a remote stream to pause
/// or resume, pauses its own streams by local decision and reads where each stream is.
///
/// The interceptor sits at [`Slot::PauseResume`] and acts for the streams whose section
/// negotiated `ccm pause`; answers follow section 9.1 (the complementary `config`, `nowait`
/// only when offered). Not part of [`register_default_interceptors`]: no browser implements it.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_pause_resume;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let (registry, handle) = configure_pause_resume(Registry::new(), &mut media_engine);
/// assert_eq!(handle.state(0x1234), None);
/// # let _ = registry;
/// ```
pub fn configure_pause_resume(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> (Registry, interceptor::PauseResumeHandle) {
    configure_pause_resume_with(
        registry,
        media_engine,
        interceptor::PauseResumeBuilder::new(),
        false,
    )
}

/// [`configure_pause_resume`] with the interceptor's parameters and, with `nowait`, the
/// `nowait` attribute in offers (RFC 7728 section 9.1: "If the offerer believes that itself
/// and the intended answerer are likely the only endpoints in the RTP session").
pub fn configure_pause_resume_with(
    registry: Registry,
    media_engine: &mut MediaEngine,
    builder: interceptor::PauseResumeBuilder,
    nowait: bool,
) -> (Registry, interceptor::PauseResumeHandle) {
    let parameter = interceptor::PauseCapability { nowait, config: 1 }.parameter();
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        media_engine.register_feedback(
            RTCPFeedback {
                typ: TYPE_RTCP_FB_CCM.to_owned(),
                parameter: parameter.clone(),
            },
            kind,
        );
    }
    let (pause_resume, handle) = builder.build();
    (registry.with(Slot::PauseResume, pause_resume), handle)
}

/// Negotiates receiver-side round trip time measurement for video (`a=rtcp-fb:<pt> rrtr`,
/// libwebrtc's feedback name for RTCP XR receiver reference times, RFC 3611 section 4.4).
///
/// With it negotiated, the receiver report interceptor ([`configure_rtcp_reports`]) sends a
/// receiver reference time block with each receiver report of a video stream; the remote sender
/// answers with a DLRR block (section 4.5), and the stream's `remote-outbound-rtp` stats report
/// `roundTripTime`, `totalRoundTripTime` and `roundTripTimeMeasurements`. The sender report
/// interceptor answers reference times whether or not this is negotiated, as libwebrtc does.
/// Part of [`register_default_interceptors`].
///
/// # Examples
///
/// ```
/// use rtci::peer_connection::configuration::interceptor_registry::configure_receiver_reference_time;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// configure_receiver_reference_time(&mut media_engine);
/// ```
pub fn configure_receiver_reference_time(media_engine: &mut MediaEngine) {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: interceptor::RTCP_FB_RRTR.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );
}

/// Registers RTP header extensions required for simulcast streaming.
///
/// Simulcast allows sending multiple resolutions/qualities of the same video
/// simultaneously. This function registers the following header extensions:
///
/// - **SDES MID** (`urn:ietf:params:rtp-hdrext:sdes:mid`): Media identification
/// - **SDES RtpStreamId** (`urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`): Stream identification
/// - **SDES RepairedRtpStreamId** (`urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id`): Repair stream identification
///
/// # Parameters
///
/// * `media_engine` - The media engine to register header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtci::peer_connection::configuration::interceptor_registry::configure_simulcast_extension_headers;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// configure_simulcast_extension_headers(&mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [RFC 8852](https://datatracker.ietf.org/doc/html/rfc8852) - RTP Stream Identifier Source Description Extensions
pub fn configure_simulcast_extension_headers(media_engine: &mut MediaEngine) -> Result<()> {
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    Ok(())
}

/// Configures full TWCC (Transport-Wide Congestion Control) for bandwidth estimation.
///
/// This function enables both sending and receiving TWCC feedback:
/// - **TWCC Sender**: Adds transport-wide sequence numbers to outgoing RTP packets
/// - **TWCC Receiver**: Generates TransportLayerCC RTCP feedback for incoming packets
///
/// # How TWCC Works
///
/// 1. Sender adds a transport-wide sequence number to each RTP packet
/// 2. Receiver records arrival time of each packet by sequence number
/// 3. Receiver periodically sends TransportLayerCC RTCP packets with timing info
/// 4. Sender uses feedback to estimate available bandwidth
///
/// # When to Use
///
/// Use full TWCC when you need bandwidth estimation in both directions,
/// such as in a two-way video call where both peers send media.
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_twcc;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
pub fn configure_twcc(registry: Registry, media_engine: &mut MediaEngine) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(registry
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::TwccReceiver, TwccReceiverBuilder::new().build()))
}

/// Configures TWCC sender only (the remote peer generates feedback).
///
/// This function enables only the TWCC sender interceptor, which adds
/// transport-wide sequence numbers to outgoing RTP packets. The remote
/// peer is expected to generate and send TransportLayerCC feedback.
///
/// # When to Use
///
/// Use sender-only TWCC when:
/// - You are sending media but not receiving (e.g., streaming/broadcasting)
/// - The remote peer handles feedback generation
/// - You want to minimize local processing overhead
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_twcc_sender_only;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_sender_only(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_sender_only(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Audio,
    );

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(registry.with(Slot::TwccSender, TwccSenderBuilder::new().build()))
}

/// Configures TWCC receiver only (generates feedback for the remote sender).
///
/// This function enables only the TWCC receiver interceptor, which:
/// - Tracks arrival times of incoming RTP packets with TWCC sequence numbers
/// - Generates TransportLayerCC RTCP feedback packets periodically
/// - Sends feedback to the remote sender for bandwidth estimation
///
/// This is the default TWCC configuration used by [`register_default_interceptors`].
///
/// # When to Use
///
/// Use receiver-only TWCC when:
/// - You are receiving media but not sending (e.g., viewer in a broadcast)
/// - The remote peer adds TWCC sequence numbers and needs feedback
/// - You want to help the sender estimate available bandwidth
///
/// # Parameters
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_twcc_receiver_only;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_receiver_only(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_receiver_only(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(registry.with(Slot::TwccReceiver, TwccReceiverBuilder::new().build()))
}

/// `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 5) on every codec of `kind`.
fn register_ccfb_feedback(media_engine: &mut MediaEngine, kind: RtpCodecKind) {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_ACK.to_owned(),
            parameter: RTCP_FB_ACK_CCFB.to_owned(),
        },
        kind,
    );
}

/// Negotiates RFC 8888 congestion control feedback and reports arrivals with it, without a
/// congestion controller.
///
/// Registers `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 5) on audio and video codecs and the
/// RFC 8888 recorder in [`Slot::Rfc8888`], which reports every received packet of a stream that
/// negotiated it, with the ECN codepoint it arrived with, about every 100 ms. What the reports
/// say becomes statistics on both sides: the receiver's `inbound-rtp`
/// `packetsReportedAsLost` / `packetsReportedAsLostButRecovered`, the sender's
/// `remote-inbound-rtp` `packetsReceivedWithEct1`, `packetsReceivedWithCe`,
/// `packetsReportedAsLost`, `packetsReportedAsLostButRecovered` and
/// `packetsWithBleachedEct1Marking`. With ECN on
/// ([`SettingEngineBuilder::with_ecn`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_ecn)),
/// a stream that negotiated it is sent ECT(1) (L4S).
///
/// [`register_default_interceptors`] does this already, beside transport-wide congestion
/// control; this helper is for a chain built piece by piece. A peer that does not offer or
/// accept `ack ccfb` negotiates without it, and nothing changes for that stream. A stream that
/// did negotiate it is reported here and not by the TWCC receiver. Use
/// [`configure_congestion_control`] to also run a congestion controller on the reports.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Registry;
/// use rtci::peer_connection::configuration::interceptor_registry::configure_congestion_control_feedback;
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = configure_congestion_control_feedback(Registry::new(), &mut media_engine);
/// ```
pub fn configure_congestion_control_feedback(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Registry {
    for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
        register_ccfb_feedback(media_engine, kind);
    }
    registry.with(Slot::Rfc8888, Rfc8888Builder::new().build())
}

/// Which congestion control feedback is offered, and so which the remote may report arrivals
/// with.
///
/// **A stream runs on one format, never both.** Both resolve into the same `PacketReport`s and
/// the estimator cannot tell them apart, so a stream reported in both would have every packet
/// counted twice and the estimate wrong by a factor of two in the direction that causes
/// congestion. Offering both is a different thing, and is what RFC 8888 section 6 expects:
/// "an SDP offer might indicate support for both the congestion control feedback mechanism
/// specified in this memo and one or more alternative congestion control feedback mechanisms
/// that offer substantially the same semantics. In this case, the answering party SHOULD
/// include only one of the offered congestion control feedback mechanisms in its answer."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CongestionFeedback {
    /// Both on offer, one in use per stream: RFC 8888 when the peer accepted `ack ccfb`,
    /// transport-wide congestion control otherwise (a browser answers `transport-cc` only).
    /// As an answerer this endpoint keeps `ack ccfb` and drops `transport-cc` when it was
    /// offered both. The default.
    #[default]
    Negotiated,
    /// Transport-wide congestion control only: `ack ccfb` is neither offered nor accepted.
    /// What browsers offer.
    Twcc,
    /// RFC 8888 congestion control feedback only. Carries ECN, which TWCC cannot. A peer
    /// that does not accept `ack ccfb` then sends no per-packet feedback at all.
    Rfc8888,
}

impl CongestionFeedback {
    fn offers_twcc(self) -> bool {
        matches!(self, Self::Negotiated | Self::Twcc)
    }

    fn offers_rfc8888(self) -> bool {
        matches!(self, Self::Negotiated | Self::Rfc8888)
    }
}

/// Configure send-side congestion control around `estimator`.
///
/// Places interceptors at the slots the chain contract reserves for them:
///
/// | Slot | Interceptor | Why there |
/// |---|---|---|
/// | [`Slot::CongestionControl`] | send history and feedback ingest | the only position that sees every byte that leaves |
/// | [`Slot::TwccSender`] | transport-wide sequence numbers (not with [`CongestionFeedback::Rfc8888`]) | so the history keys on a number that already exists |
/// | [`REMOTE_BITRATE_LIMIT_SLOT`] | bounds the estimate by the remote description's `b=TIAS` / `b=AS` | between the controller, which announces the estimate, and the pacer, which reads it |
/// | [`Slot::Pacer`] | paces departures | above the two, so `packet.now` is the release instant |
/// | [`Slot::TwccReceiver`] and / or [`Slot::Rfc8888`] | records arrivals, reports them to the remote | an arrival recorder, so it precedes the jitter buffer |
///
/// The first three are this endpoint's own control loop: number what leaves, ingest the feedback
/// that comes back, pace to the result. The recorder is the other half — it serves the *remote's*
/// estimator, and without it a symmetric pair of peers running this helper would both wait for
/// feedback neither ever sends.
///
/// The order is declared, not implied by the order these are added, so this composes with
/// [`configure_nack`] and the rest in any sequence.
///
/// [`register_default_interceptors`] installs the same thing around [`Gcc`], with the circuit
/// breaker; this is for another estimator, or a chain built piece by piece. A slot holds one
/// interceptor, so calling this after the default set replaces its estimator and pacer.
///
/// # Examples
///
/// ```
/// use rtci::interceptor::Gcc;
/// use rtci::peer_connection::configuration::interceptor_registry::{
///     CongestionFeedback, Registry, configure_congestion_control,
/// };
/// use rtci::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = configure_congestion_control(
///     Registry::new(),
///     Gcc::default(),
///     CongestionFeedback::Twcc,
///     &mut media_engine,
/// )?;
/// let registry = registry.build();
/// # Ok(())
/// # }
/// ```
/// # Errors
///
/// Returns an error if the TWCC header extension cannot be registered on the media engine.
pub fn configure_congestion_control<E: BandwidthEstimator + 'static>(
    registry: Registry,
    estimator: E,
    feedback: CongestionFeedback,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    // The remote needs to know how to report. RFC 8888 needs no header extension — it reports
    // against the RTP sequence number — so only TWCC registers one. Without `ack ccfb` in the
    // description the remote has no reason to send RFC 8888 reports, and an estimator that
    // never receives feedback holds its initial rate for the life of the connection.
    register_congestion_feedback(media_engine, feedback)?;

    // The pacer starts at the estimator's own starting rate. Left at its default it would
    // release at 1 Mbit/s until the first feedback moved the estimate, whatever the estimator
    // said it wanted to start at.
    let initial_target = estimator.target_bitrate();
    let registry = registry
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(estimator).build(),
        )
        // The remote description's `b=TIAS` / `b=AS` bounds the estimate on its way to the
        // pacer (RFC 9429 section 5.10).
        .with(
            Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
            RemoteBitrateLimitInterceptor::new(initial_target),
        )
        .with(
            Slot::Pacer,
            PacerBuilder::new()
                .with_target_bitrate(initial_target)
                .build(),
        );

    // The sequence numbers the send history keys on (TWCC only), and the other half of the
    // loop: what this endpoint reports about what it *receives*, so the remote's estimator has
    // something to work with. A stream is reported by one recorder, never both.
    // One estimator for the connection (`estimator` is one instance), so one numbering.
    let registry = with_congestion_feedback_senders(registry, feedback, false);
    let options = DefaultInterceptorOptions::for_profile(media_engine.behaviour_profile());
    Ok(with_congestion_feedback_recorders(
        registry, feedback, &options,
    ))
}

/// Creates a [`StreamInfo`](interceptor::StreamInfo) from RTC types for interceptor binding.
///
/// This helper converts RTC codec and header extension information into the format
/// expected by the interceptor layer when binding local or remote streams.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_stream_info(
    ssrc: SSRC,
    ssrc_rtx: Option<SSRC>,
    ssrc_fec: Option<SSRC>,
    payload_type: PayloadType,
    payload_type_rtx: Option<PayloadType>,
    fec_format: Option<&crate::rtp_transceiver::rtp_sender::rtp_codec::FecFormat>,
    codec: &RTCRtpCodec,
    header_extensions: &[RTCRtpHeaderExtensionParameters],
    section_codecs: &[RTCRtpCodecParameters],
) -> interceptor::StreamInfo {
    let rtp_header_extensions: Vec<interceptor::RTPHeaderExtension> = header_extensions
        .iter()
        .map(|h| interceptor::RTPHeaderExtension {
            id: h.id,
            uri: h.uri.clone(),
        })
        .collect();

    // A redundancy stream (RFC 2198 `red`) is the media of another format of its section in
    // RED blocks, and the `red` format itself is described without `a=rtcp-fb` lines (the
    // engine's own registrations, Chromium's offers): what was negotiated for the format it
    // carries is what applies to the stream. libwebrtc configures a stream's NACK and
    // transport feedback from its first media codec whatever payload type a packet arrives
    // under (media/engine/webrtc_video_engine.cc, `HasNack(recv_codecs.front().codec)`).
    // Without this a receiver that learns a stream from a RED packet binds it with no
    // feedback at all: no RFC 8888 reports about it (`ack ccfb` is read from here), so the
    // sender's congestion controller hears of its audio only and never raises its estimate.
    let carried = (crate::rtp_transceiver::rtp_sender::rtp_codec::repair_family(codec) == "red")
        .then(|| {
            let named = codec
                .sdp_fmtp_line
                .split('/')
                .next()
                .and_then(|primary| primary.trim().parse::<PayloadType>().ok());
            let media = |c: &&RTCRtpCodecParameters| {
                !crate::rtp_transceiver::rtp_sender::rtp_codec::is_repair_codec(&c.rtp_codec)
                    && !crate::peer_connection::handler::endpoint::is_auxiliary_mime_type(
                        &c.rtp_codec.mime_type,
                    )
            };
            section_codecs
                .iter()
                .filter(media)
                .find(|c| named == Some(c.payload_type))
                .or_else(|| section_codecs.iter().find(media))
        })
        .flatten();
    let mut feedbacks: Vec<_> = codec
        .rtcp_feedback
        .iter()
        .map(|f| interceptor::RTCPFeedback {
            typ: f.typ.clone(),
            parameter: f.parameter.clone(),
        })
        .collect();
    for f in carried.iter().flat_map(|c| &c.rtp_codec.rtcp_feedback) {
        let feedback = interceptor::RTCPFeedback {
            typ: f.typ.clone(),
            parameter: f.parameter.clone(),
        };
        if !feedbacks.contains(&feedback) {
            feedbacks.push(feedback);
        }
    }

    interceptor::StreamInfo {
        ssrc,
        ssrc_rtx,
        ssrc_fec,
        payload_type,
        payload_type_rtx,
        payload_type_fec: fec_format.map(|format| format.payload_type),
        rtp_header_extensions,
        mime_type: codec.mime_type.clone(),
        clock_rate: codec.clock_rate,
        channels: codec.channels,
        sdp_fmtp_line: codec.sdp_fmtp_line.clone(),
        rtcp_feedback: feedbacks,
        // Which FEC coder the repair flow needs, and its parameters (`repair-window`).
        mime_type_fec: fec_format
            .map(|format| format.mime_type.clone())
            .unwrap_or_default(),
        sdp_fmtp_line_fec: fec_format
            .map(|format| format.sdp_fmtp_line.clone())
            .unwrap_or_default(),
        // RFC 7160 section 4.3 (RFC 8834 section 4.3): the other media formats of the m=
        // section and their clock rates, for a source that switches between them on one SSRC.
        // Repair formats are left out: RTX is de-encapsulated to the media format before the
        // chain, and FEC has an SSRC of its own.
        payload_clock_rates: section_codecs
            .iter()
            .filter(|c| {
                c.payload_type != payload_type
                    && !crate::peer_connection::handler::endpoint::is_repair_mime_type(
                        &c.rtp_codec.mime_type,
                    )
            })
            .map(|c| (c.payload_type, c.rtp_codec.clock_rate))
            .collect(),
        // Set by the sender for a stream the description starts paused (RFC 8853 section 5.2).
        initially_paused: false,
        section_fmtp_lines: section_codecs
            .iter()
            .map(|c| (c.payload_type, c.rtp_codec.sdp_fmtp_line.clone()))
            .collect(),
        section_mime_types: section_codecs
            .iter()
            .map(|c| (c.payload_type, c.rtp_codec.mime_type.clone()))
            .collect(),
        // Set by the sender or receiver of a stream whose FEC runs in an RTP session of its
        // own (RFC 5109 section 14.1).
        fec_session: None,
    }
}

/// Adds redundant audio data, RED (RFC 2198), in both directions
/// ([`RedAudioInterceptor`](interceptor::RedAudioInterceptor), [`Slot::Redundancy`]): a local
/// audio stream whose section negotiated a RED format with its own encoding as primary and
/// redundancy (`a=fmtp:63 111/111`, the default codecs' form) is sent as RED with a copy of
/// the previous packet when the remote description lists RED ahead of the stream's codec
/// ([`AudioRedundancy::WhenPreferred`](interceptor::AudioRedundancy::WhenPreferred), RFC 3264
/// sections 5.1 and 6.1), and received RED packets are taken apart into their primary
/// encoding, with lost packets recovered from the next packet's copy.
pub fn configure_audio_redundancy(registry: Registry) -> Registry {
    configure_audio_redundancy_with(registry, interceptor::AudioRedundancy::default())
}

/// [`configure_audio_redundancy`], with `audio_redundancy` deciding when a local stream is
/// sent in RED. The peer connection installs it, with
/// [`SettingEngineBuilder::with_audio_redundancy`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_audio_redundancy),
/// in any chain that does not fill the slot.
pub fn configure_audio_redundancy_with(
    registry: Registry,
    audio_redundancy: interceptor::AudioRedundancy,
) -> Registry {
    registry.with(
        Slot::Redundancy,
        interceptor::RedAudioBuilder::new()
            .with_audio_redundancy(audio_redundancy)
            .build(),
    )
}

/// Adds ULPFEC (RFC 5109) carried in RED (RFC 2198) for video (`a=rtpmap:<red> red/90000`,
/// `a=rtpmap:<ulpfec> ulpfec/90000`), in both directions, with the FEC placed as RFC 5109
/// section 14.2 has it: in the same packets as the media it protects.
///
/// Every video stream bound to the chain is then sent as RED packets, FEC data is produced
/// after each frame or five packets, whichever comes first, and travels as a redundant block
/// of the next media packet. Received RED is taken apart, lost packets rebuilt, and the media
/// delivered under its own payload type, whichever of the two placements the sender used. FEC
/// replaces FlexFEC at [`Slot::FecEncoder`] / [`Slot::FecDecoder`]: a chain runs one FEC scheme.
///
/// **Browsers need the other placement.** libwebrtc sends FEC in RED packets of its own and
/// drops a RED packet with more than one block, so towards Chrome, and for video with
/// full-size packets (a redundant block holds at most 1023 octets), use
/// [`configure_ulpfec_with_placement`] with
/// [`RedPlacement::OwnPacket`](interceptor::RedPlacement::OwnPacket).
///
/// `red_payload_type` and `ulpfec_payload_type` are the payload types **in use on the
/// connection**. Register `video/red` and [`MIME_TYPE_ULP_FEC`] on the [`MediaEngine`] with the
/// same numbers; the engine offers and answers them like any codec. When the remote side makes
/// the offer and numbers them differently, the negotiated numbers are the ones to pass here.
///
/// For other shapes (uneven protection levels, `onelevelonly`, a separate FEC stream) build
/// the interceptors with [`UlpfecSendBuilder`](interceptor::UlpfecSendBuilder) and
/// [`UlpfecReceiveBuilder`](interceptor::UlpfecReceiveBuilder).
///
/// [`MIME_TYPE_ULP_FEC`]: crate::peer_connection::configuration::media_engine::MIME_TYPE_ULP_FEC
pub fn configure_ulpfec(
    registry: Registry,
    red_payload_type: PayloadType,
    ulpfec_payload_type: PayloadType,
) -> Registry {
    configure_ulpfec_with_placement(
        registry,
        red_payload_type,
        ulpfec_payload_type,
        interceptor::RedPlacement::default(),
    )
}

/// [`configure_ulpfec`] with the placement of FEC data in the RED stream chosen:
/// [`RedPlacement::WithNextMedia`](interceptor::RedPlacement::WithNextMedia), the form of
/// RFC 5109 section 14.2 and the default, or
/// [`RedPlacement::OwnPacket`](interceptor::RedPlacement::OwnPacket), the form libwebrtc
/// sends and the only one it reads.
pub fn configure_ulpfec_with_placement(
    registry: Registry,
    red_payload_type: PayloadType,
    ulpfec_payload_type: PayloadType,
    placement: interceptor::RedPlacement,
) -> Registry {
    registry
        .with(
            Slot::FecEncoder,
            interceptor::UlpfecSendBuilder::red(red_payload_type, ulpfec_payload_type)
                .with_red_placement(placement)
                .with_flush_on_marker(true)
                .build(),
        )
        .with(
            Slot::FecDecoder,
            interceptor::UlpfecReceiveBuilder::red(red_payload_type, ulpfec_payload_type).build(),
        )
}

/// The payload type [`configure_video_red_ulpfec`] registers `video/red` under.
pub const VIDEO_RED_PAYLOAD_TYPE: PayloadType = 116;
/// The payload type of the RTX format for `video/red` (`apt=116`).
pub const VIDEO_RED_RTX_PAYLOAD_TYPE: PayloadType = 117;
/// The payload type [`configure_video_red_ulpfec`] registers `video/ulpfec` under.
pub const VIDEO_ULPFEC_PAYLOAD_TYPE: PayloadType = 43;

/// Video `red` and `ulpfec` as Chromium offers them, and ULPFEC in RED in both directions
/// (the `Chrome` behaviour profile's `DefaultInterceptorOptions::video_red_ulpfec`):
///
/// - registers `video/red` ([`VIDEO_RED_PAYLOAD_TYPE`]), RTX for it
///   ([`VIDEO_RED_RTX_PAYLOAD_TYPE`], `apt=116`) and `video/ulpfec`
///   ([`VIDEO_ULPFEC_PAYLOAD_TYPE`]) after the video codecs already registered, unless the
///   media engine has a `video/red` or `video/ulpfec` of its own;
/// - the encoder at [`Slot::FecEncoder`] with its wire tap at [`Slot::FecWireImage`], so the
///   FEC protects each packet as it leaves: FEC in RED packets of its own in the media's
///   sequence space (`RedPlacement::OwnPacket`, the form libwebrtc sends and the only one it
///   reads), one block for every five packets of a frame and one for what is left at its
///   end, all of them sent behind the frame's last packet
///   (`UlpfecSendBuilder::with_fec_after_frame`: no FEC packet lies inside a frame), in the
///   amount the receiver's reported loss asks for (`FecRate`);
/// - the decoder at [`Slot::FecDecoder`]. A FEC packet received reaches the application as
///   an RTP packet without a payload under the media's payload type: its sequence number is
///   one of the stream's, and the application's frame assembly must see it as received
///   (`interceptor::UlpfecRepair`; `rtci-media`'s `SampleBuilder` and `rtci-video`'s
///   receiver take such a packet as present and no media).
///
/// A stream is protected only when its section negotiated both `red` and `ulpfec` (RFC 5109
/// section 14.2), under the payload types the section has (an answer keeps the offerer's).
///
/// # Errors
///
/// When a codec cannot be registered.
pub fn configure_video_red_ulpfec(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    configure_video_red_ulpfec_with(registry, media_engine, false)
}

/// [`configure_video_red_ulpfec`], with the transport-wide sequence number, abs-send-time and
/// toffset values zeroed in what the encoder protects and in the decoder's copies when
/// `zero_mutable_extensions` (libwebrtc's form:
/// `UlpfecSendBuilder::with_mutable_extensions_zeroed`,
/// `UlpfecReceiveBuilder::with_mutable_extensions_zeroed`;
/// `DefaultInterceptorOptions::ulpfec_zero_mutable_extensions`).
///
/// # Errors
///
/// When a codec cannot be registered.
pub fn configure_video_red_ulpfec_with(
    registry: Registry,
    media_engine: &mut MediaEngine,
    zero_mutable_extensions: bool,
) -> Result<Registry> {
    let has = |media_engine: &MediaEngine, subtype: &str| {
        media_engine.video_codecs.iter().any(|codec| {
            codec
                .rtp_codec
                .mime_type
                .rsplit_once('/')
                .is_some_and(|(_, sub)| sub.eq_ignore_ascii_case(subtype))
        })
    };
    if !has(media_engine, "red") && !has(media_engine, "ulpfec") {
        let codec = |mime_type: &str, sdp_fmtp_line: String, payload_type| RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line,
                rtcp_feedback: vec![],
            },
            payload_type,
        };
        for parameters in [
            codec("video/red", String::new(), VIDEO_RED_PAYLOAD_TYPE),
            codec(
                crate::peer_connection::configuration::media_engine::MIME_TYPE_RTX,
                format!("apt={VIDEO_RED_PAYLOAD_TYPE}"),
                VIDEO_RED_RTX_PAYLOAD_TYPE,
            ),
            codec(
                crate::peer_connection::configuration::media_engine::MIME_TYPE_ULP_FEC,
                String::new(),
                VIDEO_ULPFEC_PAYLOAD_TYPE,
            ),
        ] {
            media_engine.register_codec(parameters, RtpCodecKind::Video)?;
        }
    }
    let mut encoder =
        interceptor::UlpfecSendBuilder::red(VIDEO_RED_PAYLOAD_TYPE, VIDEO_ULPFEC_PAYLOAD_TYPE)
            .with_red_placement(interceptor::RedPlacement::OwnPacket)
            .with_flush_on_marker(true)
            .with_mutable_extensions_zeroed(zero_mutable_extensions)
            .build();
    let tap = encoder.wire_tap();
    Ok(registry
        .with(Slot::FecEncoder, encoder)
        .with(Slot::FecWireImage, tap)
        .with(
            Slot::FecDecoder,
            interceptor::UlpfecReceiveBuilder::red(
                VIDEO_RED_PAYLOAD_TYPE,
                VIDEO_ULPFEC_PAYLOAD_TYPE,
            )
            .with_mutable_extensions_zeroed(zero_mutable_extensions)
            .build(),
        ))
}

/// The payload type [`configure_video_flexfec`] registers `video/flexfec` under.
pub const VIDEO_FLEXFEC_PAYLOAD_TYPE: PayloadType = 49;
/// Where [`configure_video_flexfec`] puts the RFC 8627 encoder: `Slot::Custom(5_100)`, beside
/// [`Slot::FecEncoder`] (5_000), which ULPFEC may hold. Both are above the NACK responder and the
/// pacer, so repair packets are paced and recorded.
pub const FLEXFEC_ENCODER_SLOT: usize = 5_100;
/// Where the RFC 8627 encoder's wire tap sits: `Slot::Custom(1_510)`, beside
/// [`Slot::FecWireImage`] (1_500), below the TWCC sender, so FlexFEC protects each source
/// packet as it leaves (RFC 8627 section 4.1).
pub const FLEXFEC_WIRE_IMAGE_SLOT: usize = 1_510;
/// Where the RFC 8627 decoder sits: `Slot::Custom(10_310)`, beside [`Slot::FecDecoder`]
/// (10_300): after the arrival recorders, which must report what the path delivered, and
/// before the NACK generator, which must not ask for what FEC rebuilds.
pub const FLEXFEC_DECODER_SLOT: usize = 10_310;

/// RFC 8627 FlexFEC for video, in both directions (`DefaultInterceptorOptions::video_flexfec`,
/// on in the `StrictRfc` profile; RFC 8854 sections 5.1 and 5.2):
///
/// - registers `video/flexfec` ([`VIDEO_FLEXFEC_PAYLOAD_TYPE`]) with
///   `repair-window=10000000` (RFC 8627 section 5.1: required; 10 s,
///   `interceptor::FLEXFEC_DEFAULT_REPAIR_WINDOW`) after the video codecs already registered,
///   unless the media engine has a `video/flexfec` of its own. Each video sender then has a
///   FEC SSRC, grouped with its media SSRC by `a=ssrc-group:FEC-FR` (RFC 5956 section 4.3);
/// - the encoder at [`FLEXFEC_ENCODER_SLOT`] with its wire tap at [`FLEXFEC_WIRE_IMAGE_SLOT`]:
///   flexible masks of two repair packets per five source packets at most, in the amount the
///   receiver's reported loss asks for (`FecRate`, RFC 8854 section 8), taken out of the
///   target the application encodes at;
/// - the decoder at [`FLEXFEC_DECODER_SLOT`].
///
/// These slots are not ULPFEC's, so a chain may run both (the `Chrome` profile's ULPFEC in RED
/// at [`Slot::FecEncoder`] / [`Slot::FecDecoder`]). A stream is protected only when its section
/// negotiated `flexfec`; an answer to an offer with `flexfec` and `rtx` keeps only `flexfec`
/// (RFC 8627 section 1.1.7, `MediaEngine::set_flexfec_with_retransmission`).
///
/// # Errors
///
/// When the codec cannot be registered.
pub fn configure_video_flexfec(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    let registered = media_engine.video_codecs.iter().any(|codec| {
        codec.rtp_codec.mime_type.eq_ignore_ascii_case(
            crate::peer_connection::configuration::media_engine::MIME_TYPE_FLEX_FEC,
        )
    });
    if !registered {
        media_engine.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type:
                        crate::peer_connection::configuration::media_engine::MIME_TYPE_FLEX_FEC
                            .to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: interceptor::FlexFecParameters::with_repair_window(
                        interceptor::FLEXFEC_DEFAULT_REPAIR_WINDOW,
                    )
                    .to_fmtp(),
                    rtcp_feedback: vec![],
                },
                payload_type: VIDEO_FLEXFEC_PAYLOAD_TYPE,
            },
            RtpCodecKind::Video,
        )?;
    }
    let mut encoder = interceptor::FlexFecSendBuilder::new().build();
    let tap = encoder.wire_tap();
    Ok(registry
        .with(Slot::Custom(FLEXFEC_ENCODER_SLOT), encoder)
        .with(Slot::Custom(FLEXFEC_WIRE_IMAGE_SLOT), tap)
        .with(
            Slot::Custom(FLEXFEC_DECODER_SLOT),
            interceptor::FlexFecReceiveBuilder::new().build(),
        ))
}

/// Adds ULPFEC (RFC 5109) for FEC sessions of their own (section 14.1,
/// [`RTCPeerConnection::add_fec_session`](crate::peer_connection::RTCPeerConnection::add_fec_session),
/// `SettingEngineBuilder::with_separate_fec_sessions`), in both directions: the encoder at
/// [`Slot::FecEncoder`] with its wire tap at [`Slot::FecWireImage`], so the FEC protects each
/// media packet as it leaves, and the decoder at [`Slot::FecDecoder`], which keeps a decoder
/// for every video stream so the FEC of a session finds it.
///
/// A stream no FEC session protects is left alone (and one with a ULPFEC repair flow of its
/// own session is protected there, as a separate stream). FEC is produced after each frame or
/// five packets, whichever comes first, in the amount the receiver's reported loss asks for
/// (`FecRate`: none below 0.5% loss, at most one FEC packet for two of media), and its bit
/// rate is taken out of the target the application encodes at.
pub fn configure_ulpfec_sessions(registry: Registry) -> Registry {
    let mut encoder = interceptor::UlpfecSendBuilder::stream()
        .with_flush_on_marker(true)
        .build();
    let tap = encoder.wire_tap();
    registry
        .with(Slot::FecEncoder, encoder)
        .with(Slot::FecWireImage, tap)
        .with(
            Slot::FecDecoder,
            interceptor::UlpfecReceiveBuilder::sessions().build(),
        )
}

#[cfg(test)]
mod ulpfec_tests {
    use super::*;

    #[test]
    fn configure_ulpfec_fills_both_fec_slots() {
        let registry = configure_ulpfec(Registry::new(), 116, 117);
        let names: Vec<String> = registry.slots().into_iter().map(|(_, name)| name).collect();
        assert_eq!(
            vec![
                "UlpfecSendInterceptor".to_owned(),
                "UlpfecReceiveInterceptor".to_owned()
            ],
            names
        );
    }

    /// RFC 5109 section 13: the ULPFEC interceptors read `onelevelonly` from the negotiated
    /// `ulpfec` format, which is not the stream's own: a stream's information carries the
    /// fmtp of every format of its section, the repair and redundancy formats with them.
    #[test]
    fn a_stream_carries_the_fmtp_of_every_format_of_its_section() {
        let format = |payload_type: PayloadType, mime_type: &str, fmtp: &str| {
            crate::rtp_transceiver::rtp_sender::RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: mime_type.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: fmtp.to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type,
            }
        };
        let section = [
            format(96, "video/VP8", ""),
            format(116, "video/red", "96/117"),
            format(117, "video/ulpfec", "onelevelonly=1"),
        ];
        let info = create_stream_info(
            1,
            None,
            None,
            96,
            None,
            None,
            &section[0].rtp_codec,
            &[],
            &section,
        );
        assert_eq!(
            vec![
                (96, String::new()),
                (116, "96/117".to_owned()),
                (117, "onelevelonly=1".to_owned())
            ],
            info.section_fmtp_lines
        );
    }

    /// A stream bound under the `red` format (a receiver learns it from a RED packet) has the
    /// RTCP feedback negotiated for the format it carries: the `red` format has no
    /// `a=rtcp-fb` lines of its own, and a stream bound without them gets no RFC 8888
    /// reports, no NACK and no key frame requests. The primary format is the one the `red`
    /// fmtp names (RFC 2198 section 5: `a=fmtp:63 111/111`), else the section's first media
    /// format; a media format's own stream is as it was.
    #[test]
    fn a_red_stream_has_the_feedback_of_the_format_it_carries() {
        let feedback = |typ: &str, parameter: &str| {
            crate::rtp_transceiver::rtp_sender::rtcp_parameters::RTCPFeedback {
                typ: typ.to_owned(),
                parameter: parameter.to_owned(),
            }
        };
        let format = |payload_type: PayloadType,
                      mime_type: &str,
                      fmtp: &str,
                      rtcp_feedback: Vec<
            crate::rtp_transceiver::rtp_sender::rtcp_parameters::RTCPFeedback,
        >| {
            crate::rtp_transceiver::rtp_sender::RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: mime_type.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: fmtp.to_owned(),
                    rtcp_feedback,
                },
                payload_type,
            }
        };
        let negotiated = |info: &interceptor::StreamInfo| -> Vec<(String, String)> {
            info.rtcp_feedback
                .iter()
                .map(|f| (f.typ.clone(), f.parameter.clone()))
                .collect()
        };
        let pair = |typ: &str, parameter: &str| (typ.to_owned(), parameter.to_owned());

        let video = [
            format(
                96,
                "video/VP8",
                "",
                vec![feedback("nack", ""), feedback("ack", "ccfb")],
            ),
            format(97, "video/rtx", "apt=96", vec![]),
            format(98, "video/VP9", "", vec![feedback("nack", "pli")]),
            format(116, "video/red", "", vec![]),
            format(117, "video/ulpfec", "", vec![]),
        ];
        let red = create_stream_info(
            1,
            None,
            None,
            116,
            None,
            None,
            &video[3].rtp_codec,
            &[],
            &video,
        );
        assert_eq!(
            vec![pair("nack", ""), pair("ack", "ccfb")],
            negotiated(&red)
        );
        assert_eq!("video/red", red.mime_type);
        // The media format's own stream is unchanged, and a repair format gains nothing.
        let vp9 = create_stream_info(
            1,
            None,
            None,
            98,
            None,
            None,
            &video[2].rtp_codec,
            &[],
            &video,
        );
        assert_eq!(vec![pair("nack", "pli")], negotiated(&vp9));
        let fec = create_stream_info(
            1,
            None,
            None,
            117,
            None,
            None,
            &video[4].rtp_codec,
            &[],
            &video,
        );
        assert!(fec.rtcp_feedback.is_empty());

        // The fmtp names the primary encoding; a line of the red format's own is kept.
        let audio = [
            format(9, "audio/G722", "", vec![feedback("nack", "")]),
            format(111, "audio/opus", "", vec![feedback("transport-cc", "")]),
            format(63, "audio/red", "111/111", vec![feedback("ack", "ccfb")]),
        ];
        let red = create_stream_info(
            2,
            None,
            None,
            63,
            None,
            None,
            &audio[2].rtp_codec,
            &[],
            &audio,
        );
        assert_eq!(
            vec![pair("ack", "ccfb"), pair("transport-cc", "")],
            negotiated(&red)
        );
    }
}

#[cfg(test)]
mod nack_repair_bounds_tests {
    use super::*;

    /// `PacerBacklog::Keep` is "keep and repair everything": the NACK responder is built
    /// without its age bound and without its backlog bound, whatever the two settings say;
    /// with the default (`Flush`) it gets the settings as they are.
    #[test]
    fn pacer_backlog_keep_also_switches_off_the_nack_responders_repair_bounds() {
        let mut options = DefaultInterceptorOptions::for_profile(BehaviourProfile::Rfc);
        assert_eq!(
            (
                Some(interceptor::NACK_MAX_REPAIR_AGE),
                Some(interceptor::NACK_REPAIR_BACKLOG_BOUND)
            ),
            nack_repair_bounds(&options)
        );
        options.nack_max_repair_age = Some(Duration::from_secs(5));
        options.nack_repair_backlog_bound = None;
        assert_eq!(
            (Some(Duration::from_secs(5)), None),
            nack_repair_bounds(&options)
        );
        options.nack_repair_backlog_bound = Some(Duration::from_secs(3));
        options.pacer_backlog = interceptor::PacerBacklog::Keep;
        assert_eq!((None, None), nack_repair_bounds(&options));
    }
}

#[cfg(test)]
mod slot_order_tests {
    use super::*;

    /// Just the positions, for the tests that are about ordering rather than identity.
    fn slots(registry: &Registry) -> Vec<Slot> {
        registry.slots().into_iter().map(|(slot, _)| slot).collect()
    }

    /// The hazard this type exists for: with append-only helpers, TWCC spans NACK and no call
    /// order produces the documented ordering. Here the two orders must be indistinguishable.
    #[test]
    fn helper_call_order_does_not_affect_the_chain() {
        let mut media_engine = MediaEngine::default();

        let nack_first = configure_twcc(
            configure_nack(Registry::new(), &mut media_engine),
            &mut media_engine,
        )
        .expect("twcc");

        let mut media_engine = MediaEngine::default();
        let twcc_first = configure_nack(
            configure_twcc(Registry::new(), &mut media_engine).expect("twcc"),
            &mut media_engine,
        );

        assert_eq!(slots(&nack_first), slots(&twcc_first));
    }

    /// Whatever a registry is asked for, it emits wire-to-application.
    #[test]
    fn the_default_chain_is_emitted_in_slot_order() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let slots = slots(&registry);
        assert!(
            slots.windows(2).all(|pair| pair[0] <= pair[1]),
            "default chain is not wire-to-application: {slots:?}"
        );
        assert_eq!(
            vec![
                Slot::RtcpSession,
                Slot::CongestionControl,
                Slot::Custom(interceptor::NTP_TIMESTAMP_SLOT),
                Slot::Custom(interceptor::ABS_SEND_TIME_SLOT),
                Slot::TwccSender,
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                Slot::CircuitBreaker,
                Slot::Pacer,
                Slot::NackResponder,
                Slot::TwccReceiver,
                Slot::Rfc8888,
                Slot::Custom(interceptor::REMB_GENERATOR_SLOT),
                Slot::ExtendedReports,
                Slot::NackGenerator,
                Slot::KeyFrameRequests,
                Slot::TradeoffNotifications,
            ],
            slots
        );
    }

    /// The three slots congestion control occupies land wire-to-application, whatever order the
    /// helpers ran in. Getting this wrong means the send history records a packet *before* the
    /// TWCC sender has numbered it, and the estimator cannot match feedback to what it sent.
    #[test]
    fn congestion_control_occupies_its_three_slots_in_order() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        // Deliberately after another helper, to show the order does not matter.
        let registry = configure_nack(Registry::new(), &mut media_engine);
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                Slot::CongestionControl,
                Slot::TwccSender,
                // The remote description's send limit, between the estimate and the pacer.
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                Slot::Pacer,
                Slot::NackResponder,
                Slot::TwccReceiver,
                Slot::NackGenerator,
            ],
            slots(&registry)
        );
    }

    /// **D7.** RFC 8888 reports against the RTP sequence number, so it needs no TWCC sender — and
    /// must not get one. Two senders would number every packet twice and the estimator, which
    /// cannot tell the formats apart, would count every packet twice with it.
    #[test]
    fn rfc8888_does_not_also_install_the_twcc_sender() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = configure_congestion_control(
            Registry::new(),
            Gcc::default(),
            CongestionFeedback::Rfc8888,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                Slot::CongestionControl,
                Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                Slot::Pacer,
                Slot::Rfc8888
            ],
            slots(&registry),
            "RFC 8888 needs no transport-wide sequence numbers"
        );
    }

    /// RFC 8834 section 7: a WebRTC endpoint adapts its RTP traffic to the path and implements
    /// the RTP circuit breaker (section 7.1), so the standard set carries an estimator, the
    /// pacer that enforces its target, and the breaker.
    #[test]
    fn the_default_chain_has_congestion_control_and_a_circuit_breaker() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let named: Vec<(Slot, String)> = registry.slots();
        for (slot, name) in [
            (Slot::CongestionControl, "CongestionControlInterceptor<Gcc>"),
            (Slot::TwccSender, "TwccSenderInterceptor"),
            (Slot::CircuitBreaker, "CircuitBreakerInterceptor"),
            (Slot::Pacer, "PacerInterceptor"),
        ] {
            assert!(
                named.contains(&(slot, name.to_owned())),
                "{name} is missing from the default chain: {named:?}"
            );
        }
    }

    /// The opt-out is explicit, and is the set without the four congestion-control slots.
    #[test]
    fn the_opt_out_chain_has_no_congestion_control() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors_without_congestion_control(
            Registry::new(),
            &mut media_engine,
        )
        .expect("interceptors");

        assert_eq!(
            vec![
                Slot::RtcpSession,
                Slot::NackResponder,
                Slot::TwccReceiver,
                Slot::Rfc8888,
                Slot::ExtendedReports,
                Slot::NackGenerator,
                Slot::KeyFrameRequests,
                Slot::TradeoffNotifications,
            ],
            slots(&registry)
        );
    }

    /// A bare number puts an interceptor between two named slots — the reason they are spaced.
    #[test]
    fn a_custom_interceptor_fits_between_named_slots() {
        let mut media_engine = MediaEngine::default();
        let registry = configure_twcc(Registry::new(), &mut media_engine)
            .expect("twcc")
            .with(Slot::from(2_500), interceptor::NoopInterceptor::new());

        assert_eq!(
            vec![Slot::TwccSender, Slot::from(2_500), Slot::TwccReceiver],
            slots(&registry)
        );
    }

    /// A slot holds one interceptor, so a helper cannot quietly end up with two of anything by
    /// being called twice — the position is the identity.
    #[test]
    fn a_slot_holds_one_interceptor() {
        let registry = Registry::new()
            .with(Slot::Pacer, interceptor::NoopInterceptor::new())
            .with(Slot::Pacer, interceptor::NoopInterceptor::new());

        assert_eq!(vec![Slot::Pacer], slots(&registry));
    }

    /// What the default chain is actually made of, by name. The ordering tests above prove the
    /// positions are right; this proves the right interceptors are in them — a chain assembled from
    /// several helpers has no other single view of what it ended up containing.
    #[test]
    fn the_default_chain_names_what_it_registered() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        assert_eq!(
            vec![
                (Slot::RtcpSession, "RtcpSessionInterceptor".to_owned()),
                (
                    Slot::CongestionControl,
                    "CongestionControlInterceptor<Gcc>".to_owned()
                ),
                (
                    Slot::Custom(interceptor::NTP_TIMESTAMP_SLOT),
                    "NtpTimestampInterceptor".to_owned()
                ),
                (
                    Slot::Custom(interceptor::ABS_SEND_TIME_SLOT),
                    "AbsSendTimeInterceptor".to_owned()
                ),
                (Slot::TwccSender, "TwccSenderInterceptor".to_owned()),
                (
                    Slot::Custom(REMOTE_BITRATE_LIMIT_SLOT),
                    "RemoteBitrateLimitInterceptor".to_owned()
                ),
                (Slot::CircuitBreaker, "CircuitBreakerInterceptor".to_owned()),
                (Slot::Pacer, "PacerInterceptor".to_owned()),
                (Slot::NackResponder, "NackResponderInterceptor".to_owned()),
                (Slot::TwccReceiver, "TwccReceiverInterceptor".to_owned()),
                (Slot::Rfc8888, "Rfc8888Interceptor".to_owned()),
                (
                    Slot::Custom(interceptor::REMB_GENERATOR_SLOT),
                    "RembGeneratorInterceptor".to_owned()
                ),
                (Slot::ExtendedReports, "XrReportInterceptor".to_owned()),
                (Slot::NackGenerator, "NackGeneratorInterceptor".to_owned()),
                (
                    Slot::KeyFrameRequests,
                    "KeyFrameRequestInterceptor".to_owned()
                ),
                (
                    Slot::TradeoffNotifications,
                    "TstnResponderInterceptor".to_owned()
                ),
            ],
            registry.slots()
        );
    }

    /// The recorder this helper places and the one `register_default_interceptors` places share a
    /// slot, so a chain that asks for both carries one of them, not two. Two arrival recorders
    /// would report every packet to the remote twice, and its estimator cannot tell the reports
    /// apart — it would read the path as carrying double what it does.
    #[test]
    fn the_twcc_recorder_is_not_registered_twice() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut media_engine,
        )
        .expect("congestion control");

        let recorders = registry
            .slots()
            .into_iter()
            .filter(|(slot, _)| *slot == Slot::TwccReceiver)
            .count();
        assert_eq!(
            1, recorders,
            "one arrival recorder, however many helpers asked for one"
        );
    }

    /// RFC 8888 section 6: an offer may name RFC 8888 beside another congestion control
    /// feedback mechanism, so the standard set offers `ack ccfb` and `transport-cc` on every
    /// codec and carries a recorder for each. Which one reports a stream is decided per stream
    /// (`a_stream_is_reported_in_one_feedback_format` in `rtci-interceptor`).
    #[test]
    fn the_default_set_offers_rfc8888_beside_transport_cc() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let recorders: Vec<Slot> = slots(&registry)
            .into_iter()
            .filter(|slot| *slot == Slot::TwccReceiver || *slot == Slot::Rfc8888)
            .collect();
        assert_eq!(vec![Slot::TwccReceiver, Slot::Rfc8888], recorders);

        for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
            for codec in media_engine.get_codecs_by_kind(kind) {
                let has = |typ: &str, parameter: &str| {
                    codec
                        .rtp_codec
                        .rtcp_feedback
                        .iter()
                        .any(|f| f.typ == typ && f.parameter == parameter)
                };
                assert!(has("ack", "ccfb"), "{}", codec.rtp_codec.mime_type);
                assert!(has("transport-cc", ""), "{}", codec.rtp_codec.mime_type);
                assert!(has("ccm", "tmmbr"), "{}", codec.rtp_codec.mime_type);
            }
        }
    }

    /// The browser setting: transport-wide congestion control only, with no trace of RFC 8888.
    #[test]
    fn the_twcc_only_setting_neither_offers_nor_records_rfc8888() {
        let mut media_engine = MediaEngine::default();
        let options = DefaultInterceptorOptions {
            congestion_feedback: CongestionFeedback::Twcc,
            ..Default::default()
        };
        let (registry, _handles) = register_default_interceptors_with_options(
            Registry::new(),
            &mut media_engine,
            &options,
        )
        .expect("default interceptors");

        assert!(!slots(&registry).contains(&Slot::Rfc8888));
        assert!(slots(&registry).contains(&Slot::TwccReceiver));
        for codec in media_engine.get_codecs_by_kind(RtpCodecKind::Video) {
            assert!(
                !codec
                    .rtp_codec
                    .rtcp_feedback
                    .iter()
                    .any(|f| f.typ == "ack" && f.parameter == "ccfb")
            );
        }
    }

    /// RFC 8888 asked for over the default set: the default already carries both recorders, a
    /// slot holds one interceptor, and so there are two recorders, one per format, and none
    /// twice. Upstream asserted the same two slots as a hazard (every packet reported twice);
    /// here each stream is reported by one of them
    /// (`a_stream_is_reported_in_one_feedback_format`).
    #[test]
    fn rfc8888_alongside_the_defaults_leaves_two_recorders() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Rfc8888,
            &mut media_engine,
        )
        .expect("congestion control");

        let recorders: Vec<Slot> = slots(&registry)
            .into_iter()
            .filter(|slot| *slot == Slot::TwccReceiver || *slot == Slot::Rfc8888)
            .collect();
        assert_eq!(vec![Slot::TwccReceiver, Slot::Rfc8888], recorders);
    }
}
