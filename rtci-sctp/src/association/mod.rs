use crate::association::{
    state::{AckMode, AckState, AssociationState},
    stats::AssociationStats,
};
use crate::chunk::chunk_header::CHUNK_HEADER_SIZE;
use crate::chunk::{
    COOKIE_RECEIVED_WHILE_SHUTTING_DOWN, Chunk, ErrorCause, INVALID_MANDATORY_PARAMETER,
    INVALID_STREAM_IDENTIFIER, MISSING_MANDATORY_PARAMETER, NO_USER_DATA, PROTOCOL_VIOLATION,
    STALE_COOKIE_ERROR, UNRECOGNIZED_CHUNK_TYPE, UNRECOGNIZED_PARAMETERS, UNRESOLVABLE_ADDRESS,
    USER_INITIATED_ABORT,
    chunk_abort::ChunkAbort,
    chunk_cookie_ack::ChunkCookieAck,
    chunk_cookie_echo::ChunkCookieEcho,
    chunk_error::ChunkError,
    chunk_forward_tsn::ChunkForwardTsn,
    chunk_forward_tsn::ChunkForwardTsnStream,
    chunk_heartbeat::ChunkHeartbeat,
    chunk_heartbeat_ack::ChunkHeartbeatAck,
    chunk_i_forward_tsn::ChunkIForwardTsn,
    chunk_init::ChunkInit,
    chunk_init::ChunkInitAck,
    chunk_padding::ChunkPadding,
    chunk_payload_data::ChunkPayloadData,
    chunk_payload_data::{MessageId, MessageReliability, PayloadProtocolIdentifier},
    chunk_reconfig::ChunkReconfig,
    chunk_selective_ack::{ChunkSelectiveAck, SELECTIVE_ACK_HEADER_SIZE},
    chunk_shutdown::ChunkShutdown,
    chunk_shutdown_ack::ChunkShutdownAck,
    chunk_shutdown_complete::ChunkShutdownComplete,
    chunk_type::{CT_FORWARD_TSN, CT_I_DATA, CT_I_FORWARD_TSN, CT_RECONFIG},
    chunk_unknown::ChunkUnknown,
};
use crate::config::{COMMON_HEADER_SIZE, DATA_CHUNK_HEADER_SIZE, ServerConfig, TransportConfig};
use crate::cookie::{CookieFields, CookieSigner};
use crate::packet::{CommonHeader, Packet};
use crate::param::{
    Param, UNRECOGNIZED_PARAMETER,
    param_forward_tsn_supported::ParamForwardTsnSupported,
    param_heartbeat_info::ParamHeartbeatInfo,
    param_outgoing_reset_request::ParamOutgoingResetRequest,
    param_reconfig_response::{ParamReconfigResponse, ReconfigResult},
    param_state_cookie::ParamStateCookie,
    param_supported_extensions::ParamSupportedExtensions,
    param_uknown::ParamUnknown,
    param_zero_checksum_acceptable::{EDMID_SCTP_OVER_DTLS, ParamZeroChecksumAcceptable},
};
use crate::queue::{
    payload_queue::{PayloadQueue, counted_wire_size},
    pending_queue::{PendingQueue, ResetMarker},
};
use crate::shared::{AssociationEventInner, AssociationId, EndpointEvent, EndpointEventInner};
use crate::util::{
    RandomSource, constant_time_eq, get_padding_size, sna16lt, sna32gt, sna32gte, sna32lt, sna32lte,
};
use crate::{AssociationEvent, Payload, Side};
use shared::error::{Error, Result};
use shared::{TransportContext, TransportMessage, TransportProtocol};
use stream::{Stream, StreamEvent, StreamId, StreamState};
use timer::{ACK_INTERVAL, RtoManager, Timer, TimerTable};

use crate::association::stream::RecvSendState;
use bytes::{Bytes, BytesMut};
use log::{debug, error, trace, warn};
pub use reconfig::ReconfigEvent;
use reconfig::{IncomingResetWaiting, OwnRequest};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use thiserror::Error;

pub(crate) mod bundling;
pub(crate) mod interleaving;
pub(crate) mod pmtud;
use pmtud::PathMtuState;
pub(crate) mod reconfig;
pub(crate) mod state;
pub(crate) mod stats;
pub(crate) mod stream;
pub(crate) mod timer;
pub(crate) mod undelivered;
use undelivered::{UndeliveredMessage, UndeliveredMode};

#[cfg(test)]
mod association_test;
#[cfg(any(fuzzing, feature = "bench"))]
pub(crate) mod recovery_bench;

/// Incoming stream reset requests held at once while they wait for the peer's TSN or for the
/// application to drain a stream. RFC 6525 has a peer keep one request in flight; a request
/// beyond this many is answered Denied and not stored.
pub(crate) const MAX_PENDING_RECONFIG_REQUESTS: usize = 64;

/// Sequence numbers of incoming reset requests already performed, remembered so a
/// retransmission is answered again without being performed a second time.
pub(crate) const MAX_COMPLETED_RECONFIG_REQUESTS: usize = 64;

/// Re-configuration requests of this side's own that may wait for the one in flight to be
/// answered (RFC 6525 5.1.1 has one in flight). Past it a peer's reset is still performed and
/// answered, but this side's own direction is not reset in turn, and the application's
/// requests are refused.
pub(crate) const MAX_OUTSTANDING_RECONFIGS: usize = 64;

/// How long an accepting association waits for the COOKIE ECHO after an INIT before it gives
/// itself up, in milliseconds. A peer that is still trying sends something within RTO.Max
/// (60 s): another INIT if the INIT ACK was lost, or the COOKIE ECHO. Twice that leaves room
/// for the last retransmission to arrive.
pub(crate) const HALF_OPEN_LIFETIME: u64 = 120_000;

/// The most TSNs kept outstanding, from the Cumulative TSN Ack Point to the next TSN to assign.
///
/// RFC 9260 6.1: fewer ordered messages of a stream may be outstanding than the Stream
/// Sequence Number space holds, or the receiver cannot order them (it compares 16-bit serial
/// numbers, which works within half the space). Every message takes at least one TSN, so
/// bounding the TSNs bounds the messages of every stream. It also keeps the receiver's Gap Ack
/// Blocks within their 16-bit offsets.
pub(crate) const MAX_OUTSTANDING_TSNS: u32 = 0x7fff;

/// The Host Name Address parameter (RFC 9260 3.3.2.1.4), deprecated: an INIT or INIT ACK that
/// carries one is answered with an ABORT.
const PARAM_HOST_NAME_ADDRESS: u16 = 11;

/// The State Cookie parameter, for the "Missing Mandatory Parameter" cause.
const PARAM_STATE_COOKIE: u16 = 7;

/// Path.Max.Retrans (RFC 9260 16): the consecutive failures (T3-rtx expiries, HEARTBEATs
/// without an answer) after which the path to the peer is reported inactive.
pub(crate) const PATH_MAX_RETRANS: usize = 5;

/// T5-shutdown-guard (RFC 9260 9.2, 16): five times RTO.Max, in milliseconds.
pub(crate) const T5_SHUTDOWN_GUARD: u64 = 5 * 60_000;

/// What an accepted INIT said about its sender, kept with the State Cookie sent in answer
/// and taken into the TCB when that cookie comes back (RFC 9260 5.1.3: "the State Cookie
/// carries the information needed to create the association"; here the association holds
/// it, see the note on [`Association::handle_cookie_echo`]).
#[derive(Debug, Clone)]
struct CookieTcb {
    created_at: Instant,
    peer_verification_tag: u32,
    peer_initial_tsn: u32,
    peer_rwnd: u32,
    inbound_streams: u16,
    outbound_streams: u16,
    use_forward_tsn: bool,
    /// User message interleaving is used: both sides listed I-DATA (RFC 8260 2.2.1).
    use_interleaving: bool,
    /// The INIT listed the RE-CONFIG chunk among its supported extensions (RFC 6525 5.1.1).
    reconfig: bool,
    /// The peer takes a zero checksum over DTLS and this side may send one (RFC 9653 5.2).
    send_zero_checksum: bool,
    /// This side's port and the peer's, as the INIT's packet had them.
    source_port: u16,
    destination_port: u16,
}

/// The optional parameters of an INIT or INIT ACK, as far as the engine reads them.
#[derive(Default)]
struct HandshakeParams {
    cookie: Option<Bytes>,
    /// Unrecognized parameters the sender asked to hear about, each as it arrived.
    unrecognized: Vec<Bytes>,
    /// A Host Name Address parameter, as it arrived.
    host_name: Option<Bytes>,
    forward_tsn: bool,
    /// The peer reported this side's Forward-TSN-Supported parameter as unrecognized.
    forward_tsn_rejected: bool,
    /// The Supported Extensions parameter lists the RE-CONFIG chunk (RFC 6525 5.1.1).
    reconfig: bool,
    /// The Supported Extensions parameter lists the I-DATA chunk (RFC 8260 2.2.1).
    i_data: bool,
    /// The Supported Extensions parameter lists the I-FORWARD-TSN chunk (RFC 8260 2.3.1).
    i_forward_tsn: bool,
    /// The Error Detection Method Identifier of a Zero Checksum Acceptable parameter (RFC
    /// 9653 4), the first one if the peer sent several.
    zero_checksum_edmid: Option<u32>,
}

/// The Forward-TSN-Supported parameter (RFC 3758 3.1).
const PARAM_FORWARD_TSN_SUPPORTED: u16 = 49152;

/// Whether `raw`, the value of an Unrecognized Parameter parameter or of an "Unrecognized
/// Parameters" error cause, names the Forward-TSN-Supported parameter.
fn names_forward_tsn_supported(mut raw: &[u8]) -> bool {
    while raw.len() >= 4 {
        if u16::from_be_bytes([raw[0], raw[1]]) == PARAM_FORWARD_TSN_SUPPORTED {
            return true;
        }
        let length = usize::from(u16::from_be_bytes([raw[2], raw[3]])).max(4);
        let padded = length.next_multiple_of(4);
        if padded > raw.len() {
            break;
        }
        raw = &raw[padded..];
    }
    false
}

/// Error causes reported for one received packet, at most.
const MAX_ERROR_CAUSES_PER_PACKET: usize = 16;

/// Parameter types the engine has no parser for but RFC 9260 defines for INIT / INIT ACK:
/// IPv4 Address, IPv6 Address, Unrecognized Parameter, Cookie Preservative, Supported Address
/// Types. Accepted and ignored: an association over DTLS has one path (RFC 8261), and a
/// longer cookie lifetime is the receiver's to grant or not (RFC 9260 5.2.6).
const IGNORED_HANDSHAKE_PARAMS: [u16; 5] = [5, 6, 8, 9, 12];

/// Reasons why an association might be lost
#[derive(Debug, Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum AssociationError {
    /// Handshake failed
    #[error("handshake failed due to {0}")]
    HandshakeFailed(String),
    /// The peer violated the QUIC specification as understood by this implementation
    #[error("transport error")]
    TransportError,
    /// The peer's QUIC stack aborted the association automatically
    #[error("aborted by peer")]
    AssociationClosed,
    /// The peer closed the association
    #[error("closed by peer")]
    ApplicationClosed,
    /// The peer is unable to continue processing this association, usually due to having restarted
    #[error("reset by peer")]
    Reset,
    /// Communication with the peer has lapsed for longer than the negotiated idle timeout
    ///
    /// If neither side is sending keep-alives, an association will time out after a long enough idle
    /// period even if the peer is still reachable
    #[error("timed out")]
    TimedOut,
    /// The local application closed the association
    #[error("closed")]
    LocallyClosed,
}

/// Events of interest to the application
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// Handshake was failed
    HandshakeFailed {
        /// Reason that the association was closed
        reason: AssociationError,
    },

    /// The association was successfully established
    Connected,
    /// The peer restarted the association (RFC 9260 5.2.4 action A): it sent an INIT and
    /// then a COOKIE ECHO with the Tie-Tags of this association, as an endpoint that lost
    /// its state does. The association is a new one from here on, with new tags and TSNs,
    /// no streams and congestion control from its initial values; what was queued or in
    /// flight on the old one is gone. Reported instead of [`Event::AssociationLost`] (5.2.4:
    /// "a RESTART notification").
    Restarted,
    /// The association was lost
    ///
    /// Emitted if the peer closes the association or an error is encountered.
    AssociationLost {
        /// Reason that the association was closed
        reason: AssociationError,
        /// The stream the loss was reported against.
        id: StreamId,
    },
    /// The association closed, after an `AssociationLost` for each of its streams. Emitted
    /// whether or not it had streams, so an application that keeps state beside the
    /// association (a pre-negotiated data channel that never carried data) learns of it.
    AssociationClosed {
        /// Reason that the association was closed
        reason: AssociationError,
    },
    /// The path to the peer is inactive: Path.Max.Retrans consecutive retransmissions or
    /// HEARTBEATs went unanswered (RFC 9260 sections 8.2, 8.3). The association goes on
    /// trying, up to [`TimerConfig::max_t3_rtx_retrans`](crate::TimerConfig).
    PathInactive,
    /// The path to the peer answers again after [`Event::PathInactive`].
    PathActive,
    /// The peer sent an ERROR chunk (RFC 9260 11.2.5 COMMUNICATION ERROR): each cause's code
    /// and its cause-specific information as received (RFC 9260 3.3.10).
    CommunicationError {
        /// The causes, in the order the chunk carried them.
        causes: Vec<(crate::ErrorCauseCode, Bytes)>,
    },
    /// The association ended with user messages it did not deliver (RFC 9260 11.2.2 SEND
    /// FAILURE, 8.1): read them with
    /// [`Association::take_undelivered_messages`]. Reported before
    /// [`Event::AssociationClosed`]. A message of a partially reliable stream given up while
    /// the association ran is reported with
    /// [`StreamEvent::MessageAbandoned`](crate::StreamEvent::MessageAbandoned) instead.
    SendFailure {
        /// Messages no part of which was sent.
        unsent: usize,
        /// Messages sent, at least in part, and not completely acknowledged.
        unacknowledged: usize,
    },
    /// Stream events
    Stream(StreamEvent),
    /// One or more application datagrams have been received
    DatagramReceived,
    /// The outcome of a stream re-configuration (RFC 6525): a request of this side's own was
    /// answered, or the peer changed the association.
    Reconfig(ReconfigEvent),
}

/// What [`Association::status`] reports (RFC 9260 11.1.8).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AssociationStatus {
    /// The association ended.
    pub closed: bool,
    /// The peer's receive window ("current receiver window size"), in bytes.
    pub peer_receive_window: u32,
    /// The congestion window, in bytes.
    pub congestion_window: u32,
    /// The slow start threshold, in bytes.
    pub slow_start_threshold: u32,
    /// DATA chunks sent and not cumulatively acknowledged ("number of unacknowledged DATA
    /// chunks").
    pub unacknowledged_data_chunks: usize,
    /// DATA chunks waiting to be sent for the first time.
    pub pending_data_chunks: usize,
    /// The smoothed round-trip time; zero before the first measurement.
    pub srtt: Duration,
    /// The retransmission timeout.
    pub rto: Duration,
    /// The path MTU the association packs to.
    pub path_mtu: u32,
}

/// How many T3-rtx retransmitted TSNs are remembered for SACK loss detection (RFC 9260 6.2).
const MAX_T3_RETRANSMITTED_KEPT: usize = 512;

/// Selection is stable even after fragments leave either queue.
#[derive(Debug, Copy, Clone)]
struct MessageToAbandon {
    id: MessageId,
    // TSN of an inflight candidate; None when selected from pending.
    // This permits a direct lookup for whole messages. Fragmented messages
    // and pending selections use the index keyed by `id`.
    sent_tsn: Option<u32>,
}

///Association represents an SCTP association
//13.2.  Parameters Necessary per Association (i.e., the TCB)
//Peer : Tag value to be sent in every packet and is received
//Verification: in the INIT or INIT ACK chunk.
//Tag :
//
//My : Tag expected in every inbound packet and sent in the
//Verification: INIT or INIT ACK chunk.
//
//Tag :
//State : A state variable indicating what state the association
// : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
// : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
// : SHUTDOWN-ACK-SENT.
//
// No Closed state is illustrated since if a
// association is Closed its TCB SHOULD be removed.
pub struct Association {
    side: Side,
    state: AssociationState,
    handshake_completed: bool,
    /// This side entered ESTABLISHED on the peer's COOKIE ECHO and nothing from the peer has
    /// shown since that its COOKIE ACK arrived: the peer may still be in COOKIE-ECHOED,
    /// discarding DATA (RFC 9260 5.1).
    peer_awaits_cookie_ack: bool,
    max_message_size: u32,
    /// The largest message accepted from the peer: what this side advertised (RFC 8841 6.1).
    max_receive_message_size: u32,
    /// See [`TransportConfig::with_zero_window_overcommit`].
    zero_window_overcommit: bool,
    /// See [`TransportConfig::with_handshake_timers_back_off_rto`].
    handshake_timers_back_off_rto: bool,
    /// The partial delivery point (RFC 6458 8.1.21): see
    /// [`TransportConfig::with_partial_delivery_point`].
    partial_delivery_point: u32,
    will_send_shutdown: bool,
    bytes_received: usize,
    bytes_sent: usize,

    pub(crate) peer_verification_tag: u32,
    my_verification_tag: u32,
    pub(crate) my_next_tsn: u32,
    peer_last_tsn: u32,
    // for RTT measurement
    min_tsn2measure_rtt: u32,
    will_send_forward_tsn: bool,
    will_retransmit_fast: bool,
    will_retransmit_reconfig: bool,
    /// The peer answered a request "In progress": the reconfiguration timer starts over,
    /// and the wait is not counted against the request (RFC 6525 5.2.7).
    restart_reconfig_timer: bool,
    /// True only while the in-flight queue may still hold chunks flagged for
    /// T3-rtx retransmission (set when the timer marks them, cleared once the
    /// scan has re-sent them all). Lets `gather_outbound` skip the O(in-flight)
    /// retransmit scan entirely in the steady state, where nothing is ever
    /// marked — that scan was the single hottest function in the send profile.
    t3_retransmit_pending: bool,

    will_send_shutdown_ack: bool,
    will_send_shutdown_complete: bool,

    // Reconfig
    pub(crate) my_next_rsn: u32,
    /// The request in flight, by its sequence number, as the chunk that is retransmitted.
    /// RFC 6525 5.1.1: there is at most one.
    reconfigs: HashMap<u32, ChunkReconfig>,
    /// What the request in flight asks for.
    reconfig_in_flight: Option<OwnRequest>,
    /// The peer answered the request in flight "In progress": the next expiry of its timer
    /// is not counted as an error (RFC 6525 5.2.7 H2).
    reconfig_in_progress: bool,
    /// Requests waiting for the one in flight to be answered.
    reconfig_queue: VecDeque<OwnRequest>,
    /// The peer's Outgoing SSN Reset Requests not performed yet: its TSN is not reached, or
    /// the application has not read what the streams hold.
    reconfig_requests: HashMap<u32, ParamOutgoingResetRequest>,
    /// The peer's requests answered for good, each with the chunk it was answered with: a
    /// retransmission gets the same chunk again (RFC 6525 5.2.1).
    completed_reconfig_requests: VecDeque<(u32, ChunkReconfig)>,
    /// The request sequence numbers accepted from the peer: the lowest still acceptable and
    /// the next one expected. `None` until the peer's initial TSN is known.
    peer_rsn_window: Option<(u32, u32)>,
    /// The peer listed the RE-CONFIG chunk in its Supported Extensions (RFC 6525 5.1.1).
    peer_supports_reconfig: bool,
    /// The peer's Incoming SSN Reset Requests being answered: the Outgoing SSN Reset Request
    /// that answers one goes out when the data queued on its streams has been sent.
    incoming_resets_waiting: HashMap<u32, IncomingResetWaiting>,
    /// DATA held back while a reset of its stream is deferred, or while this side's SSN/TSN
    /// reset is in flight: it belongs to the stream as it is after the reset (RFC 6525 5.2.2
    /// E2). Its bytes count against the receive window.
    held_reset_data: Vec<ChunkPayloadData>,
    /// DATA fragments dropped because they could never be part of a complete message
    /// (`ReassemblyQueue::discard_orphans`).
    pub(crate) orphans_dropped: usize,
    /// The TSN of the last of them, so a run of them is reported once.
    last_orphan_tsn: Option<u32>,
    /// This side asked for an SSN/TSN reset that is not answered yet: no new DATA is sent
    /// (RFC 6525 5.1.4 C2).
    tsn_reset_requested: bool,
    /// The peer's SSN/TSN Reset Request, answered "In progress" until what this side has
    /// outstanding is acknowledged.
    deferred_tsn_reset: Option<u32>,
    /// When this side last sent an SSN/TSN Reset Request (RFC 6525 5.1.4: one per 30 s).
    last_tsn_reset_request: Option<Instant>,
    /// Messages written to streams whose outgoing reset is not answered yet, across all
    /// streams: they are still to be sent.
    held_write_count: usize,

    // Non-RFC internal data
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    transport_protocol: TransportProtocol,

    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    my_max_num_inbound_streams: u16,
    my_max_num_outbound_streams: u16,
    /// The stream counts this side is configured to offer, before a peer's INIT or INIT ACK
    /// narrowed them.
    configured_inbound_streams: u16,
    configured_outbound_streams: u16,
    my_cookie: Option<ParamStateCookie>,
    /// What the INIT answered with `my_cookie` said, applied when the cookie is echoed.
    cookie_tcb: Option<CookieTcb>,
    /// Makes this association's State Cookies with a MAC (RFC 9260 5.1.3), when the endpoint
    /// was given a crypto provider for it. Without one a cookie is random bytes, good only
    /// because this association remembers them.
    cookie_signer: Option<Arc<CookieSigner>>,
    /// The Tie-Tags (RFC 9260 5.2.1, 5.2.2): random, drawn the first time an INIT is
    /// answered while the association exists, and kept for its life; 0 until then.
    local_tie_tag: u32,
    peer_tie_tag: u32,
    /// Without a cookie signer: the State Cookie of the INIT ACK that answered an
    /// unexpected INIT, what it stands for, and when it was made. Its COOKIE ECHO restarts
    /// the association (5.2.4 action A).
    restart_cookie: Option<(Bytes, CookieFields, Instant)>,
    /// The configuration the association was made with, for a restart.
    transport_config: Option<Arc<TransportConfig>>,
    /// Where the random values come from: the initial TSN, an unauthenticated State Cookie,
    /// the Initiate Tag of an INIT ACK for an existing association, HEARTBEAT nonces and
    /// jitter (`EndpointConfig::random_source`).
    random: RandomSource,
    /// Valid.Cookie.Life (RFC 9260 16): how long a State Cookie is accepted after it was made.
    valid_cookie_life: Duration,
    /// How many times a Stale Cookie error sent this side back to a new INIT.
    stale_cookie_restarts: usize,
    /// The TSNs most recently sent again on a retransmission timeout (at most
    /// `MAX_T3_RETRANSMITTED_KEPT`): one the peer then reports as a duplicate shows a lost
    /// SACK (RFC 9260 6.2).
    t3_retransmitted: VecDeque<u32>,
    /// When the last COOKIE ECHO was sent: the start of the COOKIE ECHO / ERROR exchange a
    /// Cookie Preservative is sized from (RFC 9260 5.2.6).
    cookie_echo_sent_at: Option<Instant>,
    /// The TSN and wire size of DATA chunks acknowledged lately, for the bytes of the
    /// duplicates a SACK reports (RFC 9260 7.2.2). Each counts once.
    recently_acknowledged: VecDeque<(u32, u32)>,
    /// The first DATA chunk of an association is acknowledged at once (RFC 9260 5.1).
    first_data_received: bool,
    /// Set while a packet is processed whose DATA must be acknowledged at once: it came with
    /// the COOKIE ECHO (RFC 9260 5.1.5), or in SHUTDOWN-SENT (9.2).
    sack_packet_immediately: bool,
    /// Set by a chunk handler: the chunks after it in the packet are discarded.
    discard_rest_of_packet: bool,
    /// The SACK that is due and found no control packet to travel with: it goes with
    /// outbound DATA, or alone.
    unbundled_sack: Option<ChunkSelectiveAck>,
    /// Where the packets of DATA begin among the packets being gathered.
    first_data_packet: usize,

    /// HB.interval (RFC 9260 8.3, 16); `None` sends no HEARTBEAT.
    heartbeat_interval: Option<Duration>,
    /// The HEARTBEAT sent and not yet acknowledged: its nonce and when it left.
    heartbeat_outstanding: Option<(u64, Instant)>,
    /// When a chunk that can measure the round trip last left: a DATA chunk sent for the
    /// first time, or a HEARTBEAT. The path is idle from then on.
    last_rtt_probe: Option<Instant>,
    /// Consecutive failures on the path to the peer, for `Event::PathInactive`.
    path_error_count: usize,
    path_inactive: bool,
    /// When the association was made: the zero of the time a HEARTBEAT carries.
    created_at: Option<Instant>,
    /// Path MTU discovery (RFC 8899), when configured.
    pmtud: Option<pmtud::PathMtuDiscovery>,

    pub(crate) payload_queue: PayloadQueue,
    pub(crate) inflight_queue: PayloadQueue,
    pub(crate) pending_queue: PendingQueue,
    control_queue: VecDeque<Packet>,
    stream_queue: VecDeque<u16>,

    pub(crate) mtu: u32,
    // max DATA chunk payload size
    max_payload_size: u32,
    cumulative_tsn_ack_point: u32,
    pub(crate) advanced_peer_tsn_ack_point: u32,
    use_forward_tsn: bool,
    /// PR-SCTP is announced and used at all (`TransportConfig::with_partial_reliability`).
    partial_reliability_enabled: bool,
    /// User message interleaving is announced (`TransportConfig::with_message_interleaving`).
    interleaving_enabled: bool,
    /// "Zero Checksum Acceptable" is announced, for SCTP over DTLS, and packets with a zero
    /// checksum are taken (`TransportConfig::with_zero_checksum`; RFC 9653 5.1, 5.3).
    zero_checksum_enabled: bool,
    /// The peer announced that it takes a zero checksum over DTLS, and this side may send
    /// one: the CRC32c of what is sent is not computed (RFC 9653 5.2).
    send_zero_checksum: bool,
    /// User message interleaving is in use: both sides announced it (RFC 8260 2.2.1). DATA
    /// and FORWARD TSN are then replaced by I-DATA and I-FORWARD-TSN.
    use_interleaving: bool,
    /// As `fwd_tsn_stream_map`, for I-FORWARD-TSN: the greatest Message Identifier among the
    /// abandoned chunks of each stream, for its ordered (`false`) and its unordered (`true`)
    /// messages (RFC 8260 2.3.1).
    i_fwd_tsn_stream_map: FxHashMap<(u16, bool), u32>,
    /// Max stream-sequence-number per *ordered* stream among abandoned chunks
    /// currently in the forward-TSN window `(cumulative_tsn_ack_point,
    /// advanced_peer_tsn_ack_point]`. Maintained incrementally as chunks are
    /// abandoned (the two RFC 3758 C2 loops) so that `create_forward_tsn` is
    /// O(streams) instead of rescanning the whole in-flight window — which, for
    /// PR-SCTP data channels, ran ~1000 hashmap probes per FORWARD-TSN and was
    /// ~9% of send CPU in profiles. Unordered chunks are omitted: the receiver
    /// ignores the per-stream list for them (it advances by `new_cumulative_tsn`
    /// alone), so reporting them was pure waste.
    fwd_tsn_stream_map: FxHashMap<u16, u16>,

    pub(crate) rto_mgr: RtoManager,
    timers: TimerTable,

    // Congestion control parameters
    max_receive_buffer_size: u32,
    // my congestion window size
    pub(crate) cwnd: u32,
    // calculated peer's receiver windows size
    rwnd: u32,
    // slow start threshold
    pub(crate) ssthresh: u32,
    partial_bytes_acked: u32,
    pub(crate) in_fast_recovery: bool,
    fast_recover_exit_point: u32,
    /// The Path Maximum DATA Chunk Size (RFC 9260 2.2): the largest DATA chunk, header
    /// included, that fits a packet. The unit of the congestion window rules.
    pub(crate) pmdcs: u32,
    /// L of RFC 9260 7.2.1: in slow start one SACK grows cwnd by at most L x PMDCS.
    slow_start_growth_limit: u32,
    /// Max.Burst (RFC 9260 6.1 D), when applied.
    pub(crate) max_burst: Option<u32>,
    /// When DATA was last sent, for the decay of an idle congestion window (7.2.1).
    last_data_sent: Option<Instant>,
    /// Set by a T3-rtx expiry: the retransmission that follows is one packet (6.3.3 E3).
    t3_single_packet: bool,
    /// The TSNs marked for Fast Retransmit (their third miss indication) since the last
    /// Fast Retransmit packet. What of them does not fit that packet waits for cwnd.
    fast_retransmit_marked: Vec<u32>,
    /// RFC 9260 6.1 A: when the peer's SACK closed its window (a_rwnd 0), the first zero
    /// window probe waits one RTO from then.
    zero_window_probe_at: Option<Instant>,
    /// The TSN of the zero window probe outstanding (RFC 9260 6.1 A): new DATA sent with
    /// nothing in flight although rwnd did not have room for it. A SACK that acknowledges it
    /// shows the receiver taking DATA through its closed window (the chunk that completes a
    /// message its full buffer holds the start of), which is progress: the next probe goes
    /// at once instead of one RTO later.
    zero_window_probe_tsn: Option<u32>,
    /// The TSNs the last SACK showed the peer reneged on: they got their one miss indication
    /// there (RFC 9260 6.2.1 D iii), not another from the same SACK's Fast Retransmit count.
    reneged_in_last_sack: Vec<u32>,
    /// A SHUTDOWN's Cumulative TSN Ack is being taken as a SACK without Gap Ack Blocks.
    acknowledging_by_shutdown: bool,
    /// The a_rwnd of the last SACK sent (of the INIT or INIT ACK before any).
    last_advertised_window: u32,
    /// User data taken since the last SACK: the sender counts it against
    /// `last_advertised_window` until a SACK says otherwise.
    received_since_sack: u32,
    /// SACK.Delay (RFC 9260 6.2, 16), in milliseconds.
    sack_delay: u64,

    // Chunks stored for retransmission
    stored_init: Option<ChunkInit>,
    stored_cookie_echo: Option<ChunkCookieEcho>,
    next_stream_generation: u64,
    next_message_id: u64,
    /// Per-chunk lookups on the receive path; SIDs are bounded by the
    /// negotiated stream count, so the faster non-SipHash hasher is safe.
    pub(crate) streams: FxHashMap<StreamId, StreamState>,
    /// The `bytes_dequeued` of each stream at the moment it was unregistered, until a stream
    /// with the same identifier is created again (see [`Association::stream_bytes_dequeued`]).
    closed_stream_bytes_dequeued: FxHashMap<StreamId, u64>,
    /// The streams the association held when the peer restarted it (RFC 9260 5.2.4 action
    /// A), with the application bytes each had sent: see [`Self::streams_lost_in_restart`].
    streams_lost_in_restart: Vec<(StreamId, u64)>,
    /// Bytes held in every stream's reassembly queue, kept as a running total so the receive
    /// window is not recomputed by walking every stream on each DATA chunk.
    reassembly_bytes: usize,
    /// Streams whose reassembly queue holds a readable message.
    readable_streams: FxHashSet<StreamId>,
    /// Streams with no readable message whose reassembly queue has part of a message to give
    /// [`Stream::read_part`] (RFC 9260 6.9), each announced once with `StreamEvent::Readable`.
    part_readable_streams: FxHashSet<StreamId>,
    /// Streams whose reassembly queue holds anything at all; the only ones a FORWARD TSN can
    /// change.
    streams_with_data: FxHashSet<StreamId>,

    events: VecDeque<Event>,
    endpoint_events: VecDeque<EndpointEventInner>,
    error: Option<AssociationError>,
    /// Set by [`close`](Self::close): the association is over, whatever state it was in.
    ended: bool,
    /// The cause code (RFC 9260 section 3.3.10) the association was aborted with: the first
    /// cause of the ABORT it received or sent.
    abort_cause_code: Option<u16>,
    /// The Upper Layer Abort Reason of the peer's User-Initiated Abort (RFC 9260 9.1).
    peer_abort_reason: Option<Bytes>,
    /// `ended`, as the endpoint that routes to this association sees it: an ended association
    /// takes no more packets and no longer counts against the endpoint's limit.
    ended_flag: Arc<AtomicBool>,
    /// `Drained` is reported to the endpoint once.
    drained_emitted: bool,
    /// Error causes to report for the packet being processed, sent as one ERROR chunk when
    /// its last chunk has been handled.
    pending_error_causes: Vec<ErrorCause>,
    /// What the association did not deliver, once it ended (RFC 9260 8.1, 11.1.14, 11.1.15).
    undelivered: Vec<UndeliveredMessage>,
    /// Messages held for a stream reset when the association ended.
    undelivered_held: Vec<Vec<ChunkPayloadData>>,

    // per inbound packet context
    delayed_ack_triggered: bool,
    immediate_ack_triggered: bool,

    pub(crate) stats: AssociationStats,
    ack_state: AckState,

    // for testing
    pub(crate) ack_mode: AckMode,
}

impl Default for Association {
    fn default() -> Self {
        Association {
            side: Side::default(),
            state: AssociationState::default(),
            handshake_completed: false,
            peer_awaits_cookie_ack: false,
            max_message_size: 0,
            max_receive_message_size: 0,
            zero_window_overcommit: false,
            handshake_timers_back_off_rto: true,
            partial_delivery_point: 1,
            will_send_shutdown: false,
            bytes_received: 0,
            bytes_sent: 0,

            peer_verification_tag: 0,
            my_verification_tag: 0,
            my_next_tsn: 0,
            peer_last_tsn: 0,
            // for RTT measurement
            min_tsn2measure_rtt: 0,
            will_send_forward_tsn: false,
            will_retransmit_fast: false,
            will_retransmit_reconfig: false,
            restart_reconfig_timer: false,
            t3_retransmit_pending: false,

            will_send_shutdown_ack: false,
            will_send_shutdown_complete: false,

            // Reconfig
            my_next_rsn: 0,
            reconfigs: HashMap::default(),
            reconfig_in_flight: None,
            reconfig_in_progress: false,
            reconfig_queue: VecDeque::new(),
            reconfig_requests: HashMap::default(),
            completed_reconfig_requests: VecDeque::new(),
            peer_rsn_window: None,
            peer_supports_reconfig: true,
            incoming_resets_waiting: HashMap::default(),
            held_reset_data: vec![],
            orphans_dropped: 0,
            last_orphan_tsn: None,
            tsn_reset_requested: false,
            deferred_tsn_reset: None,
            last_tsn_reset_request: None,
            held_write_count: 0,

            // Non-RFC internal data
            remote_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            local_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            transport_protocol: TransportProtocol::UDP,

            source_port: 0,
            destination_port: 0,
            my_max_num_inbound_streams: 0,
            my_max_num_outbound_streams: 0,
            configured_inbound_streams: 0,
            configured_outbound_streams: 0,
            my_cookie: None,
            cookie_tcb: None,
            cookie_signer: None,
            local_tie_tag: 0,
            peer_tie_tag: 0,
            restart_cookie: None,
            transport_config: None,
            random: RandomSource::default(),
            valid_cookie_life: Duration::from_secs(60),
            stale_cookie_restarts: 0,
            t3_retransmitted: VecDeque::new(),
            cookie_echo_sent_at: None,
            recently_acknowledged: VecDeque::new(),
            first_data_received: false,
            sack_packet_immediately: false,
            discard_rest_of_packet: false,
            unbundled_sack: None,
            first_data_packet: 0,
            heartbeat_interval: None,
            heartbeat_outstanding: None,
            last_rtt_probe: None,
            path_error_count: 0,
            path_inactive: false,
            created_at: None,
            pmtud: None,

            payload_queue: PayloadQueue::default(),
            inflight_queue: PayloadQueue::default(),
            pending_queue: PendingQueue::default(),
            control_queue: VecDeque::default(),
            stream_queue: VecDeque::default(),

            mtu: 0,
            // max DATA chunk payload size
            max_payload_size: 0,
            cumulative_tsn_ack_point: 0,
            advanced_peer_tsn_ack_point: 0,
            use_forward_tsn: false,
            partial_reliability_enabled: true,
            interleaving_enabled: false,
            zero_checksum_enabled: false,
            send_zero_checksum: false,
            use_interleaving: false,
            i_fwd_tsn_stream_map: FxHashMap::default(),
            fwd_tsn_stream_map: FxHashMap::default(),

            rto_mgr: RtoManager::default(),
            timers: TimerTable::default().with_t1_following_rto(true),

            // Congestion control parameters
            max_receive_buffer_size: 0,
            // my congestion window size
            cwnd: 0,
            // calculated peer's receiver windows size
            rwnd: 0,
            // slow start threshold
            ssthresh: 0,
            partial_bytes_acked: 0,
            in_fast_recovery: false,
            fast_recover_exit_point: 0,
            pmdcs: 0,
            slow_start_growth_limit: 1,
            max_burst: None,
            last_data_sent: None,
            t3_single_packet: false,
            fast_retransmit_marked: vec![],
            zero_window_probe_at: None,
            zero_window_probe_tsn: None,
            reneged_in_last_sack: vec![],
            acknowledging_by_shutdown: false,
            last_advertised_window: 0,
            received_since_sack: 0,
            sack_delay: ACK_INTERVAL,

            // Chunks stored for retransmission
            stored_init: None,
            stored_cookie_echo: None,
            next_stream_generation: 0,
            next_message_id: 0,
            streams: FxHashMap::default(),
            closed_stream_bytes_dequeued: FxHashMap::default(),
            streams_lost_in_restart: vec![],
            reassembly_bytes: 0,
            readable_streams: FxHashSet::default(),
            part_readable_streams: FxHashSet::default(),
            streams_with_data: FxHashSet::default(),

            events: VecDeque::default(),
            endpoint_events: VecDeque::default(),
            error: None,
            ended: false,
            abort_cause_code: None,
            peer_abort_reason: None,
            ended_flag: Arc::new(AtomicBool::new(false)),
            drained_emitted: false,
            pending_error_causes: vec![],
            undelivered: vec![],
            undelivered_held: vec![],

            // per inbound packet context
            delayed_ack_triggered: false,
            immediate_ack_triggered: false,

            stats: AssociationStats::default(),
            ack_state: AckState::default(),

            // for testing
            ack_mode: AckMode::default(),
        }
    }
}

impl Association {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        server_config: Option<Arc<ServerConfig>>,
        config: Arc<TransportConfig>,
        max_payload_size: u32,
        local_aid: AssociationId,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        protocol: TransportProtocol,
        now: Instant,
        random: RandomSource,
    ) -> Self {
        let side = if server_config.is_some() {
            Side::Server
        } else {
            Side::Client
        };

        // It's a bit strange, but we're going backwards from the calculation in
        // config.rs to get max_payload_size from INITIAL_MTU.
        let mtu = max_payload_size.saturating_add(COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);

        let pmdcs = mtu.saturating_sub(COMMON_HEADER_SIZE);
        let cwnd = Self::initial_cwnd(pmdcs, remote_addr.is_ipv6());
        // RFC 9260 3.3.2: an unpredictable initial TSN, from the endpoint's random source
        // (`rand`'s thread-local CSPRNG unless a provider was given).
        let tsn = random.nonzero_u32();

        let mut this = Association {
            side,
            handshake_completed: false,
            peer_awaits_cookie_ack: false,
            max_receive_buffer_size: config.max_receive_buffer_size(),
            max_message_size: config.max_message_size(),
            max_receive_message_size: config.max_receive_message_size(),
            zero_window_overcommit: config.zero_window_overcommit(),
            handshake_timers_back_off_rto: config.handshake_timers_back_off_rto(),
            partial_delivery_point: config.partial_delivery_point(),
            transport_config: Some(config.clone()),
            my_max_num_outbound_streams: config.max_num_outbound_streams(),
            my_max_num_inbound_streams: config.max_num_inbound_streams(),
            configured_outbound_streams: config.max_num_outbound_streams(),
            configured_inbound_streams: config.max_num_inbound_streams(),
            valid_cookie_life: config.valid_cookie_life(),
            partial_reliability_enabled: config.partial_reliability(),
            interleaving_enabled: config.message_interleaving(),
            zero_checksum_enabled: config.zero_checksum(),
            heartbeat_interval: config.heartbeat_interval(),
            pmtud: config
                .path_mtu_discovery()
                .map(|pmtud| pmtud::PathMtuDiscovery::new(pmtud, mtu)),
            created_at: Some(now),
            random,
            max_payload_size,
            // RFC 8841 5: each side's `a=sctp-port`. An accepting side takes the INIT's ports
            // instead (`handle_init`).
            source_port: config.sctp_port(),
            destination_port: config.remote_sctp_port(),

            rto_mgr: RtoManager::with_config(config.rto_config()),
            timers: TimerTable::new(config.timer_config())
                .with_rto_config(config.rto_config())
                .with_t1_following_rto(config.handshake_timers_back_off_rto()),
            pending_queue: {
                let mut queue = PendingQueue::with_scheduler(config.stream_scheduler());
                queue.set_packet_budget(mtu.saturating_sub(COMMON_HEADER_SIZE) as usize);
                queue
            },

            mtu,
            cwnd,
            pmdcs,
            slow_start_growth_limit: config.slow_start_growth_limit(),
            max_burst: config.max_burst(),
            last_advertised_window: config.max_receive_buffer_size(),
            received_since_sack: 0,
            sack_delay: config.sack_delay().as_millis() as u64,
            remote_addr,
            local_addr,
            transport_protocol: protocol,

            my_verification_tag: local_aid,
            my_next_tsn: tsn,
            my_next_rsn: tsn,
            min_tsn2measure_rtt: tsn,
            cumulative_tsn_ack_point: tsn - 1,
            advanced_peer_tsn_ack_point: tsn - 1,
            error: None,

            ..Default::default()
        };

        if !side.is_client() {
            // The accepting side exists from the peer's INIT on. Without a COOKIE ECHO it
            // must not exist for ever (and an INIT that is not valid starts no handshake at
            // all), so the wait is timed from the start.
            this.timers.start(Timer::HalfOpen, now, HALF_OPEN_LIFETIME);
        }

        if side.is_client() {
            let mut init = ChunkInit {
                initial_tsn: this.my_next_tsn,
                num_outbound_streams: this.my_max_num_outbound_streams,
                num_inbound_streams: this.my_max_num_inbound_streams,
                initiate_tag: this.my_verification_tag,
                advertised_receiver_window_credit: this.max_receive_buffer_size,
                ..Default::default()
            };
            init.announce_extensions(
                this.partial_reliability_enabled,
                this.interleaving_enabled,
                this.zero_checksum_enabled,
            );

            this.set_state(AssociationState::CookieWait);
            this.stored_init = Some(init);
            let _ = this.send_init();
            this.timers
                .start(Timer::T1Init, now, this.rto_mgr.get_rto());
        }

        this
    }

    /// RFC 9260 7.2.1: the initial cwnd, before DATA is sent and after a change of path, is
    /// min(4 x PMDCS, max(2 x PMDCS, 4404)), with 4344 in place of 4404 over IPv6.
    ///
    /// Written in total form: `clamp` panics when the bounds cross, which a small PMDCS
    /// makes them do, and the products saturate.
    fn initial_cwnd(pmdcs: u32, ipv6: bool) -> u32 {
        let floor = if ipv6 { 4344 } else { 4404 };
        pmdcs
            .saturating_mul(2)
            .max(floor)
            .min(pmdcs.saturating_mul(4))
    }

    /// The congestion window, in bytes of user data.
    pub fn congestion_window(&self) -> u32 {
        self.cwnd
    }

    /// The slow start threshold, in bytes of user data.
    pub fn slow_start_threshold(&self) -> u32 {
        self.ssthresh
    }

    /// The current retransmission timeout.
    pub fn rto(&self) -> Duration {
        Duration::from_millis(self.rto_mgr.get_rto())
    }

    /// The peer's receive window as this side tracks it (RFC 9260 6.2.1: the last a_rwnd
    /// less the bytes sent since and not acknowledged), in bytes of user data.
    pub fn peer_receive_window(&self) -> u32 {
        self.rwnd
    }

    /// RFC 9260 11.1.8 Status: the association's state in one call (single-homed, RFC 8261
    /// 6.1, so one destination: no address list or primary path).
    pub fn status(&self) -> AssociationStatus {
        AssociationStatus {
            closed: self.is_closed(),
            peer_receive_window: self.rwnd,
            congestion_window: self.cwnd,
            slow_start_threshold: self.ssthresh,
            unacknowledged_data_chunks: self.inflight_queue.len(),
            pending_data_chunks: self.pending_queue.len(),
            srtt: self.rtt(),
            rto: self.rto(),
            path_mtu: self.path_mtu(),
        }
    }

    /// Tells the association that its packets take another path from now on: the transport
    /// underneath switched (for WebRTC, ICE selected another candidate pair).
    ///
    /// RFC 9260 7.2.5: what was learned about the old path says nothing about the new one, so
    /// the congestion control state and the RTO start again from their initial values. DATA
    /// outstanding stays outstanding, and its retransmission timer runs on with the initial
    /// RTO.
    pub fn on_path_change(&mut self, now: Instant) {
        debug!(
            "[{}] path change: congestion control starts over",
            self.side
        );
        // RFC 8261 section 6.1 and RFC 8831 section 5: the path MTU is tested again. The
        // discovery starts over from BASE_PLPMTU, which is what the packets use until a
        // probe confirms more.
        if let Some(pmtud) = self.pmtud.as_mut() {
            let base = pmtud.base();
            pmtud.reset(base);
            self.use_path_mtu(base, true);
        }
        self.cwnd = Self::initial_cwnd(self.pmdcs, self.remote_addr.is_ipv6());
        // RFC 9260 7.2.1: the initial ssthresh is arbitrarily high; the peer's window is.
        self.ssthresh = self
            .rwnd
            .saturating_add(self.inflight_queue.get_num_bytes() as u32);
        self.partial_bytes_acked = 0;
        self.in_fast_recovery = false;
        self.will_retransmit_fast = false;
        self.last_data_sent = None;
        self.rto_mgr.reset();
        // No RTT sample of the old path may be taken for the new one.
        self.min_tsn2measure_rtt = self.my_next_tsn;
        self.path_error_count = 0;
        if self.timers.get(Timer::T3RTX).is_some() {
            self.timers.stop(Timer::T3RTX);
            self.timers.start(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }
    }

    /// The largest SCTP packet (common header and chunks) the association sends: the path
    /// MTU as it knows it.
    pub fn path_mtu(&self) -> u32 {
        self.mtu
    }

    /// Tells the association the largest SCTP packet the path below carries, in bytes: the
    /// path MTU less what lies beneath SCTP (for WebRTC: the DTLS record overhead, the UDP
    /// and IP headers, and TURN framing where a relay is used). The entry point for whatever
    /// learns the path MTU: the transport's initial value for a path, the application's own
    /// discovery, or an ICMP "Packet Too Big" it has validated (RFC 9260 section 7.3, RFC 8261
    /// section 4).
    ///
    /// With path MTU discovery on ([`TransportConfig::with_path_mtu_discovery`]) the value
    /// is BASE_PLPMTU (RFC 8899 section 5.1.2): the association uses it, confirms it with a
    /// probe once established and searches above it; a new value starts the discovery over.
    /// Setting the value in use again changes nothing.
    ///
    /// From now on packets are bundled up to the packet size, the Path Maximum DATA Chunk
    /// Size of the congestion control rules follows it, and messages written from now on are
    /// fragmented to fit. A message already fragmented keeps its fragments: after a reduction
    /// they are sent as they are, each alone in a packet larger than the new MTU, and the
    /// layer below has to fragment or the caller to accept the loss (RFC 9260 section 6.9:
    /// SCTP does not re-fragment). A value below
    /// [`MIN_DATA_PACKET_MTU`](crate::MIN_DATA_PACKET_MTU) is raised to it.
    pub fn set_path_mtu(&mut self, mtu: u32) {
        let mtu = mtu.max(crate::config::MIN_DATA_PACKET_MTU);
        if let Some(pmtud) = self.pmtud.as_mut() {
            if pmtud.base() == mtu {
                return;
            }
            pmtud.reset(mtu);
        }
        self.use_path_mtu(mtu, true);
    }

    /// MAX_PLPMTU of the path MTU discovery (RFC 8899 section 5.1.2): the largest SCTP packet
    /// the search tries, the local interface MTU less what lies under SCTP. Nothing without
    /// discovery.
    pub fn set_max_path_mtu(&mut self, max: u32) {
        if let Some(mtu) = self.pmtud.as_mut().and_then(|p| p.set_max_path_mtu(max)) {
            self.use_path_mtu(mtu, false);
        }
    }

    /// Where the path MTU discovery is (RFC 8899 section 5.2); `None` without discovery.
    pub fn path_mtu_state(&self) -> Option<PathMtuState> {
        self.pmtud.as_ref().map(|p| p.state())
    }

    /// Takes `mtu` as the size of the packets sent from now on. `raise_cwnd`: the congestion
    /// window grows to one packet if it is smaller (RFC 9260 7.2.1); a PLPMTU found by
    /// discovery leaves it as it is (RFC 8899 section 3 item 7: "An update to the PLPMTU (or
    /// MPS) MUST NOT increase the congestion window measured in bytes").
    fn use_path_mtu(&mut self, mtu: u32, raise_cwnd: bool) {
        let mtu = mtu.max(crate::config::MIN_DATA_PACKET_MTU);
        if mtu == self.mtu {
            return;
        }
        debug!("[{}] path MTU {} -> {}", self.side, self.mtu, mtu);
        self.mtu = mtu;
        self.pmdcs = mtu.saturating_sub(COMMON_HEADER_SIZE);
        self.max_payload_size = crate::config::max_payload_size_for_mtu(mtu);
        for s in self.streams.values_mut() {
            s.max_payload_size = self.max_payload_size;
        }
        self.pending_queue.set_packet_budget(self.pmdcs as usize);
        if raise_cwnd {
            // RFC 9260 7.2.1: cwnd is never below one packet of the size now in use.
            self.cwnd = self.cwnd.max(self.pmdcs);
        }
    }

    /// Returns application-facing event
    ///
    /// Associations should be polled for events after:
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll(&mut self) -> Option<Event> {
        if let Some(x) = self.events.pop_front() {
            return Some(x);
        }

        /*TODO: if let Some(event) = self.streams.poll() {
            return Some(Event::Stream(event));
        }*/

        if let Some(err) = self.error.take() {
            return Some(Event::HandshakeFailed { reason: err });
        }

        None
    }

    /// Return endpoint-facing event
    #[must_use]
    pub fn poll_endpoint_event(&mut self) -> Option<EndpointEvent> {
        self.endpoint_events.pop_front().map(EndpointEvent)
    }

    /// Returns the next time at which `handle_timeout` should be called
    ///
    /// The value returned may change after:
    /// - the application performed some I/O on the association
    /// - a call was made to `handle_transmit`
    /// - a call to `poll_transmit` returned `Some`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        // The discovery runs while the association is established only.
        let pmtud = self
            .pmtud
            .as_ref()
            .filter(|_| self.state() == AssociationState::Established)
            .and_then(|p| p.deadline());
        // The first zero window probe's time, while there is DATA to probe with.
        let probe = self.zero_window_probe_at;
        [self.timers.next_timeout(), pmtud, probe]
            .into_iter()
            .flatten()
            .min()
    }

    /// Returns packets to transmit
    ///
    /// Associations should be polled for transmit after:
    /// - the application performed some I/O on the Association
    /// - a call was made to `handle_event`
    /// - a call was made to `handle_timeout`
    #[must_use]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<TransportMessage<Payload>> {
        let (contents, keep_open) = self.gather_outbound(now);
        if !keep_open && !self.ended {
            // The SHUTDOWN COMPLETE just gathered is the last packet of a graceful shutdown
            // this side started: RFC 9260 9.2 removes the association once it is sent. It
            // stayed in SHUTDOWN-SENT for good, with nothing left to happen.
            if let Err(err) = self.close(AssociationError::LocallyClosed) {
                error!("[{}] failed to close association: {err}", self.side);
            }
        }
        if contents.is_empty() {
            None
        } else {
            self.bytes_sent = self
                .bytes_sent
                .saturating_add(contents.iter().map(Bytes::len).sum());
            trace!(
                "[{}] sending {} bytes (total {} datagrams)",
                self.side,
                contents.iter().fold(0, |l, c| l + c.len()),
                contents.len()
            );
            Some(TransportMessage {
                now,
                transport: TransportContext {
                    local_addr: self.local_addr,
                    peer_addr: self.remote_addr,
                    ecn: None,
                    transport_protocol: Default::default(),
                },
                message: Payload::RawEncode(contents),
            })
        }
    }

    /// Process timer expirations
    ///
    /// Executes protocol logic, potentially preparing signals (including application `Event`s,
    /// `EndpointEvent`s and outgoing datagrams) that should be extracted through the relevant
    /// methods.
    ///
    /// It is most efficient to call this immediately after the system clock reaches the latest
    /// `Instant` that was output by `poll_timeout`; however spurious extra calls will simply
    /// no-op and therefore are safe.
    pub fn handle_timeout(&mut self, now: Instant) {
        // RFC 9260 6.1 A: the first zero window probe may go now.
        if self.zero_window_probe_at.is_some_and(|at| now >= at) {
            self.zero_window_probe_at = None;
        }
        for &timer in &Timer::VALUES {
            let (expired, failure, n_rtos) = self.timers.is_expired(timer, now);
            if !expired {
                continue;
            }
            self.timers.set(timer, None);
            //trace!("{:?} timeout", timer);

            if timer == Timer::Ack {
                self.on_ack_timeout();
            } else if timer == Timer::Heartbeat {
                self.on_heartbeat_timeout(now);
            } else if failure && timer != Timer::Reconfig {
                self.on_retransmission_failure(timer);
            } else {
                self.on_retransmission_timeout(timer, n_rtos, now);
                if self.state() == AssociationState::Closed {
                    break;
                }
                self.timers.start(timer, now, self.rto_mgr.get_rto());
            }
        }
        if self
            .pmtud
            .as_ref()
            .and_then(|p| p.deadline())
            .is_some_and(|at| now >= at)
        {
            self.handle_path_mtu_timeout(now);
        }
    }

    /// Process `AssociationEvent`s generated by the associated `Endpoint`
    ///
    /// Will execute protocol logic upon receipt of an association event, in turn preparing signals
    /// (including application `Event`s, `EndpointEvent`s and outgoing datagrams) that should be
    /// extracted through the relevant methods.
    pub fn handle_event(&mut self, event: AssociationEvent) {
        match event.0 {
            AssociationEventInner::Datagram(transmit) => {
                // If this packet could initiate a migration and we're a client or a server that
                // forbids migration, drop the datagram. This could be relaxed to heuristically
                // permit NAT-rebinding-like migration.
                /*TODO:if remote != self.remote && self.server_config.as_ref().map_or(true, |x| !x.migration)
                {
                    trace!("discarding packet from unrecognized peer {}", remote);
                    return;
                }*/

                if let Payload::PartialDecode(partial_decode) = transmit.message {
                    // RFC 9653 5.3: a zero checksum is taken only by an endpoint that
                    // announced it; otherwise the packet is dropped as one with a wrong
                    // CRC32c (RFC 9260 6.8).
                    if !partial_decode.checksum_ok(self.zero_checksum_enabled) {
                        debug!("[{}] discarding a packet with a zero checksum", self.side);
                        return;
                    }
                    let len = COMMON_HEADER_SIZE as usize + partial_decode.remaining.len();
                    debug!("[{}] recving {} bytes", self.side, len);
                    self.bytes_received = self.bytes_received.saturating_add(len);

                    let pkt = match partial_decode.finish() {
                        Ok(p) => p,
                        Err(err) => {
                            warn!("[{}] unable to parse SCTP packet {}", self.side, err);
                            return;
                        }
                    };

                    if let Err(err) = self.handle_inbound(pkt, transmit.now) {
                        error!("handle_inbound got err: {}", err);
                        let _ = self.close(AssociationError::TransportError);
                    }
                } else {
                    trace!("discarding invalid partial_decode");
                }
            } //TODO:
        }
    }

    /// Whether PR-SCTP (RFC 3758) is in use: both sides announced it. `false` while the
    /// association is being set up, and for good when the peer does not support it, in which
    /// case every message is sent reliably whatever its stream's reliability parameters say.
    pub fn partial_reliability(&self) -> bool {
        self.use_forward_tsn
    }

    /// Returns Association statistics
    pub fn stats(&self) -> AssociationStats {
        self.stats
    }

    /// Whether the Association is in the process of being established
    ///
    /// If this returns `false`, the Association may be either established or closed, signaled by the
    /// emission of a `Connected` or `AssociationLost` message respectively.
    pub fn is_handshaking(&self) -> bool {
        !self.handshake_completed
    }

    /// The number of streams negotiated for this association: the smaller of the inbound and
    /// outbound counts the two endpoints agreed on in INIT/INIT ACK.
    ///
    /// `None` while the association is still handshaking. Before the peer's INIT (or INIT ACK) has
    /// been processed, the two counts still hold this endpoint's *configured* limits rather than
    /// anything agreed, so reporting them would overstate what the association can carry.
    ///
    /// This is what [RFC 8831] data channels are limited by, and what W3C
    /// `RTCSctpTransport.maxChannels` reports.
    ///
    /// [RFC 8831]: https://datatracker.ietf.org/doc/html/rfc8831
    pub fn negotiated_max_streams(&self) -> Option<u16> {
        if self.is_handshaking() {
            None
        } else {
            Some(
                self.my_max_num_inbound_streams
                    .min(self.my_max_num_outbound_streams),
            )
        }
    }

    /// Whether the Association is closed
    ///
    /// Closed Associations cannot transport any further data. An association becomes closed when
    /// either peer application intentionally closes it, or when either transport layer detects an
    /// error such as a time-out or certificate validation failure.
    ///
    /// A `AssociationLost` event is emitted with details when the association becomes closed.
    pub fn is_closed(&self) -> bool {
        self.state == AssociationState::Closed
    }

    /// Whether the association is over: closed by either side, by an error, or by a handshake
    /// that failed.
    ///
    /// Unlike [`is_closed`](Self::is_closed), false for an association still handshaking in
    /// SCTP's initial CLOSED state (RFC 9260 section 4), which has not ended.
    pub fn is_ended(&self) -> bool {
        self.ended
    }

    /// Whether there is no longer any need to keep the association around
    ///
    /// Closed associations become drained after a brief timeout to absorb any remaining in-flight
    /// packets from the peer. All drained associations have been closed.
    pub fn is_drained(&self) -> bool {
        self.state.is_drained()
    }

    /// The Verification Tag this association expects in the packets it receives (RFC 9260
    /// section 8.5): its own Initiate Tag.
    pub fn verification_tag(&self) -> u32 {
        self.my_verification_tag
    }

    /// Look up whether we're the client or server of this Association
    pub fn side(&self) -> Side {
        self.side
    }

    /// The latest socket address for this Association's peer
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Smoothed round-trip time, or zero before the first RTT measurement.
    /// Retransmission timeout backoff does not change this estimate.
    pub fn rtt(&self) -> Duration {
        Duration::from_millis(self.rto_mgr.srtt)
    }

    /// The local IP address which was used when the peer established
    /// the association
    ///
    /// This can be different from the address the endpoint is bound to, in case
    /// the endpoint is bound to a wildcard address like `0.0.0.0` or `::`.
    ///
    /// This will return `None` for clients.
    ///
    /// Retrieving the local IP address is currently supported on the following
    /// platforms:
    /// - Linux
    ///
    /// On all non-supported platforms the local IP address will not be available,
    /// and the method will return `None`.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shutdown initiates the shutdown sequence. The method blocks until the
    /// shutdown sequence is completed and the association is closed, or until the
    /// passed context is done, in which case the context's error is returned.
    pub fn shutdown(&mut self) -> Result<()> {
        debug!("[{}] closing association..", self.side);

        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrShutdownNonEstablished);
        }

        // Attempt a graceful shutdown. RFC 9260 9.2: SHUTDOWN-PENDING lasts until everything
        // the application handed over has been sent and acknowledged. This tested a counter
        // that was never updated, so SHUTDOWN went out at once, ahead of the DATA still in
        // flight or queued, and the queued DATA was never sent.
        self.set_state(AssociationState::ShutdownPending);

        if self.nothing_left_to_send() {
            // No more outstanding, send shutdown.
            self.send_shutdown();
        }

        Ok(())
    }

    /// Moves SHUTDOWN-PENDING on to SHUTDOWN-SENT and queues the SHUTDOWN.
    ///
    /// The endpoint's `Drained` goes out with it, as it always has: the owner flushes this
    /// association's final packets and may then stop routing to it. It used to be emitted by
    /// `shutdown()` itself, which with DATA still outstanding cut the association off from the
    /// SACKs it was waiting for.
    fn send_shutdown(&mut self) {
        self.will_send_shutdown = true;
        self.awake_write_loop();
        self.set_state(AssociationState::ShutdownSent);
        self.emit_drained();
    }

    /// RFC 9260 9.2: the T5-shutdown-guard timer bounds the whole shutdown, however often the
    /// peer's packets restart T2-shutdown.
    fn start_shutdown_guard(&mut self, now: Instant) {
        if self.timers.get(Timer::T5ShutdownGuard).is_none() {
            self.timers
                .start(Timer::T5ShutdownGuard, now, T5_SHUTDOWN_GUARD);
        }
    }

    /// Tells the endpoint to stop routing to this association, once.
    fn emit_drained(&mut self) {
        if !self.drained_emitted {
            self.drained_emitted = true;
            self.endpoint_events.push_back(EndpointEventInner::Drained);
        }
    }

    /// The flag the endpoint reads to learn that this association has ended.
    pub(crate) fn ended_flag(&self) -> Arc<AtomicBool> {
        self.ended_flag.clone()
    }

    /// Aborts the association (RFC 9260 §9.1): queues an ABORT chunk and closes the association.
    ///
    /// Unlike [`shutdown`](Self::shutdown) this needs no round trip, which is what closing a
    /// WebRTC peer connection calls for: W3C `close()` tears the association down "by sending an
    /// SCTP ABORT chunk". The ABORT carries a "User-Initiated Abort" error cause (RFC 9260
    /// §3.3.10.12), which a peer takes as an intentional close rather than an error.
    ///
    /// The ABORT is sent by the next [`poll_transmit`](Self::poll_transmit). Anything not handed to
    /// `poll_transmit` before this call is discarded, so drain it first if it should still go out.
    /// A no-op on a closed association.
    pub fn abort(&mut self) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.abort_with(
            vec![ErrorCause {
                code: USER_INITIATED_ABORT,
                ..Default::default()
            }],
            AssociationError::LocallyClosed,
        )
    }

    /// Sends an ABORT with `causes` to the peer and ends the association with `reason`
    /// (RFC 9260 9.1). The ABORT goes alone in its packet, with the peer's tag; before the
    /// peer's tag is known (no INIT ACK yet) there is no one to send it to.
    fn abort_with(&mut self, causes: Vec<ErrorCause>, reason: AssociationError) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        if let Some(cause) = causes.first() {
            self.abort_cause_code.get_or_insert(cause.code.0);
        }
        if self.peer_verification_tag != 0 {
            let packet = self.abort_packet(self.peer_verification_tag, false, causes);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
        }
        self.close(reason)
    }

    /// A packet holding one ABORT chunk, sent with Verification Tag `tag`. `reflected` sets
    /// the T bit: the tag is the one of the packet being answered, not the receiver's own
    /// (RFC 9260 8.4, 8.5.1).
    fn abort_packet(&self, tag: u32, reflected: bool, causes: Vec<ErrorCause>) -> Packet {
        Packet {
            common_header: CommonHeader {
                verification_tag: tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(ChunkAbort {
                error_causes: causes,
                tag_reflected: reflected,
            })],
        }
    }

    fn protocol_violation(text: &str) -> ErrorCause {
        ErrorCause {
            code: PROTOCOL_VIOLATION,
            raw: Bytes::copy_from_slice(text.as_bytes()),
        }
    }

    /// The cause code (RFC 9260 section 3.3.10) of the ABORT that ended the association: the
    /// first error cause of the one received, or of the one this side sent. `None` when no
    /// ABORT ended it, or the ABORT carried no cause. What W3C webrtc-pc reports as an
    /// `RTCError`'s `sctpCauseCode`.
    pub fn abort_cause_code(&self) -> Option<u16> {
        self.abort_cause_code
    }

    /// The Upper Layer Abort Reason the peer gave when it aborted the association (RFC 9260
    /// sections 3.3.10.12 and 9.1: "the Upper Layer Abort Reason ... SHOULD be made available
    /// to the upper layer"). `None` when the association did not end by the peer's
    /// User-Initiated Abort; empty when that carried no reason.
    pub fn peer_abort_reason(&self) -> Option<&[u8]> {
        self.peer_abort_reason.as_deref()
    }

    /// As [`abort`](Self::abort), with an Upper Layer Abort Reason in the User-Initiated
    /// Abort error cause (RFC 9260 section 3.3.10.12) for the peer's application.
    pub fn abort_with_reason(&mut self, reason: &[u8]) -> Result<()> {
        if self.ended {
            return Ok(());
        }
        self.abort_with(
            vec![ErrorCause {
                code: USER_INITIATED_ABORT,
                raw: Bytes::copy_from_slice(reason),
            }],
            AssociationError::LocallyClosed,
        )
    }

    /// Close ends the SCTP Association and cleans up any state
    pub fn close(&mut self, reason: AssociationError) -> Result<()> {
        // Keyed on `ended`, not on the CLOSED state: an accepting association is in SCTP's
        // initial CLOSED state until the COOKIE ECHO, so an ABORT or an error during its
        // handshake used to close nothing and leave it handshaking for good.
        if !self.ended {
            self.ended = true;
            // The endpoint stops routing to an ended association and frees its place for the
            // next one (RFC 9260 9.1: the association is removed from the record). The owner
            // may keep the association itself to read how it ended.
            self.ended_flag.store(true, Ordering::Relaxed);
            self.set_state(AssociationState::Closed);

            debug!("[{}] closing association..", self.side);

            self.close_all_timers();

            for si in self.streams.keys().cloned().collect::<Vec<u16>>() {
                self.unregister_stream(si, reason.clone());
            }
            self.collect_undelivered_messages();
            self.events.push_back(Event::AssociationClosed {
                reason: reason.clone(),
            });

            debug!("[{}] association closed", self.side);
            debug!(
                "[{}] stats nDATAs (in) : {}",
                self.side,
                self.stats.get_num_datas()
            );
            debug!(
                "[{}] stats nSACKs (in) : {}",
                self.side,
                self.stats.get_num_sacks()
            );
            debug!(
                "[{}] stats nT3Timeouts : {}",
                self.side,
                self.stats.get_num_t3timeouts()
            );
            debug!(
                "[{}] stats nAckTimeouts: {}",
                self.side,
                self.stats.get_num_ack_timeouts()
            );
            debug!(
                "[{}] stats nFastRetrans: {}",
                self.side,
                self.stats.get_num_fast_retrans()
            );
        }

        Ok(())
    }

    /// open_stream opens a stream
    pub fn open_stream(
        &mut self,
        stream_identifier: StreamId,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Result<Stream<'_>> {
        if self.streams.contains_key(&stream_identifier) {
            return Err(Error::ErrStreamAlreadyExist);
        }

        // RFC 9260 5.1.1, 6.5: the outgoing stream ids are 0 to min(own OS, peer's MIS) - 1.
        // DATA on any other is answered by the peer with an ERROR and thrown away.
        if self.my_max_num_outbound_streams != 0
            && stream_identifier >= self.my_max_num_outbound_streams
        {
            return Err(Error::ErrStreamCreateFailed);
        }

        if let Some(s) = self.create_stream(stream_identifier, false, default_payload_type) {
            Ok(s)
        } else {
            Err(Error::ErrStreamCreateFailed)
        }
    }

    /// accept_stream accepts a stream
    pub fn accept_stream(&mut self) -> Option<Stream<'_>> {
        self.stream_queue
            .pop_front()
            .map(move |stream_identifier| Stream {
                stream_identifier,
                association: self,
            })
    }

    /// stream returns a stream
    pub fn stream(&mut self, stream_identifier: StreamId) -> Result<Stream<'_>> {
        if !self.streams.contains_key(&stream_identifier) {
            Err(Error::ErrStreamNotExisted)
        } else {
            Ok(Stream {
                stream_identifier,
                association: self,
            })
        }
    }

    /// The identifiers of every stream currently open on this association.
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.keys().cloned().collect()
    }

    /// The bytes of every SCTP packet handed out by `poll_transmit`, common headers included.
    pub(crate) fn bytes_sent(&self) -> usize {
        self.bytes_sent
    }

    /// The bytes of every SCTP packet handed in through `handle_event`, common headers included.
    pub(crate) fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    /// max_message_size returns the maximum message size you can send.
    pub(crate) fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    /// Sets the maximum message size this side may send: what a later offer/answer exchange
    /// negotiated (W3C webrtc 4.4.1.4 "update the data max message size", RFC 8841 section
    /// 6.1).
    pub fn set_max_message_size(&mut self, max_message_size: u32) {
        self.max_message_size = max_message_size;
    }

    /// unregister_stream un-registers a stream from the association
    /// The caller should hold the association write lock.
    fn unregister_stream(&mut self, stream_identifier: StreamId, reason: AssociationError) {
        if let Some(s) = self.streams.get_mut(&stream_identifier) {
            // What the stream wrote and has not sent yet still goes, numbered by the stream
            // it was written to.
            let generation = s.generation;
            self.pending_queue
                .number_messages(stream_identifier, generation, false, |unordered| {
                    s.next_message_numbers(unordered)
                });
        }
        if let Some(mut s) = self.streams.remove(&stream_identifier) {
            debug!("[{}] unregister_stream {}", self.side, stream_identifier);
            self.closed_stream_bytes_dequeued
                .insert(stream_identifier, s.bytes_dequeued);
            self.reindex_stream(stream_identifier, s.get_num_bytes_in_reassembly_queue());
            // Messages held for a reset of the stream go with it: when the association is
            // ending, they are handed back as unsent (RFC 9260 8.1).
            self.held_write_count = self.held_write_count.saturating_sub(s.held_writes.len());
            if self.ended {
                self.undelivered_held.append(&mut s.held_writes);
            }
            self.events.push_back(Event::AssociationLost {
                reason,
                id: stream_identifier,
            });
            s.state = RecvSendState::Closed;
        }
    }

    /// RFC 9260 8.1: an association that ends "SHOULD report the failure to the upper layer
    /// and optionally report back all outstanding user data remaining in its outbound
    /// queue". What was sent and not cumulatively acknowledged, what waits to be sent and
    /// what was held for a stream reset become [`UndeliveredMessage`]s, reported with one
    /// [`Event::SendFailure`] (11.2.2) and read with [`Self::take_undelivered_messages`].
    fn collect_undelivered_messages(&mut self) {
        let sent = self.inflight_queue.take_all();
        let mut unsent = self.pending_queue.take_all_messages();
        unsent.append(&mut self.undelivered_held);
        let messages = undelivered::undelivered_messages(sent, unsent);
        if messages.is_empty() {
            return;
        }
        let unacknowledged = messages
            .iter()
            .filter(|m| m.mode == UndeliveredMode::Unacknowledged)
            .count();
        self.events.push_back(Event::SendFailure {
            unsent: messages.len() - unacknowledged,
            unacknowledged,
        });
        self.undelivered.extend(messages);
    }

    /// The user messages this association did not deliver, once it ended (RFC 9260 11.1.14
    /// Receive Unsent Message, 11.1.15 Receive Unacknowledged Message): each message that
    /// was never sent and each one sent and not completely acknowledged, in the order sent
    /// then written, as [`Event::SendFailure`] counted them. Taken once; empty while the
    /// association runs. A graceful shutdown ends only when everything was acknowledged, so
    /// it leaves none.
    pub fn take_undelivered_messages(&mut self) -> Vec<UndeliveredMessage> {
        std::mem::take(&mut self.undelivered)
    }

    /// set_state atomically sets the state of the Association.
    fn set_state(&mut self, new_state: AssociationState) {
        if new_state != self.state {
            debug!(
                "[{}] state change: '{}' => '{}'",
                self.side, self.state, new_state,
            );
        }
        self.state = new_state;
    }

    /// state atomically returns the state of the Association.
    pub(crate) fn state(&self) -> AssociationState {
        self.state
    }

    /// caller must hold self.lock
    fn send_init(&mut self) -> Result<()> {
        if let Some(stored_init) = &self.stored_init {
            debug!("[{}] sending INIT", self.side);

            let outbound = Packet {
                common_header: CommonHeader {
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![Box::new(stored_init.clone())],
            };

            self.control_queue.push_back(outbound);
            self.awake_write_loop();

            Ok(())
        } else {
            Err(Error::ErrInitNotStoredToSend)
        }
    }

    /// caller must hold self.lock
    fn send_cookie_echo(&mut self) -> Result<()> {
        if let Some(stored_cookie_echo) = &self.stored_cookie_echo {
            debug!("[{}] sending COOKIE-ECHO", self.side);

            let outbound = Packet {
                common_header: CommonHeader {
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                    verification_tag: self.peer_verification_tag,
                },
                chunks: vec![Box::new(stored_cookie_echo.clone())],
            };

            self.control_queue.push_back(outbound);
            self.awake_write_loop();

            Ok(())
        } else {
            Err(Error::ErrCookieEchoNotStoredToSend)
        }
    }

    /// handle_inbound parses incoming raw packets
    fn handle_inbound(&mut self, p: Packet, now: Instant) -> Result<()> {
        // RFC 9260 9.1: an association that has ended is gone. Whatever still arrives for it
        // (a copy of the COOKIE ECHO, DATA in flight) is discarded.
        if self.ended {
            trace!(
                "[{}] discarding a packet for an ended association",
                self.side
            );
            return Ok(());
        }

        if let Err(err) = p.check_packet() {
            warn!("[{}] failed validating packet {}", self.side, err);
            return Ok(());
        }

        // RFC 9260 8.5.1 E: a SHUTDOWN ACK while this side is still setting the association
        // up belongs to an association it no longer has. It is answered as an out-of-the-blue
        // packet (8.4): SHUTDOWN COMPLETE with the tag of the SHUTDOWN ACK and the T bit.
        if matches!(
            self.state(),
            AssociationState::CookieWait | AssociationState::CookieEchoed
        ) && p.chunks.iter().any(|c| c.as_any().is::<ChunkShutdownAck>())
        {
            let packet = Packet {
                common_header: CommonHeader {
                    verification_tag: p.common_header.verification_tag,
                    source_port: self.source_port,
                    destination_port: self.destination_port,
                },
                chunks: vec![Box::new(ChunkShutdownComplete {
                    tag_reflected: true,
                })],
            };
            self.control_queue.push_back(packet);
            self.awake_write_loop();
            return Ok(());
        }

        if !self.accepts_verification_tag(&p) {
            debug!(
                "[{}] discarding a packet with Verification Tag {}",
                self.side, p.common_header.verification_tag
            );
            return Ok(());
        }

        self.handle_chunk_start();
        let replies_before = self.control_queue.len();

        // RFC 9260 9.1: a packet that carries an ABORT is not answered. The ABORT is taken
        // first, so nothing queued for the chunks bundled before it goes out.
        if let Some(abort) = p.chunks.iter().find(|c| c.as_any().is::<ChunkAbort>()) {
            self.handle_chunk(&p, abort, now)?;
            return Ok(());
        }

        // RFC 9260 9.2: in SHUTDOWN-SENT any packet from the peer shows it is still there
        // (it is sending what it had queued): the retransmission count starts over and so
        // does T2-shutdown.
        if self.state() == AssociationState::ShutdownSent {
            self.timers.reset_retrans(Timer::T2Shutdown);
            if self.timers.get(Timer::T2Shutdown).is_some() {
                self.timers.stop(Timer::T2Shutdown);
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
            }
        }

        for c in &p.chunks {
            // `false`: the rest of the packet is discarded. An association that a chunk ended
            // processes none of the chunks after it either.
            if !self.handle_chunk(&p, c, now)? || self.ended || self.discard_rest_of_packet {
                break;
            }
        }

        self.handle_chunk_end(now);
        // RFC 9260 12.4: one packet of control chunks answers one received packet.
        self.bundle_replies(replies_before);

        Ok(())
    }

    /// RFC 9260 8.5, 8.5.1: whether a received packet carries the Verification Tag it must.
    ///
    /// A packet with an INIT has tag 0 (and nothing else: `check_packet`). A packet with an
    /// ABORT or a SHUTDOWN COMPLETE has this side's tag, or the peer's tag with the T bit set
    /// (the sender had no TCB and reflected the tag it was sent). Every other packet has this
    /// side's tag.
    fn accepts_verification_tag(&self, p: &Packet) -> bool {
        let tag = p.common_header.verification_tag;
        // RFC 9260 8.5.1 D: the receiver of a COOKIE ECHO follows section 5, which compares
        // the tag with the one in the cookie (`handle_cookie_echo`): the cookie of a restart
        // (5.2.4) carries a new tag of this side's.
        if p.chunks
            .first()
            .is_some_and(|chunk| chunk.as_any().is::<ChunkCookieEcho>())
        {
            return true;
        }
        for chunk in &p.chunks {
            let any = chunk.as_any();
            if any.downcast_ref::<ChunkInit>().is_some_and(|c| !c.is_ack) {
                return tag == 0;
            }
            let reflected = any
                .downcast_ref::<ChunkAbort>()
                .map(|c| c.tag_reflected)
                .or_else(|| {
                    any.downcast_ref::<ChunkShutdownComplete>()
                        .map(|c| c.tag_reflected)
                });
            if let Some(reflected) = reflected {
                return if reflected {
                    tag != 0 && tag == self.peer_verification_tag
                } else {
                    tag == self.my_verification_tag
                };
            }
        }
        tag == self.my_verification_tag
    }

    fn handle_chunk_start(&mut self) {
        self.delayed_ack_triggered = false;
        self.immediate_ack_triggered = false;
        self.pending_error_causes.clear();
        self.sack_packet_immediately = false;
        self.discard_rest_of_packet = false;
    }

    /// Queues an error cause for the ERROR chunk that answers the packet being processed.
    fn report_error(&mut self, cause: ErrorCause) {
        if self.pending_error_causes.len() < MAX_ERROR_CAUSES_PER_PACKET {
            self.pending_error_causes.push(cause);
        }
    }

    /// Sends the causes collected for this packet as one ERROR chunk, no larger than the MTU.
    fn flush_error_causes(&mut self) {
        if self.pending_error_causes.is_empty() || self.ended {
            self.pending_error_causes.clear();
            return;
        }
        let room = (self.mtu as usize)
            .saturating_sub(COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE)
            & !3;
        let mut used = 0;
        let mut causes = vec![];
        for mut cause in std::mem::take(&mut self.pending_error_causes) {
            let header = crate::chunk::ERROR_CAUSE_HEADER_LENGTH;
            if used + header >= room {
                break;
            }
            // A cause that quotes what was received (an unrecognized chunk) can be as large
            // as the packet it came in: it is cut to what fits.
            let fits = room - used - header;
            if cause.raw.len() > fits {
                cause.raw.truncate(fits);
            }
            used += cause.length() + get_padding_size(cause.length());
            causes.push(cause);
        }
        if !causes.is_empty() {
            let packet = self.create_packet(vec![Box::new(ChunkError {
                error_causes: causes,
            })]);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
        }
    }

    fn handle_chunk_end(&mut self, now: Instant) {
        self.flush_error_causes();
        if self.immediate_ack_triggered {
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
        } else if self.delayed_ack_triggered {
            // Will send delayed ack in the next ack timeout
            self.ack_state = AckState::Delay;
            self.timers.start(Timer::Ack, now, self.sack_delay);
        }
    }

    /// Handles one chunk. `Ok(false)` stops the processing of its packet: the chunks that
    /// follow are discarded.
    #[allow(clippy::borrowed_box)]
    fn handle_chunk(&mut self, p: &Packet, chunk: &Box<dyn Chunk>, now: Instant) -> Result<bool> {
        // A chunk that is not valid in itself (an INIT with a zero Initiate Tag, an a_rwnd
        // below the minimum) is discarded with the rest of its packet. It is no reason to
        // close an association: anyone who can reach this endpoint can send one.
        if let Err(err) = chunk.check() {
            warn!("[{}] discarding an invalid chunk: {}", self.side, err);
            if let Some(c) = chunk.as_any().downcast_ref::<ChunkInit>() {
                self.refuse_invalid_init(p, c, &err);
            }
            return Ok(false);
        }
        let chunk_any = chunk.as_any();
        // Anything but the handshake's own chunks comes from a peer past COOKIE-ECHOED
        // (RFC 9260 5.1 C: it sends nothing else until the COOKIE ACK arrives).
        if !chunk_any.is::<ChunkInit>() && !chunk_any.is::<ChunkCookieEcho>() {
            self.peer_awaits_cookie_ack = false;
        }
        let packets = if let Some(c) = chunk_any.downcast_ref::<ChunkInit>() {
            if c.is_ack {
                self.handle_init_ack(p, c, now)?
            } else {
                self.handle_init(p, c, now)?
            }
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkAbort>() {
            if let Some(cause) = c.error_causes.first() {
                self.abort_cause_code.get_or_insert(cause.code.0);
            }
            let mut err_str = String::new();
            for e in &c.error_causes {
                if matches!(e.code, USER_INITIATED_ABORT) {
                    debug!("User initiated abort received");
                    self.peer_abort_reason = Some(e.raw.clone());
                    // The peer aborted the association: its streams are lost with it, which
                    // is not the stream reset `Reset` reports for a channel's own close.
                    let _ = self.close(AssociationError::AssociationClosed);
                    return Ok(false);
                }
                err_str += &format!("({})", e);
            }
            return Err(Error::ErrAbortChunk(err_str));
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkError>() {
            self.handle_error(c, now);
            // RFC 9260 §3.3.10 (RFC 4960 §3.3.10): "An Operation Error is not considered fatal
            // in and of itself". Only an ABORT ends the association, so report the causes and
            // carry on with the rest of the packet.
            let mut err_str = String::new();
            for e in &c.error_causes {
                err_str += &format!("({})", e);
            }
            warn!(
                "[{}] received ERROR chunk, with following errors: {}",
                self.side, err_str
            );
            vec![]
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkHeartbeat>() {
            self.handle_heartbeat(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkHeartbeatAck>() {
            self.handle_heartbeat_ack(c, now);
            vec![]
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkCookieEcho>() {
            self.handle_cookie_echo(p, c, now)?
        } else if chunk_any.downcast_ref::<ChunkCookieAck>().is_some() {
            self.handle_cookie_ack(now)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkPayloadData>() {
            self.handle_data(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkSelectiveAck>() {
            match self.handle_sack(c, now) {
                Ok(packets) => packets,
                Err(err) => {
                    // RFC 9260 6.2.1, 12.4: a SACK that acknowledges a TSN this side never
                    // sent is a protocol violation, and the association is aborted. It was
                    // closed without telling the peer (or, for the cumulative TSN, ignored).
                    warn!("[{}] aborting on an invalid SACK: {}", self.side, err);
                    self.abort_with(
                        vec![Self::protocol_violation(
                            "SACK acknowledges a TSN that was not sent",
                        )],
                        AssociationError::TransportError,
                    )?;
                    return Ok(false);
                }
            }
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkReconfig>() {
            self.handle_reconfig(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkForwardTsn>() {
            self.handle_forward_tsn(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkIForwardTsn>() {
            self.handle_i_forward_tsn(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdown>() {
            self.handle_shutdown(c, now)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdownAck>() {
            self.handle_shutdown_ack(c)?
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkShutdownComplete>() {
            self.handle_shutdown_complete(c)?
        } else if chunk_any.downcast_ref::<ChunkPadding>().is_some() {
            // RFC 4820 section 3: the PAD chunk is discarded, and the rest of the packet is
            // processed.
            vec![]
        } else if let Some(c) = chunk_any.downcast_ref::<ChunkUnknown>() {
            return Ok(self.handle_unknown_chunk(c));
        } else {
            return Err(Error::ErrChunkTypeUnhandled);
        };

        if !packets.is_empty() {
            let mut buf: VecDeque<_> = packets.into_iter().collect();
            self.control_queue.append(&mut buf);
            self.awake_write_loop();
        }

        Ok(true)
    }

    /// RFC 9260 3.2: a chunk of an unrecognized type is handled by the upper two bits of the
    /// type. Returns whether the chunks after it are processed.
    fn handle_unknown_chunk(&mut self, c: &ChunkUnknown) -> bool {
        debug!(
            "[{}] unrecognized chunk type {}: {}{}",
            self.side,
            c.typ.0,
            if c.stops_processing() { "stop" } else { "skip" },
            if c.is_reported() { ", report" } else { "" },
        );
        if c.is_reported()
            && let Ok(raw) = c.marshal()
        {
            // The cause holds the chunk: type, flags, length and value.
            self.report_error(ErrorCause {
                code: UNRECOGNIZED_CHUNK_TYPE,
                raw,
            });
        }
        !c.stops_processing()
    }

    /// RFC 9260 3.3.2, 3.3.3: what follows the discarding of an INIT or INIT ACK that failed
    /// its checks. A zero Initiate Tag in an INIT is discarded silently. The other failures
    /// (a_rwnd below 1500, no outbound or no inbound streams) are answered with an ABORT sent
    /// to the chunk's Initiate Tag. The state of an existing association does not change,
    /// with the one exception the RFC makes: an INIT ACK in COOKIE-WAIT with a zero Initiate
    /// Tag or no streams is the answer to this side's INIT, and destroys the TCB.
    fn refuse_invalid_init(&mut self, p: &Packet, c: &ChunkInit, err: &Error) {
        let cause = ErrorCause {
            code: INVALID_MANDATORY_PARAMETER,
            ..Default::default()
        };
        let ends_handshake = c.is_ack
            && self.state() == AssociationState::CookieWait
            && (c.initiate_tag == 0 || c.num_outbound_streams == 0 || c.num_inbound_streams == 0);
        let abort = if c.initiate_tag != 0 {
            Some(self.abort_packet(c.initiate_tag, false, vec![cause]))
        } else if ends_handshake {
            // The peer gave no tag to send to: its own packet's tag is reflected.
            Some(self.abort_packet(p.common_header.verification_tag, true, vec![cause]))
        } else {
            None
        };
        if c.is_ack && self.state() != AssociationState::CookieWait {
            // RFC 9260 3.3.3: outside COOKIE-WAIT such an INIT ACK is discarded silently.
            return;
        }
        if let Some(mut abort) = abort {
            if !c.is_ack {
                // The answer to an INIT goes between the ports its packet came between.
                abort.common_header.source_port = p.common_header.destination_port;
                abort.common_header.destination_port = p.common_header.source_port;
            }
            self.control_queue.push_back(abort);
            self.awake_write_loop();
        }
        // An accepting association that was made for this INIT and has seen no valid one has
        // nothing to keep: it ends now and gives its place back.
        let unused_acceptor = !c.is_ack
            && self.side == Side::Server
            && self.state() == AssociationState::Closed
            && self.cookie_tcb.is_none();
        if ends_handshake || unused_acceptor {
            let reason = AssociationError::HandshakeFailed(err.to_string());
            self.error = Some(reason.clone());
            let _ = self.close(reason);
        }
    }

    /// RFC 9260 3.3.10: an ERROR is not fatal in itself. One cause is acted on: "Stale Cookie
    /// Error" in COOKIE-ECHOED (5.2.6), where the cookie this side echoed had outlived its
    /// lifetime. The setup is tried again with a new INIT, a bounded number of times.
    fn handle_error(&mut self, c: &ChunkError, now: Instant) {
        // RFC 9260 11.2.5 COMMUNICATION ERROR: the causes the peer's ERROR chunk carried.
        if !self.ended {
            self.events.push_back(Event::CommunicationError {
                causes: c
                    .error_causes
                    .iter()
                    .map(|e| (e.code, e.raw.clone()))
                    .collect(),
            });
        }
        // RFC 3758 3.3.3: a peer that reports the Forward-TSN-Supported parameter as
        // unrecognized does not do PR-SCTP: no FORWARD TSN for the life of the association.
        if c.error_causes
            .iter()
            .any(|e| e.code == UNRECOGNIZED_PARAMETERS && names_forward_tsn_supported(&e.raw))
            && self.use_forward_tsn
        {
            warn!("[{}] the peer does not support PR-SCTP", self.side);
            self.use_forward_tsn = false;
        }
        if self.state() != AssociationState::CookieEchoed
            || !c.error_causes.iter().any(|e| e.code == STALE_COOKIE_ERROR)
        {
            return;
        }
        self.timers.stop(Timer::T1Cookie);
        self.stored_cookie_echo = None;
        self.stale_cookie_restarts += 1;
        if self.stale_cookie_restarts > self.timers.max_retrans(Timer::T1Init) {
            let reason =
                AssociationError::HandshakeFailed(Error::ErrHandshakeCookieEcho.to_string());
            self.error = Some(reason.clone());
            let _ = self.close(reason);
            return;
        }
        debug!("[{}] stale cookie: sending a new INIT", self.side);
        // What the INIT ACK said is void with its cookie.
        self.peer_verification_tag = 0;
        let mut init = ChunkInit {
            initial_tsn: self.my_next_tsn,
            num_outbound_streams: self.configured_outbound_streams,
            num_inbound_streams: self.configured_inbound_streams,
            initiate_tag: self.my_verification_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            ..Default::default()
        };
        init.announce_extensions(
            self.partial_reliability_enabled,
            self.interleaving_enabled,
            self.zero_checksum_enabled,
        );
        // RFC 9260 5.2.6: "The endpoint MAY add a Cookie Preservative parameter requesting
        // an extension to the lifetime of the State Cookie. When calculating the time
        // extension, an implementation SHOULD use the RTT information measured based on the
        // previous COOKIE ECHO / ERROR exchange and SHOULD add no more than 1 second beyond
        // the measured RTT". The increment is what the cookie was late by (the Measure of
        // Staleness, in microseconds), at least that round trip and at most a second more.
        let rtt_ms = self
            .cookie_echo_sent_at
            .take()
            .map_or(0, |sent| now.saturating_duration_since(sent).as_millis())
            .min(u128::from(u32::MAX)) as u32;
        let staleness_ms = c
            .error_causes
            .iter()
            .find(|e| e.code == STALE_COOKIE_ERROR)
            .and_then(|e| e.raw.get(..4))
            .map_or(0, |b| {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]).div_ceil(1000)
            });
        let increment = staleness_ms
            .max(rtt_ms)
            .min(rtt_ms.saturating_add(1000))
            .max(1);
        init.params.push(Box::new(
            crate::param::param_cookie_preservative::ParamCookiePreservative {
                suggested_increment_ms: increment,
            },
        ));
        self.stored_init = Some(init);
        self.set_state(AssociationState::CookieWait);
        let _ = self.send_init();
        self.timers
            .start(Timer::T1Init, now, self.rto_mgr.get_rto());
    }

    /// Reads the optional parameters of a received INIT or INIT ACK (RFC 9260 3.3.2, 3.3.3).
    ///
    /// An unrecognized parameter is handled by the upper two bits of its type (RFC 9260
    /// 3.2.1): it ends the processing of the parameters after it or is skipped, and is
    /// reported or not.
    fn process_handshake_params(&self, params: &[Box<dyn Param>]) -> HandshakeParams {
        let mut out = HandshakeParams::default();
        for param in params {
            let any = param.as_any();
            if let Some(v) = any.downcast_ref::<ParamStateCookie>() {
                out.cookie = Some(v.cookie.clone());
            } else if let Some(v) = any.downcast_ref::<ParamSupportedExtensions>() {
                if v.chunk_types.contains(&CT_FORWARD_TSN) {
                    out.forward_tsn = true;
                }
                if v.chunk_types.contains(&CT_RECONFIG) {
                    out.reconfig = true;
                }
                if v.chunk_types.contains(&CT_I_DATA) {
                    out.i_data = true;
                }
                if v.chunk_types.contains(&CT_I_FORWARD_TSN) {
                    out.i_forward_tsn = true;
                }
            } else if any.downcast_ref::<ParamForwardTsnSupported>().is_some() {
                // RFC 3758 3.3.1: this parameter alone announces PR-SCTP.
                out.forward_tsn = true;
            } else if let Some(v) = any.downcast_ref::<ParamZeroChecksumAcceptable>() {
                // RFC 9653 4: the parameter appears once; a second one changes nothing.
                out.zero_checksum_edmid.get_or_insert(v.edmid);
            } else if let Some(v) = any.downcast_ref::<ParamUnknown>() {
                if v.typ() == PARAM_HOST_NAME_ADDRESS {
                    out.host_name = param.marshal().ok();
                    continue;
                }
                if v.typ() == UNRECOGNIZED_PARAMETER && names_forward_tsn_supported(v.value()) {
                    out.forward_tsn_rejected = true;
                }
                if IGNORED_HANDSHAKE_PARAMS.contains(&v.typ()) {
                    continue;
                }
                if v.is_reported()
                    && let Ok(raw) = param.marshal()
                {
                    out.unrecognized.push(raw);
                }
                if v.stops_processing() {
                    break;
                }
            }
        }
        out
    }

    fn handle_init(&mut self, p: &Packet, i: &ChunkInit, now: Instant) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] chunkInit received in state '{}'", self.side, state);

        if state == AssociationState::ShutdownAckSent {
            // RFC 9260 9.2: an INIT in SHUTDOWN-ACK-SENT (the SHUTDOWN COMPLETE was lost and
            // the peer starts over) is discarded and the SHUTDOWN ACK sent again.
            self.will_send_shutdown_ack = true;
            self.awake_write_loop();
            return Ok(vec![]);
        }
        if state != AssociationState::Closed
            && state != AssociationState::CookieWait
            && state != AssociationState::CookieEchoed
        {
            // RFC 9260 5.2.2: an unexpected INIT is answered and changes nothing. It used to
            // be an error, and an error closed the association: a late copy of the peer's own
            // INIT ended an established association.
            return Ok(vec![self.answer_unexpected_init(i, now)]);
        }

        let params = self.process_handshake_params(&i.params);
        if let Some(host_name) = params.host_name {
            // RFC 9260 5.1.2: an INIT with a Host Name Address is answered with an ABORT.
            debug!("[{}] INIT with a Host Name Address: ABORT", self.side);
            let mut abort = self.abort_packet(
                i.initiate_tag,
                false,
                vec![ErrorCause {
                    code: UNRESOLVABLE_ADDRESS,
                    raw: host_name,
                }],
            );
            abort.common_header.source_port = p.common_header.destination_port;
            abort.common_header.destination_port = p.common_header.source_port;
            if state == AssociationState::Closed && self.cookie_tcb.is_none() {
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeInitAck.to_string());
                self.error = Some(reason.clone());
                self.close(reason)?;
            }
            return Ok(vec![abort]);
        }

        // RFC 9260 5.1.1: this side sends on min(own OS, peer's MIS) streams and receives on
        // min(own MIS, peer's OS). Taken from the configured counts each time, so an INIT sent
        // again with other values is not narrowed by the one before it.
        let inbound_streams =
            std::cmp::min(i.num_outbound_streams, self.configured_inbound_streams);
        let outbound_streams =
            std::cmp::min(i.num_inbound_streams, self.configured_outbound_streams);
        let source_port = p.common_header.destination_port;
        let destination_port = p.common_header.source_port;

        // A State Cookie for this INIT: a new one for a new attempt (another Initiate Tag) or
        // when the one in hand has outlived its lifetime, the same one for an INIT sent again,
        // so that the cookie of an INIT ACK already under way stays good.
        // RFC 9260 5.2.1, 5.2.2: the Tie-Tags are 0 for an INIT in CLOSED or COOKIE-WAIT, and
        // this association's in COOKIE-ECHOED.
        let tie_tags = if state == AssociationState::CookieEchoed {
            self.tie_tags()
        } else {
            (0, 0)
        };
        let reuse = self.my_cookie.is_some()
            && state != AssociationState::CookieEchoed
            && self.cookie_tcb.as_ref().is_some_and(|tcb| {
                tcb.peer_verification_tag == i.initiate_tag
                    && now.saturating_duration_since(tcb.created_at) < self.valid_cookie_life
            });
        let created_at = match (&self.cookie_tcb, reuse) {
            (Some(tcb), true) => tcb.created_at,
            _ => now,
        };
        let tcb = CookieTcb {
            created_at,
            peer_verification_tag: i.initiate_tag,
            peer_initial_tsn: i.initial_tsn,
            peer_rwnd: i.advertised_receiver_window_credit,
            inbound_streams,
            outbound_streams,
            use_forward_tsn: self.negotiated_partial_reliability(&params),
            use_interleaving: self.negotiated_interleaving(&params),
            reconfig: params.reconfig,
            send_zero_checksum: self.may_send_zero_checksum(&params),
            source_port,
            destination_port,
        };

        // RFC 9260 5.2.1: in COOKIE-WAIT and COOKIE-ECHOED the INIT is answered with this
        // side's own INIT parameters and nothing in the TCB changes: what the INIT said is
        // kept with the cookie and taken when the cookie comes back. In CLOSED the accepting
        // association has no TCB to protect, and takes it now.
        if state == AssociationState::Closed {
            self.apply_cookie_tcb(&tcb);
            if !self.use_forward_tsn {
                warn!("[{}] not using ForwardTSN (on init)", self.side);
            }
        }
        if !reuse {
            // RFC 9260 5.1.3: the cookie holds what the association is made from, the time
            // it was made, and a MAC over both. Without a crypto provider to make the MAC
            // with, it is random bytes this association remembers.
            let sealed = self.cookie_signer.as_ref().and_then(|signer| {
                signer.seal(&self.cookie_fields(&tcb, signer.timestamp(now), tie_tags))
            });
            self.my_cookie = Some(match sealed {
                Some(cookie) => ParamStateCookie { cookie },
                None => ParamStateCookie::random(&self.random),
            });
        }
        self.cookie_tcb = Some(tcb);

        let mut init_ack = ChunkInit {
            is_ack: true,
            initial_tsn: self.my_next_tsn,
            num_outbound_streams: outbound_streams,
            num_inbound_streams: inbound_streams,
            initiate_tag: self.my_verification_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            ..Default::default()
        };

        if let Some(my_cookie) = &self.my_cookie {
            init_ack.params = vec![Box::new(my_cookie.clone())];
        }

        // RFC 9260 3.2.2, 3.3.3: the unrecognized parameters the INIT asked to hear about go
        // back in the INIT ACK, each in an Unrecognized Parameter parameter.
        for raw in params.unrecognized {
            init_ack
                .params
                .push(Box::new(ParamUnknown::new(UNRECOGNIZED_PARAMETER, raw)));
        }

        init_ack.announce_extensions(
            self.partial_reliability_enabled,
            self.interleaving_enabled,
            self.zero_checksum_enabled,
        );

        if state == AssociationState::Closed {
            // The accepting side holds this association from the INIT on. If no COOKIE ECHO
            // follows it must not be held for ever: every INIT restarts the wait.
            self.timers.stop(Timer::HalfOpen);
            self.timers.start(Timer::HalfOpen, now, HALF_OPEN_LIFETIME);
        }

        Ok(vec![Packet {
            common_header: CommonHeader {
                verification_tag: i.initiate_tag,
                source_port,
                destination_port,
            },
            chunks: vec![Box::new(init_ack)],
        }])
    }

    /// What a State Cookie made at `created_ms` says for `tcb` (RFC 9260 5.1.3).
    fn cookie_fields(
        &self,
        tcb: &CookieTcb,
        created_ms: u64,
        tie_tags: (u32, u32),
    ) -> CookieFields {
        CookieFields {
            key_id: 0,
            created_ms,
            my_tag: self.my_verification_tag,
            my_initial_tsn: self.my_next_tsn,
            peer_tag: tcb.peer_verification_tag,
            peer_initial_tsn: tcb.peer_initial_tsn,
            peer_rwnd: tcb.peer_rwnd,
            inbound_streams: tcb.inbound_streams,
            outbound_streams: tcb.outbound_streams,
            use_forward_tsn: tcb.use_forward_tsn,
            use_interleaving: tcb.use_interleaving,
            reconfig: tcb.reconfig,
            send_zero_checksum: tcb.send_zero_checksum,
            source_port: tcb.source_port,
            destination_port: tcb.destination_port,
            local_tie_tag: tie_tags.0,
            peer_tie_tag: tie_tags.1,
        }
    }

    /// This association's Tie-Tags, drawn the first time they are needed (RFC 9260 5.2.2:
    /// "populated with a random value other than 0").
    fn tie_tags(&mut self) -> (u32, u32) {
        if self.local_tie_tag == 0 {
            self.local_tie_tag = self.random.nonzero_u32();
            self.peer_tie_tag = self.random.nonzero_u32();
        }
        (self.local_tie_tag, self.peer_tie_tag)
    }

    /// RFC 9653 5.2: this side sends a zero checksum when the peer announced that it takes
    /// one for an error detection method this side uses, which is SCTP over DTLS, and the
    /// application said the association runs over DTLS (`TransportConfig::with_zero_checksum`).
    fn may_send_zero_checksum(&self, params: &HandshakeParams) -> bool {
        self.zero_checksum_enabled && params.zero_checksum_edmid == Some(EDMID_SCTP_OVER_DTLS)
    }

    /// Whether packets are sent with a zero checksum (RFC 9653): both sides announced that
    /// they take one over DTLS.
    pub fn zero_checksum(&self) -> bool {
        self.send_zero_checksum
    }

    /// Serializes a packet. Its CRC32c is left out when the peer takes a zero checksum,
    /// except where RFC 9653 5.2 asks for a correct one: a packet with an INIT or a COOKIE
    /// ECHO, and one that answers an out-of-the-blue packet (it reflects a tag, or does not
    /// carry the peer's).
    fn marshal_packet(&self, p: &Packet) -> Result<Bytes> {
        let zero = self.send_zero_checksum
            && p.common_header.verification_tag == self.peer_verification_tag
            && p.chunks.iter().all(|c| {
                let any = c.as_any();
                !any.is::<ChunkCookieEcho>()
                    && any.downcast_ref::<ChunkInit>().is_none_or(|i| i.is_ack)
                    && any
                        .downcast_ref::<ChunkAbort>()
                        .is_none_or(|a| !a.tag_reflected)
                    && any
                        .downcast_ref::<ChunkShutdownComplete>()
                        .is_none_or(|s| !s.tag_reflected)
            });
        p.marshal_with(zero)
    }

    /// Has this association make its State Cookies with a MAC.
    pub(crate) fn set_cookie_signer(&mut self, signer: Arc<CookieSigner>) {
        self.cookie_signer = Some(signer);
    }

    /// Makes this association what it was when it answered an INIT with the State Cookie
    /// `cookie`, whose MAC the endpoint has verified: nothing was kept since, and the
    /// cookie says it all (RFC 9260 5.1.3, 5.1.5). The COOKIE ECHO is then handled as if the
    /// association had been there all along.
    pub(crate) fn restore_from_cookie(
        &mut self,
        fields: &CookieFields,
        cookie: Bytes,
        signer: Arc<CookieSigner>,
        now: Instant,
    ) {
        let tsn = fields.my_initial_tsn;
        self.my_next_tsn = tsn;
        self.my_next_rsn = tsn;
        self.min_tsn2measure_rtt = tsn;
        self.cumulative_tsn_ack_point = tsn.wrapping_sub(1);
        self.advanced_peer_tsn_ack_point = tsn.wrapping_sub(1);
        let age = signer.age(fields, now);
        let tcb = CookieTcb {
            created_at: now.checked_sub(age).unwrap_or(now),
            peer_verification_tag: fields.peer_tag,
            peer_initial_tsn: fields.peer_initial_tsn,
            peer_rwnd: fields.peer_rwnd,
            inbound_streams: fields.inbound_streams,
            outbound_streams: fields.outbound_streams,
            use_forward_tsn: fields.use_forward_tsn,
            use_interleaving: fields.use_interleaving,
            reconfig: fields.reconfig,
            send_zero_checksum: fields.send_zero_checksum,
            source_port: fields.source_port,
            destination_port: fields.destination_port,
        };
        self.apply_cookie_tcb(&tcb);
        self.cookie_tcb = Some(tcb);
        self.my_cookie = Some(ParamStateCookie { cookie });
        self.cookie_signer = Some(signer);
    }

    /// Takes into the TCB what the peer's INIT said (RFC 9260 5.1 B, 5.2.4 B).
    fn apply_cookie_tcb(&mut self, tcb: &CookieTcb) {
        self.my_max_num_inbound_streams = tcb.inbound_streams;
        self.my_max_num_outbound_streams = tcb.outbound_streams;
        self.peer_verification_tag = tcb.peer_verification_tag;
        self.source_port = tcb.source_port;
        self.destination_port = tcb.destination_port;

        // 13.2 This is the last TSN received in sequence.  This value
        // is set initially by taking the peer's initial TSN,
        // received in the INIT or INIT ACK chunk, and
        // subtracting one from it.
        self.peer_last_tsn = tcb.peer_initial_tsn.wrapping_sub(1);

        // Adopt the peer's advertised receive window and seed ssthresh from it,
        // mirroring handle_init_ack (and Pion's shared init path). RFC 4960
        // §7.2.1 (Slow-Start) permits initialising ssthresh to the advertised
        // receiver window; without this the answerer keeps ssthresh at its
        // initial 0, so cwnd never starts below it, slow-start never runs, and
        // cwnd only grows linearly under congestion avoidance (§7.2.2).
        self.rwnd = tcb.peer_rwnd;
        debug!("[{}] initial rwnd={}", self.side, self.rwnd);
        self.ssthresh = self.rwnd;
        self.use_forward_tsn = tcb.use_forward_tsn;
        self.set_interleaving(tcb.use_interleaving);
        self.peer_supports_reconfig = tcb.reconfig;
        self.send_zero_checksum = tcb.send_zero_checksum;
        // RFC 6525 4.1: the peer's request sequence numbers start at its initial TSN.
        self.peer_rsn_window = Some((tcb.peer_initial_tsn, tcb.peer_initial_tsn));
    }

    /// RFC 9260 5.2.2: the INIT ACK for an INIT that arrives while the association exists. It
    /// goes to the INIT's Initiate Tag and carries a new one of its own; the association and
    /// its TCB stay as they are.
    ///
    /// Its State Cookie stands for a new association with the peer as the INIT describes it,
    /// this side's new tag and initial TSN, and this association's Tie-Tags: a COOKIE ECHO
    /// that brings it back is a restart (5.2.4 action A). With a cookie signer it is sealed
    /// and nothing is kept; without one it is kept beside the association's own cookie.
    fn answer_unexpected_init(&mut self, i: &ChunkInit, now: Instant) -> Packet {
        let initiate_tag = self.random.nonzero_u32();
        let initial_tsn = self.random.nonzero_u32();
        let tie_tags = self.tie_tags();
        let params = self.process_handshake_params(&i.params);
        // 5.2.2: the other parameters are the association's.
        let tcb = CookieTcb {
            created_at: now,
            peer_verification_tag: i.initiate_tag,
            peer_initial_tsn: i.initial_tsn,
            peer_rwnd: i.advertised_receiver_window_credit,
            inbound_streams: std::cmp::min(i.num_outbound_streams, self.my_max_num_inbound_streams),
            outbound_streams: std::cmp::min(
                i.num_inbound_streams,
                self.my_max_num_outbound_streams,
            ),
            use_forward_tsn: self.negotiated_partial_reliability(&params),
            use_interleaving: self.negotiated_interleaving(&params),
            reconfig: params.reconfig,
            send_zero_checksum: self.may_send_zero_checksum(&params),
            source_port: self.source_port,
            destination_port: self.destination_port,
        };
        let fields = |created_ms| {
            let mut fields = self.cookie_fields(&tcb, created_ms, tie_tags);
            fields.my_tag = initiate_tag;
            fields.my_initial_tsn = initial_tsn;
            fields
        };
        let cookie = match self.cookie_signer.clone() {
            Some(signer) => {
                let sealed = signer.seal(&fields(signer.timestamp(now)));
                sealed.unwrap_or_else(|| ParamStateCookie::random(&self.random).cookie)
            }
            None => {
                let cookie = ParamStateCookie::random(&self.random).cookie;
                let kept = fields(0);
                self.restart_cookie = Some((cookie.clone(), kept, now));
                cookie
            }
        };
        let mut init_ack = ChunkInit {
            is_ack: true,
            initial_tsn,
            num_outbound_streams: self.my_max_num_outbound_streams,
            num_inbound_streams: self.my_max_num_inbound_streams,
            initiate_tag,
            advertised_receiver_window_credit: self.max_receive_buffer_size,
            params: vec![Box::new(ParamStateCookie { cookie })],
        };
        init_ack.announce_extensions(
            self.partial_reliability_enabled,
            self.interleaving_enabled,
            self.zero_checksum_enabled,
        );
        Packet {
            common_header: CommonHeader {
                verification_tag: i.initiate_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(init_ack)],
        }
    }

    /// The cookie of a COOKIE ECHO, if it is one of this association's restart cookies
    /// (RFC 9260 5.2.4, Table 12 row A): the tags of a new association, both unlike this
    /// association's, and this association's Tie-Tags. With when it was made.
    fn restart_cookie_fields(
        &self,
        cookie: &[u8],
        now: Instant,
    ) -> Option<(CookieFields, Instant)> {
        if self.local_tie_tag == 0
            || !matches!(
                self.state(),
                AssociationState::Established
                    | AssociationState::ShutdownPending
                    | AssociationState::ShutdownSent
                    | AssociationState::ShutdownReceived
                    | AssociationState::ShutdownAckSent
            )
        {
            return None;
        }
        let (fields, created_at) = match &self.cookie_signer {
            Some(signer) => {
                let fields = signer.open(cookie)?;
                let age = signer.age(&fields, now);
                (fields, now.checked_sub(age).unwrap_or(now))
            }
            None => {
                let (kept, fields, created_at) = self.restart_cookie.as_ref()?;
                if !constant_time_eq(kept, cookie) {
                    return None;
                }
                (fields.clone(), *created_at)
            }
        };
        let row_a = fields.my_tag != self.my_verification_tag
            && fields.peer_tag != self.peer_verification_tag
            && fields.local_tie_tag == self.local_tie_tag
            && fields.peer_tie_tag == self.peer_tie_tag;
        row_a.then_some((fields, created_at))
    }

    /// RFC 9260 5.2.4 action A: the peer restarted. Handled as an ABORT followed by a new
    /// COOKIE ECHO: everything of the old association goes (streams, queues, timers, the
    /// reconfiguration state; the DATA is not retained, which 5.2.4 leaves open: a peer
    /// that restarted has none of the old streams), the TCB comes from the cookie,
    /// congestion control and the RTO from their initial values, and the association is
    /// ESTABLISHED. In SHUTDOWN-ACK-SENT no new association is made: the SHUTDOWN ACK is
    /// sent again with an ERROR "Cookie Received While Shutting Down".
    fn handle_restart_cookie(
        &mut self,
        p: &Packet,
        fields: CookieFields,
        created_at: Instant,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        // 5.1.5 3): the packet's tag and ports are those the cookie was made for.
        if p.common_header.verification_tag != fields.my_tag
            || p.common_header.source_port != fields.destination_port
            || p.common_header.destination_port != fields.source_port
        {
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        }
        let to_peer = |chunk: Box<dyn Chunk + Send + Sync>| Packet {
            common_header: CommonHeader {
                verification_tag: fields.peer_tag,
                source_port: fields.source_port,
                destination_port: fields.destination_port,
            },
            chunks: vec![chunk],
        };
        // 5.2.4 3): a stale restart cookie (its tags are not the association's) is refused
        // with an ERROR "Stale Cookie".
        let age = now.saturating_duration_since(created_at);
        if age > self.valid_cookie_life {
            let staleness =
                u32::try_from((age - self.valid_cookie_life).as_micros()).unwrap_or(u32::MAX);
            self.discard_rest_of_packet = true;
            return Ok(vec![to_peer(Box::new(ChunkError {
                error_causes: vec![ErrorCause {
                    code: STALE_COOKIE_ERROR,
                    raw: Bytes::copy_from_slice(&staleness.to_be_bytes()),
                }],
            }))]);
        }
        if self.state() == AssociationState::ShutdownAckSent {
            debug!(
                "[{}] COOKIE ECHO of a restart in SHUTDOWN-ACK-SENT: no new association",
                self.side
            );
            self.discard_rest_of_packet = true;
            self.will_send_shutdown_ack = true;
            self.awake_write_loop();
            return Ok(vec![to_peer(Box::new(ChunkError {
                error_causes: vec![ErrorCause {
                    code: COOKIE_RECEIVED_WHILE_SHUTTING_DOWN,
                    raw: Bytes::new(),
                }],
            }))]);
        }
        if !self.restart(&fields, created_at, now) {
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        }
        Ok(vec![Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(ChunkCookieAck {})],
        }])
    }

    /// Replaces this association with the one the restart cookie `fields` describes.
    /// Returns false when it cannot (an association not made by `new`).
    fn restart(&mut self, fields: &CookieFields, created_at: Instant, now: Instant) -> bool {
        let Some(config) = self.transport_config.clone() else {
            return false;
        };
        let old_tag = self.my_verification_tag;
        let old_peer_tag = self.peer_verification_tag;
        let random = std::mem::take(&mut self.random);
        let mut fresh = Association::new(
            None,
            config,
            self.max_payload_size,
            fields.my_tag,
            self.remote_addr,
            self.local_addr,
            self.transport_protocol,
            now,
            random,
        );
        // `new` made an initiating association: it is an accepting one, made from the
        // cookie, as `Endpoint::accept_cookie_echo` makes one.
        fresh.side = self.side;
        fresh.stored_init = None;
        fresh.control_queue.clear();
        fresh.timers.stop(Timer::T1Init);
        fresh.timers.stop(Timer::HalfOpen);
        fresh.mtu = self.mtu;
        // The path is the same: its discovery starts over from the same base.
        if let Some(pmtud) = &self.pmtud {
            fresh.pmtud = Some(pmtud::PathMtuDiscovery::new(*pmtud.config(), pmtud.base()));
            fresh.use_path_mtu(pmtud.base(), true);
        }
        fresh.cookie_signer = self.cookie_signer.clone();
        let tsn = fields.my_initial_tsn;
        fresh.my_next_tsn = tsn;
        fresh.my_next_rsn = tsn;
        fresh.min_tsn2measure_rtt = tsn;
        fresh.cumulative_tsn_ack_point = tsn.wrapping_sub(1);
        fresh.advanced_peer_tsn_ack_point = tsn.wrapping_sub(1);
        let tcb = CookieTcb {
            created_at,
            peer_verification_tag: fields.peer_tag,
            peer_initial_tsn: fields.peer_initial_tsn,
            peer_rwnd: fields.peer_rwnd,
            inbound_streams: fields.inbound_streams,
            outbound_streams: fields.outbound_streams,
            use_forward_tsn: fields.use_forward_tsn,
            use_interleaving: fields.use_interleaving,
            reconfig: fields.reconfig,
            send_zero_checksum: fields.send_zero_checksum,
            source_port: fields.source_port,
            destination_port: fields.destination_port,
        };
        fresh.apply_cookie_tcb(&tcb);
        fresh.cookie_tcb = Some(tcb);
        fresh.handshake_completed = true;
        fresh.set_state(AssociationState::Established);
        fresh.start_heartbeat_timer(now);
        // 5.1.5 7): DATA that came with the COOKIE ECHO is acknowledged at once.
        fresh.sack_packet_immediately = true;
        // What the application has not read of the old association's events stays, and the
        // restart follows it.
        // The old association's streams are gone: what each had sent is kept, for the
        // application to settle its own accounts of them (`streams_lost_in_restart`,
        // `stream_bytes_dequeued`).
        let mut lost: Vec<(StreamId, u64)> = self
            .streams
            .iter()
            .map(|(id, s)| (*id, s.bytes_dequeued))
            .collect();
        lost.sort_unstable();
        fresh.closed_stream_bytes_dequeued = std::mem::take(&mut self.closed_stream_bytes_dequeued);
        fresh
            .closed_stream_bytes_dequeued
            .extend(lost.iter().copied());
        fresh.streams_lost_in_restart = lost;
        fresh.events = std::mem::take(&mut self.events);
        fresh.events.push_back(Event::Restarted);
        fresh.endpoint_events = std::mem::take(&mut self.endpoint_events);
        fresh
            .endpoint_events
            .push_back(EndpointEventInner::Retagged {
                old_local: old_tag,
                new_local: fields.my_tag,
                old_peer: old_peer_tag,
                new_peer: fields.peer_tag,
            });
        debug!(
            "[{}] the peer restarted the association: tag {:#x} -> {:#x}",
            self.side, old_tag, fields.my_tag
        );
        *self = fresh;
        true
    }

    fn handle_init_ack(
        &mut self,
        p: &Packet,
        i: &ChunkInitAck,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] chunkInitAck received in state '{}'", self.side, state);
        if state != AssociationState::CookieWait {
            // RFC 4960
            // 5.2.3.  Unexpected INIT ACK
            //   If an INIT ACK is received by an endpoint in any state other than the
            //   COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
            //   An unexpected INIT ACK usually indicates the processing of an old or
            //   duplicated INIT chunk.
            return Ok(vec![]);
        }

        // Checked before anything is taken from the chunk: an INIT ACK between other ports
        // is not this association's.
        if self.source_port != p.common_header.destination_port
            || self.destination_port != p.common_header.source_port
        {
            warn!("[{}] handle_init_ack: port mismatch", self.side);
            return Ok(vec![]);
        }

        // RFC 9260 5.1.1: own OS against the peer's MIS, own MIS against the peer's OS.
        self.my_max_num_inbound_streams =
            std::cmp::min(i.num_outbound_streams, self.configured_inbound_streams);
        self.my_max_num_outbound_streams =
            std::cmp::min(i.num_inbound_streams, self.configured_outbound_streams);
        self.peer_verification_tag = i.initiate_tag;
        self.peer_last_tsn = i.initial_tsn.wrapping_sub(1);

        self.rwnd = i.advertised_receiver_window_credit;
        debug!("[{}] initial rwnd={}", self.side, self.rwnd);

        // RFC 4690 Sec 7.2.1
        //  o  The initial value of ssthresh MAY be arbitrarily high (for
        //     example, implementations MAY use the size of the receiver
        //     advertised window).
        self.ssthresh = self.rwnd;
        trace!(
            "[{}] updated cwnd={} ssthresh={} inflight={} (INI)",
            self.side,
            self.cwnd,
            self.ssthresh,
            self.inflight_queue.get_num_bytes()
        );

        self.timers.stop(Timer::T1Init);
        self.stored_init = None;

        let params = self.process_handshake_params(&i.params);
        // RFC 3758 3.3.2, 3.3.3: PR-SCTP is used when the peer announced it too, and not when
        // the peer reported this side's Forward-TSN-Supported parameter as unrecognized.
        self.use_forward_tsn = self.negotiated_partial_reliability(&params);
        self.set_interleaving(self.negotiated_interleaving(&params));
        self.send_zero_checksum = self.may_send_zero_checksum(&params);
        if !self.use_forward_tsn {
            warn!("[{}] not using ForwardTSN (on initAck)", self.side);
        }
        self.peer_supports_reconfig = params.reconfig;
        // RFC 6525 4.1: the peer's request sequence numbers start at its initial TSN.
        self.peer_rsn_window = Some((i.initial_tsn, i.initial_tsn));

        if let Some(host_name) = params.host_name {
            // RFC 9260 3.3.3, 5.1.2: an INIT ACK with a Host Name Address is answered with
            // an ABORT, and the attempt is over.
            let reason = AssociationError::HandshakeFailed(Error::ErrHandshakeInitAck.to_string());
            self.error = Some(reason.clone());
            self.abort_with(
                vec![ErrorCause {
                    code: UNRESOLVABLE_ADDRESS,
                    raw: host_name,
                }],
                reason,
            )?;
            return Ok(vec![]);
        }

        let Some(cookie) = params.cookie else {
            // RFC 9260 3.3.3: the State Cookie is mandatory. An INIT ACK without one cannot
            // be answered: ABORT "Missing Mandatory Parameter" (one parameter, type 7), and
            // the attempt is over.
            let mut raw = BytesMut::with_capacity(6);
            raw.extend_from_slice(&1u32.to_be_bytes());
            raw.extend_from_slice(&PARAM_STATE_COOKIE.to_be_bytes());
            let reason = AssociationError::HandshakeFailed(Error::ErrInitAckNoCookie.to_string());
            self.error = Some(reason.clone());
            self.abort_with(
                vec![ErrorCause {
                    code: MISSING_MANDATORY_PARAMETER,
                    raw: raw.freeze(),
                }],
                reason,
            )?;
            return Ok(vec![]);
        };

        self.stored_cookie_echo = Some(ChunkCookieEcho { cookie });

        if params.unrecognized.is_empty() {
            self.send_cookie_echo()?;
        } else {
            // RFC 9260 3.2.2, 3.3.3: the unrecognized parameters the INIT ACK asked to
            // hear about are reported in an ERROR chunk bundled with the COOKIE ECHO,
            // which stays the first chunk of the packet. A retransmission carries the
            // COOKIE ECHO alone.
            let mut raw = BytesMut::new();
            for (n, param) in params.unrecognized.iter().enumerate() {
                raw.extend_from_slice(param);
                if n + 1 != params.unrecognized.len() {
                    raw.extend_from_slice(&[0u8; 3][..get_padding_size(param.len())]);
                }
            }
            let error = ChunkError {
                error_causes: vec![ErrorCause {
                    code: UNRECOGNIZED_PARAMETERS,
                    raw: raw.freeze(),
                }],
            };
            let cookie_echo = self
                .stored_cookie_echo
                .clone()
                .ok_or(Error::ErrCookieEchoNotStoredToSend)?;
            let packet = self.create_packet(vec![Box::new(cookie_echo), Box::new(error)]);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
        }

        self.timers
            .start(Timer::T1Cookie, now, self.rto_mgr.get_rto());
        self.cookie_echo_sent_at = Some(now);

        self.set_state(AssociationState::CookieEchoed);

        Ok(vec![])
    }

    fn handle_heartbeat(&self, c: &ChunkHeartbeat) -> Result<Vec<Packet>> {
        trace!("[{}] chunkHeartbeat", self.side);
        // RFC 9260 5.1 C: in COOKIE-WAIT and COOKIE-ECHOED, "until the COOKIE ACK chunk is
        // returned, the sender MUST NOT send any other packets to the peer" (than the INIT and
        // the COOKIE ECHO). A HEARTBEAT (or a path MTU probe) from a peer that is ESTABLISHED
        // while its COOKIE ACK to this side was lost is not answered: the answer told the peer
        // this side was up when it was not.
        if matches!(
            self.state(),
            AssociationState::CookieWait | AssociationState::CookieEchoed
        ) {
            debug!(
                "[{}] HEARTBEAT before the COOKIE ACK: not answered",
                self.side
            );
            return Ok(vec![]);
        }
        // RFC 9260 5.1 C: in COOKIE-WAIT and COOKIE-ECHOED, "until the COOKIE ACK chunk is
        // returned, the sender MUST NOT send any other packets to the peer" (than the INIT and
        // the COOKIE ECHO). A HEARTBEAT (or a path MTU probe) from a peer that is ESTABLISHED
        // while its COOKIE ACK to this side was lost is not answered: the answer also told the
        // peer this side was up when it was not.
        if matches!(
            self.state(),
            AssociationState::CookieWait | AssociationState::CookieEchoed
        ) {
            debug!(
                "[{}] HEARTBEAT before the COOKIE ACK: not answered",
                self.side
            );
            return Ok(vec![]);
        }
        if let Some(p) = c.params.first() {
            if let Some(hbi) = p.as_any().downcast_ref::<ParamHeartbeatInfo>() {
                return Ok(vec![Packet {
                    common_header: CommonHeader {
                        verification_tag: self.peer_verification_tag,
                        source_port: self.source_port,
                        destination_port: self.destination_port,
                    },
                    chunks: vec![Box::new(ChunkHeartbeatAck {
                        params: vec![Box::new(ParamHeartbeatInfo {
                            heartbeat_information: hbi.heartbeat_information.clone(),
                        })],
                    })],
                }]);
            } else {
                warn!(
                    "[{}] failed to handle Heartbeat, no ParamHeartbeatInfo",
                    self.side,
                );
            }
        }

        Ok(vec![])
    }

    /// RFC 9260 5.1.5 and 5.2.4: a COOKIE ECHO.
    ///
    /// An association handles the COOKIE ECHO for a cookie it sent itself and remembers
    /// (`my_cookie`, with what it stands for in `cookie_tcb`): the cookie echoed is compared
    /// with it in constant time, and its creation time and the peer's tag and ports are
    /// checked from the kept copy. That is so in two cases. Without a crypto provider
    /// (`ServerConfig::cookie_authentication`) the accepting association exists from the
    /// INIT on (see `HALF_OPEN_LIFETIME`) and the cookie is 32 random bytes. With one, the
    /// endpoint keeps nothing after the INIT ACK: the cookie is a MAC-protected TCB
    /// (`crate::cookie`), the endpoint verifies it and makes this association from it
    /// (`restore_from_cookie`) just before handing it the COOKIE ECHO, and the MAC is
    /// verified here once more.
    ///
    /// With one cookie per association there is no cookie whose tags differ from the TCB's,
    /// so of Table 12 only the actions for matching tags arise: B and D (enter or stay in
    /// ESTABLISHED, send COOKIE ACK) for the cookie in hand, and the silent discard of C for
    /// any other. Restarting an association (action A) is not supported.
    fn handle_cookie_echo(
        &mut self,
        p: &Packet,
        c: &ChunkCookieEcho,
        now: Instant,
    ) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] COOKIE-ECHO received in state '{}'", self.side, state);

        // RFC 9260 5.2.4, Table 12 row A: the cookie of an INIT ACK that answered an
        // unexpected INIT, with this association's Tie-Tags: the peer restarted.
        if let Some((fields, created_at)) = self.restart_cookie_fields(&c.cookie, now) {
            return self.handle_restart_cookie(p, fields, created_at, now);
        }

        // RFC 9260 5.1.5 2), 3): a cookie that is not the one sent, or that comes between
        // other ports, has its whole packet discarded, DATA included.
        let (Some(my_cookie), Some(tcb)) = (&self.my_cookie, self.cookie_tcb.clone()) else {
            debug!("[{}] COOKIE-ECHO received before initialization", self.side);
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        };
        // 5.1.5 1), 2): the MAC is computed over the cookie and compared with the one it
        // carries; a cookie that fails is discarded silently.
        if let Some(signer) = &self.cookie_signer
            && signer.open(&c.cookie).is_none()
        {
            debug!("[{}] COOKIE-ECHO: the MAC does not verify", self.side);
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        }
        if !constant_time_eq(&my_cookie.cookie, &c.cookie)
            || p.common_header.source_port != tcb.destination_port
            || p.common_header.destination_port != tcb.source_port
        {
            self.discard_rest_of_packet = true;
            return Ok(vec![]);
        }

        match state {
            AssociationState::Closed
            | AssociationState::CookieWait
            | AssociationState::CookieEchoed => {
                // RFC 9260 5.1.5 4): past its lifetime the cookie is refused with an ERROR
                // "Stale Cookie", which tells the peer by how many microseconds.
                let age = now.saturating_duration_since(tcb.created_at);
                if age > self.valid_cookie_life {
                    let staleness = (age - self.valid_cookie_life).as_micros();
                    let staleness = u32::try_from(staleness).unwrap_or(u32::MAX);
                    self.discard_rest_of_packet = true;
                    return Ok(vec![Packet {
                        common_header: CommonHeader {
                            verification_tag: tcb.peer_verification_tag,
                            source_port: tcb.source_port,
                            destination_port: tcb.destination_port,
                        },
                        chunks: vec![Box::new(ChunkError {
                            error_causes: vec![ErrorCause {
                                code: STALE_COOKIE_ERROR,
                                raw: Bytes::copy_from_slice(&staleness.to_be_bytes()),
                            }],
                        })],
                    }]);
                }

                // RFC 9260 5.2.4 B: after an INIT collision the peer's tag is the one that
                // came with this cookie.
                if state != AssociationState::Closed {
                    self.apply_cookie_tcb(&tcb);
                }

                self.timers.stop(Timer::T1Init);
                self.stored_init = None;

                self.timers.stop(Timer::T1Cookie);
                self.stored_cookie_echo = None;
                self.timers.stop(Timer::HalfOpen);

                self.events.push_back(Event::Connected);
                self.set_state(AssociationState::Established);
                self.handshake_completed = true;
                self.peer_awaits_cookie_ack = true;
                self.start_heartbeat_timer(now);
                // RFC 9260 5.1.5 7): DATA that came with the COOKIE ECHO is acknowledged
                // at once.
                self.sack_packet_immediately = true;
            }
            // RFC 9260 5.2.4 D, and case E of 5.2: the cookie of the association that exists
            // (the COOKIE ACK was lost) is acknowledged again, whatever its age.
            AssociationState::Established => {
                let mut chunks: Vec<Box<dyn Chunk>> = vec![Box::new(ChunkCookieAck {})];
                for data in self.outstanding_data_after_a_cookie_ack(now)? {
                    chunks.push(Box::new(data));
                }
                return Ok(vec![Packet {
                    common_header: CommonHeader {
                        verification_tag: self.peer_verification_tag,
                        source_port: self.source_port,
                        destination_port: self.destination_port,
                    },
                    chunks,
                }]);
            }
            _ => {}
        };

        Ok(vec![Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks: vec![Box::new(ChunkCookieAck {})],
        }])
    }

    /// The DATA that goes after the COOKIE ACK answering a duplicate COOKIE ECHO in
    /// ESTABLISHED: the earliest outstanding chunks that fit the packet with it, sent again.
    ///
    /// The duplicate says the peer is still in COOKIE-ECHOED: it did not receive the COOKIE
    /// ACK, and it discarded what DATA reached it (RFC 9260 5.1, "SHOULD discard" in
    /// COOKIE-ECHOED), so what is outstanding is waiting for T3-rtx, whose RTO those discards
    /// have backed off. RFC 9260 5.1 D lets DATA come with the COOKIE ACK, and the peer takes
    /// the packet's COOKIE ACK first (5.1 E), so this DATA arrives in ESTABLISHED. It counts as
    /// a retransmission: no round trip is measured with it (6.3.1 C5), and partially reliable
    /// DATA whose retransmissions are spent is abandoned instead (RFC 3758 3.5 A3).
    fn outstanding_data_after_a_cookie_ack(
        &mut self,
        now: Instant,
    ) -> Result<Vec<ChunkPayloadData>> {
        // The common header and the COOKIE ACK chunk (a 4-byte chunk header).
        let mut size = COMMON_HEADER_SIZE as usize + 4;
        let mut chosen = vec![];
        let mut tsn = self.cumulative_tsn_ack_point.wrapping_add(1);
        while sna32lt(tsn, self.my_next_tsn) {
            let outstanding = self
                .inflight_queue
                .get(tsn)
                .is_some_and(|c| c.is_outstanding() && c.nsent > 0);
            if outstanding && !self.abandon_retransmit_candidate(tsn, now)? {
                let Some(c) = self.inflight_queue.get(tsn) else {
                    break;
                };
                if size + c.wire_size() > self.mtu as usize {
                    break;
                }
                size += c.wire_size();
                chosen.push(tsn);
            }
            tsn = tsn.wrapping_add(1);
        }
        let mut chunks = vec![];
        for tsn in chosen {
            if let Some(c) = self.inflight_queue.get_mut(tsn)
                && c.is_outstanding()
            {
                c.retransmit = false;
                c.nsent += 1;
                self.stats.inc_retransmissions();
                if !matches!(c.reliability, MessageReliability::Reliable) {
                    self.stats.inc_partially_reliable_retransmissions();
                }
                chunks.push(c.clone());
            }
        }
        if !chunks.is_empty() {
            debug!(
                "[{}] COOKIE ACK again, with {} outstanding DATA chunk(s)",
                self.side,
                chunks.len()
            );
            self.min_tsn2measure_rtt = self.my_next_tsn;
        }
        Ok(chunks)
    }

    fn handle_cookie_ack(&mut self, now: Instant) -> Result<Vec<Packet>> {
        let state = self.state();
        debug!("[{}] COOKIE-ACK received in state '{}'", self.side, state);
        if state != AssociationState::CookieEchoed {
            // RFC 4960
            // 5.2.5.  Handle Duplicate COOKIE-ACK.
            //   At any state other than COOKIE-ECHOED, an endpoint should silently
            //   discard a received COOKIE ACK chunk.
            return Ok(vec![]);
        }

        self.timers.stop(Timer::T1Cookie);
        self.stored_cookie_echo = None;

        self.events.push_back(Event::Connected);
        self.set_state(AssociationState::Established);
        self.handshake_completed = true;
        self.start_heartbeat_timer(now);

        Ok(vec![])
    }

    /// The time a HEARTBEAT is sent after the path went idle: RTO + HB.interval, with a
    /// jitter of up to half an RTO either way (RFC 9260 8.3).
    fn heartbeat_period(&self) -> Option<Duration> {
        let interval = self.heartbeat_interval?;
        let rto = self.rto_mgr.get_rto();
        let jitter = u64::from(self.random.u32()) % (rto + 1);
        Some(interval + Duration::from_millis(rto / 2 + jitter))
    }

    /// RFC 9260 8.3: HEARTBEATs start when the association is established.
    fn start_heartbeat_timer(&mut self, now: Instant) {
        self.heartbeat_outstanding = None;
        match self.heartbeat_period() {
            Some(period) => self.timers.set(Timer::Heartbeat, Some(now + period)),
            None => self.timers.stop(Timer::Heartbeat),
        }
    }

    /// The heartbeat timer expired: either the wait for the path to be idle is over and a
    /// HEARTBEAT goes out, or the HEARTBEAT that went out has not been answered within an
    /// RTO.
    fn on_heartbeat_timeout(&mut self, now: Instant) {
        if !self.may_send_heartbeat() {
            return;
        }

        if self.heartbeat_outstanding.take().is_some() {
            // RFC 9260 8.3: a HEARTBEAT not acknowledged within an RTO counts against the
            // path and the association, and the RTO backs off. The next one follows after
            // HB.interval.
            debug!("[{}] HEARTBEAT not acknowledged", self.side);
            self.rto_mgr.backoff();
            if self.on_path_failure() {
                return;
            }
            if let Some(interval) = self.heartbeat_interval {
                self.timers.set(Timer::Heartbeat, Some(now + interval));
            }
            return;
        }
        let Some(interval) = self.heartbeat_interval else {
            return;
        };

        // The path is idle when nothing that measures the round trip has left for a
        // heartbeat period: not while DATA is being sent for the first time.
        let Some(period) = self.heartbeat_period() else {
            return;
        };
        if let Some(last) = self.last_rtt_probe
            && now.saturating_duration_since(last) < interval
        {
            self.timers.set(Timer::Heartbeat, Some(last + period));
            return;
        }
        self.send_heartbeat(now);
    }

    /// HEARTBEATs go in ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-RECEIVED only.
    fn may_send_heartbeat(&self) -> bool {
        matches!(
            self.state(),
            AssociationState::Established
                | AssociationState::ShutdownPending
                | AssociationState::ShutdownReceived
        )
    }

    /// Queues a HEARTBEAT and waits an RTO for its HEARTBEAT ACK (RFC 9260 8.3).
    fn send_heartbeat(&mut self, now: Instant) {
        // RFC 9260 8.3: the HEARTBEAT carries the time it is sent, and a nonce, so that the
        // HEARTBEAT ACK can be told from any other.
        let nonce = self.random.u64();
        let sent_ms = self.created_at.map_or(0, |start| {
            now.saturating_duration_since(start).as_millis() as u64
        });
        let mut info = BytesMut::with_capacity(16);
        info.extend_from_slice(&sent_ms.to_be_bytes());
        info.extend_from_slice(&nonce.to_be_bytes());
        let packet = self.create_packet(vec![Box::new(ChunkHeartbeat {
            params: vec![Box::new(ParamHeartbeatInfo {
                heartbeat_information: info.freeze(),
            })],
        })]);
        self.control_queue.push_back(packet);
        self.awake_write_loop();
        self.heartbeat_outstanding = Some((nonce, now));
        self.last_rtt_probe = Some(now);
        self.timers.set(
            Timer::Heartbeat,
            Some(now + Duration::from_millis(self.rto_mgr.get_rto())),
        );
    }

    /// RFC 9260 11.1.10 Request Heartbeat: "Instructs the local endpoint to perform a
    /// heartbeat on the specified destination transport address". Sends a HEARTBEAT now,
    /// whether or not heartbeats are enabled ([`TransportConfig::with_heartbeat_interval`]),
    /// unless one is waiting for its HEARTBEAT ACK already (its answer serves). Its HEARTBEAT
    /// ACK measures the round trip ([`Self::rtt`]); left unanswered for an RTO it counts as an
    /// error of the path, as a periodic one does (8.3). Returns whether a HEARTBEAT was
    /// queued: `false` outside ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-RECEIVED, or with
    /// one outstanding. The association is single-homed (RFC 8261 6.1), so there is no
    /// address to name.
    pub fn request_heartbeat(&mut self, now: Instant) -> bool {
        if !self.may_send_heartbeat() || self.heartbeat_outstanding.is_some() {
            return false;
        }
        self.send_heartbeat(now);
        true
    }

    /// RFC 8899 section 6.2: the path MTU probe that is due, if any, as a packet of its own
    /// that is exactly the size probed: a HEARTBEAT whose Heartbeat Information is the probe
    /// size, the time it is sent and a nonce, and a PAD chunk (RFC 4820) for the rest. It
    /// carries no user data and is not held back by the congestion or the receive window
    /// (section 3, items 7 and 8); it waits for the established association.
    fn gather_path_mtu_probe(&mut self, raw_packets: &mut Vec<Bytes>, now: Instant) {
        let Some(pmtud) = self.pmtud.as_mut() else {
            return;
        };
        pmtud.start();
        let Some(size) = pmtud.poll_probe() else {
            return;
        };
        let nonce = self.random.u64();
        let sent_ms = self.created_at.map_or(0, |start| {
            now.saturating_duration_since(start).as_millis() as u64
        });
        let mut info = BytesMut::with_capacity(20);
        info.extend_from_slice(&size.to_be_bytes());
        info.extend_from_slice(&sent_ms.to_be_bytes());
        info.extend_from_slice(&nonce.to_be_bytes());
        let padding_length = size.saturating_sub(pmtud::PROBE_OVERHEAD) as usize;
        let packet = self.create_packet(vec![
            Box::new(ChunkHeartbeat {
                params: vec![Box::new(ParamHeartbeatInfo {
                    heartbeat_information: info.freeze(),
                })],
            }),
            Box::new(ChunkPadding { padding_length }),
        ]);
        match self.marshal_packet(&packet) {
            Ok(raw) => {
                debug!("[{}] path MTU probe of {} bytes", self.side, raw.len());
                raw_packets.push(raw);
                if let Some(pmtud) = self.pmtud.as_mut() {
                    pmtud.probe_sent(nonce, size, now);
                }
            }
            Err(err) => warn!(
                "[{}] failed to serialize a path MTU probe: {err}",
                self.side
            ),
        }
    }

    /// A HEARTBEAT ACK that echoes a path MTU probe (`gather_path_mtu_probe`): the probe
    /// crossed the path. A successful probe counts as an answer from the peer (RFC 8899
    /// section 6.2.1.2: it "updates the association and path counters"). Returns whether the
    /// acknowledgement was a probe's.
    fn handle_path_mtu_probe_ack(&mut self, info: &Bytes, now: Instant) -> bool {
        if info.len() != 20 || self.pmtud.is_none() {
            return false;
        }
        let nonce = u64::from_be_bytes(info[12..20].try_into().unwrap_or_default());
        if let Some(mtu) = self.pmtud.as_mut().and_then(|p| p.on_probe_ack(nonce, now)) {
            self.use_path_mtu(mtu, false);
        }
        self.on_path_success();
        true
    }

    /// The path MTU discovery's timers (PROBE_TIMER, PMTU_RAISE_TIMER).
    fn handle_path_mtu_timeout(&mut self, now: Instant) {
        if let Some(mtu) = self.pmtud.as_mut().and_then(|p| p.on_timeout(now)) {
            self.use_path_mtu(mtu, false);
        }
        if self
            .pmtud
            .as_ref()
            .is_some_and(|p| p.poll_probe().is_some())
        {
            self.awake_write_loop();
        }
    }

    /// RFC 9260 8.3: a HEARTBEAT ACK for the HEARTBEAT outstanding measures the round trip,
    /// clears the error counters and shows the path active. Any other is ignored.
    fn handle_heartbeat_ack(&mut self, c: &ChunkHeartbeatAck, now: Instant) {
        if let Some(info) = c.params.first().and_then(|p| {
            p.as_any()
                .downcast_ref::<ParamHeartbeatInfo>()
                .map(|info| info.heartbeat_information.clone())
        }) && self.handle_path_mtu_probe_ack(&info, now)
        {
            return;
        }
        let Some((nonce, sent_at)) = self.heartbeat_outstanding else {
            trace!("[{}] HEARTBEAT ACK for no HEARTBEAT", self.side);
            return;
        };
        let echoed = c.params.first().and_then(|p| {
            p.as_any()
                .downcast_ref::<ParamHeartbeatInfo>()
                .map(|info| info.heartbeat_information.clone())
        });
        let matches = echoed.is_some_and(|info| {
            info.len() == 16 && constant_time_eq(&info[8..], &nonce.to_be_bytes())
        });
        if !matches {
            debug!(
                "[{}] HEARTBEAT ACK does not match the HEARTBEAT sent",
                self.side
            );
            return;
        }
        self.heartbeat_outstanding = None;
        let rtt = now.saturating_duration_since(sent_at);
        self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
        self.timers.reset_retrans(Timer::T3RTX);
        self.on_path_success();
        if let Some(period) = self.heartbeat_period() {
            self.timers.set(Timer::Heartbeat, Some(now + period));
        }
    }

    /// One more consecutive failure on the path (RFC 9260 8.1, 8.2): a HEARTBEAT without an
    /// answer. Returns whether the association ended over it.
    fn on_path_failure(&mut self) -> bool {
        self.note_path_error();
        if self.timers.count_error(Timer::T3RTX) {
            // RFC 9260 8.1: past Association.Max.Retrans the peer is unreachable.
            error!("[{}] the peer does not answer: giving up", self.side);
            if let Err(err) = self.close(AssociationError::TimedOut) {
                error!("[{}] failed to close association: {err}", self.side);
            }
            return true;
        }
        false
    }

    /// Counts a failure against the path and reports the path inactive past
    /// Path.Max.Retrans.
    fn note_path_error(&mut self) {
        self.path_error_count += 1;
        if self.path_error_count > PATH_MAX_RETRANS && !self.path_inactive {
            self.path_inactive = true;
            self.events.push_back(Event::PathInactive);
        }
    }

    /// The peer answered: new DATA was acknowledged, or a HEARTBEAT.
    fn on_path_success(&mut self) {
        self.path_error_count = 0;
        if self.path_inactive {
            self.path_inactive = false;
            self.events.push_back(Event::PathActive);
        }
    }

    /// Sets HB.interval for this association (RFC 9260 11.1.9, "Change Heartbeat"). `None`
    /// stops the HEARTBEATs.
    pub fn set_heartbeat_interval(&mut self, interval: Option<Duration>, now: Instant) {
        self.heartbeat_interval = interval;
        if self.state() == AssociationState::Established {
            self.start_heartbeat_timer(now);
        }
    }

    fn handle_data(&mut self, d: &ChunkPayloadData) -> Result<Vec<Packet>> {
        debug!(
            "[{}] DATA: tsn={} peer_last_tsn={} immediateSack={} len={}, unordered={}",
            self.side,
            d.tsn,
            self.peer_last_tsn,
            d.immediate_sack,
            d.user_data.len(),
            d.unordered,
        );
        self.stats.inc_datas();

        // RFC 8260 2.2.3: with user message interleaving negotiated a DATA chunk is a
        // violation, and without it an I-DATA chunk is: the association is aborted.
        if d.i_data != self.use_interleaving {
            warn!(
                "[{}] {} chunk on an association that uses the other: aborting",
                self.side,
                if d.i_data { "I-DATA" } else { "DATA" }
            );
            self.abort_with(
                vec![Self::protocol_violation(if d.i_data {
                    "I-DATA without user message interleaving (RFC 8260 2.2.3)"
                } else {
                    "DATA with user message interleaving (RFC 8260 2.2.3)"
                })],
                AssociationError::TransportError,
            )?;
            return Ok(vec![]);
        }

        // RFC 9260 section 6: DATA is received by the normal rules in ESTABLISHED,
        // SHUTDOWN-PENDING and SHUTDOWN-SENT, and discarded in any other state.
        match self.state() {
            AssociationState::Established
            | AssociationState::ShutdownPending
            | AssociationState::ShutdownSent => {}
            AssociationState::Closed if self.side == Side::Server => {
                // An accepting association that has seen no COOKIE ECHO has no association
                // to receive on: the DATA is out of the blue (8.4), answered with an ABORT
                // that reflects the packet's tag.
                debug!("[{}] DATA before the COOKIE ECHO: ABORT", self.side);
                self.discard_rest_of_packet = true;
                return Ok(vec![self.abort_packet(
                    self.my_verification_tag,
                    true,
                    vec![],
                )]);
            }
            state => {
                // COOKIE-WAIT and COOKIE-ECHOED (DATA that overtook the COOKIE ACK is sent
                // again by the peer); SHUTDOWN-RECEIVED and SHUTDOWN-ACK-SENT, where the peer
                // has said it sends nothing more: discarded.
                debug!("[{}] discarding DATA in state '{}'", self.side, state);
                return Ok(vec![]);
            }
        }

        // RFC 9260 section 6.2: a DATA chunk with no user data is answered with an ABORT
        // carrying the "No User Data" cause. Accepting one would cost receive state without
        // counting against the byte-based receive window.
        if d.user_data.is_empty() {
            debug!(
                "[{}] DATA tsn={} has no user data: aborting",
                self.side, d.tsn
            );
            let abort = ChunkAbort {
                error_causes: vec![ErrorCause {
                    code: NO_USER_DATA,
                    raw: Bytes::copy_from_slice(&d.tsn.to_be_bytes()),
                }],
                ..Default::default()
            };
            let packet = self.create_packet(vec![Box::new(abort)]);
            self.control_queue.push_back(packet);
            self.awake_write_loop();
            self.close(AssociationError::TransportError)?;
            return Err(Error::ErrAbortChunk(NO_USER_DATA.to_string()));
        }

        // A stream id at or past the inbound stream count negotiated in INIT/INIT-ACK is not
        // one the peer may use (RFC 9260 6.5); creating state for it would let a peer make us
        // hold up to 65536 streams.
        //
        // RFC 9260 6.5: such a chunk is still acknowledged (it only is not delivered), and
        // answered with an ERROR "Invalid Stream Identifier". Its TSN is recorded without the
        // payload. Left unrecorded, as it was, the cumulative TSN could never pass it: the
        // peer retransmitted it for ever and in the end every chunk after it was refused.
        if self.my_max_num_inbound_streams != 0
            && d.stream_identifier >= self.my_max_num_inbound_streams
        {
            debug!(
                "[{}] discard DATA on stream {} (negotiated inbound streams: {})",
                self.side, d.stream_identifier, self.my_max_num_inbound_streams
            );
            let can_push = self.payload_queue.can_push(d, self.peer_last_tsn);
            if can_push {
                self.payload_queue.push(
                    ChunkPayloadData {
                        user_data: Bytes::new(),
                        ..d.clone()
                    },
                    self.peer_last_tsn,
                );
                let mut raw = BytesMut::with_capacity(4);
                raw.extend_from_slice(&d.stream_identifier.to_be_bytes());
                raw.extend_from_slice(&[0, 0]);
                self.report_error(ErrorCause {
                    code: INVALID_STREAM_IDENTIFIER,
                    raw: raw.freeze(),
                });
            } else {
                self.payload_queue.record_duplicate(d.tsn);
            }
            return self.handle_peer_last_tsn_and_acknowledgement(d.immediate_sack || !can_push);
        }

        let can_push = self.payload_queue.can_push(d, self.peer_last_tsn);
        let mut stream_handle_data = false;
        let mut dropped_for_window = false;
        // RFC 9260 6.1 A: after a SACK advertised a_rwnd 0, the sender sends one chunk at a
        // time (a zero window probe) and the next only when that one is acknowledged. A
        // delayed SACK (6.2) would hold each of them for up to the SACK delay; what this side
        // takes then is acknowledged at once.
        let window_was_closed = self.last_advertised_window == 0;
        let mut taken_through_closed_window = false;
        if can_push {
            if self.get_or_create_stream(d.stream_identifier).is_some() {
                if self.get_my_receiver_window_credit() > 0 {
                    // Pass the new chunk to stream level as soon as it arrives
                    self.payload_queue.push(d.clone(), self.peer_last_tsn);
                    stream_handle_data = true;
                    taken_through_closed_window = window_was_closed;
                } else {
                    // Receive buffer is full. Two kinds of chunk are still worth taking,
                    // because refusing them is not something the application can relieve by
                    // draining.
                    //
                    // The first fills a gap below the highest TSN already queued.
                    let fills_gap = self
                        .payload_queue
                        .get_last_tsn_received()
                        .is_some_and(|last_tsn| sna32lt(d.tsn, *last_tsn));

                    // The second is the next in-sequence chunk when nothing is readable at
                    // all, and it is what keeps a full buffer from becoming permanent. Bytes
                    // are released only when the application reads; `is_readable()` is
                    // head-of-line blocked by an incomplete chunk set; and the chunk that
                    // would complete that set is exactly `peer_last_tsn + 1`. Dropping it
                    // leaves the window at zero with no way to reopen — every retransmission
                    // is refused for the same reason, forever.
                    // See <https://github.com/webrtc-rs/webrtc/issues/822>.
                    //
                    // Guarded on nothing being readable so this stays an escape from deadlock
                    // rather than a licence to overrun the bound. A merely slow receiver has
                    // data to take and must be made to take it. Without the guard, the chunk
                    // accepted here is `peer_last_tsn + 1` — precisely the one that advances
                    // the cumulative ack — so every chunk would qualify and
                    // `max_receive_buffer_size` would stop bounding anything.
                    //
                    // RFC 9260 6.2: once the window has been advertised as closed, a new DATA
                    // chunk above the largest TSN received MUST be dropped; the escape then
                    // needs `TransportConfig::with_zero_window_overcommit`. An application
                    // that reads in parts (`Stream::read_part`, RFC 9260 6.9) needs no
                    // escape: a buffer full of incomplete messages is given out in parts
                    // (`partial_delivery_threshold`), and the window opens again.
                    let window_advertised_closed = self.last_advertised_window == 0;
                    let unblocks_reassembly = d.tsn == self.peer_last_tsn.wrapping_add(1)
                        && !self.has_readable_data()
                        && (!window_advertised_closed || self.zero_window_overcommit);

                    // Either kind may take the receiver past `max_receive_buffer_size`, which
                    // is what lets a message larger than the buffer be reassembled at all. But
                    // the headroom this needs is one message, so neither kind is taken past
                    // one inbound message (the size this side advertised) beyond the buffer.
                    let within_headroom = self.bytes_in_reassembly_queues() + d.user_data.len()
                        <= self.max_receive_buffer_size as usize
                            + self.max_receive_message_size as usize;

                    if (fills_gap || unblocks_reassembly) && within_headroom {
                        debug!(
                            "[{}] receive buffer full, but accepted {} with tsn={} ssn={}",
                            self.side,
                            if fills_gap {
                                "as this is a missing chunk"
                            } else {
                                "as the in-sequence chunk that unblocks reassembly"
                            },
                            d.tsn,
                            d.stream_sequence_number
                        );
                        self.payload_queue.push(d.clone(), self.peer_last_tsn);
                        stream_handle_data = true;
                        taken_through_closed_window = window_was_closed;
                    } else {
                        debug!(
                            "[{}] receive buffer full. dropping DATA with tsn={} ssn={}",
                            self.side, d.tsn, d.stream_sequence_number
                        );
                        // RFC 9260 6.2: a DATA chunk dropped for lack of window is
                        // answered with a SACK at once, which shows the sender the window
                        // and that the chunk is not held.
                        dropped_for_window = true;
                    }
                }
            } else {
                // silently discard the data. (sender will retry on T3-rtx timeout)
                debug!("[{}] discard {}", self.side, d.stream_sequence_number);
                return Ok(vec![]);
            }
        } else {
            self.payload_queue.record_duplicate(d.tsn);
        }

        // RFC 9260 section 6.2: a repeat is listed in a SACK sent at once. So is the first
        // DATA chunk of the association (5.1), DATA that came with the COOKIE ECHO (5.1.5),
        // and DATA received in SHUTDOWN-SENT (9.2), which is also answered with the SHUTDOWN
        // again.
        let first = !self.first_data_received;
        self.first_data_received = true;
        let mut immediate_sack = d.immediate_sack
            || !can_push
            || first
            || self.sack_packet_immediately
            || dropped_for_window
            || taken_through_closed_window;
        if self.state() == AssociationState::ShutdownSent {
            immediate_sack = true;
            self.will_send_shutdown = true;
            self.awake_write_loop();
        }

        if stream_handle_data {
            self.received_since_sack = self
                .received_since_sack
                .saturating_add(u32::try_from(d.user_data.len()).unwrap_or(u32::MAX));
            if self.holds_for_reset(d) {
                // RFC 6525 5.2.2 E2: this DATA belongs to its stream as it will be after a
                // reset that is not performed yet. Its TSN is acknowledged; it is delivered
                // when the reset is done.
                debug!(
                    "[{}] holding DATA tsn={} of stream {} for a deferred reset",
                    self.side, d.tsn, d.stream_identifier
                );
                self.reassembly_bytes = self.reassembly_bytes.saturating_add(d.user_data.len());
                self.held_reset_data.push(d.clone());
            } else {
                self.deliver_to_stream(d);
            }
        }
        // A chunk taken may have used the buffer up; one dropped arrives while it is.
        self.offer_partial_delivery();

        self.handle_peer_last_tsn_and_acknowledgement(immediate_sack)
    }

    /// Hands a DATA chunk that was accepted to its stream.
    fn deliver_to_stream(&mut self, d: &ChunkPayloadData) {
        let cumulative_tsn = self.peer_last_tsn;
        // A fragment that does not begin a message, for a stream that holds nothing, when the
        // TSN before it has been received: the start of its message went to a stream that is
        // gone (see `ReassemblyQueue::discard_orphans`). It makes no stream.
        if !self.streams.contains_key(&d.stream_identifier)
            && !d.beginning_fragment
            && sna32lte(d.tsn.wrapping_sub(1), cumulative_tsn)
        {
            self.note_orphan(d);
            return;
        }
        if self.get_or_create_stream(d.stream_identifier).is_none() {
            return;
        }
        if let Some(s) = self.streams.get_mut(&d.stream_identifier) {
            if s.reads_stopped {
                // The application closed the stream: nothing will read this. Its TSN stays
                // acknowledged.
                trace!(
                    "[{}] dropping DATA tsn={} of stream {}, which is no longer read",
                    self.side, d.tsn, d.stream_identifier
                );
                return;
            }
            self.events.push_back(Event::DatagramReceived);
            let bytes_before = s.get_num_bytes_in_reassembly_queue();
            let orphans_before = s.reassembly_queue.orphans_dropped;
            if s.handle_received(d, cumulative_tsn) && s.reassembly_queue.is_readable() {
                self.events.push_back(Event::Stream(StreamEvent::Readable {
                    id: s.stream_identifier,
                }));
            }
            let dropped = s.reassembly_queue.orphans_dropped - orphans_before;
            self.reindex_stream(d.stream_identifier, bytes_before);
            if dropped == 0 {
                // Nothing dropped.
            } else if !d.beginning_fragment {
                // The chunk itself: the rest of a message whose start went elsewhere.
                self.note_orphan(d);
            } else {
                // Held fragments the message this chunk begins supersedes.
                self.orphans_dropped += dropped;
                self.last_orphan_tsn = None;
                warn!(
                    "[{}] dropped {dropped} DATA fragments of stream {} held ahead of the \
                     message starting at tsn={}: sent before it with later numbers, they are \
                     from before a reset of the stream (a peer that sent data queued on the \
                     stream after its Sender's Last Assigned TSN, RFC 6525 5.1.2 A3)",
                    self.side, d.stream_identifier, d.tsn
                );
            }
        }
    }

    /// What this side has acknowledged and not delivered: a description of every stream whose
    /// reassembly queue holds a fragment or a message, and of DATA held for a reset. `None`
    /// when there is nothing. Once the link is quiet (the peer has nothing outstanding) and the
    /// application has read everything it was told was readable, a reliable association holds
    /// nothing: whatever it holds then is stuck, acknowledged and never to be delivered.
    #[cfg(test)]
    pub(crate) fn undelivered(&self) -> Option<String> {
        let mut held: Vec<String> = self
            .streams
            .iter()
            .filter(|(_, s)| !s.reassembly_queue.is_empty())
            .map(|(id, s)| {
                let q = &s.reassembly_queue;
                format!(
                    "stream {id}: {} bytes, ordered sets {:?} (next ssn {} mid {}), {} unordered \
                     messages, {} unordered fragments, in partial delivery: {}",
                    q.get_num_bytes(),
                    q.ordered
                        .iter()
                        .map(|c| (c.ssn, c.mid, c.chunks.len(), c.is_complete()))
                        .collect::<Vec<_>>(),
                    q.next_ssn,
                    q.next_mid,
                    q.unordered.len(),
                    q.unordered_chunks.len(),
                    q.in_partial_delivery(),
                )
            })
            .collect();
        held.sort();
        if !self.held_reset_data.is_empty() {
            held.push(format!(
                "{} DATA chunks held for a reset",
                self.held_reset_data.len()
            ));
        }
        (!held.is_empty()).then(|| held.join("; "))
    }

    /// DATA chunk `d` was dropped as a fragment that can never be part of a complete message.
    /// Its TSN stays acknowledged.
    fn note_orphan(&mut self, d: &ChunkPayloadData) {
        self.orphans_dropped += 1;
        if self.last_orphan_tsn != Some(d.tsn.wrapping_sub(1)) {
            warn!(
                "[{}] dropping DATA of stream {} at tsn={} (ssn={} mid={}): it can never be \
                 delivered in its place, being the rest of a message from before a reset of the \
                 stream (a peer that sent data queued on the stream after its Sender's Last \
                 Assigned TSN, RFC 6525 5.1.2 A3)",
                self.side, d.stream_identifier, d.tsn, d.stream_sequence_number, d.mid
            );
        }
        self.last_orphan_tsn = Some(d.tsn);
    }

    /// Drops, on every stream, the fragments that can never be part of a complete message
    /// now that the cumulative TSN has passed TSNs that were missing
    /// (`ReassemblyQueue::discard_orphans`).
    fn discard_orphaned_fragments(&mut self) {
        let cumulative_tsn = self.peer_last_tsn;
        let ids: Vec<StreamId> = self.streams_with_data.iter().copied().collect();
        for id in ids {
            let Some(s) = self.streams.get_mut(&id) else {
                continue;
            };
            let bytes_before = s.get_num_bytes_in_reassembly_queue();
            let dropped = s.reassembly_queue.discard_orphans(cumulative_tsn);
            if dropped == 0 {
                continue;
            }
            let readable = s.reassembly_queue.is_readable();
            self.orphans_dropped += dropped;
            warn!(
                "[{}] dropped {dropped} DATA fragments of stream {id} that can never be \
                 completed: the start of their message went to another stream",
                self.side
            );
            self.reindex_stream(id, bytes_before);
            if readable {
                self.events
                    .push_back(Event::Stream(StreamEvent::Readable { id }));
            }
        }
    }

    fn handle_sack(&mut self, d: &ChunkSelectiveAck, now: Instant) -> Result<Vec<Packet>> {
        trace!(
            "[{}] {}, SACK: cumTSN={} a_rwnd={}",
            self.side,
            self.cumulative_tsn_ack_point,
            d.cumulative_tsn_ack,
            d.advertised_receiver_window_credit
        );
        let state = self.state();
        if state == AssociationState::Closed && self.side == Side::Server && !self.ended {
            // RFC 9260 section 6: a SACK for an association that is not there yet is out of
            // the blue (8.4).
            self.discard_rest_of_packet = true;
            return Ok(vec![self.abort_packet(
                self.my_verification_tag,
                true,
                vec![],
            )]);
        }
        if state != AssociationState::Established
            && state != AssociationState::ShutdownPending
            && state != AssociationState::ShutdownReceived
        {
            return Ok(vec![]);
        }

        self.stats.inc_sacks();

        if sna32gt(self.cumulative_tsn_ack_point, d.cumulative_tsn_ack) {
            // RFC 4960 sec 6.2.1.  Processing a Received SACK
            // D)
            //   i) If Cumulative TSN Ack is less than the Cumulative TSN Ack
            //      Point, then drop the SACK.  Since Cumulative TSN Ack is
            //      monotonically increasing, a SACK whose Cumulative TSN Ack is
            //      less than the Cumulative TSN Ack Point indicates an out-of-
            //      order SACK.

            debug!(
                "[{}] SACK Cumulative ACK {} is older than ACK point {}",
                self.side, d.cumulative_tsn_ack, self.cumulative_tsn_ack_point
            );

            return Ok(vec![]);
        }

        // A SACK may not acknowledge DATA this side never sent (RFC 9260 6.2.1, 12.4): it is
        // an error, and the caller aborts the association. Nothing is taken from it.
        if sna32gte(d.cumulative_tsn_ack, self.my_next_tsn) {
            debug!(
                "[{}] SACK Cumulative ACK {} is beyond the next TSN {}",
                self.side, d.cumulative_tsn_ack, self.my_next_tsn
            );
            return Err(Error::ErrTsnRequestNotExist);
        }

        // RFC 9260 6.2: "When an endpoint receives a SACK chunk, it MAY use the duplicate TSN
        // information to determine if SACK chunk loss is occurring." A TSN this side sent
        // again on a retransmission timeout and that the peer reports as a duplicate had
        // reached the peer before: the SACK that said so was lost (or came after the RTO).
        for tsn in &d.duplicate_tsn {
            if let Some(i) = self.t3_retransmitted.iter().position(|t| t == tsn) {
                self.t3_retransmitted.remove(i);
                self.stats.inc_sack_losses();
            }
        }

        // The bytes outstanding before this SACK: the congestion window may grow only when
        // it was in full use (RFC 9260 7.2.1, 7.2.2).
        let flight_before =
            u32::try_from(self.inflight_queue.get_num_wire_bytes()).unwrap_or(u32::MAX);
        let marked_before = self.fast_retransmit_marked.len();

        // Process selective ack
        let (bytes_acked_per_stream, total_bytes_acked, htna) =
            self.process_selective_ack(d, now)?;

        let mut cum_tsn_ack_point_advanced = false;
        if sna32lt(self.cumulative_tsn_ack_point, d.cumulative_tsn_ack) {
            trace!(
                "[{}] SACK: cumTSN advanced: {} -> {}",
                self.side, self.cumulative_tsn_ack_point, d.cumulative_tsn_ack
            );

            self.cumulative_tsn_ack_point = d.cumulative_tsn_ack;
            cum_tsn_ack_point_advanced = true;
            if let Some(pmtud) = self.pmtud.as_mut() {
                pmtud.on_progress();
            }
            self.on_cumulative_tsn_ack_point_advanced(now);
        }
        // RFC 9260 7.2.4: the window growth of 7.2.1 and 7.2.2 comes before the adjustments
        // for loss this SACK may bring.
        // RFC 9260 7.2.2: partial_bytes_acked also counts "the number of bytes of duplicated
        // chunks reported in Duplicate TSNs". Only chunks this side sent and saw acknowledged
        // count, each once, so a receiver cannot inflate the count by repeating TSNs.
        let duplicate_bytes = self.duplicate_bytes(&d.duplicate_tsn);
        self.grow_congestion_window(
            total_bytes_acked,
            duplicate_bytes,
            flight_before,
            cum_tsn_ack_point_advanced,
        );

        self.release_stream_buffers(&bytes_acked_per_stream);

        // New rwnd value
        // RFC 4960 sec 6.2.1.  Processing a Received SACK
        // D)
        //   ii) Set rwnd equal to the newly received a_rwnd minus the number
        //       of bytes still outstanding after processing the Cumulative
        //       TSN Ack and the Gap Ack Blocks.

        // acknowledged payload bytes were already released from the in-flight queue
        let bytes_outstanding = self.inflight_queue.get_num_bytes() as u32;
        if bytes_outstanding >= d.advertised_receiver_window_credit {
            self.rwnd = 0;
        } else {
            self.rwnd = d.advertised_receiver_window_credit - bytes_outstanding;
        }
        // RFC 9260 6.1 A: the receiver closed its window. The first zero window probe goes one
        // RTO from now, and the probes sent while SACKs keep coming do not count as errors: the
        // receiver may keep its window closed for as long as it likes.
        //
        // A SACK that acknowledges the outstanding probe is not the window closing again: the
        // receiver took that DATA although it advertised no room (it completes a message its
        // full buffer holds the start of). Waiting one RTO before each such chunk delivered a
        // message larger than the receive buffer at one fragment per RTO, which is a stall.
        // The next probe goes at once; one that is dropped stays outstanding and is
        // retransmitted by T3-rtx, whose interval doubles.
        let probe_acknowledged = self
            .zero_window_probe_tsn
            .is_some_and(|tsn| sna32gte(d.cumulative_tsn_ack, tsn));
        if probe_acknowledged {
            self.zero_window_probe_tsn = None;
        }
        if d.advertised_receiver_window_credit == 0 {
            if probe_acknowledged {
                self.zero_window_probe_at = None;
            } else if self.zero_window_probe_at.is_none() {
                self.zero_window_probe_at =
                    Some(now + Duration::from_millis(self.rto_mgr.get_rto()));
            }
            self.timers.reset_retrans(Timer::T3RTX);
            self.on_path_success();
        } else {
            self.zero_window_probe_at = None;
        }

        // The highest TSN this SACK acknowledges: every outstanding TSN below it is one the
        // SACK reports missing (RFC 9260 7.2.4).
        let highest_reported = d
            .gap_ack_blocks
            .iter()
            .map(|g| d.cumulative_tsn_ack.wrapping_add(g.end as u32))
            .fold(d.cumulative_tsn_ack, |highest, tsn| {
                if sna32gt(tsn, highest) { tsn } else { highest }
            });
        self.process_fast_retransmission(
            d.cumulative_tsn_ack,
            htna,
            highest_reported,
            cum_tsn_ack_point_advanced,
            now,
        )?;

        if self.use_forward_tsn {
            // RFC 3758 Sec 3.5 C1
            if sna32lt(
                self.advanced_peer_tsn_ack_point,
                self.cumulative_tsn_ack_point,
            ) {
                self.advanced_peer_tsn_ack_point = self.cumulative_tsn_ack_point;
                // Window reset: everything previously tracked is now at/below
                // the cumulative ack point, so start the stream map fresh.
                self.fwd_tsn_stream_map.clear();
                self.i_fwd_tsn_stream_map.clear();
            }

            self.advance_peer_ack_point();
            self.awake_write_loop();
        }

        // RFC 9260 6.2.1 C: the chunks this SACK marked for retransmission go back to rwnd.
        let marked: usize = self.fast_retransmit_marked
            [marked_before.min(self.fast_retransmit_marked.len())..]
            .iter()
            .filter_map(|tsn| self.inflight_queue.get(*tsn))
            .map(|c| c.user_data.len())
            .sum();
        self.rwnd = self
            .rwnd
            .saturating_add(u32::try_from(marked).unwrap_or(u32::MAX));

        self.postprocess_sack(state, cum_tsn_ack_point_advanced, now);

        // The peer's SSN/TSN reset waited for what this side had outstanding.
        Ok(self.perform_deferred_tsn_reset())
    }

    fn handle_forward_tsn(&mut self, c: &ChunkForwardTsn) -> Result<Vec<Packet>> {
        trace!("[{}] FwdTSN: {}", self.side, c);

        if self.use_interleaving {
            // RFC 8260 2.3.1: FORWARD TSN is not used with I-DATA.
            warn!("[{}] FORWARD TSN with I-DATA in use: aborting", self.side);
            self.abort_with(
                vec![Self::protocol_violation(
                    "FORWARD-TSN with user message interleaving (RFC 8260 2.3.1)",
                )],
                AssociationError::TransportError,
            )?;
            return Ok(vec![]);
        }

        if !self.use_forward_tsn {
            warn!("[{}] received FwdTSN but not enabled", self.side);
            // RFC 3758 3.3.1: answered as a chunk this side does not recognize, with the
            // chunk in the cause.
            self.report_error(ErrorCause {
                code: UNRECOGNIZED_CHUNK_TYPE,
                raw: c.marshal()?,
            });
            return Ok(vec![]);
        }

        // From RFC 3758 Sec 3.6:
        //   Note, if the "New Cumulative TSN" value carried in the arrived
        //   FORWARD TSN chunk is found to be behind or at the current cumulative
        //   TSN point, the data receiver MUST treat this FORWARD TSN as out-of-
        //   date and MUST NOT update its Cumulative TSN.  The receiver SHOULD
        //   send a SACK to its peer (the sender of the FORWARD TSN) since such a
        //   duplicate may indicate the previous SACK was lost in the network.

        trace!(
            "[{}] should send ack? newCumTSN={} peer_last_tsn={}",
            self.side, c.new_cumulative_tsn, self.peer_last_tsn
        );
        let Some(prev_peer_last_tsn) = self.forward_cumulative_tsn(c.new_cumulative_tsn) else {
            return Ok(vec![]);
        };

        // From RFC 3758 Sec 3.6:
        //   the receiver MUST perform the same TSN handling, including duplicate
        //   detection, gap detection, SACK generation, cumulative TSN
        //   advancement, etc. as defined in RFC 2960 [2]---with the following
        //   exceptions and additions.

        //   When a FORWARD TSN chunk arrives, the data receiver MUST first update
        //   its cumulative TSN point to the value carried in the FORWARD TSN
        //   chunk,

        // Report new peer_last_tsn value and abandoned largest SSN value to
        // corresponding streams so that the abandoned chunks can be removed
        // from the reassemblyQueue.
        for forwarded in &c.streams {
            if let Some(s) = self.streams.get_mut(&forwarded.identifier) {
                let bytes_before = s.get_num_bytes_in_reassembly_queue();
                s.handle_forward_tsn_for_ordered(forwarded.sequence);
                if s.reassembly_queue.is_readable() {
                    self.events.push_back(Event::Stream(StreamEvent::Readable {
                        id: s.stream_identifier,
                    }));
                }
                self.reindex_stream(forwarded.identifier, bytes_before);
            }
        }

        // TSN may be forwarded for unordered chunks. ForwardTSN chunk does not
        // report which stream identifier it skipped for unordered chunks.
        // Therefore, we need to broadcast this event to all existing streams for
        // unordered chunks. A stream with an empty reassembly queue has nothing to
        // forward and nothing to read, so only the streams holding data are visited.
        let with_data: Vec<StreamId> = self.streams_with_data.iter().copied().collect();
        for id in with_data {
            if let Some(s) = self.streams.get_mut(&id) {
                let bytes_before = s.get_num_bytes_in_reassembly_queue();
                s.handle_forward_tsn_for_unordered(c.new_cumulative_tsn);
                if s.reassembly_queue.is_readable() {
                    self.events.push_back(Event::Stream(StreamEvent::Readable {
                        id: s.stream_identifier,
                    }));
                }
                self.reindex_stream(id, bytes_before);
            }
        }

        // A stored reset request the new cumulative TSN reached is performed now, after the
        // streams have taken what the FORWARD TSN made readable.
        let mut reset_reply = vec![];
        self.reset_streams_reached_since(prev_peer_last_tsn, &mut reset_reply)?;
        let mut reply = self.handle_peer_last_tsn_and_acknowledgement(false)?;
        reset_reply.append(&mut reply);
        Ok(reset_reply)
    }

    fn handle_shutdown(&mut self, c: &ChunkShutdown, now: Instant) -> Result<Vec<Packet>> {
        let state = self.state();

        if state == AssociationState::Established
            || state == AssociationState::ShutdownReceived
            || state == AssociationState::ShutdownPending
        {
            // RFC 9260 9.2: a SHUTDOWN is taken in SHUTDOWN-PENDING too (both sides are
            // shutting down and the peer's SHUTDOWN came first).
            //
            // RFC 9260 9.2: the SHUTDOWN's Cumulative TSN Ack acknowledges our DATA up to it,
            // and the receiver checks by it that all its outstanding DATA has arrived. A
            // SHUTDOWN that crossed our last SACK is the only acknowledgement left for the
            // data in flight, so without this the association waited for T3-rtx.
            self.acknowledge_by_shutdown(c.cumulative_tsn_ack, now)?;
            if self.state() != state {
                // The acknowledgement drained the queue from SHUTDOWN-RECEIVED, which
                // already moved on to SHUTDOWN-ACK-SENT.
                return Ok(vec![]);
            }

            if !self.nothing_left_to_send() {
                self.set_state(AssociationState::ShutdownReceived);
            } else {
                // No more outstanding, send shutdown ack.
                self.will_send_shutdown_ack = true;
                self.set_state(AssociationState::ShutdownAckSent);

                self.awake_write_loop();
            }
        } else if state == AssociationState::ShutdownSent {
            self.will_send_shutdown_ack = true;
            self.set_state(AssociationState::ShutdownAckSent);

            self.awake_write_loop();
        }

        Ok(vec![])
    }

    /// Processes a SHUTDOWN's Cumulative TSN Ack as a SACK without gap blocks (RFC 9260 9.2).
    ///
    /// The peer's receive window is left as it was: a SHUTDOWN does not carry one.
    fn acknowledge_by_shutdown(&mut self, cumulative_tsn_ack: u32, now: Instant) -> Result<()> {
        if !sna32gt(cumulative_tsn_ack, self.cumulative_tsn_ack_point)
            || sna32gte(cumulative_tsn_ack, self.my_next_tsn)
        {
            return Ok(());
        }
        let outstanding = self.inflight_queue.get_num_bytes() as u32;
        let sack = ChunkSelectiveAck {
            cumulative_tsn_ack,
            advertised_receiver_window_credit: self.rwnd.saturating_add(outstanding),
            gap_ack_blocks: vec![],
            duplicate_tsn: vec![],
        };
        // RFC 9260 3.3.8: a SHUTDOWN has no Gap Ack Blocks, and their absence is no renege.
        self.acknowledging_by_shutdown = true;
        let handled = self.handle_sack(&sack, now);
        self.acknowledging_by_shutdown = false;
        handled?;
        Ok(())
    }

    fn handle_shutdown_ack(&mut self, _: &ChunkShutdownAck) -> Result<Vec<Packet>> {
        let state = self.state();
        if state == AssociationState::ShutdownSent || state == AssociationState::ShutdownAckSent {
            self.timers.stop(Timer::T2Shutdown);
            self.will_send_shutdown_complete = true;

            self.awake_write_loop();
        }

        Ok(vec![])
    }

    fn handle_shutdown_complete(&mut self, _: &ChunkShutdownComplete) -> Result<Vec<Packet>> {
        let state = self.state();
        if state == AssociationState::ShutdownAckSent {
            self.timers.stop(Timer::T2Shutdown);
            self.close(AssociationError::AssociationClosed)?;
        }

        Ok(vec![])
    }

    /// A common routine for handle_data and handle_forward_tsn routines
    fn handle_peer_last_tsn_and_acknowledgement(
        &mut self,
        sack_immediately: bool,
    ) -> Result<Vec<Packet>> {
        let mut reply = vec![];
        let prev_peer_last_tsn = self.peer_last_tsn;

        // Try to advance peer_last_tsn

        // From RFC 3758 Sec 3.6:
        //   .. and then MUST further advance its cumulative TSN point locally
        //   if possible
        // Meaning, if peer_last_tsn+1 points to a chunk that is received,
        // advance peer_last_tsn until peer_last_tsn+1 points to unreceived chunk.
        //debug!("[{}] peer_last_tsn = {}", self.side, self.peer_last_tsn);
        // TSNs are serial numbers (RFC 4960 §1.6): the cumulative point wraps past u32::MAX,
        // which a peer reaches at once with an initial TSN of 0 or a FORWARD-TSN to u32::MAX.
        while self
            .payload_queue
            .pop(self.peer_last_tsn.wrapping_add(1))
            .is_some()
        {
            self.peer_last_tsn = self.peer_last_tsn.wrapping_add(1);
            //debug!("[{}] peer_last_tsn = {}", self.side, self.peer_last_tsn);
        }
        // The cumulative TSN passed a TSN that came late and the ones held after it: a
        // fragment held from before may only now be known to have lost the start of its
        // message (the check made as each fragment arrives saw the TSN before it missing).
        if self.peer_last_tsn.wrapping_sub(prev_peer_last_tsn) >= 2
            && sna32gt(self.peer_last_tsn, prev_peer_last_tsn)
        {
            self.discard_orphaned_fragments();
        }

        // Perform the stored reset requests the cumulative TSN has just reached, each once.
        // A request reached earlier and still stored waits for its stream to drain
        // (`retry_deferred_resets`), so it is not answered again here.
        self.reset_streams_reached_since(prev_peer_last_tsn, &mut reply)?;

        let has_packet_loss = !self.payload_queue.is_empty();
        if has_packet_loss {
            trace!(
                "[{}] packetloss: {}",
                self.side,
                self.payload_queue
                    .get_gap_ack_blocks_string(self.peer_last_tsn)
            );
        }

        if (self.ack_state != AckState::Immediate
            && !sack_immediately
            && !has_packet_loss
            && self.ack_mode == AckMode::Normal)
            || self.ack_mode == AckMode::AlwaysDelay
        {
            if self.ack_state == AckState::Idle {
                self.delayed_ack_triggered = true;
            } else {
                self.immediate_ack_triggered = true;
            }
        } else {
            self.immediate_ack_triggered = true;
        }

        Ok(reply)
    }

    fn process_selective_ack(
        &mut self,
        d: &ChunkSelectiveAck,
        now: Instant,
    ) -> Result<(FxHashMap<u16, i64>, i64, u32)> {
        let mut bytes_acked_per_stream = FxHashMap::default();
        let mut total_bytes_acked = 0;
        let mut newly_acked_data = false;
        // Abandoned DATA can precede the earliest outstanding TSN. RFC 9260
        // 6.3.2 R3 applies to that outstanding DATA, including gap acknowledgments.
        let earliest_outstanding = self.inflight_queue.sorted.iter().copied().find(|tsn| {
            self.inflight_queue
                .get(*tsn)
                .is_some_and(ChunkPayloadData::is_outstanding)
        });

        // New ack point, so pop all ACKed packets from inflight_queue
        // We add 1 because the "currentAckPoint" has already been popped from the inflight queue
        // For the first SACK we take care of this by setting the ackpoint to cumAck - 1
        let mut i = self.cumulative_tsn_ack_point.wrapping_add(1);
        //log::debug!("[{}] i={} d={}", self.name, i, d.cumulative_tsn_ack);
        while sna32lte(i, d.cumulative_tsn_ack) {
            if let Some(mut c) = self.inflight_queue.pop(i) {
                let wire = counted_wire_size(&c);
                if wire > 0 && !c.abandoned() {
                    self.note_acknowledged(c.tsn, wire);
                }
                if c.acknowledge() {
                    newly_acked_data |= c.nsent > 0;

                    let n_bytes_acked = c.user_data.len() as i64;
                    // RFC 9260 7.2, 7.2.1, 7.2.2: the congestion control counts the chunk with
                    // its header and padding.
                    total_bytes_acked += wire as i64;
                    // A late SACK for a retired stream must not release bytes
                    // belonging to a new channel that reused its SID.
                    if self.is_current_stream_data(&c) {
                        *bytes_acked_per_stream
                            .entry(c.stream_identifier)
                            .or_default() += n_bytes_acked;
                    }

                    // RFC 4960 sec 6.3.1.  RTO Calculation
                    //   C4)  When data is in flight and when allowed by rule C5 below, a new
                    //        RTT measurement MUST be made each round trip.  Furthermore, new
                    //        RTT measurements SHOULD be made no more than once per round trip
                    //        for a given destination transport address.
                    //   C5)  Karn's algorithm: RTT measurements MUST NOT be made using
                    //        packets that were retransmitted (and thus for which it is
                    //        ambiguous whether the reply was for the first instance of the
                    //        chunk or for a later instance)
                    if !c.abandoned() && c.nsent == 1 && sna32gte(c.tsn, self.min_tsn2measure_rtt) {
                        self.min_tsn2measure_rtt = self.my_next_tsn;
                        if let Some(since) = &c.since {
                            let rtt = now.duration_since(*since);
                            let srtt = self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
                            trace!(
                                "[{}] SACK: measured-rtt={} srtt={} new-rto={}",
                                self.side,
                                rtt.as_millis(),
                                srtt,
                                self.rto_mgr.get_rto()
                            );
                        } else {
                            error!("[{}] invalid c.since", self.side);
                        }
                    }
                }

                if self.in_fast_recovery && c.tsn == self.fast_recover_exit_point {
                    debug!("[{}] exit fast-recovery", self.side);
                    self.in_fast_recovery = false;
                }
            } else {
                return Err(Error::ErrInflightQueueTsnPop);
            }

            i = i.wrapping_add(1);
        }

        let mut htna = d.cumulative_tsn_ack;

        // RFC 9260 6.2.1 D iii, 6.3.2 R4: a TSN an earlier Gap Ack Block acknowledged that
        // this SACK neither covers cumulatively nor in a block was reneged on by the
        // receiver: it is outstanding again, counts one miss indication towards Fast
        // Retransmit, and T3-rtx runs if it was not running.
        let gap_acknowledged = if self.acknowledging_by_shutdown {
            vec![]
        } else {
            self.inflight_queue.gap_acknowledged()
        };
        let reneged: Vec<u32> = gap_acknowledged
            .into_iter()
            .filter(|tsn| {
                sna32gt(*tsn, d.cumulative_tsn_ack)
                    && !d.gap_ack_blocks.iter().any(|g| {
                        let offset = tsn.wrapping_sub(d.cumulative_tsn_ack);
                        offset >= u32::from(g.start) && offset <= u32::from(g.end)
                    })
            })
            .collect();
        for tsn in &reneged {
            if self.inflight_queue.renege(*tsn) {
                debug!("[{}] SACK: the peer reneged on TSN {}", self.side, tsn);
                if let Some(c) = self.inflight_queue.get_mut(*tsn)
                    && c.miss_indicator < 3
                {
                    c.miss_indicator += 1;
                    if c.miss_indicator == 3 {
                        self.fast_retransmit_marked.push(*tsn);
                    }
                }
            }
        }
        if !reneged.is_empty() {
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }
        self.reneged_in_last_sack = reneged;

        // Record peer acknowledgments independently of local payload release.
        for g in &d.gap_ack_blocks {
            for i in g.start..=g.end {
                let tsn = d.cumulative_tsn_ack.wrapping_add(i as u32);

                let newly_acknowledged = self.inflight_queue.acknowledge(tsn);
                let wire = if newly_acknowledged {
                    self.inflight_queue.get(tsn).map_or(0, counted_wire_size) as i64
                } else {
                    0
                };
                // The payload stays until the Cumulative TSN Ack covers it: the receiver
                // may renege on what a Gap Ack Block acknowledged (RFC 9260 6.2.1).
                let n_bytes_acked = if newly_acknowledged {
                    self.inflight_queue.hold_acknowledged(tsn) as i64
                } else {
                    0
                };

                if let Some(c) = self.inflight_queue.get(tsn) {
                    if newly_acknowledged {
                        newly_acked_data |= c.nsent > 0;
                        total_bytes_acked += wire;
                        if self.is_current_stream_data(c) {
                            *bytes_acked_per_stream
                                .entry(c.stream_identifier)
                                .or_default() += n_bytes_acked;
                        }

                        trace!("[{}] tsn={} has been sacked", self.side, c.tsn);

                        // RFC 9260 6.3.1 C4, C5: as for the cumulative TSN above, one
                        // measurement per round trip and none across a retransmission.
                        if !c.abandoned()
                            && c.nsent == 1
                            && sna32gte(c.tsn, self.min_tsn2measure_rtt)
                        {
                            self.min_tsn2measure_rtt = self.my_next_tsn;
                            if let Some(since) = &c.since {
                                let rtt = now.duration_since(*since);
                                let srtt = self.rto_mgr.set_new_rtt(rtt.as_millis() as u64);
                                trace!(
                                    "[{}] SACK: measured-rtt={} srtt={} new-rto={}",
                                    self.side,
                                    rtt.as_millis(),
                                    srtt,
                                    self.rto_mgr.get_rto()
                                );
                            } else {
                                error!("[{}] invalid c.since", self.side);
                            }
                        }

                        if sna32lt(htna, tsn) {
                            htna = tsn;
                        }
                    }
                } else {
                    return Err(Error::ErrTsnRequestNotExist);
                }
            }
        }

        // RFC 9260 8.1-8.2: an acknowledgment of new DATA clears the error
        // counter, including a late SACK after local abandonment. Payload
        // release does not acknowledge DATA; duplicates and never-sent TSNs
        // assigned only for FORWARD TSN do not count as newly acknowledged DATA.
        if newly_acked_data {
            self.timers.reset_retrans(Timer::T3RTX);
            self.on_path_success();
        }
        if earliest_outstanding.is_some_and(|tsn| {
            sna32lte(tsn, d.cumulative_tsn_ack)
                || self.inflight_queue.get(tsn).is_some_and(|c| c.acknowledged)
        }) {
            // Postprocessing restarts T3 with the current RTO if DATA/FORWARD
            // TSN remains outstanding.
            self.timers.set(Timer::T3RTX, None);
        }
        Ok((bytes_acked_per_stream, total_bytes_acked, htna))
    }

    fn on_cumulative_tsn_ack_point_advanced(&mut self, now: Instant) {
        // RFC 4096, sec 6.3.2.  Retransmission Timer Rules
        //   R2)  Whenever all outstanding data sent to an address have been
        //        acknowledged, turn off the T3-rtx timer of that address.
        if self.inflight_queue.is_empty() {
            trace!(
                "[{}] SACK: no more packet in-flight (pending={})",
                self.side,
                self.pending_queue.len()
            );
            self.timers.stop(Timer::T3RTX);
        } else {
            trace!("[{}] T3-rtx timer start (pt2)", self.side);
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }
    }

    /// RFC 9260 7.2.1 and 7.2.2: what a SACK does to the congestion window.
    ///
    /// `total_bytes_acked` is what the SACK newly acknowledged, by its Cumulative TSN Ack and
    /// by Gap Ack Blocks; `flight_before` the bytes outstanding before it.
    fn grow_congestion_window(
        &mut self,
        total_bytes_acked: i64,
        duplicate_bytes: u32,
        flight_before: u32,
        cum_tsn_ack_point_advanced: bool,
    ) {
        // Every addition below saturates: cwnd is bounded by nothing else, and a plain `+=`
        // wrapped it to a tiny window (and panicked with overflow checks on).
        let acked = u32::try_from(total_bytes_acked.max(0)).unwrap_or(u32::MAX);
        // The window was in full use if as much as it allows was outstanding. Rule B of 6.1
        // lets the last chunk sent cross it, so a sender with data to send gets there.
        let fully_utilized = flight_before >= self.cwnd;

        if self.cwnd <= self.ssthresh {
            // 7.2.1, slow start: cwnd grows only if it is fully utilized, the SACK advances
            // the Cumulative TSN Ack Point and the sender is not in Fast Recovery, and then
            // by at most the lesser of the bytes acknowledged and L x PMDCS. The second bound
            // is what keeps a receiver from growing the window by splitting its SACKs.
            if fully_utilized && cum_tsn_ack_point_advanced && !self.in_fast_recovery {
                let limit = self.slow_start_growth_limit.saturating_mul(self.pmdcs);
                self.cwnd = self.cwnd.saturating_add(acked.min(limit));
                trace!(
                    "[{}] updated cwnd={} ssthresh={} acked={} (SS)",
                    self.side, self.cwnd, self.ssthresh, acked
                );
            }
        } else {
            // 7.2.2, congestion avoidance: partial_bytes_acked counts what every SACK newly
            // acknowledges. Once it reaches cwnd, and cwnd was in full use, cwnd grows by one
            // PMDCS: at most one per round trip. When cwnd was not in full use the count is
            // held at cwnd.
            self.partial_bytes_acked = self
                .partial_bytes_acked
                .saturating_add(acked)
                .saturating_add(duplicate_bytes);
            if fully_utilized {
                if self.partial_bytes_acked >= self.cwnd {
                    self.partial_bytes_acked -= self.cwnd;
                    self.cwnd = self.cwnd.saturating_add(self.pmdcs);
                    trace!(
                        "[{}] updated cwnd={} ssthresh={} acked={} (CA)",
                        self.side, self.cwnd, self.ssthresh, acked
                    );
                }
            } else if self.partial_bytes_acked > self.cwnd {
                self.partial_bytes_acked = self.cwnd;
            }
        }

        // 7.2.2: when all the data sent has been acknowledged the count starts over.
        if self.inflight_queue.is_empty() {
            self.partial_bytes_acked = 0;
        }
    }

    /// Remembers that the chunk `tsn`, `wire` bytes on the wire, was acknowledged, for a
    /// duplicate report of it later (`duplicate_bytes`).
    fn note_acknowledged(&mut self, tsn: u32, wire: usize) {
        const KEPT: usize = 4096;
        if self.recently_acknowledged.len() >= KEPT {
            self.recently_acknowledged.pop_front();
        }
        self.recently_acknowledged
            .push_back((tsn, u32::try_from(wire).unwrap_or(u32::MAX)));
    }

    /// The wire bytes of the chunks a SACK reports as duplicates (RFC 9260 7.2.2), each chunk
    /// this side saw acknowledged counted once.
    fn duplicate_bytes(&mut self, duplicates: &[u32]) -> u32 {
        let mut bytes = 0u32;
        for tsn in duplicates {
            if let Some(at) = self
                .recently_acknowledged
                .iter()
                .position(|(acked, _)| acked == tsn)
                && let Some((_, wire)) = self.recently_acknowledged.remove(at)
            {
                bytes = bytes.saturating_add(wire);
            }
        }
        bytes
    }

    /// RFC 9260 7.2.1: a congestion window that is not used decays, to max(cwnd / 2,
    /// 4 x PMDCS) once per RTO without DATA sent, and ssthresh takes the value cwnd had
    /// before the first of those steps. Applied when DATA is about to be sent after the
    /// pause, which is when the window matters.
    fn decay_idle_congestion_window(&mut self, now: Instant) {
        let Some(last) = self.last_data_sent else {
            return;
        };
        if !self.inflight_queue.is_empty() {
            return;
        }
        let rto = self.rto_mgr.get_rto().max(1);
        let idle = now.saturating_duration_since(last).as_millis() as u64;
        let floor = self.pmdcs.saturating_mul(4);
        let mut periods = idle / rto;
        if periods == 0 || self.cwnd <= floor {
            return;
        }
        self.ssthresh = self.cwnd;
        while periods > 0 && self.cwnd > floor {
            self.cwnd = (self.cwnd / 2).max(floor);
            periods -= 1;
        }
        self.partial_bytes_acked = 0;
        trace!(
            "[{}] updated cwnd={} ssthresh={} after {} ms idle",
            self.side, self.cwnd, self.ssthresh, idle
        );
    }

    fn process_fast_retransmission(
        &mut self,
        cum_tsn_ack_point: u32,
        htna: u32,
        highest_reported: u32,
        cum_tsn_ack_point_advanced: bool,
        now: Instant,
    ) -> Result<()> {
        // RFC 9260 7.2.4, the HTNA algorithm: "For each incoming SACK chunk, miss indications
        // are incremented only for missing TSNs prior to the HTNA in the SACK chunk", and "if an
        // endpoint is in Fast Recovery and a SACK chunk arrives that advances the Cumulative
        // TSN Ack Point, the miss indications are incremented for all TSNs reported missing",
        // which are those below the highest TSN the SACK acknowledges. DATA sent after that
        // is not reported missing, only not acknowledged yet: counting it, as the whole
        // in-flight queue was counted here, retransmitted DATA that was not lost and
        // abandoned partially reliable messages that would have arrived.
        //
        // In Fast Recovery a SACK that does not advance the Cumulative TSN Ack Point counted
        // nothing here: a chunk lost inside the recovery window after it began was never
        // retransmitted by gap reports, however many reported it missing, and waited for
        // T3-rtx, which leaves one packet in flight at a doubling RTO. At 10 % loss a few lost
        // SACKs after that held 176 reliable messages back for more than 90 seconds.
        let max_tsn = if self.in_fast_recovery && cum_tsn_ack_point_advanced {
            highest_reported
        } else {
            htna
        };
        // A chunk that reaches three miss indications during a Fast Recovery that began
        // before this SACK, whether or not the SACK advances the Cumulative TSN Ack Point, is
        // not sent at once, ignoring cwnd: step 3 is "If not in Fast Recovery", for the SACK
        // that starts it. The chunk is marked for retransmission (step 1), goes out "as soon as
        // cwnd allows" and is not fast retransmitted again (step 5). A partially reliable
        // chunk whose retransmission budget is spent (RFC 3758 3.5 A3, RFC 7496 3.1) is never
        // sent again: it takes the fast retransmit path, which abandons it and sends FORWARD
        // TSN (RFC 3758 3.5 C1-C3) without waiting for the timer.
        let recovering = self.in_fast_recovery;

        let mut tsn = cum_tsn_ack_point.wrapping_add(1);
        while sna32lt(tsn, max_tsn) {
            let reneged = self.reneged_in_last_sack.contains(&tsn);
            let Some(c) = self.inflight_queue.get(tsn) else {
                return Err(Error::ErrTsnRequestNotExist);
            };
            let exhausted = recovering
                && self.use_forward_tsn
                && c.is_outstanding()
                && self.retransmission_policy_exhausted(c, now, true);
            if let Some(c) = self.inflight_queue.get_mut(tsn)
                && c.is_outstanding()
                && c.miss_indicator < 3
                && !reneged
            {
                c.miss_indicator += 1;
                if c.miss_indicator == 3 {
                    if recovering && !exhausted {
                        if c.is_fast_retransmit_candidate() {
                            c.no_fast_retransmit = true;
                            c.retransmit = true;
                            self.t3_retransmit_pending = true;
                        }
                    } else {
                        self.fast_retransmit_marked.push(tsn);
                        if recovering {
                            self.will_retransmit_fast = true;
                        }
                    }
                }
                if c.miss_indicator == 3 && !self.in_fast_recovery {
                    // 2)  If not in Fast Recovery, adjust the ssthresh and cwnd of the
                    //     destination address(es) to which the missing DATA chunks were
                    //     last sent, according to the formula described in Section 7.2.3.
                    self.in_fast_recovery = true;
                    // RFC 9260 7.2.4 step 6: Fast Recovery lasts until everything
                    // outstanding now is acknowledged. The exit point was the highest
                    // TSN this SACK newly acknowledged, below it, so recovery ended
                    // early and a second loss in the same window cut cwnd again.
                    self.fast_recover_exit_point = self.my_next_tsn.wrapping_sub(1);
                    self.ssthresh = std::cmp::max(self.cwnd / 2, self.pmdcs.saturating_mul(4));
                    self.cwnd = self.ssthresh;
                    self.partial_bytes_acked = 0;
                    self.will_retransmit_fast = true;

                    trace!(
                        "[{}] updated cwnd={} ssthresh={} inflight={} (FR)",
                        self.side,
                        self.cwnd,
                        self.ssthresh,
                        self.inflight_queue.get_num_bytes()
                    );
                }
            }

            tsn = tsn.wrapping_add(1);
        }

        Ok(())
    }

    /// The caller must hold the lock. This method was only added because the
    /// linter was complaining about the "cognitive complexity" of handle_sack.
    fn postprocess_sack(
        &mut self,
        state: AssociationState,
        mut should_awake_write_loop: bool,
        now: Instant,
    ) {
        if !self.inflight_queue.is_empty() {
            // Start timer. (noop if already started)
            trace!("[{}] T3-rtx timer start (pt3)", self.side);
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        } else if !self.pending_queue.is_empty() || self.held_write_count > 0 {
            // Queued DATA still goes out before the shutdown proceeds (RFC 9260 9.2).
        } else if state == AssociationState::ShutdownPending {
            // No more outstanding, send shutdown.
            should_awake_write_loop = true;
            self.send_shutdown();
        } else if state == AssociationState::ShutdownReceived {
            // No more outstanding, send shutdown ack.
            should_awake_write_loop = true;
            self.will_send_shutdown_ack = true;
            self.set_state(AssociationState::ShutdownAckSent);
        }

        if should_awake_write_loop {
            self.awake_write_loop();
        }
    }

    /// create_packet wraps chunks in a packet.
    /// The caller should hold the read lock.
    pub(crate) fn create_packet(&self, chunks: Vec<Box<dyn Chunk>>) -> Packet {
        Packet {
            common_header: CommonHeader {
                verification_tag: self.peer_verification_tag,
                source_port: self.source_port,
                destination_port: self.destination_port,
            },
            chunks,
        }
    }

    /// Marshal a single control chunk into one SCTP packet, bypassing the
    /// `Vec<Box<dyn Chunk>>` + `Packet` allocations of `create_packet(..).marshal()`.
    /// Feeds the borrowed chunk straight to the shared framing path
    /// ([`Packet::write_framed`]). Used on the hot SACK / FORWARD-TSN send path
    /// (a SACK is emitted roughly every 1-2 inbound DATA chunks). The caller holds
    /// the lock.
    fn marshal_control_chunk(&self, chunk: &dyn Chunk) -> Result<Bytes> {
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };
        // common header + chunk header + value + up to 3 bytes of trailing padding.
        let mut buf = BytesMut::with_capacity(
            COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + chunk.value_length() + 3,
        );
        Packet::write_framed_with(
            &common_header,
            std::iter::once(chunk),
            &mut buf,
            self.send_zero_checksum,
        )?;
        Ok(buf.freeze())
    }

    /// create_stream creates a stream. The caller should hold the lock and check no stream exists for this id.
    fn create_stream(
        &mut self,
        stream_identifier: StreamId,
        accept: bool,
        default_payload_type: PayloadProtocolIdentifier,
    ) -> Option<Stream<'_>> {
        let mut s = StreamState::new(
            self.side,
            stream_identifier,
            self.max_payload_size,
            default_payload_type,
        );

        s.generation = self.next_stream_generation;
        self.next_stream_generation = self.next_stream_generation.wrapping_add(1);
        self.closed_stream_bytes_dequeued.remove(&stream_identifier);
        s.reassembly_queue.interleaved = self.use_interleaving;
        self.pending_queue.forget_weight(stream_identifier);

        if accept {
            self.stream_queue.push_back(stream_identifier);
            self.events.push_back(Event::Stream(StreamEvent::Opened {
                id: stream_identifier,
            }));
        }

        let replaced_bytes = self
            .streams
            .insert(stream_identifier, s)
            .map_or(0, |old| old.get_num_bytes_in_reassembly_queue());
        self.reindex_stream(stream_identifier, replaced_bytes);

        Some(Stream {
            stream_identifier,
            association: self,
        })
    }

    /// get_or_create_stream gets or creates a stream. The caller should hold the lock.
    fn get_or_create_stream(&mut self, stream_identifier: StreamId) -> Option<Stream<'_>> {
        if self.streams.contains_key(&stream_identifier) {
            Some(Stream {
                stream_identifier,
                association: self,
            })
        } else {
            self.create_stream(
                stream_identifier,
                true,
                PayloadProtocolIdentifier::default(),
            )
        }
    }

    /// Whether any stream currently holds a complete message the application could read.
    ///
    /// Distinguishes a receiver that is merely slow — it has data to take, and back-pressure
    /// should make it take it — from one wedged behind an incomplete chunk set, which cannot
    /// drain anything however attentive it is. Only the second justifies accepting a chunk
    /// into a full receive buffer.
    fn has_readable_data(&self) -> bool {
        !self.readable_streams.is_empty()
    }

    fn bytes_in_reassembly_queues(&self) -> usize {
        self.reassembly_bytes
    }

    /// Brings the running totals up to date after stream `id`'s reassembly queue changed
    /// from holding `bytes_before` bytes. A stream no longer in `streams` counts as empty.
    ///
    /// Every change to a reassembly queue goes through here, so the receive window and
    /// "is anything readable" cost the same however many streams the peer opened.
    pub(crate) fn reindex_stream(&mut self, id: StreamId, bytes_before: usize) {
        let (bytes_after, readable, holds_data, aborted) = match self.streams.get_mut(&id) {
            Some(s) => (
                s.get_num_bytes_in_reassembly_queue(),
                s.reassembly_queue.is_readable(),
                !s.reassembly_queue.is_empty(),
                s.reassembly_queue.take_partial_abort(),
            ),
            None => (0, false, false, None),
        };
        // RFC 6458 6.1.7, SCTP_PARTIAL_DELIVERY_ABORTED: "the user message gets abandoned
        // using PR-SCTP while the partial delivery of this message is going on".
        if let Some(abort) = aborted {
            debug!(
                "[{}] partial delivery of message {} on stream {id} aborted",
                self.side, abort.sequence
            );
            self.events
                .push_back(Event::Stream(StreamEvent::PartialDeliveryAborted {
                    id,
                    unordered: abort.unordered,
                    sequence: abort.sequence,
                }));
        }
        self.reassembly_bytes = self
            .reassembly_bytes
            .saturating_sub(bytes_before)
            .saturating_add(bytes_after);
        if readable {
            self.readable_streams.insert(id);
        } else {
            self.readable_streams.remove(&id);
        }
        if holds_data {
            self.streams_with_data.insert(id);
        } else {
            self.streams_with_data.remove(&id);
        }
        self.reindex_parts(id, readable);
    }

    /// Brings `part_readable_streams` up to date for stream `id`, and announces a stream
    /// that has just come to hold part of a message to read (and nothing readable whole,
    /// which `StreamEvent::Readable` is raised for where the message completes).
    fn reindex_parts(&mut self, id: StreamId, readable: bool) {
        let threshold = self.partial_delivery_threshold();
        let parts = !readable
            && self
                .streams
                .get(&id)
                .is_some_and(|s| s.reassembly_queue.part_readable(threshold));
        if parts {
            if self.part_readable_streams.insert(id) {
                self.events
                    .push_back(Event::Stream(StreamEvent::Readable { id }));
            }
        } else {
            self.part_readable_streams.remove(&id);
        }
    }

    /// RFC 9260 6.9: "If the data receiver runs out of buffer space while still waiting for
    /// more fragments to complete the reassembly of the message, it SHOULD dispatch part of
    /// its inbound message through a partial delivery API". Out of space is a window that
    /// would be advertised as closed (6.2, silly window avoidance included) with no message
    /// readable whole; then the first fragments of a message are given out whatever their
    /// size. Otherwise a message starts partial delivery at the partial delivery point
    /// (RFC 6458 8.1.21).
    pub(crate) fn partial_delivery_threshold(&self) -> usize {
        if self.advertised_window() == 0 && !self.has_readable_data() {
            1
        } else {
            self.partial_delivery_point.max(1) as usize
        }
    }

    /// The receive buffer may have run out of space: every stream that holds the first
    /// fragments of a message is announced, so the application can take them in parts.
    pub(crate) fn offer_partial_delivery(&mut self) {
        if self.partial_delivery_threshold() > 1 || self.partial_delivery_point <= 1 {
            return;
        }
        let candidates: Vec<StreamId> = self
            .streams_with_data
            .iter()
            .copied()
            .filter(|id| {
                !self.readable_streams.contains(id) && !self.part_readable_streams.contains(id)
            })
            .collect();
        for id in candidates {
            self.reindex_parts(id, false);
        }
    }

    pub(crate) fn get_my_receiver_window_credit(&self) -> u32 {
        let bytes_queued = u32::try_from(self.bytes_in_reassembly_queues()).unwrap_or(u32::MAX);
        self.max_receive_buffer_size.saturating_sub(bytes_queued)
    }

    /// gather_outbound gathers outgoing packets. The returned bool value set to
    /// false means the association should be closed down after the final send.
    fn gather_outbound(&mut self, now: Instant) -> (Vec<Bytes>, bool) {
        let mut raw_packets = vec![];
        let state = self.state();

        // RFC 9260 6.10, 12.4: control chunks share packets. The SACK that is due goes
        // with them; if there are none it goes with outbound DATA (6.1), or alone.
        let mut sack = None;
        if self.ack_state == AckState::Immediate
            && matches!(
                state,
                AssociationState::Established
                    | AssociationState::ShutdownPending
                    | AssociationState::ShutdownSent
                    | AssociationState::ShutdownReceived
            )
        {
            self.ack_state = AckState::Idle;
            let chunk = self.create_selective_ack_chunk();
            debug!("[{}] sending SACK: {}", self.side, chunk);
            sack = Some(chunk);
        }
        if !self.control_queue.is_empty() {
            let packets: Vec<Packet> = self.control_queue.drain(..).collect();
            for p in self.bundle_control_packets(packets, &mut sack) {
                if let Ok(raw) = self.marshal_packet(&p) {
                    raw_packets.push(raw);
                } else {
                    warn!("[{}] failed to serialize a control packet", self.side);
                    continue;
                }
            }
        }
        self.unbundled_sack = sack;
        self.first_data_packet = raw_packets.len();

        match state {
            AssociationState::Established => {
                raw_packets = self.gather_data_packets_to_retransmit(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_data_and_reconfig_packets(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_fast_retransmission_packets(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_sack_packets(raw_packets);
                raw_packets = self.gather_outbound_forward_tsn_packets(raw_packets);
                self.gather_path_mtu_probe(&mut raw_packets, now);
                (raw_packets, true)
            }
            AssociationState::ShutdownPending
            | AssociationState::ShutdownSent
            | AssociationState::ShutdownReceived => {
                raw_packets = self.gather_data_packets_to_retransmit(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                // RFC 9260 9.2: no new data is accepted, but what is already queued is still
                // sent, by the endpoint shutting down and by the one that received SHUTDOWN.
                // (In SHUTDOWN-SENT nothing is queued: SHUTDOWN waited for the queue.)
                if state != AssociationState::ShutdownSent {
                    raw_packets = self.gather_outbound_data_and_reconfig_packets(raw_packets, now);
                    if self.state() == AssociationState::Closed {
                        return (vec![], false);
                    }
                }
                raw_packets = self.gather_outbound_fast_retransmission_packets(raw_packets, now);
                if self.state() == AssociationState::Closed {
                    return (vec![], false);
                }
                raw_packets = self.gather_outbound_sack_packets(raw_packets);
                raw_packets = self.gather_outbound_forward_tsn_packets(raw_packets);
                // Everything handed over is sent and acknowledged (a queue can also empty by
                // abandonment, with no SACK to notice it): the shutdown proceeds.
                if self.nothing_left_to_send() {
                    if state == AssociationState::ShutdownPending {
                        self.send_shutdown();
                    } else if state == AssociationState::ShutdownReceived {
                        self.will_send_shutdown_ack = true;
                        self.set_state(AssociationState::ShutdownAckSent);
                    }
                }
                self.gather_outbound_shutdown_packets(raw_packets, now)
            }
            AssociationState::ShutdownAckSent => {
                self.gather_outbound_shutdown_packets(raw_packets, now)
            }
            _ => (raw_packets, true),
        }
    }

    fn gather_data_packets_to_retransmit(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        // Nothing is ever flagged for T3-rtx in the steady state, so skip the
        // full in-flight scan unless the T3-rtx timer has actually marked chunks.
        if self.t3_retransmit_pending
            && let Err(err) = self.get_data_packets_to_retransmit(now, &mut raw_packets)
        {
            self.fail_message_queue(err);
            raw_packets.clear();
        }
        raw_packets
    }

    fn gather_outbound_data_and_reconfig_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        // Pop unsent data chunks from the pending queue to send as much as
        // cwnd and rwnd allow.
        let (mut chunks, resets) = self.pop_pending_data_chunks_to_send(now);
        if self.state() == AssociationState::Closed {
            return vec![];
        }
        // RFC 9260 3.3.1: "The (I)mmediate bit MAY be set by the sender whenever the sender of
        // a DATA chunk can benefit from the corresponding SACK chunk being sent back without
        // delay" (RFC 7053 4). The last DATA before a SHUTDOWN is such a chunk: the SHUTDOWN
        // waits for its acknowledgement (9.2), which a delayed SACK would hold back.
        if self.state() == AssociationState::ShutdownPending
            && self.pending_queue.is_empty()
            && self.held_write_count == 0
            && let Some(last) = chunks.last_mut()
        {
            last.immediate_sack = true;
        }
        if !chunks.is_empty() {
            // Start timer. (noop if already started)
            trace!("[{}] T3-rtx timer start (pt1)", self.side);
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());

            if self.pending_queue.one_stream_per_packet() {
                // RFC 8260 3.3: only chunks of the same stream are bundled in a packet.
                let mut run: Vec<ChunkPayloadData> = vec![];
                for chunk in chunks {
                    if run
                        .last()
                        .is_some_and(|last| last.stream_identifier != chunk.stream_identifier)
                    {
                        self.bundle_data_chunks_into_packets(
                            std::mem::take(&mut run),
                            &mut raw_packets,
                        );
                    }
                    run.push(chunk);
                }
                self.bundle_data_chunks_into_packets(run, &mut raw_packets);
            } else {
                self.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
            }
        }

        // RFC 6525 5.1.1: the request in flight is sent again when its timer has expired.
        if std::mem::take(&mut self.will_retransmit_reconfig) {
            debug!(
                "[{}] retransmit {} RECONFIG chunk(s)",
                self.side,
                self.reconfigs.len()
            );
            for c in self.reconfigs.values() {
                let p = self.create_packet(vec![Box::new(c.clone())]);
                if let Ok(raw) = self.marshal_packet(&p) {
                    raw_packets.push(raw);
                } else {
                    warn!(
                        "[{}] failed to serialize a RECONFIG packet to be retransmitted",
                        self.side,
                    );
                }
            }
        }

        // The resets whose streams have sent what was queued before them become requests,
        // and the next request goes out if none is in flight.
        for marker in resets {
            self.on_reset_marker_ready(marker);
        }
        while let Some(packet) = self.next_reconfig_request(now) {
            if let Ok(raw) = self.marshal_packet(&packet) {
                raw_packets.push(raw);
            } else {
                warn!(
                    "[{}] failed to serialize a RECONFIG packet to be transmitted",
                    self.side
                );
            }
        }

        // RFC 6525 5.1.1: a request outstanding is timed, whoever started it. The request
        // sent in answer to the peer's reset had no timer, so it was never retransmitted.
        if std::mem::take(&mut self.restart_reconfig_timer) {
            self.timers.stop(Timer::Reconfig);
        }
        if !self.reconfigs.is_empty() {
            self.timers
                .start_if_idle(Timer::Reconfig, now, self.rto_mgr.get_rto());
        }

        raw_packets
    }

    fn gather_outbound_fast_retransmission_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> Vec<Bytes> {
        if self.will_retransmit_fast {
            self.will_retransmit_fast = false;

            let mut to_fast_retrans: Vec<ChunkPayloadData> = vec![];
            let mut fast_retrans_size = COMMON_HEADER_SIZE;

            let mut i = 0;
            loop {
                let tsn = self.cumulative_tsn_ack_point.wrapping_add(i + 1);
                if let Some(c) = self.inflight_queue.get(tsn) {
                    if !c.is_fast_retransmit_candidate() {
                        i += 1;
                        continue;
                    }

                    // Only the retry being considered needs a policy check.
                    // Retire an exhausted candidate's whole message first.
                    match self.abandon_retransmit_candidate(tsn, now) {
                        Ok(true) => {
                            self.stats.inc_fast_retrans_abandoned();
                            to_fast_retrans.retain(|chunk| {
                                self.inflight_queue
                                    .get(chunk.tsn)
                                    .is_some_and(|c| !c.abandoned())
                            });
                            fast_retrans_size = COMMON_HEADER_SIZE
                                + to_fast_retrans
                                    .iter()
                                    .map(|c| c.wire_size() as u32)
                                    .sum::<u32>();
                            i += 1;
                            continue;
                        }
                        Ok(false) => {}
                        Err(err) => {
                            self.fail_message_queue(err);
                            return vec![];
                        }
                    }
                    let Some(c) = self.inflight_queue.get(tsn) else {
                        break;
                    };

                    // RFC 4960 Sec 7.2.4 Fast Retransmit on Gap Reports
                    //  3)  Determine how many of the earliest (i.e., lowest TSN) DATA chunks
                    //      marked for retransmission will fit into a single packet, subject
                    //      to constraint of the path MTU of the destination transport
                    //      address to which the packet is being sent.  Call this value K.
                    //      Retransmit those K DATA chunks in a single packet.  When a Fast
                    //      Retransmit is being performed, the sender SHOULD ignore the value
                    //      of cwnd and SHOULD NOT delay retransmission for this single
                    //		packet.

                    // Padded wire size, the same accounting
                    // bundle_data_chunks_into_packets uses for bundle
                    // decisions.
                    let data_chunk_size = c.wire_size() as u32;
                    if self.mtu < fast_retrans_size + data_chunk_size {
                        break;
                    }

                    fast_retrans_size += data_chunk_size;
                } else {
                    break; // end of pending data
                }

                if let Some(c) = self.inflight_queue.get(tsn) {
                    to_fast_retrans.push(c.clone());
                }
                i += 1;
            }

            // RFC 9260 7.2.4 step 5: the chunks marked for retransmission that did not fit
            // this one packet are no longer eligible for Fast Retransmit. They go out as
            // retransmissions when cwnd allows, instead of in a later burst that ignores it.
            // Only the chunks marked since the last Fast Retransmit are looked at, not the
            // window.
            for tsn in std::mem::take(&mut self.fast_retransmit_marked) {
                if to_fast_retrans.iter().any(|c| c.tsn == tsn) {
                    continue;
                }
                if let Some(c) = self.inflight_queue.get_mut(tsn)
                    && c.is_fast_retransmit_candidate()
                {
                    c.no_fast_retransmit = true;
                    c.retransmit = true;
                    self.t3_retransmit_pending = true;
                }
            }

            // RFC 9260 7.2.4 step 4: T3-rtx starts over when the first outstanding chunk is
            // among those retransmitted (the count of its expiries is kept).
            let earliest_outstanding = self.inflight_queue.sorted.iter().copied().find(|tsn| {
                self.inflight_queue
                    .get(*tsn)
                    .is_some_and(ChunkPayloadData::is_outstanding)
            });
            if earliest_outstanding.is_some()
                && to_fast_retrans.first().map(|c| c.tsn) == earliest_outstanding
            {
                self.timers.set(
                    Timer::T3RTX,
                    Some(now + Duration::from_millis(self.rto_mgr.get_rto())),
                );
            }

            if !to_fast_retrans.is_empty() {
                // RFC 9260 6.3.1 C5, as after a T3-rtx retransmission.
                self.min_tsn2measure_rtt = self.my_next_tsn;
            }
            for chunk in &mut to_fast_retrans {
                if let Some(c) = self.inflight_queue.get_mut(chunk.tsn) {
                    c.nsent += 1;
                    chunk.nsent = c.nsent;
                    self.stats.inc_retransmissions();
                    if !matches!(c.reliability, MessageReliability::Reliable) {
                        self.stats.inc_partially_reliable_retransmissions();
                    }
                    // RFC 9260 6.2.1 B, for a Fast Retransmit too.
                    self.rwnd = self
                        .rwnd
                        .saturating_sub(u32::try_from(c.user_data.len()).unwrap_or(u32::MAX));
                    self.stats.inc_fast_retrans();
                    trace!(
                        "[{}] fast-retransmit: tsn={} sent={} htna={}",
                        self.side, c.tsn, c.nsent, self.fast_recover_exit_point
                    );
                }
            }
            self.bundle_data_chunks_into_packets(to_fast_retrans, &mut raw_packets);
        }

        raw_packets
    }

    fn gather_outbound_sack_packets(&mut self, mut raw_packets: Vec<Bytes>) -> Vec<Bytes> {
        if let Some(sack) = self.unbundled_sack.take() {
            // RFC 9260 6.1: "the endpoint SHOULD bundle the SACK with the outbound DATA".
            if self.bundle_with_data(&sack, &mut raw_packets, self.first_data_packet) {
                return raw_packets;
            }
            if let Ok(raw) = self.marshal_control_chunk(&sack) {
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a SACK packet", self.side);
            }
        }

        raw_packets
    }

    fn gather_outbound_forward_tsn_packets(&mut self, mut raw_packets: Vec<Bytes>) -> Vec<Bytes> {
        /*log::debug!(
            "[{}] gatherOutboundForwardTSNPackets {}",
            self.name,
            self.will_send_forward_tsn
        );*/
        if self.will_send_forward_tsn {
            self.will_send_forward_tsn = false;
            if sna32gt(
                self.advanced_peer_tsn_ack_point,
                self.cumulative_tsn_ack_point,
            ) {
                // RFC 8260 2.3.1: with I-DATA the chunk is I-FORWARD-TSN.
                // RFC 3758 3.5 F2: it goes with outbound DATA when a packet has room.
                let first_data_packet = self.first_data_packet;
                let raw = if self.use_interleaving {
                    let fwd_tsn = self.create_i_forward_tsn();
                    self.stats.inc_forward_tsns();
                    if self.bundle_with_data(&fwd_tsn, &mut raw_packets, first_data_packet) {
                        return raw_packets;
                    }
                    self.marshal_control_chunk(&fwd_tsn)
                } else {
                    let fwd_tsn = self.create_forward_tsn();
                    self.stats.inc_forward_tsns();
                    if self.bundle_with_data(&fwd_tsn, &mut raw_packets, first_data_packet) {
                        return raw_packets;
                    }
                    self.marshal_control_chunk(&fwd_tsn)
                };
                if let Ok(raw) = raw {
                    raw_packets.push(raw);
                } else {
                    warn!("[{}] failed to serialize a Forward TSN packet", self.side);
                }
            }
        }

        raw_packets
    }

    fn gather_outbound_shutdown_packets(
        &mut self,
        mut raw_packets: Vec<Bytes>,
        now: Instant,
    ) -> (Vec<Bytes>, bool) {
        let mut ok = true;

        if self.will_send_shutdown {
            self.will_send_shutdown = false;

            // RFC 9260 9.2: the SHUTDOWN carries the TSN of the last DATA chunk received in
            // sequence from the peer, which is what a SACK would acknowledge, not this side's
            // own acknowledgement point.
            let shutdown = ChunkShutdown {
                cumulative_tsn_ack: self.peer_last_tsn,
            };
            // RFC 9260 3.3.8: "The sender of the SHUTDOWN chunk MAY bundle a SACK chunk to
            // indicate any gaps in the received TSNs", which the SHUTDOWN's Cumulative TSN Ack
            // cannot report: the peer then knows what arrived beyond it and need not send it
            // again.
            let mut chunks: Vec<Box<dyn Chunk>> = vec![];
            if !self
                .payload_queue
                .get_gap_ack_blocks(self.peer_last_tsn)
                .is_empty()
            {
                chunks.push(Box::new(self.create_selective_ack_chunk()));
            }
            chunks.push(Box::new(shutdown));

            if let Ok(raw) = self.marshal_packet(&self.create_packet(chunks)) {
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
                self.start_shutdown_guard(now);
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a Shutdown packet", self.side);
            }
        } else if self.will_send_shutdown_ack {
            self.will_send_shutdown_ack = false;

            let shutdown_ack = ChunkShutdownAck {};

            if let Ok(raw) = self.marshal_packet(&self.create_packet(vec![Box::new(shutdown_ack)]))
            {
                self.timers
                    .start(Timer::T2Shutdown, now, self.rto_mgr.get_rto());
                raw_packets.push(raw);
            } else {
                warn!("[{}] failed to serialize a ShutdownAck packet", self.side);
            }
        } else if self.will_send_shutdown_complete {
            self.will_send_shutdown_complete = false;

            let shutdown_complete = ChunkShutdownComplete::default();

            if let Ok(raw) =
                self.marshal_packet(&self.create_packet(vec![Box::new(shutdown_complete)]))
            {
                raw_packets.push(raw);
                ok = false;
            } else {
                warn!(
                    "[{}] failed to serialize a ShutdownComplete packet",
                    self.side
                );
            }
        }

        (raw_packets, ok)
    }

    /// get_data_packets_to_retransmit is called when T3-rtx is timed out and retransmit outstanding data chunks
    /// that are not acked or abandoned yet.
    fn get_data_packets_to_retransmit(
        &mut self,
        now: Instant,
        raw_packets: &mut Vec<Bytes>,
    ) -> Result<()> {
        // RFC 9260 6.3.3 E3, 7.2.3: the retransmission that follows a T3-rtx expiry is the
        // earliest outstanding chunks that fit one packet, and that packet is alone in flight
        // until it is acknowledged. cwnd (one PMDCS) is counted in user bytes, which a second
        // packet of small chunks could still fit under.
        let single_packet = std::mem::take(&mut self.t3_single_packet);
        let mut packet_size = COMMON_HEADER_SIZE as usize;
        // RFC 9260 6.1: retransmissions are limited by cwnd too. What is marked for
        // retransmission is taken as lost, not as in flight; each chunk retransmitted is in
        // flight again. Counting only the bytes of one call, as this did, retransmitted a
        // window's worth on every poll, the whole of what was outstanding in the end.
        let mut in_flight = self
            .inflight_queue
            .get_num_bytes()
            .saturating_sub(self.inflight_queue.marked_for_retransmission_bytes());
        // What this call retransmits, against rwnd (6.2.1 B: rwnd is the peer's buffer
        // space, the bytes outstanding already taken out of it).
        let mut retransmitted = 0usize;
        let mut chunks: Vec<ChunkPayloadData> = vec![];
        let mut done = false;
        let mut i = 0;
        // Assume we will re-send every flagged chunk; flip back on if we stop
        // early (a marked chunk that doesn't fit awnd, or a zero-window probe)
        // so the next gather_outbound still scans.
        let mut chunks_remaining = false;
        while !done {
            let tsn = self.cumulative_tsn_ack_point.wrapping_add(i + 1);
            if let Some(c) = self.inflight_queue.get(tsn) {
                if !c.retransmit {
                    i += 1;
                    continue;
                }

                // A T3-marked candidate can expire while waiting for the send
                // window. Recheck it now (RFC 3758 TR4), without a window scan.
                if self.abandon_retransmit_candidate(tsn, now)? {
                    chunks.retain(|chunk| {
                        self.inflight_queue
                            .get(chunk.tsn)
                            .is_some_and(|c| !c.abandoned())
                    });
                    // The abandonment released payload and cleared marks: count again.
                    in_flight = self
                        .inflight_queue
                        .get_num_bytes()
                        .saturating_sub(self.inflight_queue.marked_for_retransmission_bytes())
                        + chunks.iter().map(|c| c.user_data.len()).sum::<usize>();
                    retransmitted = chunks.iter().map(|c| c.user_data.len()).sum::<usize>();
                    packet_size = COMMON_HEADER_SIZE as usize
                        + chunks.iter().map(|c| c.wire_size()).sum::<usize>();
                    i += 1;
                    continue;
                }
                let Some(c) = self.inflight_queue.get(tsn) else {
                    break;
                };

                let wire = c.wire_size();
                if single_packet && !chunks.is_empty() && packet_size + wire > self.mtu as usize {
                    chunks_remaining = true;
                    break;
                }
                packet_size += wire;

                if i == 0 && self.rwnd < c.user_data.len() as u32 {
                    // Send it as a zero window probe
                    done = true;
                    chunks_remaining = true;
                } else if (in_flight + c.user_data.len() > self.cwnd as usize && in_flight > 0)
                    || (retransmitted + c.user_data.len() > self.rwnd as usize
                        && !chunks.is_empty())
                {
                    // With nothing in flight one chunk always goes, whatever its size.
                    chunks_remaining = true;
                    break;
                }

                in_flight += c.user_data.len();
                retransmitted += c.user_data.len();
            } else {
                break; // end of pending data
            }

            if let Some(c) = self.inflight_queue.get(tsn) {
                chunks.push(c.clone());
            }
            i += 1;
        }

        // Cleared once the whole in-flight window has been rescanned with nothing
        // left flagged; kept set while awnd/zero-window left chunks behind.
        self.t3_retransmit_pending = chunks_remaining;

        // RFC 9260 6.3.1 C5: no round trip is measured with a TSN sent before this
        // retransmission; an acknowledgement of it may be for either transmission of what
        // was sent again.
        if !chunks.is_empty() {
            self.min_tsn2measure_rtt = self.my_next_tsn;
        }

        // A later candidate can abandon an earlier fragment already selected
        // into this batch. Commit attempts only after whole-message retirement.
        for chunk in &mut chunks {
            if let Some(c) = self.inflight_queue.get_mut(chunk.tsn) {
                c.retransmit = false;
                c.nsent += 1;
                chunk.nsent = c.nsent;
                self.stats.inc_retransmissions();
                if !matches!(c.reliability, MessageReliability::Reliable) {
                    self.stats.inc_partially_reliable_retransmissions();
                }
                if self.t3_retransmitted.len() == MAX_T3_RETRANSMITTED_KEPT {
                    self.t3_retransmitted.pop_front();
                }
                self.t3_retransmitted.push_back(chunk.tsn);
                // RFC 9260 6.2.1 B: a retransmitted chunk takes its size from rwnd again.
                self.rwnd = self
                    .rwnd
                    .saturating_sub(u32::try_from(c.user_data.len()).unwrap_or(u32::MAX));
                trace!(
                    "[{}] retransmitting tsn={} ssn={} sent={}",
                    self.side, c.tsn, c.stream_sequence_number, c.nsent
                );
            }
        }
        self.bundle_data_chunks_into_packets(chunks, raw_packets);
        Ok(())
    }

    fn release_stream_buffers(&mut self, bytes_acked_per_stream: &FxHashMap<u16, i64>) {
        for (si, n_bytes_acked) in bytes_acked_per_stream {
            if *n_bytes_acked > 0 {
                // Report the exact bytes released for this stream (acknowledged OR
                // abandoned — both funnel through bytes_acked_per_stream) so upper
                // layers can decrement their own send-buffer accounting. Unlike the
                // edge-triggered BufferedAmountLow advisory below, this fires on
                // every release with the byte delta.
                self.events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountReleased {
                        id: *si,
                        n_bytes: *n_bytes_acked as usize,
                    }));
            }
            if let Some(s) = self.streams.get_mut(si)
                && s.on_buffer_released(*n_bytes_acked)
            {
                trace!("StreamEvent::BufferedAmountLow");
                self.events
                    .push_back(Event::Stream(StreamEvent::BufferedAmountLow { id: *si }))
            }
        }
    }

    /// RFC 3758 section 3.5 C2-C4. Retain the stream map until the peer catches up.
    fn advance_peer_ack_point(&mut self) {
        let mut tsn = self.advanced_peer_tsn_ack_point.wrapping_add(1);
        while let Some(c) = self.inflight_queue.get(tsn) {
            if !c.abandoned() {
                break;
            }
            let (unordered, si, ssn) = (c.unordered, c.stream_identifier, c.stream_sequence_number);
            let (i_data, mid) = (c.i_data, c.mid);
            self.advanced_peer_tsn_ack_point = tsn;
            if i_data {
                self.note_abandoned_for_i_forward_tsn(unordered, si, mid);
            } else {
                self.note_abandoned_for_forward_tsn(unordered, si, ssn);
            }
            tsn = tsn.wrapping_add(1);
        }
        if sna32gt(
            self.advanced_peer_tsn_ack_point,
            self.cumulative_tsn_ack_point,
        ) {
            self.will_send_forward_tsn = true;
        } else {
            self.fwd_tsn_stream_map.clear();
            self.i_fwd_tsn_stream_map.clear();
        }
    }

    fn timed_data_expired(&self, c: &ChunkPayloadData, now: Instant) -> bool {
        self.use_forward_tsn
            && c.reliability
                .deadline()
                .is_some_and(|deadline| now >= deadline)
    }

    /// Application bytes of `stream_identifier` that have left the send queue (see
    /// [`Stream::bytes_dequeued`]). For a stream that was closed (reset, or lost with the
    /// association), the count it had when it was closed, until a stream with the same
    /// identifier is opened; 0 for a stream this association never held.
    pub fn stream_bytes_dequeued(&self, stream_identifier: StreamId) -> u64 {
        self.streams.get(&stream_identifier).map_or_else(
            || {
                self.closed_stream_bytes_dequeued
                    .get(&stream_identifier)
                    .copied()
                    .unwrap_or(0)
            },
            |s| s.bytes_dequeued,
        )
    }

    /// The streams of the association before the peer's last restart (`Event::Restarted`),
    /// each with the application bytes that had left its send queue: what was sent on it
    /// before it went with the restart.
    pub fn streams_lost_in_restart(&self) -> &[(StreamId, u64)] {
        &self.streams_lost_in_restart
    }

    /// Credits a chunk leaving the send queue to its stream's `bytes_dequeued`.
    fn note_dequeued(&mut self, c: &ChunkPayloadData) {
        if !matches!(
            c.payload_type,
            PayloadProtocolIdentifier::String | PayloadProtocolIdentifier::Binary
        ) || !self.is_current_stream_data(c)
        {
            return;
        }
        if let Some(s) = self.streams.get_mut(&c.stream_identifier) {
            s.bytes_dequeued += c.user_data.len() as u64;
        }
    }

    fn is_current_stream_data(&self, c: &ChunkPayloadData) -> bool {
        self.streams
            .get(&c.stream_identifier)
            .is_some_and(|s| s.generation == c.stream_generation)
    }

    /// A positive deadline can expire at any time. Timed(0) and Rexmit limits
    /// instead apply when this particular DATA is considered for retransmission.
    fn retransmission_policy_exhausted(
        &self,
        c: &ChunkPayloadData,
        now: Instant,
        is_candidate: bool,
    ) -> bool {
        if !self.use_forward_tsn {
            return false;
        }
        match c.reliability {
            MessageReliability::Reliable => false,
            MessageReliability::Timed { deadline } => {
                now >= deadline && (Some(deadline) != c.created_at || is_candidate)
            }
            // RFC 7496 3.1: the limit excludes the first transmission and counts
            // both fast and timer-based retries. nsent includes that first send.
            MessageReliability::Rexmit { max_retransmits } => {
                is_candidate && c.nsent > max_retransmits
            }
        }
    }

    fn abandon_retransmit_candidate(&mut self, tsn: u32, now: Instant) -> Result<bool> {
        let c = self
            .inflight_queue
            .get(tsn)
            .ok_or_else(|| Error::OtherSctpErr("missing retransmission candidate".into()))?;
        if !self.retransmission_policy_exhausted(c, now, true) {
            return Ok(false);
        }
        let message = MessageToAbandon {
            id: c.message_id.ok_or_else(|| {
                Error::OtherSctpErr("outbound DATA has no message identity".into())
            })?,
            sent_tsn: Some(tsn),
        };
        if self.abandon_message(message)? {
            self.on_messages_abandoned(now);
        }
        Ok(true)
    }

    /// Select identities without changing ACK, retry or buffer state. Only a
    /// fragment selected for recovery can exhaust that message's retry budget.
    fn unretransmittable_messages(
        &self,
        now: Instant,
        is_candidate: impl Fn(&ChunkPayloadData) -> bool,
    ) -> Result<Vec<MessageToAbandon>> {
        let mut messages = vec![];
        let mut selected = FxHashSet::default();
        for &tsn in &self.inflight_queue.sorted {
            let c = self
                .inflight_queue
                .get(tsn)
                .ok_or_else(|| Error::OtherSctpErr("missing inflight message fragment".into()))?;
            if c.is_outstanding()
                && self.retransmission_policy_exhausted(c, now, is_candidate(c))
                && let Some(id) = c.message_id
                && selected.insert(id)
            {
                messages.push(MessageToAbandon {
                    id,
                    sent_tsn: Some(tsn),
                });
            }
        }
        Ok(messages)
    }

    /// RFC 3758 A2/A3: abandon all fragments by identity, including Gap-ACKed
    /// siblings and an unsent tail. Each payload is released at most once.
    /// FORWARD TSN and timers are updated after the complete operation.
    fn abandon_message(&mut self, message: MessageToAbandon) -> Result<bool> {
        let whole_tsn = message.sent_tsn.filter(|&tsn| {
            self.inflight_queue.get(tsn).is_some_and(|c| {
                c.message_id == Some(message.id) && c.beginning_fragment && c.ending_fragment
            })
        });
        let mut inflight = whole_tsn.map_or_else(
            || self.inflight_queue.message_tsns(message.id),
            |tsn| vec![tsn],
        );
        let mut released_per_stream = FxHashMap::default();
        let mut changed = false;
        let transmitted = !inflight.is_empty();
        let tail = self.pending_queue.drain_message(message.id)?;
        // The stream the message was written to, if it is still the stream of that id.
        let stream = tail
            .first()
            .or_else(|| {
                inflight
                    .first()
                    .and_then(|tsn| self.inflight_queue.get(*tsn))
            })
            .filter(|c| self.is_current_stream_data(c))
            .map(|c| c.stream_identifier);
        // A message none of which was sent goes without TSNs, unless it is ordered and has
        // its Stream Sequence Number already: the peer then waits for that number, and only
        // a FORWARD TSN past it lets the stream go on.
        let assign_tsns = !inflight.is_empty()
            || tail
                .first()
                .is_some_and(|c| !c.beginning_fragment || (!c.unordered && !c.numbers_pending));
        for mut c in tail {
            self.note_dequeued(&c);
            if assign_tsns {
                c.tsn = self.generate_next_tsn();
                inflight.push(c.tsn);
                self.inflight_queue.push_no_check(c);
            } else {
                if self.is_current_stream_data(&c) {
                    *released_per_stream.entry(c.stream_identifier).or_default() +=
                        c.user_data.len() as i64;
                }
                changed = true;
            }
        }
        for tsn in inflight {
            if let Some(c) = self.inflight_queue.get_mut(tsn) {
                changed |= !c.abandoned();
                c.mark_abandoned();
                let (si, generation) = (c.stream_identifier, c.stream_generation);
                let released = self.inflight_queue.release_payload(tsn) as i64;
                if released > 0
                    && self
                        .streams
                        .get(&si)
                        .is_some_and(|s| s.generation == generation)
                {
                    *released_per_stream.entry(si).or_default() += released;
                }
            }
        }
        self.release_stream_buffers(&released_per_stream);
        if changed {
            self.stats.inc_abandoned_messages();
        }
        if changed && let Some(id) = stream {
            // RFC 3758 4.1 TR3: the upper layer is told.
            self.events
                .push_back(Event::Stream(StreamEvent::MessageAbandoned {
                    id,
                    transmitted,
                }));
        }
        Ok(changed)
    }

    fn fail_message_queue(&mut self, err: Error) {
        error!("[{}] inconsistent message queue: {err}", self.side);
        if let Err(err) = self.close(AssociationError::TransportError) {
            error!("[{}] failed to close association: {err}", self.side);
        }
        self.control_queue.clear();
        self.emit_drained();
    }

    fn on_messages_abandoned(&mut self, now: Instant) {
        self.advance_peer_ack_point();
        // RFC 3758 C5: recovery must continue even with no DATA left to retry.
        if sna32gt(
            self.advanced_peer_tsn_ack_point,
            self.cumulative_tsn_ack_point,
        ) {
            self.timers
                .start_if_idle(Timer::T3RTX, now, self.rto_mgr.get_rto());
        }
    }

    fn abandon_unretransmittable_messages(
        &mut self,
        now: Instant,
        is_candidate: impl Fn(&ChunkPayloadData) -> bool,
    ) -> Result<()> {
        let mut changed = false;
        for message in self.unretransmittable_messages(now, is_candidate)? {
            changed |= self.abandon_message(message)?;
        }
        if changed {
            self.on_messages_abandoned(now);
        }
        Ok(())
    }

    /// An unsent unordered message can be dropped without assigning TSNs.
    /// A selected fragment tail instead needs the whole-message abandonment path.
    /// Timed(0) permits first transmissions until an actual retry is considered.
    ///
    /// RFC 3758 4.1 (TR3, TR4): the lifetime is checked before every transmission, the first
    /// included, of ordered messages too. A message takes its Stream Sequence Number when its
    /// first fragment is sent, so one that expires before that is dropped without a TSN or a
    /// FORWARD TSN; one that expires part sent is abandoned by `abandon_message` with them.
    fn pending_message_expired(&self, c: &ChunkPayloadData, now: Instant) -> bool {
        c.reliability.deadline() != c.created_at && self.timed_data_expired(c, now)
    }

    fn pending_message_to_abandon(&self) -> Result<MessageToAbandon> {
        Ok(MessageToAbandon {
            id: self
                .pending_queue
                .peek()
                .and_then(|c| c.message_id)
                .ok_or_else(|| {
                    Error::OtherSctpErr("outbound DATA has no message identity".into())
                })?,
            sent_tsn: None,
        })
    }

    /// pop_pending_data_chunks_to_send pops chunks from the pending queues as many as
    /// the cwnd and rwnd allows to send.
    fn pop_pending_data_chunks_to_send(
        &mut self,
        now: Instant,
    ) -> (Vec<ChunkPayloadData>, Vec<ResetMarker>) {
        let mut chunks = vec![];
        let mut resets = vec![]; // the stream resets whose turn has come
        // RFC 6525 5.1.4 C2: while an SSN/TSN reset is under way no new DATA is sent. A
        // message part sent is finished first: its fragments have consecutive TSNs.
        let suspended = self.sending_suspended();
        if !self.pending_queue.is_empty() {
            self.decay_idle_congestion_window(now);
            // RFC 9260 6.1 D: with Max.Burst, cwnd is brought down to what is outstanding
            // plus Max.Burst packets before DATA is sent, so that a SACK for many chunks at
            // once does not release them all at once.
            if let Some(max_burst) = self.max_burst {
                let flight =
                    u32::try_from(self.inflight_queue.get_num_wire_bytes()).unwrap_or(u32::MAX);
                let limit = flight.saturating_add(max_burst.saturating_mul(self.pmdcs));
                if limit < self.cwnd {
                    self.cwnd = limit;
                }
            }
            // RFC 4960 sec 6.1.  Transmission of DATA Chunks
            //   A) At any given time, the data sender MUST NOT transmit new data to
            //      any destination transport address if its peer's rwnd indicates
            //      that the peer has no buffer space (i.e., rwnd is 0; see Section
            //      6.2.1).  However, regardless of the value of rwnd (including if it
            //      is 0), the data sender can always have one DATA chunk in flight to
            //      the receiver if allowed by cwnd (see rule B, below).

            // What is sent now starts a new packet (RFC 8260 3.3, for the scheduler that
            // gives a packet to one stream).
            self.pending_queue.start_packet();
            self.pending_queue.set_only_part_sent(suspended);
            loop {
                if suspended && !self.pending_queue.is_mid_message() {
                    break;
                }
                // A reset whose stream has sent what was written before it takes no window.
                if !suspended && let Some(reset) = self.pending_queue.pop_ready_reset() {
                    resets.push(reset);
                    continue;
                }
                let Some(c) = self.pending_queue.peek() else {
                    break;
                };
                let (beginning_fragment, unordered, data_len) =
                    (c.beginning_fragment, c.unordered, c.user_data.len());

                if data_len == 0 {
                    self.fail_message_queue(Error::OtherSctpErr(
                        "outbound DATA has no user data".into(),
                    ));
                    return (vec![], vec![]);
                }

                // RFC 3758 timed reliability: a message whose lifetime has run
                // out must be abandoned even if it was never transmitted. Doing
                // this here, ahead of the window checks and before a TSN is
                // allocated, means there is no gap for the peer to reconcile and
                // no ForwardTSN to send.
                if self.pending_message_expired(c, now) {
                    // Abandoning an ordered message that has its number takes TSNs: not
                    // past what may be outstanding (see `MAX_OUTSTANDING_TSNS`).
                    if !unordered
                        && !c.numbers_pending
                        && self.my_next_tsn.wrapping_sub(self.cumulative_tsn_ack_point)
                            > MAX_OUTSTANDING_TSNS
                    {
                        break;
                    }
                    match self
                        .pending_message_to_abandon()
                        .and_then(|message| self.abandon_message(message))
                    {
                        Ok(true) => self.on_messages_abandoned(now),
                        Ok(false) => {}
                        Err(err) => {
                            self.fail_message_queue(err);
                            return (vec![], vec![]);
                        }
                    }
                    continue;
                }

                // RFC 9260 6.1 B: new DATA is sent while less than cwnd is outstanding. The
                // chunk that crosses cwnd is still sent (by less than one PMDCS), and it is
                // the last: a window that the next chunk does not fit exactly would
                // otherwise never be in full use, and so never grow.
                if self.inflight_queue.get_num_wire_bytes() >= self.cwnd as usize {
                    break; // cwnd is in full use
                }

                if self.my_next_tsn.wrapping_sub(self.cumulative_tsn_ack_point)
                    > MAX_OUTSTANDING_TSNS
                {
                    break; // the receiver could no longer order what is outstanding
                }

                if data_len > self.rwnd as usize {
                    break; // no more rwnd
                }

                if let Some(chunk) = self.move_pending_data_chunk_to_inflight_queue(
                    beginning_fragment,
                    unordered,
                    now,
                ) {
                    self.rwnd -= data_len as u32;
                    chunks.push(chunk);
                } else {
                    self.fail_message_queue(Error::OtherSctpErr(
                        "failed to pop pending DATA".into(),
                    ));
                    return (vec![], vec![]);
                }
            }

            // the data sender can always have one DATA chunk in flight to the receiver; after
            // the receiver closed its window, from one RTO on (RFC 9260 6.1 A)
            if chunks.is_empty()
                && self.inflight_queue.is_empty()
                && !(suspended && !self.pending_queue.is_mid_message())
                // Its time is cleared by `handle_timeout` once it has come.
                && self.zero_window_probe_at.is_none()
            {
                // Send zero window probe.
                //
                // With I-DATA (RFC 8260) several messages may be part sent, and together they
                // can fill the receiver's buffer without one of them being complete. What
                // reopens a closed window is a message completed and read, so while probing,
                // a message that is part sent goes on before another is started: the probes
                // finish one message at a time, which the receiver can always take (it keeps
                // room for one message beyond its buffer while nothing is readable).
                let finish_first = self.pending_queue.is_mid_message();
                self.pending_queue
                    .set_only_part_sent(suspended || finish_first);
                let probe = self
                    .pending_queue
                    .peek()
                    .map(|c| (c.beginning_fragment, c.unordered));
                let moved = probe.map(|(beginning_fragment, unordered)| {
                    self.move_pending_data_chunk_to_inflight_queue(
                        beginning_fragment,
                        unordered,
                        now,
                    )
                });
                self.pending_queue.set_only_part_sent(suspended);
                match moved {
                    Some(Some(chunk)) => {
                        self.zero_window_probe_tsn = Some(chunk.tsn);
                        chunks.push(chunk);
                    }
                    Some(None) => {
                        self.fail_message_queue(Error::OtherSctpErr(
                            "failed to pop pending DATA".into(),
                        ));
                        return (vec![], vec![]);
                    }
                    None => {}
                }
            }
        }

        (chunks, resets)
    }

    /// bundle_data_chunks_into_packets packs DATA chunks into packets. It tries to bundle
    /// DATA chunks into a packet so long as the resulting packet size does not exceed
    /// the path MTU.
    fn bundle_data_chunks_into_packets(
        &self,
        chunks: Vec<ChunkPayloadData>,
        raw_packets: &mut Vec<Bytes>,
    ) {
        // RFC 4960 sec 6.1.  Transmission of DATA Chunks
        //   Multiple DATA chunks committed for transmission MAY be bundled in a
        //   single packet.  Furthermore, DATA chunks being retransmitted MAY be
        //   bundled with new DATA chunks, as long as the resulting packet size
        //   does not exceed the path MTU.
        //
        // Marshal each bundle straight into `raw_packets` from the borrowed
        // chunks: no intermediate `Vec<Packet>`, no `Box<dyn Chunk>` per chunk.
        // The chunks are already retained in the in-flight queue, so this send
        // copy is throwaway.
        if chunks.is_empty() {
            return;
        }
        let common_header = CommonHeader {
            verification_tag: self.peer_verification_tag,
            source_port: self.source_port,
            destination_port: self.destination_port,
        };

        // First pass: split the chunks into MTU-bounded datagrams and total up
        // their marshalled (4-byte-padded) length. The whole burst is then
        // written into ONE buffer and `split_to` hands out each datagram as a
        // zero-copy `Bytes` view sharing that single allocation — one malloc per
        // burst instead of one per packet on the hot send path. The bundle
        // boundaries are computed once here and reused below, so the MTU-split
        // rule lives in exactly one place.
        let hdr = COMMON_HEADER_SIZE as usize;
        let mut bundles: Vec<(usize, usize)> = Vec::new();
        let mut total_len = 0usize;
        let mut bundle_start = 0;
        let mut bundle_len = hdr;
        for (i, chunk) in chunks.iter().enumerate() {
            // Marshalled chunk size: header + payload, padded up to the SCTP
            // 4-byte boundary. Bundle decisions must use this wire size —
            // deciding on raw payload sizes admitted bundles that marshalled
            // past the MTU (e.g. payloads of 1147 + 16 pass a payload-only
            // check at an MTU of 1191 but serialize to a 1208-byte packet).
            let wire = chunk.wire_size();
            // Close the current bundle before a chunk whose padded wire size
            // would push the datagram past the MTU.
            if bundle_len + wire > self.mtu as usize && i > bundle_start {
                bundles.push((bundle_start, i));
                total_len += bundle_len;
                bundle_start = i;
                bundle_len = hdr;
            }
            bundle_len += wire;
        }
        bundles.push((bundle_start, chunks.len()));
        total_len += bundle_len;

        // Second pass: marshal each datagram into the shared buffer.
        let mut buf = BytesMut::with_capacity(total_len);
        for (start, end) in bundles {
            match Packet::write_framed_with(
                &common_header,
                chunks[start..end].iter().map(|c| c as &dyn Chunk),
                &mut buf,
                self.send_zero_checksum,
            ) {
                Ok(_) => {
                    let plen = buf.len();
                    raw_packets.push(buf.split_to(plen).freeze());
                }
                Err(_) => {
                    warn!("[{}] failed to serialize a DATA packet", self.side);
                    buf.clear();
                }
            }
        }
    }

    /// generate_next_tsn returns the my_next_tsn and increases it. The caller should hold the lock.
    fn generate_next_tsn(&mut self) -> u32 {
        let tsn = self.my_next_tsn;
        self.my_next_tsn = self.my_next_tsn.wrapping_add(1);
        tsn
    }

    /// generate_next_rsn returns the my_next_rsn and increases it. The caller should hold the lock.
    fn generate_next_rsn(&mut self) -> u32 {
        let rsn = self.my_next_rsn;
        self.my_next_rsn = self.my_next_rsn.wrapping_add(1);
        rsn
    }

    /// Builds the SACK, keeping the gap blocks nearest the cumulative TSN and then the repeats
    /// that fit, so the packet carrying it stays within the MTU.
    fn create_selective_ack_chunk(&mut self) -> ChunkSelectiveAck {
        let fixed = COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + SELECTIVE_ACK_HEADER_SIZE;
        let room = (self.mtu as usize).saturating_sub(fixed) / 4;
        let mut gap_ack_blocks = self.payload_queue.get_gap_ack_blocks(self.peer_last_tsn);
        gap_ack_blocks.truncate(room);
        let mut duplicate_tsn = self.payload_queue.pop_duplicates();
        duplicate_tsn.truncate(room - gap_ack_blocks.len());
        self.last_advertised_window = self.advertised_window();
        self.received_since_sack = 0;
        ChunkSelectiveAck {
            cumulative_tsn_ack: self.peer_last_tsn,
            advertised_receiver_window_credit: self.last_advertised_window,
            gap_ack_blocks,
            duplicate_tsn,
        }
    }

    /// The a_rwnd to advertise. RFC 9260 6.2 asks the receiver for silly window syndrome
    /// avoidance (RFC 1122 4.2.3.3): a window too small for a full packet is advertised as
    /// closed, so the sender does not fill it with scraps.
    fn advertised_window(&self) -> u32 {
        let free = self.get_my_receiver_window_credit();
        let threshold = (self.max_receive_buffer_size / 2).min(self.pmdcs);
        if free < threshold { 0 } else { free }
    }

    /// The application took data from the receive buffer. RFC 9260 6.2: "When the window
    /// opens up, an SCTP receiver SHOULD send additional SACK chunks to update the window even
    /// if no new data is received." A window the sender sees as too small for a full chunk
    /// (advertised as closed, or used up by what it sent since the last SACK) that has opened
    /// again is announced by a SACK at once. Without it the sender, stopped by a_rwnd 0,
    /// learns of the space only from its next window probe, a retransmission timeout later
    /// (and that timeout doubles); and one whose window a single chunk used up waits for the
    /// delayed SACK. A sender that still sees room for a full chunk gets no extra SACK.
    pub(crate) fn on_receive_buffer_drained(&mut self) {
        // The window as the sender sees it: what the last SACK advertised, less what it has
        // sent since. Too small for a full chunk, the sender waits for a SACK (RFC 9260 6.1
        // A); a delayed one held each chunk of a receiver with a small buffer that reads in
        // parts for the SACK delay, though its window was open again at once.
        let threshold = (self.max_receive_buffer_size / 2).min(self.pmdcs);
        let sender_view = self
            .last_advertised_window
            .saturating_sub(self.received_since_sack);
        if sender_view < threshold
            && self.advertised_window() > 0
            && matches!(
                self.state(),
                AssociationState::Established
                    | AssociationState::ShutdownPending
                    | AssociationState::ShutdownSent
            )
        {
            self.ack_state = AckState::Immediate;
            self.timers.stop(Timer::Ack);
            self.awake_write_loop();
        }
    }

    /// Record an abandoned chunk into the forward-TSN stream map (RFC 3758 C4),
    /// called from the two C2 loops as `advanced_peer_tsn_ack_point` advances
    /// over each newly-abandoned in-flight chunk. Only *ordered* streams are
    /// tracked: the receiver ignores the per-stream SSN list for unordered
    /// chunks (it advances purely by `new_cumulative_tsn`). Keeps the greatest
    /// SSN seen per stream, which is the value RFC 3758 C4 requires to report.
    ///
    /// A stream's entry may briefly outlive the chunk that set it (until the
    /// window closes and the map is cleared), so a stale SSN can be re-reported;
    /// that is safe because the receiver only advances a stream forward and the
    /// SSN always corresponds to a really-abandoned chunk. The `u16` SSN compare
    /// (`sna16lt`) is sound because the window span is bounded by rwnd — a
    /// stream cannot lap the full 65536-sequence space before the window closes.
    fn note_abandoned_for_forward_tsn(&mut self, unordered: bool, si: u16, ssn: u16) {
        if unordered {
            return;
        }
        self.fwd_tsn_stream_map
            .entry(si)
            .and_modify(|cur| {
                if sna16lt(*cur, ssn) {
                    *cur = ssn;
                }
            })
            .or_insert(ssn);
    }

    /// Test-only observer for the incremental forward-TSN stream map, so the
    /// endpoint tests can assert it is cleared once the forward-TSN window
    /// closes (the C1/C3 clear paths, which the unit tests can't reach).
    #[cfg(test)]
    pub(crate) fn fwd_tsn_stream_map_is_empty(&self) -> bool {
        self.fwd_tsn_stream_map.is_empty()
    }

    /// create_forward_tsn generates ForwardTSN chunk.
    /// This method will be be called if use_forward_tsn is set to false.
    fn create_forward_tsn(&self) -> ChunkForwardTsn {
        // RFC 3758 Sec 3.5 C4: report, once per ordered stream, the greatest
        // stream-sequence-number among abandoned chunks in the forward-TSN
        // window. This is maintained incrementally in `fwd_tsn_stream_map` (see
        // its declaration and the two C2 loops that feed it), so we no longer
        // rescan `(cumulative_tsn_ack_point, advanced_peer_tsn_ack_point]` with
        // a per-TSN hashmap probe on every FORWARD-TSN — that scan was O(rwnd)
        // (~1000 probes/call for a 1 MB window) and dominated the send profile.
        // RFC 3758 3.5 C4: the chunk fits one packet. When more streams have abandoned data
        // than fit, it covers the TSNs up to the last one whose streams do, and the next
        // FORWARD TSN goes on from there once the peer has acknowledged this one. Only then
        // is the window walked.
        let room = if self.mtu == 0 {
            // No packet size is known (an association that was never set up): no bound.
            usize::MAX
        } else {
            (self.mtu as usize).saturating_sub(COMMON_HEADER_SIZE as usize + CHUNK_HEADER_SIZE + 4)
                / 4
        };
        let mut fwd_tsn = ChunkForwardTsn {
            new_cumulative_tsn: self.advanced_peer_tsn_ack_point,
            streams: Vec::with_capacity(self.fwd_tsn_stream_map.len().min(room)),
        };
        if self.fwd_tsn_stream_map.len() <= room {
            for (si, ssn) in &self.fwd_tsn_stream_map {
                fwd_tsn.streams.push(ChunkForwardTsnStream {
                    identifier: *si,
                    sequence: *ssn,
                });
            }
        } else {
            let mut streams: FxHashMap<u16, u16> = FxHashMap::default();
            let mut covered = self.cumulative_tsn_ack_point;
            let mut tsn = self.cumulative_tsn_ack_point.wrapping_add(1);
            while sna32lte(tsn, self.advanced_peer_tsn_ack_point) {
                let Some(c) = self.inflight_queue.get(tsn) else {
                    break;
                };
                if !c.unordered {
                    if !streams.contains_key(&c.stream_identifier) && streams.len() == room {
                        break;
                    }
                    let ssn = c.stream_sequence_number;
                    streams
                        .entry(c.stream_identifier)
                        .and_modify(|cur| {
                            if sna16lt(*cur, ssn) {
                                *cur = ssn;
                            }
                        })
                        .or_insert(ssn);
                }
                covered = tsn;
                tsn = tsn.wrapping_add(1);
            }
            fwd_tsn.new_cumulative_tsn = covered;
            for (si, ssn) in streams {
                fwd_tsn.streams.push(ChunkForwardTsnStream {
                    identifier: si,
                    sequence: ssn,
                });
            }
        }
        // `trace!` evaluates its arguments lazily, so the stream list is only
        // formatted when trace logging is enabled -- no per-FORWARD-TSN string
        // allocation on the hot send path (this fires often for PR-SCTP data
        // channels, which is exactly where it was showing up in profiles).
        trace!(
            "[{}] building fwd_tsn: newCumulativeTSN={} cumTSN={} streams={:?}",
            self.side, fwd_tsn.new_cumulative_tsn, self.cumulative_tsn_ack_point, fwd_tsn.streams
        );

        fwd_tsn
    }

    /// Move the chunk peeked with self.pending_queue.peek() to the inflight_queue.
    /// The message whose first fragment is about to leave the pending queue takes its Stream
    /// Sequence Number and Message Identifier now (RFC 3758 4.1 TR3: a message abandoned
    /// while it waited took none).
    fn number_next_message(&mut self) {
        let Some(c) = self.pending_queue.peek() else {
            return;
        };
        if !c.numbers_pending || !c.beginning_fragment {
            return;
        }
        let (id, generation) = (c.stream_identifier, c.stream_generation);
        let Some(s) = self.streams.get_mut(&id) else {
            return;
        };
        if s.generation == generation {
            self.pending_queue
                .number_messages(id, generation, true, |unordered| {
                    s.next_message_numbers(unordered)
                });
        }
    }

    fn move_pending_data_chunk_to_inflight_queue(
        &mut self,
        beginning_fragment: bool,
        unordered: bool,
        now: Instant,
    ) -> Option<ChunkPayloadData> {
        self.number_next_message();
        if let Some(mut c) = self.pending_queue.pop(beginning_fragment, unordered) {
            // Assign TSN
            c.tsn = self.generate_next_tsn();

            // RTT baseline only; maxPacketLifeTime measures from `created_at`.
            c.since = Some(now);
            self.last_rtt_probe = Some(now);
            self.last_data_sent = Some(now);
            c.nsent = 1; // being sent for the first time

            trace!(
                "[{}] sending ppi={} tsn={} ssn={} sent={} len={} ({},{})",
                self.side,
                c.ppid(),
                c.tsn,
                c.stream_sequence_number,
                c.nsent,
                c.user_data.len(),
                c.beginning_fragment,
                c.ending_fragment
            );

            self.inflight_queue.push_no_check(c.clone());
            self.note_dequeued(&c);

            Some(c)
        } else {
            error!("[{}] failed to pop from pending queue", self.side);
            None
        }
    }

    /// Allocate an identity before consuming input or changing stream state.
    pub(crate) fn allocate_message_id(&mut self) -> Result<MessageId> {
        let state = self.state();
        if state != AssociationState::Established {
            return Err(Error::ErrPayloadDataStateNotExist);
        }

        let id = MessageId::new(self.next_message_id)
            .ok_or_else(|| Error::OtherSctpErr("message identity exhausted".into()))?;
        // MessageId::new has already checked that this increment cannot overflow.
        self.next_message_id += 1;
        Ok(id)
    }

    /// send_payload_data sends the data chunks with their allocated identity.
    ///
    /// The queueing instant is already recorded on each chunk by `Stream::packetize`, so this
    /// does not need one of its own.
    pub(crate) fn send_payload_data(&mut self, id: MessageId, mut chunks: Vec<ChunkPayloadData>) {
        for c in &mut chunks {
            c.message_id = Some(id);
        }
        self.pending_queue.push_message(chunks);

        self.awake_write_loop();
    }

    /// buffered_amount returns total amount (in bytes) of currently buffered user data.
    /// This is used only by testing.
    pub(crate) fn buffered_amount(&self) -> usize {
        self.pending_queue.get_num_bytes() + self.inflight_queue.get_num_bytes()
    }

    /// Whether everything the application handed over has been sent and acknowledged
    /// (RFC 9260 9.2), messages held for a stream reset included.
    fn nothing_left_to_send(&self) -> bool {
        self.inflight_queue.is_empty()
            && self.pending_queue.is_empty()
            && self.held_write_count == 0
    }

    fn awake_write_loop(&self) {
        // No Op on Purpose
    }

    fn close_all_timers(&mut self) {
        // Close all retransmission & ack timers
        for timer in Timer::VALUES {
            self.timers.stop(timer);
        }
    }

    fn on_ack_timeout(&mut self) {
        trace!(
            "[{}] ack timed out (ack_state: {})",
            self.side, self.ack_state
        );
        self.stats.inc_ack_timeouts();
        self.ack_state = AckState::Immediate;
        self.awake_write_loop();
    }

    /// RFC 9260 5.1: "The T1-init timer and T1-cookie timer SHOULD follow the same rules
    /// given in Section 6.3": an expiry backs off the path's RTO (6.3.3 E2, bounded by
    /// RTO.Max), which the timer is started again with, as the next handshake timer and the
    /// first T3-rtx are, until a round trip is measured. Not with
    /// `TransportConfig::with_handshake_timers_back_off_rto(false)` (dcSCTP's form), where
    /// the timer doubles its own interval and the RTO is left alone.
    fn back_off_rto_for_handshake_timer(&mut self) {
        if self.handshake_timers_back_off_rto {
            self.rto_mgr.backoff();
        }
    }

    fn on_retransmission_timeout(&mut self, timer_id: Timer, n_rtos: usize, now: Instant) {
        match timer_id {
            Timer::T1Init => {
                self.back_off_rto_for_handshake_timer();
                if let Err(err) = self.send_init() {
                    debug!(
                        "[{}] failed to retransmit init (n_rtos={}): {:?}",
                        self.side, n_rtos, err
                    );
                }
            }

            Timer::T1Cookie => {
                self.cookie_echo_sent_at = Some(now);
                self.back_off_rto_for_handshake_timer();
                if let Err(err) = self.send_cookie_echo() {
                    debug!(
                        "[{}] failed to retransmit cookie-echo (n_rtos={}): {:?}",
                        self.side, n_rtos, err
                    );
                }
            }

            Timer::T2Shutdown => {
                debug!(
                    "[{}] retransmission of shutdown timeout (n_rtos={})",
                    self.side, n_rtos
                );
                let state = self.state();
                match state {
                    AssociationState::ShutdownSent => {
                        self.will_send_shutdown = true;
                        self.awake_write_loop();
                    }
                    AssociationState::ShutdownAckSent => {
                        self.will_send_shutdown_ack = true;
                        self.awake_write_loop();
                    }
                    _ => {}
                }
            }

            Timer::T3RTX => {
                self.stats.inc_t3timeouts();
                self.stats.add_t3_wait(self.rto_mgr.get_rto());
                self.rto_mgr.backoff();
                self.note_path_error();
                // Refresh before C2 or mark_all_to_retrasmit reads abandoned().
                if let Err(err) =
                    self.abandon_unretransmittable_messages(now, ChunkPayloadData::is_outstanding)
                {
                    self.fail_message_queue(err);
                    return;
                }

                // RFC 4960 sec 6.3.3
                //  E1)  For the destination address for which the timer expires, adjust
                //       its ssthresh with rules defined in Section 7.2.3 and set the
                //       cwnd <- MTU.
                // RFC 4960 sec 7.2.3
                //   When the T3-rtx timer expires on an address, SCTP should perform slow
                //   start by:
                //      ssthresh = max(cwnd/2, 4*MTU)
                //      cwnd = 1*MTU

                // RFC 9260 7.2.3: ssthresh = max(cwnd / 2, 4 x PMDCS), cwnd = PMDCS,
                // partial_bytes_acked = 0, and one packet in flight until it is acknowledged.
                self.ssthresh = std::cmp::max(self.cwnd / 2, self.pmdcs.saturating_mul(4));
                self.cwnd = self.pmdcs;
                self.partial_bytes_acked = 0;
                self.t3_single_packet = true;
                // A retransmission timeout ends Fast Recovery: the window is one packet now.
                self.in_fast_recovery = false;
                trace!(
                    "[{}] updated cwnd={} ssthresh={} inflight={} (RTO)",
                    self.side,
                    self.cwnd,
                    self.ssthresh,
                    self.inflight_queue.get_num_bytes()
                );

                // RFC 3758 sec 3.5
                //  A5) Any time the T3-rtx timer expires, on any destination, the sender
                //  SHOULD try to advance the "Advanced.Peer.Ack.Point" by following
                //  the procedures outlined in C2 - C5.
                if self.use_forward_tsn {
                    self.advance_peer_ack_point();
                }

                debug!(
                    "[{}] T3-rtx timed out: n_rtos={} cwnd={} ssthresh={}",
                    self.side, n_rtos, self.cwnd, self.ssthresh
                );

                // RFC 8899 section 4.3: data at the PLPMTU that keeps going unacknowledged
                // is the sign of a path that no longer carries it.
                if let Some(mtu) = self
                    .pmtud
                    .as_mut()
                    .and_then(|p| p.on_retransmission_timeout())
                {
                    debug!("[{}] path MTU black hole: back to {mtu} bytes", self.side);
                    self.use_path_mtu(mtu, false);
                }

                // RFC 9260 6.2.1 C: what is marked for retransmission goes back to rwnd.
                let marked = self.inflight_queue.mark_all_for_retransmission();
                self.rwnd = self
                    .rwnd
                    .saturating_add(u32::try_from(marked).unwrap_or(u32::MAX));
                self.t3_retransmit_pending = true;
                // RFC 9260 5.1 D, 5.2.5: while nothing from the peer has shown that the COOKIE
                // ACK reached it, the peer may be in COOKIE-ECHOED, discarding this DATA
                // again. The retransmission goes behind a COOKIE ACK, which a peer in
                // COOKIE-ECHOED takes first, and one in ESTABLISHED discards. Without it the
                // DATA waits until the peer's T1-cookie, backed off to 16 s and more, gets a
                // COOKIE ECHO through and its answer back.
                if self.peer_awaits_cookie_ack && self.state() == AssociationState::Established {
                    match self.outstanding_data_after_a_cookie_ack(now) {
                        Ok(chunks) => {
                            let mut packet: Vec<Box<dyn Chunk>> = vec![Box::new(ChunkCookieAck {})];
                            for chunk in chunks {
                                packet.push(Box::new(chunk));
                            }
                            self.control_queue.push_back(Packet {
                                common_header: CommonHeader {
                                    verification_tag: self.peer_verification_tag,
                                    source_port: self.source_port,
                                    destination_port: self.destination_port,
                                },
                                chunks: packet,
                            });
                        }
                        Err(err) => {
                            self.fail_message_queue(err);
                            return;
                        }
                    }
                }
                self.awake_write_loop();
            }

            Timer::Reconfig => {
                // RFC 6525 5.1.1: an expiry counts against the association and the path,
                // and past the retransmission limit the association ends. 5.2.7 H2: not the
                // expiry that follows an "In progress" answer, which only says the peer is
                // not done yet.
                if !std::mem::take(&mut self.reconfig_in_progress) && self.on_path_failure() {
                    return;
                }
                self.will_retransmit_reconfig = true;
                self.awake_write_loop();
            }

            _ => {}
        }
    }

    fn on_retransmission_failure(&mut self, id: Timer) {
        match id {
            // A handshake that runs out of retransmissions is over (RFC 9260 5.1 A, C). It
            // used to only report HandshakeFailed and stay in COOKIE-WAIT / COOKIE-ECHOED, so
            // whatever watched the association saw it connecting for good.
            Timer::T1Init => {
                error!("[{}] retransmission failure: T1-init", self.side);
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeInitAck.to_string());
                self.error = Some(reason.clone());
                if let Err(err) = self.close(reason) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T1Cookie => {
                error!("[{}] retransmission failure: T1-cookie", self.side);
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeCookieEcho.to_string());
                self.error = Some(reason.clone());
                if let Err(err) = self.close(reason) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T2Shutdown => {
                // RFC 9260 9.2: past the limit the peer is unreachable and the association is
                // over. This only logged, and the timer was not started again: the association
                // stayed in SHUTDOWN-SENT (or SHUTDOWN-ACK-SENT) for good.
                error!("[{}] retransmission failure: T2-shutdown", self.side);
                if let Err(err) = self.close(AssociationError::TimedOut) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T5ShutdownGuard => {
                // RFC 9260 9.2: the shutdown did not finish in time. The association is
                // aborted and the upper layer told.
                error!("[{}] T5-shutdown-guard expired", self.side);
                if let Err(err) = self.abort_with(vec![], AssociationError::TimedOut) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::HalfOpen => {
                debug!("[{}] no COOKIE ECHO followed the INIT", self.side);
                let reason =
                    AssociationError::HandshakeFailed(Error::ErrHandshakeCookieEcho.to_string());
                self.error = Some(reason.clone());
                if let Err(err) = self.close(reason) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            Timer::T3RTX => {
                // Reached only with a finite `TimerConfig::max_t3_rtx_retrans`; the default
                // is unlimited because a WebRTC peer learns of a lost path from ICE. RFC 9260
                // 8.1: once the limit is exceeded the peer is unreachable and the association
                // ends. Returning without re-arming the timer, as this did, left it running
                // with no retransmission and no FORWARD TSN for ever.
                error!("[{}] retransmission failure: T3-rtx (DATA)", self.side);
                if let Err(err) = self.close(AssociationError::TimedOut) {
                    error!("[{}] failed to close association: {err}", self.side);
                }
            }

            _ => {}
        }
    }

    /// Whether no timers are running
    #[cfg(test)]
    pub(crate) fn is_idle(&self) -> bool {
        // A zero window probe waiting for its time (RFC 9260 6.1 A) is something to wake for.
        self.zero_window_probe_at.is_none()
            && Timer::VALUES
                .iter()
                // The heartbeat timer always runs on an established association.
                .filter(|&&t| t != Timer::Heartbeat)
                .filter_map(|&t| Some((t, self.timers.get(t)?)))
                .min_by_key(|&(_, time)| time)
                //.map_or(true, |(timer, _)| timer == Timer::Idle)
                .is_none()
    }
}
