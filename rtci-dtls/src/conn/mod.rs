//! The DTLS association.
//!
//! [`DTLSConn`](crate::conn::DTLSConn) joins the handshake state machine to the record layer for one peer: inbound
//! datagrams go in through [`read`](crate::conn::DTLSConn::read), application data comes out through
//! [`incoming_application_data`](crate::conn::DTLSConn::incoming_application_data), and whatever should go on
//! the wire is collected from [`outgoing_raw_packet`](crate::conn::DTLSConn::outgoing_raw_packet).
//!
//! Normally an application drives [`Endpoint`](crate::endpoint::Endpoint) instead, which owns one
//! of these per remote address.
#[cfg(test)]
pub(crate) mod conn_conformance_test;
#[cfg(test)]
mod conn_ported_test;
#[cfg(test)]
mod conn_test;
#[cfg(test)]
mod conn_transport_test;
#[cfg(test)]
mod connection_id_test;
#[cfg(test)]
mod mbedtls_cid_kat_test;
#[cfg(test)]
mod openssl_kat_test;
#[cfg(test)]
mod openssl_recordings;
#[cfg(test)]
mod rfc5246_rows_test;

use crate::alert::*;
use crate::application_data::*;
use crate::content::*;
use crate::curve::named_curve::NamedCurve;
use crate::extension::extension_use_srtp::*;
use crate::flight::flight0::*;
use crate::flight::flight1::*;
use crate::flight::flight5::*;
use crate::flight::flight6::*;
use crate::flight::*;
use crate::fragment_buffer::*;
use crate::handshake::handshake_cache::*;
use crate::handshake::handshake_header::{HANDSHAKE_HEADER_LENGTH, HandshakeHeader};
use crate::handshake::handshake_random::HandshakeRandom;
use crate::handshake::*;
use crate::handshaker::*;
use crate::record_layer::record_layer_header::*;
use crate::record_layer::*;
use crate::state::*;
use std::collections::VecDeque;

use shared::{error::*, replay_detector::*};

use crate::config::HandshakeConfig;
use bytes::BytesMut;
use log::*;
use std::io::BufWriter;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The retransmission timer's initial value (RFC 6347 4.2.4.1).
pub(crate) const INITIAL_TICKER_INTERVAL: Duration = Duration::from_secs(1);
/// What the retransmission timer doubles up to (RFC 6347 4.2.4.1, the RFC 6298 maximum).
pub(crate) const MAXIMUM_RETRANSMIT_INTERVAL: Duration = Duration::from_secs(60);
/// The most bytes a record carries before protection (RFC 5246 6.2.1).
pub const MAX_RECORD_PAYLOAD: usize = 1 << 14;
/// The most bytes a protected record's fragment may hold (RFC 5246 6.2.3).
pub(crate) const MAX_PROTECTED_RECORD_PAYLOAD: usize = MAX_RECORD_PAYLOAD + 2048;
/// The smallest MTU a configuration may name: room for a record header, a handshake header,
/// the largest record expansion and some payload.
pub(crate) const MINIMUM_MTU: usize = 128;
/// The smallest datagram size handshake records are cut for when retransmissions go unanswered
/// and the path MTU may be the reason (RFC 6347 4.1.1.1): 256 bytes less the IPv4 and UDP
/// headers, the floor OpenSSL uses as well.
pub(crate) const FALLBACK_HANDSHAKE_MTU: usize = 228;
/// Retransmissions of one flight after which its records are cut smaller (RFC 6347 4.1.1.1).
pub(crate) const RETRANSMITS_BEFORE_MTU_BACKOFF: usize = 2;
pub(crate) const COOKIE_LENGTH: usize = 20;
pub(crate) const DEFAULT_NAMED_CURVE: NamedCurve = NamedCurve::X25519;
pub(crate) const INBOUND_BUFFER_SIZE: usize = 8192;
// Default replay protection window is specified by RFC 6347 Section 4.1.2.6
pub(crate) const DEFAULT_REPLAY_PROTECTION_WINDOW: usize = 64;
/// The smallest replay protection window RFC 6347 4.1.2.6 allows.
pub(crate) const MINIMUM_REPLAY_PROTECTION_WINDOW: usize = 32;
/// Most not-yet-decryptable records held for later (next epoch / cipher suite not ready).
/// A flight needs only a few; the rest are unauthenticated until decrypted.
pub(crate) const MAX_EARLY_ENCRYPTED_PACKETS: usize = 64;
/// Most application-data records held before the handshake completes. A genuine peer sends them
/// only after its Finished (the first ones can arrive just before we have processed it); until
/// the handshake completes the sender is not authenticated, so past this cap (or
/// [`MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES`]) further records are dropped, as lost datagrams
/// would be.
pub(crate) const MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS: usize = 16;
/// Most application-data bytes held before the handshake completes.
pub(crate) const MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES: usize = 64 * 1024;
/// The highest epoch a peer's records move to. A DTLS 1.2 handshake has one epoch transition,
/// 0 to 1, and this stack does not renegotiate (a DTLS restart builds a new connection), so a
/// ChangeCipherSpec is honoured only for that transition. It also bounds the per-epoch replay
/// detectors: records more than one epoch ahead of `remote_epoch` are discarded, so at most
/// `MAX_REMOTE_EPOCH + 2` exist.
pub(crate) const MAX_REMOTE_EPOCH: u16 = 1;
/// How many times a handshake flight may be retransmitted before the handshake fails.
///
/// Zero means "no retries at all": the first firing of the retransmit timer ends the handshake,
/// so any reply slower than one `retransmit_interval` is fatal. That is almost never what a
/// caller wants, and it is what `ConfigBuilder::build` accidentally used between P7 and this
/// constant being introduced.
pub(crate) const DEFAULT_MAXIMUM_RETRANSMIT_NUMBER: usize = 7;
/// How long a completed association answers a repeat of the peer's last flight with its own
/// last flight again: "at least twice the default MSL defined for [TCP]" (RFC 6347 4.2.4),
/// the TCP MSL being two minutes (RFC 793 3.3). The same as DTLS 1.3 keeps its handshake keys
/// for (`dtls13::conn::HANDSHAKE_KEYS_LINGER`, RFC 9147 5.8.1).
pub(crate) const FINAL_FLIGHT_ANSWER_PERIOD: Duration = Duration::from_secs(240);

pub(crate) static INVALID_KEYING_LABELS: &[&str] = &[
    "client finished",
    "server finished",
    "master secret",
    "key expansion",
];

// Conn represents a DTLS connection
/// One DTLS association: the handshake state machine plus the record layer around it.
pub struct DTLSConn {
    is_client: bool,
    maximum_transmission_unit: usize,
    pub(crate) maximum_retransmit_number: usize,
    replay_protection_window: usize,
    replay_detector: Vec<Box<dyn ReplayDetector>>,
    incoming_decrypted_packets: VecDeque<BytesMut>, // Decrypted Application Data or error, pull by calling `Read`
    incoming_encrypted_packets: VecDeque<Vec<u8>>,
    fragment_buffer: FragmentBuffer,
    pub(crate) cache: HandshakeCache, // caching of handshake messages for verifyData generation
    pub(crate) outgoing_packets: VecDeque<Packet>,
    outgoing_queued_packets: VecDeque<Packet>,
    outgoing_compacted_raw_packets: VecDeque<BytesMut>,

    pub(crate) state: State, // Internal state

    handshake_completed: bool,
    /// When the handshake completed, the start of [`FINAL_FLIGHT_ANSWER_PERIOD`]: nanoseconds
    /// after `handshake_started`, `u64::MAX` until then (`handshake_completed_at`). An integer
    /// and not an `Option<Instant>`: a `None` of that type leaves eight bytes of the value
    /// uninitialized, and moving the association copies whatever the stack held there into the
    /// heap blocks it passes through, where `Zeroize` cannot reach them (the secret-erasure
    /// test found an exported SRTP key that way, on Windows).
    pub(crate) handshake_completed_after_ns: u64,
    connection_closed_by_user: bool,
    // closeLock              sync.Mutex
    closed: bool, //  *closer.Closer
    /// The peer sent close_notify. Its reply has been queued; the connection is finished.
    pub(crate) closed_by_peer: bool,
    /// The association ended in failure: a fatal alert was sent or received, or the handshake
    /// gave up (an error, or its retransmissions ran out). Terminal: nothing more is read,
    /// written or retransmitted (RFC 5246 7.2.2, W3C webrtc 5.5.1 RTCDtlsTransport "failed").
    pub(crate) failed: bool,
    //handshakeLoopsFinished sync.WaitGroup

    //readDeadline  :deadline.Deadline,
    //writeDeadline :deadline.Deadline,

    //log logging.LeveledLogger
    /*
    reading               chan struct{}
    handshakeRecv         chan chan struct{}
    cancelHandshaker      func()
    cancelHandshakeReader func()
    */
    pub(crate) current_handshake_state: HandshakeState,
    pub(crate) current_retransmit_timer: Option<Instant>,
    pub(crate) current_retransmit_count: usize,
    /// The retransmission timer's current value: the configured initial value, doubled at each
    /// retransmission up to the configured maximum, and kept until a flight is answered without
    /// any retransmission (RFC 6347 4.2.4.1).
    pub(crate) current_retransmit_interval: Duration,
    /// When the handshake began: the first time it was driven. The handshake deadline counts
    /// from here.
    pub(crate) handshake_started: Option<Instant>,
    /// The datagram size handshake records are cut for: the configured MTU, halved (down to
    /// [`FALLBACK_HANDSHAKE_MTU`]) when a flight's retransmissions go unanswered, since records
    /// too large for the path are one reason they would (RFC 6347 4.1.1.1).
    pub(crate) handshake_mtu: usize,
    /// The fatal alert this side ended the association with, and how many more times it may be
    /// sent again when the peer keeps sending handshake records (RFC 6347 4.2.7: alerts are
    /// not retransmitted on a timer, but the offending record arriving again draws a new one).
    pub(crate) fatal_alert_sent: Option<(Alert, usize)>,
    /// The fatal alert the peer ended the association with, if it did.
    pub(crate) fatal_alert_received: Option<Alert>,
    /// How many records of an epoch after 0 have authenticated. An endpoint that holds two
    /// associations for one address (RFC 6347 4.2.8) reads from it which of them a protected
    /// record belongs to.
    pub(crate) authenticated_records: u64,
    /// DTLS 1.2: protected records discarded because they failed authentication (RFC 6347
    /// 4.2.7: a peer that persistently sends bad messages; see `with_invalid_record_limit`).
    pub(crate) invalid_records: u64,
    /// DTLS 1.3 server: the client's post-handshake authentications verified so far.
    pub(crate) post_handshake_authentications: u64,
    /// DTLS 1.2: the newest (epoch, sequence number) of a record that authenticated. RFC 9146
    /// section 6 lets an association follow its peer to a new address only for a record
    /// newer than every one before.
    pub(crate) newest_authenticated_record: Option<(u16, u64)>,

    pub(crate) current_flight: Box<dyn Flight>,
    pub(crate) flights: Option<Vec<Packet>>,
    pub(crate) handshake_config: Arc<HandshakeConfig>,
    pub(crate) retransmit: bool,
    pub(crate) handshake_rx: Option<()>,
    /// Whether the datagram most recently passed to [`Self::read`] carried an accepted handshake
    /// record. After completion, only an authenticated repeat of the peer's Finished is accepted.
    /// Reset on every `read`, unlike the sticky `handshake_rx`, so a completed association can tell
    /// an RFC 6347 §4.2.4 last-flight repeat from ordinary post-handshake application data.
    pub(crate) received_handshake_in_last_datagram: bool,
    /// The peer sent again a handshake message we had already processed: it is retransmitting
    /// its flight because ours was lost, so ours is retransmitted at once (RFC 6347 4.2.4).
    /// Taken by the next `handshake()`.
    pub(crate) peer_repeated_flight: bool,
    /// The peer's source address is its own: always for a client (it chose the server's
    /// address), and for a server once the client has echoed its cookie (RFC 6347 4.2.1).
    pub(crate) address_verified: bool,
    /// The current flight has been sent again because protected application data arrived
    /// ahead of the peer's Finished (RFC 6347 4.2.4); it is not done twice for one flight.
    pub(crate) early_data_retransmit_done: bool,
    /// The association negotiated DTLS 1.3 and is run from there: every entry point below
    /// hands over to it.
    pub(crate) v13: Option<Box<crate::dtls13::conn::Conn13>>,
    /// Server: the HelloRetryRequest cookie the endpoint verified for the ClientHello this
    /// association was made for (RFC 9147 5.1), with what it holds.
    pub(crate) verified_retry: Option<(Vec<u8>, crate::dtls13::hello::RetryCookie)>,
    /// Server: the endpoint's cookie secrets and the client's address, for an association
    /// the endpoint made to run the DTLS 1.3 cookie exchange of a fragmented ClientHello.
    pub(crate) retry_keys: Option<crate::dtls13::hello::RetryKeys>,
    /// Server: when the endpoint drops this association if the client's address has not
    /// been verified by then (see `Endpoint`'s `UNVERIFIED_ASSOCIATION_LIFETIME`).
    pub(crate) unverified_until: Option<Instant>,
    /// Client: datagrams that start with a DTLS 1.3 protected record and arrived before the
    /// ServerHello that selects DTLS 1.3 (the server's flight, reordered).
    early_dtls13_datagrams: Vec<Vec<u8>>,
    /// Client: how many times the handshake has started over with a new ClientHello after
    /// the server refused the cookie of its second one (RFC 9147 section 5.1).
    fresh_client_hellos: u8,
}

/// The most datagrams a client holds for a DTLS 1.3 handshake whose ServerHello is late.
const MAX_EARLY_DTLS13_DATAGRAMS: usize = 4;

/// How many times a client starts its handshake over after the server answered its second
/// ClientHello's cookie with illegal_parameter. The alert is unprotected, so anyone on the
/// path can send it: past this the handshake fails as before.
pub(crate) const MAX_FRESH_CLIENT_HELLOS: u8 = 2;

/// What the hello of a handshake settles about the version (RFC 9147 5.3, RFC 8446 4.2.1).
enum VersionOutcome {
    /// The DTLS 1.2 handshake goes on with the message.
    Dtls12,
    /// DTLS 1.3 took the message and the association.
    Dtls13,
    /// The handshake ends with this alert.
    Refuse(AlertDescription, Error),
}

impl Drop for DTLSConn {
    /// The master secret does not outlive the association in memory.
    fn drop(&mut self) {
        self.state.forget_secrets();
    }
}

impl DTLSConn {
    /// Creates a connection in the given role, ready to handshake.
    ///
    /// # Errors
    ///
    /// Fails if the configuration is invalid — no certificate for a server, or an unusable cipher
    /// suite list.
    pub fn new(
        handshake_config: Arc<HandshakeConfig>,
        is_client: bool,
        initial_state: Option<State>,
    ) -> Self {
        let resumed = initial_state.is_some();
        let (state, flight, initial_fsm_state) = if let Some(state) = initial_state {
            let flight = if is_client {
                Box::new(Flight5 {}) as Box<dyn Flight>
            } else {
                Box::new(Flight6 {}) as Box<dyn Flight>
            };

            (state, flight, HandshakeState::Finished)
        } else {
            let flight = if is_client {
                Box::new(Flight1 {}) as Box<dyn Flight>
            } else {
                Box::new(Flight0 {}) as Box<dyn Flight>
            };

            (
                State::new(handshake_config.crypto_provider.clone(), is_client),
                flight,
                HandshakeState::Preparing,
            )
        };

        Self {
            is_client,
            maximum_transmission_unit: handshake_config.maximum_transmission_unit,
            maximum_retransmit_number: handshake_config.maximum_retransmit_number,
            replay_protection_window: handshake_config.replay_protection_window,
            replay_detector: vec![],
            incoming_decrypted_packets: VecDeque::new(),
            incoming_encrypted_packets: VecDeque::new(),
            fragment_buffer: FragmentBuffer::new(),
            outgoing_packets: VecDeque::new(),
            outgoing_queued_packets: VecDeque::new(),
            outgoing_compacted_raw_packets: VecDeque::new(),

            cache: HandshakeCache::new(),
            state,
            handshake_completed: false,
            handshake_completed_after_ns: u64::MAX,
            connection_closed_by_user: false,
            closed: false,
            closed_by_peer: false,
            failed: false,

            current_handshake_state: initial_fsm_state,
            current_retransmit_timer: None,
            current_retransmit_count: 0,
            current_retransmit_interval: handshake_config.retransmit_interval,
            handshake_started: None,
            handshake_mtu: handshake_config.maximum_transmission_unit,
            fatal_alert_sent: None,
            fatal_alert_received: None,
            authenticated_records: 0,
            invalid_records: 0,
            post_handshake_authentications: 0,
            newest_authenticated_record: None,

            current_flight: flight,
            flights: None,
            handshake_config,
            retransmit: false,
            handshake_rx: None,
            received_handshake_in_last_datagram: false,
            peer_repeated_flight: false,
            address_verified: is_client || resumed,
            early_data_retransmit_done: false,
            v13: None,
            verified_retry: None,
            retry_keys: None,
            unverified_until: None,
            early_dtls13_datagrams: vec![],
            fresh_client_hellos: 0,
        }
    }

    /// Whether the association negotiated DTLS 1.3.
    pub fn is_dtls13(&self) -> bool {
        self.v13.is_some()
    }

    /// Copies what the DTLS 1.3 association has reached into the state callers read.
    pub(crate) fn sync_dtls13(&mut self) {
        let Some(v13) = &mut self.v13 else {
            return;
        };
        self.authenticated_records = v13.authenticated_records;
        self.closed_by_peer = v13.closed_by_peer;
        self.state.resumed = v13.resumed;
        if v13.early_data_accepted.is_some() {
            self.state.early_data_accepted = v13.early_data_accepted;
        }
        self.post_handshake_authentications = v13.post_handshake_authentications;
        if let Some(chain) = v13.post_handshake_peer_certificates.take() {
            // RFC 8446 section 4.6.2: the client authenticated after the handshake; an
            // empty chain (it declined) leaves the earlier one.
            if !chain.is_empty() {
                v13.peer_certificates.clone_from(&chain);
                self.state.peer_certificates = chain;
            }
        }
        self.address_verified |= v13.address_verified;
        if v13.established && !self.handshake_completed {
            self.handshake_completed = true;
            self.state
                .peer_certificates
                .clone_from(&v13.peer_certificates);
            self.state.srtp_protection_profile = v13.srtp_profile;
            self.state
                .application_protocol
                .clone_from(&v13.application_protocol);
            if !self.is_client {
                self.state.server_name.clone_from(&v13.server_name);
            }
            if let (Some(suite), Some(exporter_secret)) = (v13.suite, &v13.exporter_secret) {
                self.state.cipher_suite = Some(Box::new(suite));
                self.state.tls13 = Some((suite, exporter_secret.clone()));
            }
            self.state.local_epoch = crate::dtls13::conn::EPOCH_APPLICATION as u16;
            self.state.remote_epoch = crate::dtls13::conn::EPOCH_APPLICATION as u16;
        }
        if v13.failed && !self.failed {
            self.failed = true;
            self.closed = true;
            self.current_retransmit_timer = None;
            self.state.forget_secrets();
        }
    }

    /// RFC 9147 section 5.1: a server whose cookie has expired (an endpoint's is good for one
    /// to two lifetimes of its secret) answers the ClientHello that carries it with
    /// illegal_parameter, and "this allows the client to restart the connection from scratch
    /// without a cookie". A client whose DTLS 1.3 handshake ended that way, with the alert
    /// received in the clear in answer to its second ClientHello (after a HelloRetryRequest,
    /// before any ServerHello), starts over: a new State (random, key shares, offer), the
    /// first flight again, the record sequence number going on. At most
    /// [`MAX_FRESH_CLIENT_HELLOS`] times. Returns whether it did.
    fn start_over_after_refused_cookie(&mut self) -> bool {
        use crate::dtls13::conn::HandshakeState as State13;
        use crate::dtls13::messages::alert;
        let Some(v13) = &self.v13 else {
            return false;
        };
        let refused_cookie = self.is_client
            && v13.failed
            && v13.hello_retry_seen
            && v13.state == State13::ClientWaitServerHello
            && v13.fatal_alerts() == (None, Some(alert::ILLEGAL_PARAMETER));
        if !refused_cookie || self.fresh_client_hellos >= MAX_FRESH_CLIENT_HELLOS {
            return false;
        }
        debug!(
            "client: the server refused the cookie (illegal_parameter): a new ClientHello ({} of {})",
            self.fresh_client_hellos + 1,
            MAX_FRESH_CLIENT_HELLOS
        );
        let next_sequence = v13.plaintext_send_sequence();
        let clock = self.state.clock;
        self.state.forget_secrets();
        self.state = State::new(self.handshake_config.crypto_provider.clone(), true);
        self.state.local_sequence_number = vec![next_sequence];
        self.state.clock = clock;
        self.v13 = None;
        self.fresh_client_hellos += 1;
        self.replay_detector.clear();
        self.incoming_decrypted_packets.clear();
        self.incoming_encrypted_packets.clear();
        self.fragment_buffer = FragmentBuffer::new();
        self.cache = HandshakeCache::new();
        self.closed = false;
        self.closed_by_peer = false;
        self.failed = false;
        self.current_flight = Box::new(Flight1 {});
        self.flights = None;
        self.current_handshake_state = HandshakeState::Preparing;
        self.current_retransmit_timer = None;
        self.current_retransmit_count = 0;
        self.current_retransmit_interval = self.handshake_config.retransmit_interval;
        self.handshake_mtu = self.handshake_config.maximum_transmission_unit;
        self.fatal_alert_sent = None;
        self.fatal_alert_received = None;
        self.retransmit = false;
        self.handshake_rx = None;
        self.peer_repeated_flight = false;
        self.early_dtls13_datagrams.clear();
        true
    }

    /// Hands a datagram, or what is left of one, to the DTLS 1.3 association.
    fn read_dtls13(&mut self, datagram: &[u8]) -> Result<()> {
        let Some(v13) = &mut self.v13 else {
            return Ok(());
        };
        if self.state.clock.is_some() {
            v13.clock = self.state.clock;
        }
        let result = v13.read(datagram);
        self.sync_dtls13();
        result
    }

    /// Starts a key update (RFC 9147 section 8, DTLS 1.3 only): this side moves to new
    /// sending keys once the peer has acknowledged its KeyUpdate. With `request_peer` the
    /// peer is asked to update its own as well.
    ///
    /// # Errors
    ///
    /// Fails for a DTLS 1.2 association (which has no key update), before the handshake is
    /// complete, and while an earlier KeyUpdate is still unacknowledged.
    pub fn update_keys(&mut self, request_peer: bool) -> Result<()> {
        match &mut self.v13 {
            Some(v13) => v13.send_key_update(request_peer),
            None => Err(Error::ErrUnsupportedProtocolVersion),
        }
    }

    /// Hands the peer new connection ids to use in records to this side (RFC 9147 section 9,
    /// DTLS 1.3 with negotiated connection ids): `count` fresh random ones. With `immediate`
    /// the peer switches to one of them at once; otherwise they are spares.
    ///
    /// # Errors
    ///
    /// Fails when no non-empty connection id was negotiated for this direction, while an
    /// earlier NewConnectionId is unacknowledged, and before the handshake is complete.
    pub fn new_connection_ids(&mut self, count: usize, immediate: bool) -> Result<()> {
        let Some(v13) = &mut self.v13 else {
            return Err(Error::ErrUnsupportedProtocolVersion);
        };
        let length = v13.local_connection_id.len();
        let mut connection_ids = vec![];
        for _ in 0..count {
            let mut connection_id = vec![0u8; length];
            self.handshake_config
                .provider()
                .random()
                .fill(&mut connection_id)
                .map_err(|err| Error::Crypto(err.to_string()))?;
            connection_ids.push(connection_id);
        }
        v13.send_new_connection_id(connection_ids, immediate)
    }

    /// DTLS 1.3 server: asks the client for its certificate now (post-handshake
    /// authentication, RFC 8446 section 4.6.2). The answer is checked as the handshake checks
    /// a client certificate; once verified, [`State::peer_certificates`] holds the chain and
    /// the endpoint reports [`EndpointEvent::PeerAuthenticated`](crate::endpoint::EndpointEvent::PeerAuthenticated).
    /// One that is refused ends the association with the alert RFC 8446 names.
    ///
    /// # Errors
    ///
    /// For DTLS 1.2, for a client, before the handshake is complete, when the client did not
    /// offer post_handshake_auth
    /// ([`ConfigBuilder::with_post_handshake_auth`](crate::config::ConfigBuilder::with_post_handshake_auth)),
    /// and with four requests unanswered.
    pub fn request_client_certificate(&mut self) -> Result<()> {
        match &mut self.v13 {
            Some(v13) => v13.request_client_certificate(),
            None => Err(Error::ErrUnsupportedProtocolVersion),
        }
    }

    /// How many post-handshake authentications of the client this server has verified.
    pub fn post_handshake_authentications(&self) -> u64 {
        self.post_handshake_authentications
    }

    /// Asks the peer for `count` more connection ids (RFC 9147 section 9).
    ///
    /// # Errors
    ///
    /// Fails when this side sends no connection id, and while an earlier request is
    /// unfulfilled.
    pub fn request_connection_ids(&mut self, count: u8) -> Result<()> {
        match &mut self.v13 {
            Some(v13) => v13.send_request_connection_id(count),
            None => Err(Error::ErrUnsupportedProtocolVersion),
        }
    }

    /// Switches to the next spare connection id the peer has provided, as RFC 9147 section 9
    /// asks of an endpoint that starts sending on a new path. `false` when it has none.
    pub fn use_next_connection_id(&mut self) -> bool {
        self.v13
            .as_mut()
            .is_some_and(|v13| v13.use_next_connection_id())
    }

    /// How many bytes a protected record this side sends adds to its content: the record
    /// header, the connection id if one is sent, and what the cipher suite adds (an explicit
    /// nonce, the tag or MAC and padding, the inner content type of DTLS 1.3 and of a
    /// `tls12_cid` record). A DTLS 1.3 record with a 16-byte tag adds 22 bytes, a DTLS 1.2
    /// AES-GCM record 37. `None` before the cipher suite is known. CBC padding is counted at
    /// its largest.
    pub fn record_overhead(&self) -> Option<usize> {
        if let Some(v13) = &self.v13 {
            return v13.protected_record_overhead();
        }
        let cipher_suite = self.state.cipher_suite.as_ref()?;
        let connection_id = self
            .state
            .send_connection_id()
            .map_or(0, |connection_id| connection_id.len() + 1);
        Some(RECORD_LAYER_HEADER_SIZE + cipher_suite.record_expansion() + connection_id)
    }

    /// The connection ids in use: the one this side expects in records it receives, and the
    /// one it puts in records it sends. Empty where none is used. `None` for a DTLS 1.2
    /// association that did not negotiate the extension (RFC 9146 section 3).
    pub fn connection_ids(&self) -> Option<(&[u8], &[u8])> {
        if let Some(v13) = &self.v13 {
            return Some((
                v13.local_connection_id.as_slice(),
                v13.remote_connection_id.as_slice(),
            ));
        }
        match (
            &self.state.local_connection_id,
            &self.state.remote_connection_id,
        ) {
            (Some(local), Some(remote)) => Some((local.as_slice(), remote.as_slice())),
            _ => None,
        }
    }

    /// Tells the association the time, ahead of a datagram: what a DTLS 1.3 handshake dates
    /// session tickets by (it reads no clock of its own). [`Endpoint`](crate::endpoint::Endpoint)
    /// calls it before every datagram it delivers; a caller that drives a `DTLSConn` itself
    /// calls it, or [`Self::read`] goes by the `now` of the last timer call.
    pub fn set_clock(&mut self, now: Instant) {
        self.state.clock = Some(now);
    }

    /// Settles the version from a hello: `message` is one whole ClientHello (to a server)
    /// or ServerHello (to a client), with its handshake header, from `record`.
    fn negotiate_version(
        &mut self,
        handshake_type: HandshakeType,
        message: &[u8],
        record: &RecordLayerHeader,
    ) -> VersionOutcome {
        use crate::config::DtlsVersion;
        use crate::dtls13::conn::Conn13;
        use crate::dtls13::handshake::ServerStart;
        use crate::dtls13::messages;

        let cfg = self.handshake_config.clone();
        let Some(body) = message.get(HANDSHAKE_HEADER_LENGTH..) else {
            return VersionOutcome::Dtls12;
        };
        let message_seq = u16::from_be_bytes([message[4], message[5]]);
        match handshake_type {
            HandshakeType::ClientHello if !self.is_client && !self.is_handshake_completed() => {
                // A ClientHello that does not parse is the DTLS 1.2 code's to judge.
                let Ok(hello) = messages::ClientHello::parse(body) else {
                    return VersionOutcome::Dtls12;
                };
                if cfg.supports_dtls13() && hello.offers_dtls13() {
                    let mut reader = hello.random;
                    if let Ok(random) = HandshakeRandom::unmarshal(&mut reader) {
                        self.state.remote_random = random;
                    }
                    let start = ServerStart {
                        message_seq,
                        record_sequence: record.sequence_number,
                        address_verified: self.address_verified,
                        verified_retry: self.verified_retry.take(),
                        retry_keys: self.retry_keys.take(),
                        now: self.state.clock,
                    };
                    self.v13 = Some(Box::new(Conn13::server(cfg, body, start)));
                    self.state.negotiated_version = Some(DtlsVersion::Dtls1_3);
                    self.current_retransmit_timer = None;
                    self.sync_dtls13();
                    return VersionOutcome::Dtls13;
                }
                // RFC 8446 4.2.1: with supported_versions the server "MUST only select a
                // version of TLS present in that extension" and does not negotiate by
                // legacy_version; a list without DTLS 1.2 (unknown versions only, say) leaves
                // nothing to select.
                let dtls12_listed = hello
                    .supported_versions()
                    .is_none_or(|versions| versions.contains(&crate::dtls13::DTLS1_2_WIRE_VERSION));
                if !cfg.supports_dtls12() || !dtls12_listed {
                    // RFC 8446 4.2.1: no version in common is a protocol_version.
                    return VersionOutcome::Refuse(
                        AlertDescription::ProtocolVersion,
                        Error::ErrUnsupportedProtocolVersion,
                    );
                }
                if cfg.supports_dtls13() {
                    // RFC 8446 4.1.3, RFC 9147 5.3: a server that speaks DTLS 1.3 and
                    // negotiates DTLS 1.2 says so in the last eight bytes of its random.
                    let random = &mut self.state.local_random.random_bytes;
                    let at = random.len() - messages::DOWNGRADE_TO_1_2.len();
                    random[at..].copy_from_slice(&messages::DOWNGRADE_TO_1_2);
                }
                self.state.negotiated_version = Some(DtlsVersion::Dtls1_2);
                VersionOutcome::Dtls12
            }
            HandshakeType::ServerHello if self.is_client && !self.is_handshake_completed() => {
                let Ok(hello) = messages::ServerHello::parse(body) else {
                    return VersionOutcome::Dtls12;
                };
                if self.state.tls13_offer.is_none() {
                    self.state.negotiated_version = Some(DtlsVersion::Dtls1_2);
                    return VersionOutcome::Dtls12;
                }
                if hello.selected_version() == Some(crate::dtls13::DTLS1_3_WIRE_VERSION) {
                    // RFC 9147 5.2: DTLS 1.3 has no HelloVerifyRequest; a server that sent
                    // one and now selects DTLS 1.3 is no server of either version.
                    let client_hello = self.cache.pull_and_merge(&[HandshakeCachePullRule {
                        typ: HandshakeType::ClientHello,
                        epoch: 0,
                        is_client: true,
                        optional: false,
                    }]);
                    let offer = self.state.tls13_offer.take();
                    let (Some(offer), true, Some(client_hello_body)) = (
                        offer,
                        self.state.cookie.is_empty(),
                        client_hello.get(HANDSHAKE_HEADER_LENGTH..),
                    ) else {
                        return VersionOutcome::Refuse(
                            AlertDescription::IllegalParameter,
                            Error::ErrUnsupportedProtocolVersion,
                        );
                    };
                    let client_hello_seq = u16::from_be_bytes([client_hello[4], client_hello[5]]);
                    let next_sequence = self.state.local_sequence_number.first().copied();
                    let mut v13 = Conn13::client(
                        cfg,
                        offer,
                        client_hello_body.to_vec(),
                        client_hello_seq,
                        next_sequence.unwrap_or(0),
                    );
                    v13.set_next_receive_seq(message_seq);
                    v13.clock = self.state.clock;
                    v13.continue_retransmit_interval(self.current_retransmit_interval);
                    let server_hello = crate::dtls13::record::plaintext_record(
                        crate::dtls13::record::CONTENT_TYPE_HANDSHAKE,
                        record.sequence_number,
                        &messages::handshake_fragment(
                            messages::SERVER_HELLO,
                            body.len(),
                            message_seq,
                            0,
                            body,
                        ),
                    );
                    let _ = v13.read(&server_hello);
                    // What arrived of the server's flight ahead of its ServerHello.
                    for datagram in std::mem::take(&mut self.early_dtls13_datagrams) {
                        let _ = v13.read(&datagram);
                    }
                    self.v13 = Some(Box::new(v13));
                    self.state.negotiated_version = Some(DtlsVersion::Dtls1_3);
                    self.current_retransmit_timer = None;
                    self.sync_dtls13();
                    return VersionOutcome::Dtls13;
                }
                // RFC 8446 4.2.1: supported_versions in a ServerHello selects DTLS 1.3 and
                // nothing else; any other value there is an illegal_parameter.
                if hello.extension(messages::EXT_SUPPORTED_VERSIONS).is_some() {
                    return VersionOutcome::Refuse(
                        AlertDescription::IllegalParameter,
                        Error::ErrUnsupportedProtocolVersion,
                    );
                }
                if !cfg.supports_dtls12() {
                    return VersionOutcome::Refuse(
                        AlertDescription::ProtocolVersion,
                        Error::ErrUnsupportedProtocolVersion,
                    );
                }
                // RFC 8446 4.1.3: this client offered DTLS 1.3, so a ServerHello for an
                // older version whose random ends in the downgrade sentinel was made by a
                // server that speaks DTLS 1.3 too: something in between took the offer out.
                let sentinel = &hello.random[hello.random.len() - 8..];
                if sentinel == messages::DOWNGRADE_TO_1_2 || sentinel == messages::DOWNGRADE_TO_1_0
                {
                    return VersionOutcome::Refuse(
                        AlertDescription::IllegalParameter,
                        Error::ErrUnsupportedProtocolVersion,
                    );
                }
                self.state.tls13_offer = None;
                self.state.negotiated_version = Some(DtlsVersion::Dtls1_2);
                VersionOutcome::Dtls12
            }
            // RFC 9147 5.2: DTLS 1.3 has no HelloVerifyRequest, so one comes from a server
            // of an older version: to a client that accepts DTLS 1.3 only, no version in
            // common, as a DTLS 1.2 ServerHello would be.
            HandshakeType::HelloVerifyRequest if self.is_client && !cfg.supports_dtls12() => {
                VersionOutcome::Refuse(
                    AlertDescription::ProtocolVersion,
                    Error::ErrUnsupportedProtocolVersion,
                )
            }
            _ => VersionOutcome::Dtls12,
        }
    }

    /// Creates the server association for a client whose address is verified: the endpoint
    /// has checked the cookie of its ClientHello without keeping state (RFC 6347 4.2.1), or
    /// the cookie exchange is switched off. The association performs no cookie exchange of
    /// its own; it takes the ClientHello with `message_sequence` as the one to negotiate from.
    ///
    /// Its first handshake message carries the ClientHello's message_seq and its first record
    /// the ClientHello's record sequence number (RFC 6347 4.2.1, 4.2.2), which is why both are
    /// passed.
    ///
    /// # Errors
    ///
    /// Fails if the provider's random number generator does.
    pub(crate) fn accept(
        handshake_config: Arc<HandshakeConfig>,
        message_sequence: u16,
        record_sequence: u64,
    ) -> Result<Self> {
        let mut conn = Self::new(handshake_config, false, None);
        let cfg = conn.handshake_config.clone();

        // What `Flight0::generate` sets up for a server that runs the cookie exchange itself.
        conn.state.local_epoch = 0;
        conn.state.remote_epoch = 0;
        conn.state.named_curve = match cfg.local_named_curves.first() {
            Some(curve) if cfg.local_psk_callback.is_none() => *curve,
            _ => DEFAULT_NAMED_CURVE,
        };
        conn.state.local_random.populate(cfg.provider().random())?;

        // As if the HelloVerifyRequest had just been sent: waiting for the ClientHello that
        // answers it.
        conn.state.cookie_verified_by_endpoint = true;
        conn.address_verified = true;
        conn.state.handshake_recv_sequence = message_sequence as isize;
        conn.state.handshake_send_sequence = message_sequence as isize;
        conn.fragment_buffer.start_at(message_sequence);
        conn.state.local_sequence_number = vec![record_sequence];
        conn.current_flight = Box::new(crate::flight::flight2::Flight2 {});
        conn.current_handshake_state = HandshakeState::Waiting;
        conn.retransmit = false;
        Ok(conn)
    }

    /// DTLS 1.3 server: the next piece of 0-RTT data the client sent with its ClientHello
    /// (see [`EndpointEvent::EarlyData`](crate::endpoint::EndpointEvent::EarlyData)).
    pub fn incoming_early_data(&mut self) -> Option<BytesMut> {
        self.v13.as_mut()?.early_data.pop_front()
    }

    // Read reads data from the connection.
    /// Takes the next decrypted application payload, if one is ready.
    pub fn incoming_application_data(&mut self) -> Option<BytesMut> {
        if let Some(v13) = &mut self.v13 {
            return v13.poll_application_data();
        }
        if !self.is_handshake_completed() {
            None
        } else {
            self.incoming_decrypted_packets.pop_front()
        }
    }

    /// Takes the next datagram the caller should send.
    pub fn outgoing_raw_packet(&mut self) -> Option<BytesMut> {
        // What the DTLS 1.2 code queued before DTLS 1.3 was selected (nothing, as a rule)
        // goes first.
        if let Some(datagram) = self.outgoing_compacted_raw_packets.pop_front() {
            return Some(datagram);
        }
        if let Some(v13) = &mut self.v13 {
            return v13.poll_datagram();
        }
        if let Err(err) = self.handle_outgoing_packets() {
            warn!(
                "handle_outgoing_packets [{}] with error {}",
                srv_cli_str(self.is_client),
                err
            );
        }
        self.outgoing_compacted_raw_packets.pop_front()
    }

    // Write writes p to the DTLS connection
    /// Queues `p` as application data, encrypting it once the handshake has completed.
    ///
    /// A write made before the handshake completes is held and sent when it does (RFC 5246
    /// 7.3: no application data before the first handshake completes).
    ///
    /// # Errors
    ///
    /// Fails if the connection is closed, or if `p` is longer than [`MAX_RECORD_PAYLOAD`] (one
    /// byte less in a `tls12_cid` record, RFC 9146 section 5).
    pub fn write(&mut self, p: &[u8]) -> Result<()> {
        if let Some(v13) = &mut self.v13 {
            return v13.write(p);
        }
        if self.is_connection_closed() {
            return Err(Error::ErrConnClosed);
        }
        // RFC 5246 6.2.1: a record carries at most 2^14 bytes. A longer write is refused rather
        // than split: an application datagram is one record, and whoever sizes datagrams for
        // the path (SCTP, for a data channel) relies on that.
        // RFC 9146 section 5: a `tls12_cid` record's DTLSInnerPlaintext, the content and its
        // type, is at most 2^14 bytes, so its content is one byte shorter.
        let limit = if self.state.send_connection_id().is_some() {
            MAX_RECORD_PAYLOAD - 1
        } else {
            MAX_RECORD_PAYLOAD
        };
        if p.len() > limit {
            return Err(Error::ErrRecordOverflow);
        }

        let pkt = Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                self.get_local_epoch(),
                Content::ApplicationData(ApplicationData {
                    data: BytesMut::from(p),
                }),
            ),
            should_encrypt: true,
            reset_local_sequence_number: false,
        };

        if self.is_handshake_completed() {
            self.write_packets(vec![pkt]);
        } else {
            self.outgoing_queued_packets.push_back(pkt);
        }

        Ok(())
    }

    // Close closes the connection.
    /// Begins an orderly shutdown by queueing a `close_notify` alert.
    pub fn close(&mut self) {
        if let Some(v13) = &mut self.v13 {
            self.closed = true;
            return v13.close();
        }
        if !self.closed {
            self.closed = true;

            // Discard error from notify() to return non-error on the first user call of Close()
            // even if the underlying connection is already closed.
            self.notify(AlertLevel::Warning, AlertDescription::CloseNotify);
        }
    }

    /// connection_state returns basic DTLS details about the connection.
    /// Note that this replaced the `Export` function of v1.
    pub fn connection_state(&self) -> &State {
        &self.state
    }

    // selected_srtp_protection_profile returns the selected SRTPProtectionProfile
    pub(crate) fn selected_srtp_protection_profile(&self) -> SrtpProtectionProfile {
        self.state.srtp_protection_profile
    }

    /// Whether the association has failed: a fatal alert was sent or received, or the handshake
    /// gave up (a handshake error, or the retransmissions ran out). A failed association is
    /// finished: it reads, writes and retransmits nothing more. An ordinary retransmission, or a
    /// record that is silently discarded, never fails it.
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// The fatal alerts that ended the association, as their `AlertDescription` codes (RFC
    /// 5246 section 7.2, RFC 8446 section 6): (sent, received). `None` for a side that sent or
    /// received none, as when the handshake gave up after its retransmissions.
    pub fn fatal_alerts(&self) -> (Option<u8>, Option<u8>) {
        if let Some(v13) = &self.v13 {
            return v13.fatal_alerts();
        }
        (
            self.fatal_alert_sent
                .map(|(alert, _)| alert.alert_description as u8),
            self.fatal_alert_received
                .map(|alert| alert.alert_description as u8),
        )
    }

    /// Server: the peer's first handshake message is put together from `message_sequence`
    /// on (a DTLS 1.3 ClientHello that answers a HelloRetryRequest has 1).
    pub(crate) fn start_reassembly_at(&mut self, message_sequence: u16) {
        self.fragment_buffer.start_at(message_sequence);
    }

    /// How often the handshake flight under way has been sent again: zero once the handshake
    /// is complete. A handshake that goes on and on (none is given up on its own clock by
    /// default, see [`ConfigBuilder::with_handshake_timeout`](crate::config::ConfigBuilder::with_handshake_timeout))
    /// shows here, with the retransmission timer that `next_timeout` reports.
    pub fn handshake_retransmissions(&self) -> usize {
        if self.is_handshake_completed() {
            return 0;
        }
        match &self.v13 {
            Some(v13) => v13.handshake_retransmissions(),
            None => self.current_retransmit_count,
        }
    }

    /// Whether the peer's source address is known to be its own: a client's always is; a
    /// server's once the client has echoed its cookie (RFC 6347 4.2.1).
    pub(crate) fn is_address_verified(&self) -> bool {
        self.address_verified
    }

    /// Ends the association after a fatal alert (sent or received) or a handshake that gave up.
    /// After a fatal alert the connection must be closed at once and nothing more sent on it
    /// (RFC 5246 7.2.2), so the retransmit timer is cancelled too.
    pub(crate) fn fail(&mut self) {
        if !self.failed {
            debug!("{}: association failed", srv_cli_str(self.is_client));
        }
        if let Some(v13) = &mut self.v13 {
            v13.fail();
        }
        // RFC 5246 7.2, 7.2.2: the session of a failed connection is not resumed.
        if self.v13.is_none() && !self.failed {
            crate::resumption::on_failed(&mut self.state, &self.handshake_config);
        }
        self.failed = true;
        self.closed = true;
        self.current_retransmit_timer = None;
        // RFC 5246 7.2.2: the keys and secrets of a failed connection are forgotten. The
        // cipher suite stays for the one alert that may still have to be protected; its keys
        // go with the association.
        self.state.forget_secrets();
    }

    pub(crate) fn notify(&mut self, level: AlertLevel, desc: AlertDescription) {
        let is_fatal = level == AlertLevel::Fatal;
        self.write_packets(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                self.get_local_epoch(),
                Content::Alert(Alert {
                    alert_level: level,
                    alert_description: desc,
                }),
            ),
            should_encrypt: self.protects_alerts(),
            reset_local_sequence_number: false,
        }]);
        if is_fatal {
            // Sending a fatal alert ends the association (RFC 5246 7.2.2).
            self.fatal_alert_sent = Some((
                Alert {
                    alert_level: level,
                    alert_description: desc,
                },
                self.maximum_retransmit_number,
            ));
            self.fail();
        }
    }

    /// Whether an alert sent now is protected: once this side has sent ChangeCipherSpec its
    /// records are epoch-1 records, and the peer reads nothing else from that epoch (RFC 5246
    /// 7.1). That is before the handshake completes for whoever sends its Finished first, so an
    /// alert about the peer's Finished (decrypt_error) has to be encrypted to be understood.
    fn protects_alerts(&self) -> bool {
        self.get_local_epoch() > 0
    }

    /// Whether `handshake` is a ClientHello this server must not take as the one answering its
    /// HelloVerifyRequest: it comes after the first ClientHello and does not echo the cookie
    /// (RFC 6347 4.2.1). Anyone can send such a message from the client's address; it is
    /// dropped without a trace, so that the genuine ClientHello, under the same message
    /// sequence number, is still accepted when it arrives.
    fn is_client_hello_without_our_cookie(&self, handshake: &Handshake) -> bool {
        if self.is_client || self.address_verified {
            return false;
        }
        match &handshake.handshake_message {
            HandshakeMessage::ClientHello(client_hello) => {
                handshake.handshake_header.message_sequence > 0
                    && (self.state.cookie.is_empty()
                        || !crypto::constant_time_eq(&self.state.cookie, &client_hello.cookie))
            }
            _ => false,
        }
    }

    /// Whether the peer, in its role, sends a handshake message of this type in this epoch
    /// (RFC 5246 7.3, 7.4): everything in epoch 0 except Finished, which alone follows
    /// ChangeCipherSpec.
    fn expects_handshake_type(&self, handshake_type: HandshakeType, epoch: u16) -> bool {
        if epoch != 0 {
            return handshake_type == HandshakeType::Finished;
        }
        if self.is_client {
            matches!(
                handshake_type,
                HandshakeType::HelloVerifyRequest
                    | HandshakeType::ServerHello
                    | HandshakeType::NewSessionTicket
                    | HandshakeType::Certificate
                    | HandshakeType::ServerKeyExchange
                    | HandshakeType::CertificateRequest
                    | HandshakeType::ServerHelloDone
            )
        } else {
            matches!(
                handshake_type,
                HandshakeType::ClientHello
                    | HandshakeType::Certificate
                    | HandshakeType::ClientKeyExchange
                    | HandshakeType::CertificateVerify
            )
        }
    }

    pub(crate) fn write_packets(&mut self, pkts: Vec<Packet>) {
        for pkt in pkts {
            self.outgoing_packets.push_back(pkt);
        }
    }

    fn handle_outgoing_packets(&mut self) -> Result<()> {
        if self.is_handshake_completed() {
            while let Some(mut pkt) = self.outgoing_queued_packets.pop_front() {
                pkt.record.record_layer_header.epoch = self.get_local_epoch();
                self.write_packets(vec![pkt]);
            }
        }

        let mut raw_packets = vec![];
        while let Some(p) = self.outgoing_packets.pop_front() {
            if let Content::Handshake(h) = &p.record.content {
                let mut handshake_raw = vec![];
                {
                    let mut writer = BufWriter::<&mut Vec<u8>>::new(handshake_raw.as_mut());
                    p.record.marshal(&mut writer)?;
                }
                debug!(
                    "Send [handshake:{}] -> {} (epoch: {}, seq: {})",
                    srv_cli_str(self.is_client),
                    h.handshake_header.handshake_type,
                    p.record.record_layer_header.epoch,
                    h.handshake_header.message_sequence
                );
                self.cache.push(
                    handshake_raw[RECORD_LAYER_HEADER_SIZE..].to_vec(),
                    p.record.record_layer_header.epoch,
                    h.handshake_header.message_sequence,
                    h.handshake_header.handshake_type,
                    self.is_client,
                );

                let raw_handshake_packets = self.process_handshake_packet(&p, h)?;
                raw_packets.extend_from_slice(&raw_handshake_packets);
            } else {
                /*if let Content::Alert(a) = &p.record.content {
                    if a.alert_description == AlertDescription::CloseNotify {
                        closed = true;
                    }
                }*/

                let raw_packet = self.process_packet(p)?;
                raw_packets.push(raw_packet);
            }
        }

        if !raw_packets.is_empty() {
            let compacted_raw_packets = compact_raw_packets(&raw_packets, self.handshake_mtu);

            for compacted_raw_packets in compacted_raw_packets {
                self.outgoing_compacted_raw_packets
                    .push_back(compacted_raw_packets);
            }
            // A DTLS 1.3 client's 0-RTT record goes once, after its first ClientHello.
            for datagram in std::mem::take(&mut self.state.early_datagrams) {
                self.outgoing_compacted_raw_packets.push_back(datagram);
            }
        }

        Ok(())
    }

    /// Protects one record (`raw`: its 13-byte header and content) with the cipher suite,
    /// if there is one. With a connection id negotiated for the peer (RFC 9146) it becomes
    /// a `tls12_cid` record: the content, then its type, are protected as the
    /// DTLSInnerPlaintext (no padding is added), the outer type is `tls12_cid`, and the
    /// connection id goes between the sequence number and the length.
    fn protect(&mut self, header: &RecordLayerHeader, mut raw: Vec<u8>) -> Result<Vec<u8>> {
        let connection_id = self.state.send_connection_id().map(<[u8]>::to_vec);
        let Some(cipher_suite) = &mut self.state.cipher_suite else {
            return Ok(raw);
        };
        let Some(connection_id) = connection_id else {
            return cipher_suite.encrypt(header, &raw);
        };
        let mut header = *header;
        raw.push(header.content_type as u8);
        header.content_type = ContentType::Tls12Cid;
        raw[0] = ContentType::Tls12Cid as u8;
        let protected = cipher_suite.encrypt_with_connection_id(&header, &raw, &connection_id)?;
        // The connection id sits after the sequence number, in front of the length.
        let at = RECORD_LAYER_HEADER_SIZE - 2;
        let mut record = Vec::with_capacity(protected.len() + connection_id.len());
        record.extend_from_slice(&protected[..at]);
        record.extend_from_slice(&connection_id);
        record.extend_from_slice(&protected[at..]);
        Ok(record)
    }

    fn process_packet(&mut self, mut p: Packet) -> Result<Vec<u8>> {
        let epoch = p.record.record_layer_header.epoch as usize;
        let seq = {
            while self.state.local_sequence_number.len() <= epoch {
                self.state.local_sequence_number.push(0);
            }

            self.state.local_sequence_number[epoch] += 1;
            self.state.local_sequence_number[epoch] - 1
        };
        //debug!("{}: seq = {}", srv_cli_str(is_client), seq);

        if seq > MAX_SEQUENCE_NUMBER {
            // RFC 6347 Section 4.1.0
            // The implementation must either abandon an association or rehandshake
            // prior to allowing the sequence number to wrap.
            return Err(Error::ErrSequenceNumberOverflow);
        }
        p.record.record_layer_header.sequence_number = seq;

        // Marshal straight into the Vec: `BufWriter` would heap-allocate an
        // 8 KiB staging buffer for every outbound record.
        let mut raw_packet = vec![];
        p.record.marshal(&mut raw_packet)?;

        if p.should_encrypt {
            raw_packet = self.protect(&p.record.record_layer_header, raw_packet)?;
        }

        Ok(raw_packet)
    }

    fn process_handshake_packet(&mut self, p: &Packet, h: &Handshake) -> Result<Vec<Vec<u8>>> {
        let mut raw_packets = vec![];

        // RFC 6347 4.1.1, 4.2.3: each fragment travels in one record, and the record in one
        // datagram of at most the MTU, so a fragment has the MTU less the record header, the
        // handshake header and what protecting the record adds.
        // A `tls12_cid` record (RFC 9146) adds its connection id and the inner content type.
        let connection_id_expansion = self
            .state
            .send_connection_id()
            .map_or(0, |connection_id| connection_id.len() + 1);
        let record_expansion = match &self.state.cipher_suite {
            Some(cipher_suite) if p.should_encrypt => {
                cipher_suite.record_expansion() + connection_id_expansion
            }
            _ => 0,
        };
        let fragment_room = self
            .handshake_mtu
            .saturating_sub(RECORD_LAYER_HEADER_SIZE + HANDSHAKE_HEADER_LENGTH + record_expansion)
            .max(1);
        let handshake_fragments = DTLSConn::fragment_handshake(fragment_room, h)?;

        let epoch = p.record.record_layer_header.epoch as usize;

        while self.state.local_sequence_number.len() <= epoch {
            self.state.local_sequence_number.push(0);
        }

        for handshake_fragment in &handshake_fragments {
            let seq = {
                self.state.local_sequence_number[epoch] += 1;
                self.state.local_sequence_number[epoch] - 1
            };
            //debug!("seq = {}", seq);
            if seq > MAX_SEQUENCE_NUMBER {
                return Err(Error::ErrSequenceNumberOverflow);
            }

            let record_layer_header = RecordLayerHeader {
                protocol_version: p.record.record_layer_header.protocol_version,
                content_type: p.record.record_layer_header.content_type,
                content_len: handshake_fragment.len() as u16,
                epoch: p.record.record_layer_header.epoch,
                sequence_number: seq,
            };

            let mut record_layer_header_bytes = vec![];
            {
                let mut writer = BufWriter::<&mut Vec<u8>>::new(record_layer_header_bytes.as_mut());
                record_layer_header.marshal(&mut writer)?;
            }

            //p.record.record_layer_header = record_layer_header;

            let mut raw_packet = vec![];
            raw_packet.extend_from_slice(&record_layer_header_bytes);
            raw_packet.extend_from_slice(handshake_fragment);
            if p.should_encrypt {
                raw_packet = self.protect(&record_layer_header, raw_packet)?;
            }

            raw_packets.push(raw_packet);
        }

        Ok(raw_packets)
    }

    /// Cuts `h` into fragments of at most `fragment_room` body bytes, each with its own
    /// handshake header: abutting ranges that cover the message (RFC 6347 4.2.3).
    fn fragment_handshake(fragment_room: usize, h: &Handshake) -> Result<Vec<Vec<u8>>> {
        let mut content = vec![];
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(content.as_mut());
            h.handshake_message.marshal(&mut writer)?;
        }

        let mut fragmented_handshakes = vec![];

        let mut content_fragments = split_bytes(&content, fragment_room);
        if content_fragments.is_empty() {
            content_fragments = vec![vec![]];
        }

        let mut offset = 0;
        for content_fragment in &content_fragments {
            let content_fragment_len = content_fragment.len();

            let handshake_header_fragment = HandshakeHeader {
                handshake_type: h.handshake_header.handshake_type,
                length: h.handshake_header.length,
                message_sequence: h.handshake_header.message_sequence,
                fragment_offset: offset as u32,
                fragment_length: content_fragment_len as u32,
            };

            offset += content_fragment_len;

            let mut handshake_header_fragment_raw = vec![];
            {
                let mut writer =
                    BufWriter::<&mut Vec<u8>>::new(handshake_header_fragment_raw.as_mut());
                handshake_header_fragment.marshal(&mut writer)?;
            }

            let mut fragmented_handshake = vec![];
            fragmented_handshake.extend_from_slice(&handshake_header_fragment_raw);
            fragmented_handshake.extend_from_slice(content_fragment);

            fragmented_handshakes.push(fragmented_handshake);
        }

        Ok(fragmented_handshakes)
    }

    pub(crate) fn set_handshake_completed(&mut self) {
        self.handshake_completed = true;
        // DTLS 1.2: the session this handshake made or resumed, kept for the next one.
        if self.v13.is_none() {
            crate::resumption::on_completed(&mut self.state, &self.handshake_config);
        }
    }

    pub(crate) fn is_handshake_completed(&self) -> bool {
        self.handshake_completed
    }

    /// Feeds one received datagram into the connection.
    ///
    /// Records whether this datagram carried a handshake record in
    /// `received_handshake_in_last_datagram`, which a completed association uses to tell an
    /// RFC 6347 §4.2.4 last-flight repeat from ordinary post-handshake application data.
    ///
    /// # Errors
    ///
    /// Fails if the record is malformed or fails authentication.
    pub fn read(&mut self, buf: &[u8]) -> Result<()> {
        if self.v13.is_some() {
            let result = self.read_dtls13(buf);
            if self.start_over_after_refused_cookie() {
                return Ok(());
            }
            return result;
        }
        // A failed association is finished: nothing more is processed on it. One thing is
        // still said: if this side ended it with a fatal alert and the peer goes on sending
        // handshake records, it has not seen the alert (alerts are not retransmitted on a
        // timer), so a new one is generated, a bounded number of times (RFC 6347 4.2.7).
        if self.failed {
            self.repeat_fatal_alert_for(buf);
            return Err(Error::ErrConnClosed);
        }
        // Per RFC 6347: buffer future-epoch packets only until Finished is received
        // (i.e. until handshake completes). After that, discard them.
        let enqueue = !self.is_handshake_completed();
        self.received_handshake_in_last_datagram = false;
        // An invalid record is discarded alone: what follows the last whole record of the
        // datagram does not cost the valid records in front of it [RFC6347 Section-4.1.2.7].
        let (records, well_formed) = split_datagram(
            buf,
            self.state.receive_connection_id().map_or(0, <[u8]>::len),
        );
        if !well_formed {
            // A client that offered DTLS 1.3 may be sent the server's protected flight
            // ahead of the ServerHello that selects it: held, a few datagrams of it, until
            // the ServerHello says what it is.
            if records.is_empty()
                && self.state.tls13_offer.is_some()
                && buf
                    .first()
                    .is_some_and(|first| crate::dtls13::record::is_unified_header(*first))
            {
                if self.early_dtls13_datagrams.len() < MAX_EARLY_DTLS13_DATAGRAMS {
                    self.early_dtls13_datagrams.push(buf.to_vec());
                }
                return Ok(());
            }
            debug!(
                "{}: discarded the malformed end of a datagram ({} whole records before it)",
                srv_cli_str(self.is_client),
                records.len()
            );
        }
        let mut consumed = 0;
        for pkt in records {
            consumed += pkt.len();
            let (hs, alert, err) = self.handle_incoming_packet(pkt, enqueue);
            if self.v13.is_some() {
                // The record selected DTLS 1.3: the rest of the datagram is in its format.
                return self.read_dtls13(&buf[consumed.min(buf.len())..]);
            }
            if let Some(alert) = alert {
                self.outgoing_packets.push_back(Packet {
                    record: RecordLayer::new(
                        PROTOCOL_VERSION1_2,
                        self.state.local_epoch,
                        Content::Alert(Alert {
                            alert_level: alert.alert_level,
                            alert_description: alert.alert_description,
                        }),
                    ),
                    should_encrypt: self.protects_alerts(),
                    reset_local_sequence_number: false,
                });

                if alert.alert_description == AlertDescription::CloseNotify {
                    // A close_notify is only queued here as the reply to the peer's own.
                    self.closed_by_peer = true;
                }
                if alert.alert_level == AlertLevel::Fatal {
                    // A fatal alert ends the association (RFC 5246 7.2.2).
                    self.fatal_alert_sent = Some((alert, self.maximum_retransmit_number));
                    self.fail();
                }
                if alert.alert_level == AlertLevel::Fatal
                    || alert.alert_description == AlertDescription::CloseNotify
                {
                    return Err(Error::ErrAlertFatalOrClose);
                }
            }

            if let Some(err) = err {
                return Err(err);
            }

            if hs {
                self.received_handshake_in_last_datagram = true;
                self.handshake_rx = Some(());
            }
        }

        Ok(())
    }

    /// RFC 6347 4.2.7: after this side's fatal alert, a datagram that still carries a handshake
    /// record means the peer is retransmitting the flight the alert was about. The alert is
    /// sent again, at most as many times as a flight would have been retransmitted: it is an
    /// answer to unauthenticated input, and smaller than any record that provokes it.
    fn repeat_fatal_alert_for(&mut self, datagram: &[u8]) {
        let Some((alert, remaining)) = self.fatal_alert_sent else {
            return;
        };
        let (records, _) = split_datagram(
            datagram,
            self.state.receive_connection_id().map_or(0, <[u8]>::len),
        );
        let carries_handshake = records
            .iter()
            .any(|record| ContentType::from(record[0]) == ContentType::Handshake);
        if remaining == 0 || !carries_handshake {
            return;
        }
        self.fatal_alert_sent = Some((alert, remaining - 1));
        self.write_packets(vec![Packet {
            record: RecordLayer::new(
                PROTOCOL_VERSION1_2,
                self.get_local_epoch(),
                Content::Alert(alert),
            ),
            should_encrypt: self.protects_alerts(),
            reset_local_sequence_number: false,
        }]);
    }

    pub(crate) fn handle_incoming_queued_packets(&mut self) -> Result<bool> {
        if self.v13.is_some() {
            return Ok(false);
        }
        // Drain queued future-epoch packets once the cipher suite is initialized,
        // which may happen before handshake_completed (e.g. Finished arrived before
        // ChangeCipherSpec bumped remote_epoch, so Finished was queued).
        let cipher_ready = self
            .state
            .cipher_suite
            .as_ref()
            .is_some_and(|cs| cs.is_initialized());
        let mut is_handshake = false;
        if cipher_ready {
            let queued = std::mem::take(&mut self.incoming_encrypted_packets);
            for p in queued {
                // A record of an epoch the peer has not switched to yet (its
                // ChangeCipherSpec is still to come) stays held: it used to be dropped here,
                // which lost application data that arrived ahead of the peer's last flight.
                let record_epoch = p
                    .get(3..5)
                    .map(|epoch| u16::from_be_bytes([epoch[0], epoch[1]]));
                if record_epoch.is_some_and(|epoch| epoch > self.state.remote_epoch) {
                    self.incoming_encrypted_packets.push_back(p);
                    continue;
                }
                let (hs, alert, err) = self.handle_incoming_packet(p, false); // don't re-enqueue
                if hs {
                    is_handshake = true;
                    self.handshake_rx = Some(());
                }
                if let Some(alert) = alert {
                    self.outgoing_packets.push_back(Packet {
                        record: RecordLayer::new(
                            PROTOCOL_VERSION1_2,
                            self.state.local_epoch,
                            Content::Alert(Alert {
                                alert_level: alert.alert_level,
                                alert_description: alert.alert_description,
                            }),
                        ),
                        should_encrypt: self.protects_alerts(),
                        reset_local_sequence_number: false,
                    });

                    if alert.alert_description == AlertDescription::CloseNotify {
                        // A close_notify is only queued here as the reply to the peer's own.
                        self.closed_by_peer = true;
                    }
                    if alert.alert_level == AlertLevel::Fatal {
                        // A fatal alert ends the association (RFC 5246 7.2.2).
                        self.fail();
                    }
                    if alert.alert_level == AlertLevel::Fatal
                        || alert.alert_description == AlertDescription::CloseNotify
                    {
                        return Err(Error::ErrAlertFatalOrClose);
                    }
                }

                if let Some(err) = err {
                    return Err(err);
                }
            }
        }

        Ok(is_handshake)
    }

    /// Holds a record that arrived before it can be decrypted (next epoch, cipher suite not ready
    /// yet). The queue is bounded: these records are unauthenticated until decrypted, so past
    /// [`MAX_EARLY_ENCRYPTED_PACKETS`] the newest is dropped, as a lost datagram would be.
    fn enqueue_early_encrypted(&mut self, pkt: Vec<u8>) {
        if self.incoming_encrypted_packets.len() >= MAX_EARLY_ENCRYPTED_PACKETS {
            debug!(
                "{}: early encrypted queue full ({}), dropping packet",
                srv_cli_str(self.is_client),
                MAX_EARLY_ENCRYPTED_PACKETS
            );
            return;
        }
        self.incoming_encrypted_packets.push_back(pkt);
    }

    /// RFC 6347 4.2.4 (MAY): application data of the next epoch that arrives while this side
    /// still waits for the peer's ChangeCipherSpec and Finished means the peer has completed
    /// and that flight was lost or is late, so our final flight is sent again at once rather
    /// than when the timer fires. Only a record that authenticates under the negotiated keys
    /// counts (anyone can send a record that merely claims the next epoch), and only once per
    /// flight; the retransmission comes out of the flight's ordinary budget.
    ///
    /// With a connection id (`connection_id`: the record is `tls12_cid`, given without its
    /// id, RFC 9146) the content type is inside the protection: the record counts when it
    /// opens to application data.
    fn note_early_application_data(
        &mut self,
        h: &RecordLayerHeader,
        pkt: &[u8],
        connection_id: Option<&[u8]>,
    ) {
        let expected_type = if connection_id.is_some() {
            ContentType::Tls12Cid
        } else {
            ContentType::ApplicationData
        };
        if !self.handshake_config.early_data_retransmit
            || self.early_data_retransmit_done
            || h.content_type != expected_type
            || self.current_handshake_state != HandshakeState::Waiting
        {
            return;
        }
        let Some(cipher_suite) = &mut self.state.cipher_suite else {
            return;
        };
        if !cipher_suite.is_initialized() {
            return;
        }
        let opened = match connection_id {
            Some(connection_id) => cipher_suite
                .decrypt_with_connection_id(pkt, connection_id)
                .ok()
                .filter(|opened| {
                    inner_content_type(&opened[RECORD_LAYER_HEADER_SIZE.min(opened.len())..])
                        .is_some_and(|(content_type, _)| {
                            content_type == ContentType::ApplicationData
                        })
                }),
            None => cipher_suite.decrypt(pkt).ok(),
        };
        if opened.is_some() {
            debug!(
                "{}: application data before the peer's Finished, retransmitting the flight",
                srv_cli_str(self.is_client)
            );
            self.early_data_retransmit_done = true;
            self.peer_repeated_flight = true;
        }
    }

    /// Whether one more application-data record fits the pre-handshake budget
    /// ([`MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS`] records,
    /// [`MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES`] bytes).
    fn has_room_for_early_application_data(&self, a: &ApplicationData) -> bool {
        if self.incoming_decrypted_packets.len() >= MAX_PRE_HANDSHAKE_APPLICATION_DATA_PACKETS {
            return false;
        }
        let held: usize = self
            .incoming_decrypted_packets
            .iter()
            .map(|p| p.len())
            .sum();
        held.saturating_add(a.data.len()) <= MAX_PRE_HANDSHAKE_APPLICATION_DATA_BYTES
    }

    fn handle_incoming_packet(
        &mut self,
        mut pkt: Vec<u8>,
        enqueue: bool,
    ) -> (bool, Option<Alert>, Option<Error>) {
        // RFC 9146 section 4: a `tls12_cid` record has this side's connection id between
        // its sequence number and its length. It is taken out here (what follows works on
        // a record with the ordinary 13-byte header and the outer type `tls12_cid`) and
        // goes into the additional data when the record is opened. A record with another
        // connection id, or one when none was negotiated, is not this association's and is
        // discarded (section 3: without an alert). `wire` is the record as it came, which
        // is what is queued when it cannot be opened yet.
        let mut wire = None;
        let mut connection_id = None;
        if pkt.first() == Some(&(ContentType::Tls12Cid as u8)) {
            let Some(expected) = self.state.receive_connection_id().map(<[u8]>::to_vec) else {
                return (false, None, None);
            };
            let at = RECORD_LAYER_HEADER_SIZE - 2;
            if pkt.len() < RECORD_LAYER_HEADER_SIZE + expected.len()
                || pkt[at..at + expected.len()] != expected[..]
            {
                return (false, None, None);
            }
            wire = Some(pkt.clone());
            pkt.drain(at..at + expected.len());
            connection_id = Some(expected);
        }

        // Parse the 13-byte header from the slice directly: `BufReader` would
        // heap-allocate an 8 KiB buffer for every inbound record.
        let mut reader = pkt.as_slice();
        let mut h = match RecordLayerHeader::unmarshal(&mut reader) {
            Ok(h) => h,
            Err(err) => {
                // Decode error must be silently discarded
                // [RFC6347 Section-4.1.2.7]
                debug!(
                    "{}: discarded broken packet: {}",
                    srv_cli_str(self.is_client),
                    err
                );
                return (false, None, None);
            }
        };

        // RFC 9146 section 4: a `tls12_cid` record is always protected; one in epoch 0 is
        // not the peer's. Section 3: once this side has asked for a non-empty connection id,
        // every protected record the peer sends carries it, so a protected record without
        // one is not this association's. Neither is authenticated: both are discarded
        // without an alert [RFC6347 Section-4.1.2.7].
        if (connection_id.is_some() && h.epoch == 0)
            || (connection_id.is_none()
                && h.epoch != 0
                && h.content_type != ContentType::ChangeCipherSpec
                && self.state.receive_connection_id().is_some())
        {
            debug!(
                "{}: discarded {:?} record in epoch {}: its connection id does not match",
                srv_cli_str(self.is_client),
                h.content_type,
                h.epoch,
            );
            return (false, None, None);
        }

        // RFC 5246 6.2.1, 6.2.3: a record holds at most 2^14 bytes, 2^14 + 2048 once protected.
        // A header that announces more is not this protocol's; it is unauthenticated, so the
        // record is discarded rather than answered [RFC6347 Section-4.1.2.7].
        let length_limit = if h.epoch == 0 {
            MAX_RECORD_PAYLOAD
        } else {
            MAX_PROTECTED_RECORD_PAYLOAD
        };
        if h.content_len as usize > length_limit {
            debug!(
                "{}: discarded oversize record ({} bytes, epoch {})",
                srv_cli_str(self.is_client),
                h.content_len,
                h.epoch,
            );
            return (false, None, None);
        }

        // Validate epoch
        let epoch = self.state.remote_epoch;
        if h.epoch > epoch {
            if h.epoch > epoch + 1 {
                debug!(
                    "{}: discarded future packet (epoch: {}, seq: {})",
                    srv_cli_str(self.is_client),
                    h.epoch,
                    h.sequence_number,
                );
                return (false, None, None);
            }
            if enqueue {
                debug!(
                    "{}: received packet of next epoch, queuing packet",
                    srv_cli_str(self.is_client)
                );
                self.note_early_application_data(&h, &pkt, connection_id.as_deref());
                self.enqueue_early_encrypted(wire.clone().unwrap_or(pkt));
            }
            return (false, None, None);
        }

        // Once the handshake has completed, a genuine peer only sends old-epoch handshake
        // records, to repeat its final flight (RFC 6347 4.2.4 retransmission relies on them).
        // Any other old-epoch record is plaintext that can only be forged or stale: acting on it
        // (an alert, or our fatal alert answering bad ApplicationData, ChangeCipherSpec or an
        // undecodable record) would let anyone spoofing the peer's address tear down the
        // association without keys. So it is silently discarded [RFC6347 Section-4.1.2.7].
        // Before the handshake completes, old epochs must be accepted [RFC6347 Section-4.1].
        if h.epoch < epoch
            && self.is_handshake_completed()
            && h.content_type != ContentType::Handshake
        {
            debug!(
                "{}: discarded {:?} record from old epoch {} (current: {}, seq: {})",
                srv_cli_str(self.is_client),
                h.content_type,
                h.epoch,
                epoch,
                h.sequence_number,
            );
            return (false, None, None);
        }

        // Anti-replay protection: one detector per epoch. Records past `remote_epoch + 1` were
        // discarded above, and `remote_epoch` stops at `MAX_REMOTE_EPOCH`, so this stays small.
        while self.replay_detector.len() <= h.epoch as usize {
            self.replay_detector
                .push(Box::new(SlidingWindowDetector::new(
                    self.replay_protection_window,
                    MAX_SEQUENCE_NUMBER,
                )));
        }

        let ok = self.replay_detector[h.epoch as usize].check(h.sequence_number);
        if !ok {
            debug!(
                "{}: discarded duplicated packet (epoch: {}, seq: {})",
                srv_cli_str(self.is_client),
                h.epoch,
                h.sequence_number,
            );
            return (false, None, None);
        }

        // Decrypt
        if h.epoch != 0 {
            let invalid_cipher_suite = {
                if let Some(cipher_suite) = &self.state.cipher_suite {
                    !cipher_suite.is_initialized()
                } else {
                    true
                }
            };
            if invalid_cipher_suite {
                if enqueue {
                    debug!(
                        "{}: handshake not finished, queuing packet",
                        srv_cli_str(self.is_client)
                    );
                    self.enqueue_early_encrypted(wire.clone().unwrap_or(pkt));
                }
                return (false, None, None);
            }

            if let Some(cipher_suite) = &mut self.state.cipher_suite {
                let opened = match &connection_id {
                    Some(connection_id) => {
                        cipher_suite.decrypt_with_connection_id(&pkt, connection_id)
                    }
                    None => cipher_suite.decrypt(&pkt),
                };
                pkt = match opened {
                    Ok(pkt) => pkt,
                    Err(err) => {
                        debug!("{}: decrypt failed: {}", srv_cli_str(self.is_client), err);

                        // During a PSK handshake, a decrypt failure means a key mismatch, so
                        // alert: bad_record_mac, the one alert RFC 6347 4.1.2.1 allows for a
                        // record that fails authentication. Afterwards, anyone can forge such
                        // a record, so silently discard it [RFC6347 Section-4.1.2.7].
                        if cipher_suite.is_psk() && !self.handshake_completed {
                            return (
                                false,
                                Some(Alert {
                                    alert_level: AlertLevel::Fatal,
                                    alert_description: AlertDescription::BadRecordMac,
                                }),
                                None,
                            );
                        } else {
                            // RFC 6347 4.2.7: a peer that keeps sending bad records is given
                            // up on, where the configuration sets a limit; without an alert,
                            // since whoever sent them is not known to be the peer.
                            self.invalid_records += 1;
                            if self
                                .handshake_config
                                .invalid_record_limit
                                .is_some_and(|limit| self.invalid_records > limit)
                            {
                                warn!(
                                    "{}: {} invalid records, over the configured limit",
                                    srv_cli_str(self.is_client),
                                    self.invalid_records
                                );
                                self.fail();
                            }
                            return (false, None, None);
                        }
                    }
                };
            }

            self.authenticated_records += 1;
            let record_number = (h.epoch, h.sequence_number);
            if self
                .newest_authenticated_record
                .is_none_or(|newest| record_number > newest)
            {
                self.newest_authenticated_record = Some(record_number);
            }

            // RFC 9146 section 4: the DTLSInnerPlaintext is the content, its real type and
            // zeros. The type is the last byte that is not zero. A record without one, or
            // with a type that is not one of the four a DTLS 1.2 record carries (a
            // `tls12_cid` inside a `tls12_cid`), is the peer's error (it authenticated):
            // unexpected_message, as for an unknown type (RFC 5246 6).
            if connection_id.is_some() {
                // Section 5: the DTLSInnerPlaintext is at most 2^14 bytes; more, authenticated,
                // is the peer's error, as for any record (RFC 5246 6.2.1).
                if pkt.len() - RECORD_LAYER_HEADER_SIZE > MAX_RECORD_PAYLOAD {
                    return (
                        false,
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::RecordOverflow,
                        }),
                        Some(Error::ErrRecordOverflow),
                    );
                }
                let inner = inner_content_type(&pkt[RECORD_LAYER_HEADER_SIZE..]).filter(
                    |(content_type, _)| {
                        !matches!(content_type, ContentType::Invalid | ContentType::Tls12Cid)
                    },
                );
                let Some((content_type, content_len)) = inner else {
                    return (
                        false,
                        Some(Alert {
                            alert_level: AlertLevel::Fatal,
                            alert_description: AlertDescription::UnexpectedMessage,
                        }),
                        Some(Error::Other(
                            "tls12_cid record without a known content type".to_owned(),
                        )),
                    );
                };
                let at = RECORD_LAYER_HEADER_SIZE + content_len;
                h.content_type = content_type;
                pkt[0] = content_type as u8;
                pkt.truncate(at);
                let length = (pkt.len() - RECORD_LAYER_HEADER_SIZE) as u16;
                h.content_len = length;
                pkt[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
                    .copy_from_slice(&length.to_be_bytes());
            }

            // RFC 5246 6.2.1, 7.2.2: an authenticated record that opens to more than 2^14
            // bytes is the peer's error, and fatal: record_overflow.
            if pkt.len() - RECORD_LAYER_HEADER_SIZE > MAX_RECORD_PAYLOAD {
                return (
                    false,
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::RecordOverflow,
                    }),
                    Some(Error::ErrRecordOverflow),
                );
            }
        }

        // Once complete, neither plaintext handshake records nor a new transcript may draw
        // the last flight again (RFC 6347 4.2.4, `FINAL_FLIGHT_ANSWER_PERIOD`). Authenticate
        // a repeat and match it against the Finished already received before signaling the
        // endpoint.
        if self.is_handshake_completed() && h.content_type == ContentType::Handshake {
            let repeats_finished = h.epoch != 0
                && self.cache.matches_received_finished(
                    &pkt[RECORD_LAYER_HEADER_SIZE..],
                    h.epoch,
                    !self.is_client,
                );
            if repeats_finished {
                self.replay_detector[h.epoch as usize].accept();
                return (true, None, None);
            }
            // An authenticated handshake record after the handshake that is not the peer's
            // Finished again is a request to renegotiate: a HelloRequest from a server, a
            // ClientHello from a client. This stack does not renegotiate (WebRTC forbids it,
            // RFC 8827 6.5; a new association is made instead), and says so with the
            // no_renegotiation warning (RFC 5246 7.2.2, RFC 5746 4.2, 4.4); the association
            // goes on. A plaintext one is not the peer's (or is a new client's, which the
            // endpoint handles: RFC 6347 4.2.8) and is ignored here.
            let requests_renegotiation = h.epoch != 0
                && pkt
                    .get(RECORD_LAYER_HEADER_SIZE)
                    .is_some_and(|handshake_type| {
                        let handshake_type = HandshakeType::from(*handshake_type);
                        if self.is_client {
                            handshake_type == HandshakeType::HelloRequest
                        } else {
                            handshake_type == HandshakeType::ClientHello
                        }
                    });
            if requests_renegotiation {
                self.replay_detector[h.epoch as usize].accept();
                return (
                    false,
                    Some(Alert {
                        alert_level: AlertLevel::Warning,
                        alert_description: AlertDescription::NoRenegotiation,
                    }),
                    None,
                );
            }
            return (false, None, None);
        }

        let is_handshake = match self.fragment_buffer.push(&pkt) {
            Ok(is_handshake) => is_handshake,
            Err(err) => {
                // Decode error must be silently discarded
                // [RFC6347 Section-4.1.2.7]
                debug!(
                    "{}: defragment failed: {}",
                    srv_cli_str(self.is_client),
                    err
                );
                return (false, None, None);
            }
        };
        if is_handshake {
            // An epoch-0 record is not authenticated, so it moves the replay window only once it
            // has delivered something: a new handshake message, or a repeat of one already
            // received. Otherwise one forged record with a far-ahead sequence number, which
            // anyone spoofing the peer's address can send before the handshake, would push every
            // genuine record out of the window and stall the handshake. Later epochs are
            // authenticated by the decryption above.
            let mut delivered = h.epoch != 0;
            while let Ok((out, epoch)) = self.fragment_buffer.pop() {
                //log::debug!("Extension Debug: out.len()={}", out.len());
                // RFC 5246 7.4: a message the peer's role never sends, or sends only in the
                // other epoch (a Finished in the clear, anything but a Finished protected),
                // is out of order. Authenticated, it is the peer's error: unexpected_message.
                // In epoch 0 anyone can have sent it, so it is dropped without taking the
                // genuine message's place [RFC6347 Section-4.1.2.7].
                let handshake_type = HandshakeType::from(out[0]);
                if !self.expects_handshake_type(handshake_type, epoch) {
                    if epoch != 0 {
                        return (
                            true,
                            Some(Alert {
                                alert_level: AlertLevel::Fatal,
                                alert_description: AlertDescription::UnexpectedMessage,
                            }),
                            Some(Error::ErrUnhandledContextType),
                        );
                    }
                    debug!(
                        "{}: discarded out-of-place {} in epoch 0",
                        srv_cli_str(self.is_client),
                        handshake_type,
                    );
                    self.fragment_buffer.unpop();
                    continue;
                }
                match self.negotiate_version(handshake_type, &out, &h) {
                    VersionOutcome::Dtls12 => {}
                    VersionOutcome::Dtls13 => return (true, None, None),
                    VersionOutcome::Refuse(alert_description, err) => {
                        return (
                            true,
                            Some(Alert {
                                alert_level: AlertLevel::Fatal,
                                alert_description,
                            }),
                            Some(err),
                        );
                    }
                }
                let mut reader = out.as_slice();
                let raw_handshake = match Handshake::unmarshal(&mut reader) {
                    Ok(rh) => {
                        debug!(
                            "Recv [handshake:{}] -> {} (epoch: {}, seq: {})",
                            srv_cli_str(self.is_client),
                            rh.handshake_header.handshake_type,
                            h.epoch,
                            rh.handshake_header.message_sequence
                        );
                        rh
                    }
                    Err(err) => {
                        debug!(
                            "{}: handshake parse failed: {}",
                            srv_cli_str(self.is_client),
                            err
                        );
                        // A message that does not parse is forged or corrupt. Its sequence number
                        // is handed out again, so the genuine message, when the peer retransmits
                        // it, is still taken instead of being dropped as already seen.
                        self.fragment_buffer.unpop();
                        continue;
                    }
                };
                if self.is_client_hello_without_our_cookie(&raw_handshake) {
                    debug!(
                        "{}: discarded ClientHello without the cookie (seq: {})",
                        srv_cli_str(self.is_client),
                        raw_handshake.handshake_header.message_sequence
                    );
                    self.fragment_buffer.unpop();
                    continue;
                }

                delivered |= self.cache.push(
                    out,
                    epoch,
                    raw_handshake.handshake_header.message_sequence,
                    raw_handshake.handshake_header.handshake_type,
                    !self.is_client,
                );
            }

            // RFC 6347 4.2.4: a message the peer sends again after it has been processed (its
            // sequence number already handed out and parsed) means the flight we answered it
            // with was lost, so that flight is retransmitted at once rather than when our timer
            // fires. Only a byte-for-byte repeat of the cached message counts.
            while let Some((out, epoch, message_sequence)) = self.fragment_buffer.pop_stale() {
                if (message_sequence as isize) < self.state.handshake_recv_sequence
                    && self.cache.contains_message(&out, epoch, !self.is_client)
                {
                    debug!(
                        "{}: peer repeated handshake message (epoch: {}, seq: {})",
                        srv_cli_str(self.is_client),
                        epoch,
                        message_sequence
                    );
                    self.peer_repeated_flight = true;
                    delivered = true;
                }
            }

            if delivered {
                self.replay_detector[h.epoch as usize].accept();
            }
            return (true, None, None);
        }

        let mut reader = pkt.as_slice();
        let r = match RecordLayer::unmarshal(&mut reader) {
            Ok(r) => r,
            Err(err) if h.epoch == 0 => {
                // An undecodable plaintext record is silently discarded [RFC6347 Section-4.1.2.7]:
                // anyone spoofing the peer's address can send one, and answering it with a fatal
                // alert would end the handshake.
                debug!(
                    "{}: discarded undecodable epoch-0 record: {}",
                    srv_cli_str(self.is_client),
                    err
                );
                return (false, None, None);
            }
            Err(err) => {
                // Authenticated. RFC 5246 6: a record type that is not one of the four is
                // answered with unexpected_message; one of the four that does not decode,
                // with decode_error.
                let alert_description = if h.content_type == ContentType::Invalid {
                    AlertDescription::UnexpectedMessage
                } else {
                    AlertDescription::DecodeError
                };
                return (
                    false,
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description,
                    }),
                    Some(err),
                );
            }
        };

        match r.content {
            Content::Alert(a) => {
                debug!("{}: <- {}", srv_cli_str(self.is_client), a);
                // An alert is never answered with the same alert. Echoing it let two endpoints
                // bounce one alert between them for as long as both associations lived. The one
                // reply is the close_notify that answers the peer's own [RFC5246 Section 7.2.1].
                if a.alert_description == AlertDescription::CloseNotify {
                    self.replay_detector[h.epoch as usize].accept();
                    return (
                        false,
                        Some(Alert {
                            alert_level: AlertLevel::Warning,
                            alert_description: AlertDescription::CloseNotify,
                        }),
                        Some(Error::Other(format!("Error of Alert {a}"))),
                    );
                }
                if a.alert_level == AlertLevel::Fatal {
                    // A fatal alert ends the association at once, unanswered [RFC5246 Section
                    // 7.2.2].
                    self.replay_detector[h.epoch as usize].accept();
                    self.fatal_alert_received = Some(a);
                    self.fail();
                    return (false, None, Some(Error::ErrAlertFatalOrClose));
                }
                // A warning (other than close_notify) asks nothing of us: it is not answered and
                // changes nothing, not even the replay window, so a forged one with a far-ahead
                // sequence number cannot push the peer's genuine records out of it.
                return (false, None, None);
            }
            Content::ChangeCipherSpec(_) => {
                let invalid_cipher_suite = {
                    if let Some(cipher_suite) = &self.state.cipher_suite {
                        !cipher_suite.is_initialized()
                    } else {
                        true
                    }
                };

                if invalid_cipher_suite {
                    if enqueue {
                        debug!(
                            "{}: CipherSuite not initialized, queuing packet",
                            srv_cli_str(self.is_client)
                        );
                        self.enqueue_early_encrypted(wire.clone().unwrap_or(pkt));
                    }
                    return (false, None, None);
                }

                // A ChangeCipherSpec is not authenticated: every cipher hands it back
                // unchecked, so its epoch is only the sender's claim, and anyone spoofing the
                // peer's address can send one. It is acted on only for the handshake's one
                // transition, before the handshake completes. Afterwards a spoofed one would
                // move `remote_epoch` past the peer's and make every genuine record look old.
                if self.is_handshake_completed() || epoch >= MAX_REMOTE_EPOCH {
                    debug!(
                        "{}: discarded ChangeCipherSpec (epoch: {}, remote epoch: {})",
                        srv_cli_str(self.is_client),
                        h.epoch,
                        epoch
                    );
                    return (false, None, None);
                }
                let Some(new_remote_epoch) = h.epoch.checked_add(1) else {
                    return (false, None, None);
                };
                debug!(
                    "{}: <- ChangeCipherSpec (epoch: {})",
                    srv_cli_str(self.is_client),
                    new_remote_epoch
                );

                if epoch.checked_add(1) == Some(new_remote_epoch) {
                    self.state.remote_epoch = new_remote_epoch;
                    self.replay_detector[h.epoch as usize].accept();
                }
            }
            Content::ApplicationData(a) => {
                if h.epoch == 0 {
                    // Application data is never sent unprotected, so this record is invalid;
                    // it is also unauthenticated, and anyone who knows the peer's address can
                    // send it. It is silently discarded [RFC6347 Section-4.1.2.7]: an alert
                    // would let one spoofed datagram end the handshake.
                    debug!(
                        "{}: discarded application data in epoch 0 (seq: {})",
                        srv_cli_str(self.is_client),
                        h.sequence_number,
                    );
                    return (false, None, None);
                }

                if !self.is_handshake_completed() && !self.has_room_for_early_application_data(&a) {
                    debug!(
                        "{}: pre-handshake application data budget spent, dropping record",
                        srv_cli_str(self.is_client)
                    );
                    return (false, None, None);
                }

                self.replay_detector[h.epoch as usize].accept();

                self.incoming_decrypted_packets.push_back(a.data);
            }
            _ => {
                warn!(
                    "{}: <- Unexpected Handshake Message",
                    srv_cli_str(self.is_client),
                );
                return (
                    false,
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::UnexpectedMessage,
                    }),
                    Some(Error::ErrUnhandledContextType),
                );
            }
        };

        (false, None, None)
    }

    fn is_connection_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn set_local_epoch(&mut self, epoch: u16) {
        self.state.local_epoch = epoch;
    }

    pub(crate) fn get_local_epoch(&self) -> u16 {
        self.state.local_epoch
    }
}

fn compact_raw_packets(raw_packets: &[Vec<u8>], maximum_transmission_unit: usize) -> Vec<BytesMut> {
    let mut combined_raw_packets = vec![];
    let mut current_combined_raw_packet = BytesMut::new();

    for raw_packet in raw_packets {
        if !current_combined_raw_packet.is_empty()
            && current_combined_raw_packet.len() + raw_packet.len() > maximum_transmission_unit
        {
            combined_raw_packets.push(current_combined_raw_packet);
            current_combined_raw_packet = BytesMut::new();
        }
        current_combined_raw_packet.extend_from_slice(raw_packet);
    }

    if !current_combined_raw_packet.is_empty() {
        combined_raw_packets.push(current_combined_raw_packet);
    }

    combined_raw_packets
}

fn split_bytes(bytes: &[u8], split_len: usize) -> Vec<Vec<u8>> {
    let mut splits = vec![];
    let num_bytes = bytes.len();
    for i in (0..num_bytes).step_by(split_len) {
        let mut j = i + split_len;
        if j > num_bytes {
            j = num_bytes;
        }

        splits.push(bytes[i..j].to_vec());
    }

    splits
}

/// The real content type of a DTLSInnerPlaintext (RFC 9146 section 4: the content, its type,
/// then zeros) and the length of its content: the type is the last byte that is not zero.
/// `None` when every byte is zero.
pub(crate) fn inner_content_type(inner_plaintext: &[u8]) -> Option<(ContentType, usize)> {
    let at = inner_plaintext.iter().rposition(|byte| *byte != 0)?;
    Some((ContentType::from(inner_plaintext[at]), at))
}
