//! A whole peer connection driven over sockets the driver owns (feature `peer`, on by
//! default): its UDP sockets for the ICE host candidates, and the TCP sockets of the engine's
//! stream interface through a [`StreamDriver`].
//!
//! [`PeerDriver`] gathers for the application and keeps the gathering right across what makes
//! a transport lose its candidates. The engine has no sockets, so it tells the application
//! with `RTCPeerConnectionEvent::OnLocalCandidatesNeeded` when a transport needs a new set of
//! local candidates: a new DTLS association over UDP runs on a new 3-tuple (RFC 8842 section
//! 5.1), so after an ICE restart for a new association (automatic SRTP re-keying included) or
//! on the transport that replaced one an answer closed, the transport's previous UDP addresses
//! are refused. The driver reacts by itself: it binds new UDP ports (inside
//! [`PeerDriverConfig::udp_port_range`], skipping ports the host refuses), adds their host
//! candidates for the event's section, ends the generation, and closes the previous sockets
//! only once a candidate pair on a new one is selected for that transport (and then after
//! [`PeerDriverConfig::retired_socket_linger`], for what the peer still sends there before its
//! own selection switches), or the transport is closed: until then the previous path keeps
//! carrying the transport's packets. The engine's
//! ICE-TCP listener is kept (RFC 8842 asks a new 3-tuple of unordered transports only), and
//! its server-reflexive and TURN gathering follow the new host candidates by themselves.
//!
//! With `SettingEngineBuilder::with_dtls_new_association_on_previous_addresses(true)` the
//! engine keeps the candidates and fires no event: the driver keeps its sockets and gives their
//! candidates to each new ICE generation again.
//!
//! # mDNS
//!
//! A connection with mDNS on (`SettingEngineBuilder::with_multicast_dns_mode`) publishes its
//! host addresses behind `.local` names and resolves the peer's: its ICE agents write their
//! mDNS datagrams from local port 5353. At the first one the driver binds the host's mDNS
//! sockets, port 5353 joined to 224.0.0.251 and, where the host has IPv6, to ff02::fb (shared
//! with other mDNS responders of the host through address reuse), on the interface of every
//! address of [`PeerDriverConfig::addresses`]; it sends the connection's queries, probes and
//! answers there and hands what arrives back to the connection. A connection without mDNS
//! writes none, and the driver binds nothing.
//!
//! RFC 6762 section 14: a host on several links takes part in mDNS on each, and an answer
//! carries only addresses valid on the interface it leaves by. The engine names, for each
//! message, the address it is about (its record's); the driver sends it by that address's
//! interface (`Transmit::source`: `IP_MULTICAST_IF` / `IPV6_MULTICAST_IF`), an IPv6 record's
//! on the IPv6 group (and on the IPv4 group of the same interface where the driver has an IPv4
//! address there), and a query once on each interface.
//!
//! On Windows, a process that joins the IPv4 mDNS group on the loopback interface (a driver
//! given 127.0.0.1) and sends to the group there leaves a stale route for the group behind
//! it: the system's destination cache holds 224.0.0.251 with source 127.0.0.1 on the
//! "Loopback Pseudo-Interface" after the process has exited (`netsh interface ipv4 show
//! destinationcache address=224.0.0.251`), and from then on any process that asks which
//! address reaches the group (a UDP socket connected to it) gets 127.0.0.1. Measured on
//! Windows 11 and on GitHub's Windows image; the joins table entry for the group on the
//! loopback interface that the join also leaves (`show joins`, references 0) is not what moves
//! the answer. A later join, send and leave on the network interface does not clear the
//! entry; deleting it does, at once: `netsh interface ipv4 delete destinationcache
//! interface=<the loopback interface's index> address=224.0.0.251`, from an administrator
//! prompt (measured on Windows 11 and on GitHub's Windows image). The same may hold for IPv6's
//! ff02::fb; that was not measured. So on Windows the driver, by default, takes no part in
//! IPv4 mDNS on loopback: it does not join 224.0.0.251 on the loopback interface and sends
//! nothing to the group from a loopback address (the messages about a loopback address's name
//! are dropped, counted in [`PeerDriver::unsent_datagrams`]); a driver whose only IPv4
//! addresses are loopback binds no IPv4 mDNS socket and tells the connection that its IPv4
//! names cannot be published ([`PeerDriver::mdns_available`] is `false`). Loopback candidates
//! are for local use only (RFC 8445 section 5.1.1.1: "Addresses from a loopback interface MUST
//! NOT be included in the candidate addresses"), and RFC 6762 asks no mDNS on loopback.
//! [`PeerDriverConfig::mdns_on_loopback_on_windows`] turns it back on, as on other systems;
//! the driver then logs a warning when it makes such a join, and an application or test host
//! that does so cleans the entry as above when it is done. The driver changes no host routing
//! state itself.
//!
//! Where mDNS cannot be sent (a socket that cannot be bound, or a system that refuses every
//! send to the group: no multicast route, or a Mac application without the Local Network
//! permission) the driver tells the application with
//! [`PeerDriverEvent::MdnsUnavailable`] ([`PeerDriver::poll_driver_event`]), with the system's
//! error, counts it ([`PeerDriver::mdns_send_failures`], [`PeerDriver::mdns_bind_failures`]),
//! and tells the connection that the family's names cannot be published. It tries again at the
//! next gathering and, while mDNS datagrams wait, after a back-off; the first send that works
//! is reported as [`PeerDriverEvent::MdnsAvailable`]. The connection itself goes on over its
//! other candidates, or fails as ICE does.
//!
//! With `QueryAndGather` the driver binds the mDNS sockets before it adds the first host
//! candidates and tells the connection for which address families it has one
//! (`RTCPeerConnection::set_multicast_dns_publishing`): a host address of a family without one
//! cannot have its name published (draft-ietf-mmusic-mdns-ice-candidates section 3.1.1 step
//! 4), and its candidates go out under a `.local` name that is not published, or not at all
//! when the connection fails closed (`SettingEngineBuilder::with_multicast_dns_fail_closed`).
//! [`PeerDriverConfig::mdns_sockets`] `false` binds none.
//!
//! Every mDNS datagram takes one message from a budget shared by every driver of the process
//! ([`process_mdns_rate_limit`], unless [`PeerDriverConfig::mdns_rate_limit`] names another):
//! draft-ietf-mmusic-mdns-ice-candidates section 7.1 requires "an implementation-wide rate
//! limit" over the mDNS queries and responses of all connections. A datagram the budget refuses
//! waits in the driver and leaves, in order, when the budget has room.
//!
//! # The loop
//!
//! ```text
//! let mut driver = PeerDriver::new(pc, PeerDriverConfig::on(vec![ip]));
//! // offer / answer through the application's signalling, on driver.pc_mut();
//! // after the first local description, the driver gathers by itself;
//! loop {
//!     driver.step(Duration::from_millis(20)).await?;
//!     while let Some(event) = driver.poll_event() {
//!         // signal OnIceCandidateEvent candidates to the peer (the end-of-candidates one
//!         // too: without it the peer's transport is "disconnected", never "failed", when
//!         // the path is lost), answer negotiation-needed, ...
//!     }
//!     while let Some(read) = driver.pc_mut().poll_read() { /* media, data channels */ }
//! }
//! ```

use crate::mdns_io::{MDNS_MAX_DATAGRAM, MdnsEgress, mdns_v4, mdns_v6};
pub use crate::mdns_io::{
    MDNS_MULTICAST_IPV6, process_mdns_rate_limit, set_process_mdns_rate_limit,
};
use crate::runtime::{self, AsyncUdpSocket, JoinHandle, Runtime, Transmit};
use crate::sockets::{self, PortRange};
use crate::{DriverConfig, DriverInput, StreamDriver};
use bytes::BytesMut;
use rtci::ice::mdns::{MulticastDnsMode, MulticastDnsPublishing};
use rtci::mdns::{MDNS_MULTICAST_IPV4, MDNS_PORT, MdnsRateLimit};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::{
    RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason, RTCPeerConnectionEvent,
    RTCTransportEventKind,
};
use rtci::peer_connection::state::{RTCIceGatheringState, RTCSignalingState};
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCIceCandidate, RTCIceCandidateInit, RTCIceProtocol,
    RTCIceTransportState, RTCTransportId,
};
use rtci::sansio::Protocol;
use rtci::shared::error::{Error, IoError, Result};
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

/// A datagram a socket of the driver received: its local address, the sender, the bytes.
type Received = (SocketAddr, SocketAddr, Vec<u8>);

/// What a [`PeerDriver`] binds.
#[derive(Debug, Clone)]
pub struct PeerDriverConfig {
    /// The local addresses that get a host candidate: one UDP socket per address for each
    /// transport.
    pub addresses: Vec<IpAddr>,
    /// The UDP sockets take a port of this range (any free port without one). A port the
    /// host refuses to applications is skipped like a port in use
    /// ([`sockets::bind_udp_in_range`]).
    pub udp_port_range: Option<PortRange>,
    /// The engine's TCP sockets (ICE-TCP, TURN over TCP and TLS), with their port range.
    pub streams: DriverConfig,
    /// How long a previous socket stays open after its transport selected a pair on a new one:
    /// the peer may still send to the previous address until its own selection switches
    /// (each side selects on its own), and those packets must not be lost. 5 seconds by
    /// default.
    pub retired_socket_linger: Duration,
    /// The budget the connection's mDNS datagrams take from
    /// (draft-ietf-mmusic-mdns-ice-candidates section 7.1). `None`, the default: the one of
    /// the process, [`process_mdns_rate_limit`], shared by every driver that has none named
    /// (on a runtime with a virtual clock, [`Runtime::virtual_clock`], one of the driver's own).
    /// A limit given here is shared by the drivers given clones of it.
    pub mdns_rate_limit: Option<MdnsRateLimit>,
    /// Whether the driver binds the host's mDNS sockets (`true` by default). `false`: it
    /// binds none, its connection's mDNS datagrams are unsent, and the connection is told it
    /// can publish no name (`RTCPeerConnection::set_multicast_dns_publishing`), as when the
    /// host refuses the sockets.
    pub mdns_sockets: bool,
    /// On Windows, whether the driver takes part in IPv4 mDNS on loopback addresses of
    /// [`addresses`](Self::addresses): joins 224.0.0.251 on the loopback interface and sends the
    /// messages about a loopback address's name there. `false` by default: on Windows mDNS sent
    /// on loopback leaves the group's destination-cache route on loopback for every process of
    /// the host after this one has exited (see the [module documentation](self)), so loopback
    /// addresses get no mDNS and their `.local` names are not published. `true` does what other
    /// systems always do, with one warning per process. Ignored on other systems.
    pub mdns_on_loopback_on_windows: bool,
}

impl PeerDriverConfig {
    /// Host candidates on `addresses`, any free port. With a loopback address and mDNS on
    /// Windows, see the module documentation: mDNS sent on loopback leaves a stale
    /// destination-cache route for the group after the process, so by default the driver sends
    /// none there ([`mdns_on_loopback_on_windows`](Self::mdns_on_loopback_on_windows)).
    pub fn on(addresses: Vec<IpAddr>) -> Self {
        Self {
            addresses,
            udp_port_range: None,
            streams: DriverConfig::default(),
            retired_socket_linger: Duration::from_secs(5),
            mdns_rate_limit: None,
            mdns_sockets: true,
            mdns_on_loopback_on_windows: false,
        }
    }

    /// Whether this configuration keeps IPv4 mDNS off loopback addresses on this system: on
    /// Windows unless [`mdns_on_loopback_on_windows`](Self::mdns_on_loopback_on_windows).
    fn skips_loopback_mdns_v4(&self) -> bool {
        cfg!(windows) && !self.mdns_on_loopback_on_windows
    }

    /// The budget this configuration's mDNS takes from: the one named, or the process's.
    pub fn mdns_rate_limit(&self) -> MdnsRateLimit {
        self.mdns_rate_limit
            .clone()
            .unwrap_or_else(process_mdns_rate_limit)
    }
}

/// Why the driver's mDNS of one address family stopped: what [`PeerDriverEvent::MdnsUnavailable`]
/// tells the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsFailure {
    /// The family: IPv6 (`true`) or IPv4.
    pub ipv6: bool,
    /// What failed.
    pub stage: MdnsStage,
    /// The operating system's error.
    pub kind: io::ErrorKind,
    /// Its code, where it has one (`EHOSTUNREACH`, `WSAENETUNREACH`, ...).
    pub os_error: Option<i32>,
    /// Its text.
    pub message: String,
}

impl MdnsFailure {
    fn new(ipv6: bool, stage: MdnsStage, error: &io::Error) -> Self {
        Self {
            ipv6,
            stage,
            kind: error.kind(),
            os_error: error.raw_os_error(),
            message: error.to_string(),
        }
    }
}

/// What failed in a [`MdnsFailure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdnsStage {
    /// The mDNS socket could not be bound or joined to the group.
    Bind,
    /// The socket is bound but the system refuses to send to the group (no multicast route;
    /// on a Mac, an application without the Local Network permission).
    Send,
}

/// Something the driver itself reports to the application ([`PeerDriver::poll_driver_event`]),
/// beside the connection's own events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDriverEvent {
    /// The driver cannot send mDNS for a family: the socket could not be bound, or the system
    /// refused its sends. Told once until it works again. Its names are no longer published
    /// (`RTCPeerConnection::set_multicast_dns_publishing`) for the candidates gathered next,
    /// and the peer's `.local` names of that family will not resolve: the connection goes on
    /// over its other candidates, or fails as ICE does. The driver tries again at the next
    /// gathering and, while datagrams wait, after a back-off (1 s, doubling to 60 s).
    MdnsUnavailable(MdnsFailure),
    /// mDNS of the family works again (a datagram was sent after a failure).
    MdnsAvailable {
        /// The family: IPv6 (`true`) or IPv4.
        ipv6: bool,
    },
}

/// The first wait before the driver tries an mDNS socket again after a failure.
const MDNS_RETRY_FIRST: Duration = Duration::from_secs(1);
/// The longest wait between two tries.
const MDNS_RETRY_MAX: Duration = Duration::from_secs(60);
/// How many sends in a row may fail before the family is declared unavailable (an error that
/// says there is no route, or no permission, does it at once).
const MDNS_FAILURES_BEFORE_UNAVAILABLE: u32 = 3;
/// How many received mDNS datagrams wait for the driver at most; past it the oldest is
/// dropped ([`PeerDriver::mdns_datagrams_dropped`]): any host on the link can send mDNS, and a
/// driver that is not stepped must not grow with it.
const MAX_QUEUED_MDNS_RECEIVED: usize = 256;

/// One family's mDNS socket, and what the driver knows of it.
struct MdnsFamily {
    socket: Option<(Arc<dyn AsyncUdpSocket>, Box<dyn JoinHandle>)>,
    /// One configured address per interface: what a message that names no address of its
    /// own (a query) leaves from, once on each interface (RFC 6762 section 14).
    links: Vec<IpAddr>,
    /// Sends that failed in a row.
    failures: u32,
    /// Reported unavailable ([`PeerDriverEvent::MdnsUnavailable`]) and not yet working again.
    unavailable: bool,
    /// Not tried again before.
    retry_at: Option<Instant>,
    backoff: Duration,
    /// Never bound: every configured address of the family is a loopback one the driver keeps
    /// mDNS off ([`PeerDriverConfig::mdns_on_loopback_on_windows`]).
    off: bool,
}

impl MdnsFamily {
    fn new(links: Vec<IpAddr>) -> Self {
        Self {
            off: false,
            socket: None,
            links,
            failures: 0,
            unavailable: false,
            retry_at: None,
            backoff: MDNS_RETRY_FIRST,
        }
    }

    fn close(&mut self) {
        if let Some((_, reader)) = self.socket.take() {
            reader.abort();
        }
    }
}

impl Drop for MdnsFamily {
    fn drop(&mut self) {
        self.close();
    }
}

/// The host's mDNS sockets of a driver, bound at the connection's first mDNS datagram.
struct MdnsSockets {
    v4: MdnsFamily,
    v6: MdnsFamily,
    /// For an IPv6 address, the configured IPv4 address of the same interface: an IPv6
    /// record's messages also leave on the IPv4 group of its own interface.
    companions: Vec<(IpAddr, IpAddr)>,
    /// IPv4 mDNS is kept off loopback addresses: a message about one is sent nowhere
    /// ([`PeerDriverConfig::mdns_on_loopback_on_windows`]).
    skips_loopback_v4: bool,
}

impl MdnsSockets {
    /// Where one mDNS datagram of the engine goes: (destination, address it leaves from).
    /// The engine names the address of the record a message is about (its own interface's,
    /// RFC 6762 section 14), or the unspecified address for a query; it addresses every
    /// multicast message to the IPv4 group. An IPv4 record's message leaves from its address
    /// on the IPv4 group; an IPv6 record's from its address on the IPv6 group, and from the
    /// IPv4 address of its interface on the IPv4 group where the driver has one (resolvers
    /// that listen on one family); a query once from each interface, on each family's group.
    /// A multicast message about an IPv4 loopback address goes nowhere when
    /// [`skips_loopback_v4`](Self::skips_loopback_v4).
    fn routes(&self, from: IpAddr, to: SocketAddr) -> Vec<(SocketAddr, Option<IpAddr>)> {
        let group_v4 = SocketAddr::new(MDNS_MULTICAST_IPV4.into(), MDNS_PORT);
        let group_v6 = SocketAddr::new(MDNS_MULTICAST_IPV6.into(), MDNS_PORT);
        if !to.ip().is_multicast() {
            // A unicast reply to an asker (RFC 6762 sections 5.5, 6.7).
            let source = (!from.is_unspecified() && from.is_ipv4() == to.is_ipv4()).then_some(from);
            return vec![(to, source)];
        }
        if self.skips_loopback_v4 && from.is_loopback() && from.is_ipv4() {
            // Not on the group from loopback (Windows: the destination-cache route it leaves).
            return vec![];
        }
        if from.is_unspecified() {
            let routes: Vec<_> = (self.v4.links.iter().map(|ip| (group_v4, Some(*ip))))
                .chain(self.v6.links.iter().map(|ip| (group_v6, Some(*ip))))
                .collect();
            if routes.is_empty() {
                return vec![(to, None)];
            }
            return routes;
        }
        match from {
            IpAddr::V4(_) => vec![(group_v4, Some(from))],
            IpAddr::V6(_) => std::iter::once((group_v6, Some(from)))
                .chain(
                    self.companions
                        .iter()
                        .filter(|(v6, _)| *v6 == from)
                        .map(|(_, v4)| (group_v4, Some(*v4))),
                )
                .collect(),
        }
    }
}

/// `addresses` with one per interface (the first of each), of one family. An address on no
/// interface the host lists (a mock network's) counts as an interface of its own.
fn one_per_interface(addresses: &[IpAddr], ipv4: bool) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    addresses
        .iter()
        .copied()
        .filter(|ip| ip.is_ipv4() == ipv4 && !ip.is_unspecified())
        .filter(|ip| seen.insert(runtime::interface_name(*ip).unwrap_or_else(|| ip.to_string())))
        .collect()
}

/// The addresses whose interfaces get mDNS: `addresses` without the IPv4 loopback ones when
/// `skips_loopback_v4` ([`PeerDriverConfig::mdns_on_loopback_on_windows`]).
fn mdns_addresses(addresses: &[IpAddr], skips_loopback_v4: bool) -> Vec<IpAddr> {
    addresses
        .iter()
        .copied()
        .filter(|ip| !(skips_loopback_v4 && ip.is_ipv4() && ip.is_loopback()))
        .collect()
}

/// Says once per process that IPv4 mDNS is kept off loopback on Windows.
fn note_loopback_mdns_skipped() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        log::info!(
            "no IPv4 mDNS on loopback on Windows: it would leave the group's destination-cache \
             route on loopback for the whole host (PeerDriverConfig::mdns_on_loopback_on_windows)"
        );
    });
}

/// One UDP socket of the connection, with the reader that hands its datagrams to the driver.
struct HostSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    local: SocketAddr,
    /// The section its candidate was added for.
    mid: String,
    /// Set when the engine refused its address for `transport` (`OnLocalCandidatesNeeded`):
    /// it is closed once that transport has selected a pair on another socket, or closed.
    retired_for: Option<RTCTransportId>,
    /// Once its transport selected a pair on another socket: when it is closed.
    close_at: Option<Instant>,
    /// Counted in [`PeerDriver::unmarked_sockets`] (the platform refused to mark it: its
    /// datagrams leave unmarked).
    counted_unmarked: bool,
    reader: Box<dyn JoinHandle>,
}

impl Drop for HostSocket {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Drives an `RTCPeerConnection` over sockets of its own (see the [module documentation](self)).
pub struct PeerDriver {
    runtime: Arc<dyn Runtime>,
    pc: RTCPeerConnection,
    streams: StreamDriver,
    config: PeerDriverConfig,
    sockets: Vec<HostSocket>,
    datagrams_tx: async_channel::Sender<Received>,
    datagrams: async_channel::Receiver<Received>,
    /// What the mDNS sockets received: bounded, the oldest dropped.
    mdns_tx: async_channel::Sender<Received>,
    mdns_rx: async_channel::Receiver<Received>,
    /// Received mDNS datagrams dropped from a full queue ([`Self::mdns_datagrams_dropped`]).
    mdns_dropped: Arc<AtomicU64>,
    /// The driver's own events ([`Self::poll_driver_event`]).
    driver_events: VecDeque<PeerDriverEvent>,
    /// mDNS sends the system refused ([`Self::mdns_send_failures`]).
    mdns_send_failures: u64,
    /// mDNS socket binds that failed ([`Self::mdns_bind_failures`]).
    mdns_bind_failures: u64,
    /// [`Self::shutdown`] ran: nothing is left for `Drop` to do.
    shut_down: bool,
    /// The engine's events, for the application, after the driver had its look.
    events: VecDeque<RTCPeerConnectionEvent>,
    /// The transports whose generation the driver gathered for on an
    /// `OnLocalCandidatesNeeded`: their `gatheringstatechange` that follows needs nothing.
    gathered: HashSet<RTCTransportId>,
    /// Datagrams the engine wrote that no socket sent ([`Self::unsent_datagrams`]).
    unsent: u64,
    /// The connection's mDNS datagrams, held to the budget.
    mdns_egress: MdnsEgress,
    /// `None` until the connection writes its first mDNS datagram, or, with
    /// `QueryAndGather`, until it gathers.
    mdns_sockets: Option<MdnsSockets>,
    /// What the connection was last told about the families its names can be published for.
    mdns_publishing_told: Option<MulticastDnsPublishing>,
    /// mDNS datagrams sent ([`Self::mdns_datagrams_sent`]).
    mdns_sent: u64,
    /// mDNS datagrams received ([`Self::mdns_datagrams_received`]).
    mdns_received: u64,
    /// Sockets on which the platform refused a TOS / Traffic Class ([`Self::unmarked_sockets`]).
    unmarked_sockets: u64,
    /// Datagrams sent, by the TOS / Traffic Class their socket had ([`Self::sent_by_traffic_class`]).
    sent_by_traffic_class: std::collections::BTreeMap<u8, u64>,
}

impl PeerDriver {
    /// A driver for `pc` on tokio ([`runtime::TokioRuntime::new`]: it must be used inside a
    /// tokio runtime), with no socket yet: it binds when the connection's first local
    /// description begins gathering. Feature `runtime-tokio` (on by default).
    #[cfg(feature = "runtime-tokio")]
    pub fn new(pc: RTCPeerConnection, config: PeerDriverConfig) -> Self {
        Self::with_runtime(Arc::new(runtime::TokioRuntime::new()), pc, config)
    }

    /// A driver for `pc` on `runtime`, with no socket yet: it binds when the connection's first
    /// local description begins gathering. Every time it gives the connection is the
    /// runtime's ([`Runtime::now`]).
    pub fn with_runtime(
        runtime: Arc<dyn Runtime>,
        pc: RTCPeerConnection,
        config: PeerDriverConfig,
    ) -> Self {
        // The driver hands each mDNS datagram over with its destination (the group's where it
        // knows the datagram arrived there: RFC 6762 section 11 then deems it on the link).
        let mut pc = pc;
        pc.set_multicast_dns_destination_reported(true);
        let virtual_clock = runtime.virtual_clock();
        let (datagrams_tx, datagrams) = async_channel::unbounded();
        let (mdns_tx, mdns_rx) = async_channel::bounded(MAX_QUEUED_MDNS_RECEIVED);
        Self {
            streams: StreamDriver::with_runtime(runtime.clone(), config.streams),
            runtime,
            pc,
            sockets: Vec::new(),
            datagrams_tx,
            datagrams,
            mdns_tx,
            mdns_rx,
            mdns_dropped: Arc::new(AtomicU64::new(0)),
            driver_events: VecDeque::new(),
            mdns_send_failures: 0,
            mdns_bind_failures: 0,
            shut_down: false,
            events: VecDeque::new(),
            gathered: HashSet::new(),
            unsent: 0,
            // A driver on a virtual clock does not share the process's budget, whose times
            // are the wall clock's: a mock clock ahead would leave it empty for real drivers,
            // one behind would never see it refill.
            mdns_egress: MdnsEgress::new(match &config.mdns_rate_limit {
                None if virtual_clock => MdnsRateLimit::default(),
                _ => config.mdns_rate_limit(),
            }),
            mdns_sockets: None,
            mdns_publishing_told: None,
            mdns_sent: 0,
            mdns_received: 0,
            config,
            unmarked_sockets: 0,
            sent_by_traffic_class: std::collections::BTreeMap::new(),
        }
    }

    /// The runtime the driver runs on.
    pub fn runtime(&self) -> &Arc<dyn Runtime> {
        &self.runtime
    }

    /// The peer connection.
    pub fn pc(&self) -> &RTCPeerConnection {
        &self.pc
    }

    /// The peer connection, for signalling, media and data channels. Call
    /// [`flush`](Self::flush) (or [`step`](Self::step)) after changing it, so that what it
    /// wants to send leaves and the driver sees its events.
    pub fn pc_mut(&mut self) -> &mut RTCPeerConnection {
        &mut self.pc
    }

    /// The local addresses of the UDP sockets open, the previous ones still waiting for a new
    /// pair included.
    pub fn local_addresses(&self) -> Vec<SocketAddr> {
        self.sockets.iter().map(|s| s.local).collect()
    }

    /// How many datagrams the connection wrote that were not sent: from a local address with
    /// no open socket (one closed already), or refused by the socket (its send buffer full:
    /// UDP drops them, as the wire would). Counted so that none is lost unseen.
    pub fn unsent_datagrams(&self) -> u64 {
        self.unsent
    }

    /// How many mDNS datagrams the driver sent for the connection (queries, probes,
    /// announcements, answers, goodbyes), after the budget let them go.
    pub fn mdns_datagrams_sent(&self) -> u64 {
        self.mdns_sent
    }

    /// How many datagrams the driver's mDNS sockets received and handed to the connection
    /// (its own looped back by the host included).
    pub fn mdns_datagrams_received(&self) -> u64 {
        self.mdns_received
    }

    /// How many mDNS sends the system refused (to a group or an asker): a host without a
    /// multicast route, a Mac application without the Local Network permission.
    pub fn mdns_send_failures(&self) -> u64 {
        self.mdns_send_failures
    }

    /// How many times an mDNS socket could not be bound or joined.
    pub fn mdns_bind_failures(&self) -> u64 {
        self.mdns_bind_failures
    }

    /// How many received mDNS datagrams were dropped because the driver was not stepped fast
    /// enough (the oldest go first; at most 256 wait).
    pub fn mdns_datagrams_dropped(&self) -> u64 {
        self.mdns_dropped.load(Ordering::Relaxed)
    }

    /// Whether the driver can send mDNS for a family now: its socket is bound and its sends
    /// have not been refused since (see [`PeerDriverEvent::MdnsUnavailable`]).
    pub fn mdns_available(&self, ipv6: bool) -> bool {
        self.mdns_sockets.as_ref().is_some_and(|m| {
            let family = if ipv6 { &m.v6 } else { &m.v4 };
            family.socket.is_some() && !family.unavailable
        })
    }

    /// The next event of the driver itself (mDNS that cannot be sent, and that works again).
    pub fn poll_driver_event(&mut self) -> Option<PeerDriverEvent> {
        self.driver_events.pop_front()
    }

    /// How many sockets the platform refused a TOS / Traffic Class on: their datagrams leave
    /// without the DSCP the engine asked for (Windows without qWAVE, an IPv6 socket where the
    /// platform has no `IPV6_TCLASS`; see [`sockets::set_traffic_class`]).
    pub fn unmarked_sockets(&self) -> u64 {
        self.unmarked_sockets
    }

    /// How many datagrams were sent with each TOS / Traffic Class byte set on their socket
    /// (a socket the platform refused counts under 0).
    pub fn sent_by_traffic_class(&self) -> &std::collections::BTreeMap<u8, u64> {
        &self.sent_by_traffic_class
    }

    /// The TOS / Traffic Class byte the operating system reports for the UDP socket bound to
    /// `local` (`getsockopt` of `IP_TOS` / `IPV6_TCLASS`): what its next datagram carries.
    /// `None` without such a socket.
    pub fn socket_traffic_class(&self, local: SocketAddr) -> Option<io::Result<u32>> {
        let host = self.sockets.iter().find(|s| s.local == local)?;
        Some(host.socket.traffic_class())
    }

    /// The next event of the connection. The driver has already done what is its to do
    /// (gathering on `OnLocalCandidatesNeeded` and when a transport begins gathering, closing
    /// the previous sockets on a new selected pair, ending each generation's gathering with
    /// its end-of-candidates); the application signals the candidates of
    /// `OnIceCandidateEvent` to the peer, the end-of-candidates candidate included (W3C
    /// webrtc-pc 5.6.4: the peer's transport is "failed" only once it has it, "disconnected"
    /// until then), and handles the rest. The driver tears nothing down on "failed" or
    /// "disconnected": an application that does not relay the end-of-candidates candidate, or
    /// whose peer never sends its own, needs a timer of its own to restart or close.
    pub fn poll_event(&mut self) -> Option<RTCPeerConnectionEvent> {
        self.events.pop_front()
    }

    /// Hands what the connection wants to send to the sockets and the stream driver, and
    /// reacts to its events, until nothing is left.
    ///
    /// # Errors
    ///
    /// A socket that cannot be bound for a transport that needs one, or a candidate the
    /// connection refuses.
    pub fn flush(&mut self) -> Result<()> {
        loop {
            let mut progress = false;
            while let Some(command) = self.pc.poll_stream_command() {
                self.streams.execute(command);
                progress = true;
            }
            while let Some(transmit) = self.pc.poll_stream_transmit() {
                self.streams.write(transmit);
                progress = true;
            }
            while let Some(datagram) = self.pc.poll_write() {
                self.send(datagram);
                progress = true;
            }
            while let Some(event) = self.pc.poll_event() {
                self.on_event(&event)?;
                self.events.push_back(event);
                progress = true;
            }
            if !progress {
                self.send_mdns(self.runtime.now());
                return Ok(());
            }
        }
    }

    /// Ends the connection and the driver in order: closes the connection, sends what it
    /// writes on closing (the mDNS goodbyes of its published names, RFC 6762 section 10.1:
    /// records with TTL 0, so that the link's caches drop them at once instead of holding them
    /// for their 120 s; draft-ietf-mmusic-mdns-ice-candidates section 7.1), waiting up to
    /// `linger` for the mDNS budget to let them go, then closes every socket of the driver,
    /// which leaves the mDNS groups. The driver is not to be stepped afterwards.
    ///
    /// Dropping a driver that was not shut down does what can be done without waiting (see
    /// [`Drop`](#impl-Drop-for-PeerDriver)).
    ///
    /// # Errors
    ///
    /// As [`flush`](Self::flush).
    pub async fn shutdown(&mut self, linger: Duration) -> Result<()> {
        // The connection may be closed already: the application's own `close()`.
        let _ = self.pc.close();
        self.shut_down = true;
        let until = self.runtime.now() + linger;
        loop {
            self.flush()?;
            let now = self.runtime.now();
            let Some(next) = self.mdns_egress.next_ready(now) else {
                break;
            };
            if now >= until {
                break;
            }
            self.runtime.sleep_until(next.min(until)).await;
        }
        // Closing a socket leaves its groups (the system drops its memberships).
        self.mdns_sockets = None;
        self.sockets.clear();
        Ok(())
    }

    /// One round: flushes, then waits up to `wait` (less when a timer of the connection is due
    /// first) for a datagram, a stream input or the timer, hands it over, and flushes again.
    ///
    /// # Errors
    ///
    /// As [`flush`](Self::flush).
    pub async fn step(&mut self, wait: Duration) -> Result<()> {
        self.flush()?;
        let now = self.runtime.now();
        let deadline = self
            .pc
            .poll_timeout()
            .into_iter()
            .chain(self.mdns_egress.next_ready(now))
            .fold(now + wait, Instant::min)
            .max(now);
        let woke = {
            let mut datagram = std::pin::pin!(self.datagrams.recv());
            let mut mdns = std::pin::pin!(self.mdns_rx.recv());
            let mut input = std::pin::pin!(self.streams.next());
            let mut timer = self.runtime.sleep_until(deadline);
            std::future::poll_fn(|cx| {
                if let Poll::Ready(Ok(received)) = datagram.as_mut().poll(cx) {
                    return Poll::Ready(Woke::Datagram(received));
                }
                if let Poll::Ready(Ok(received)) = mdns.as_mut().poll(cx) {
                    return Poll::Ready(Woke::Mdns(received));
                }
                if let Poll::Ready(input) = input.as_mut().poll(cx) {
                    return Poll::Ready(Woke::Stream(input));
                }
                timer.as_mut().poll(cx).map(|()| Woke::Timer)
            })
            .await
        };
        match woke {
            Woke::Datagram((local, peer, data)) => {
                self.feed(local, peer, data);
                while let Ok((local, peer, data)) = self.datagrams.try_recv() {
                    self.feed(local, peer, data);
                }
            }
            Woke::Mdns((local, peer, data)) => {
                self.mdns_received += 1;
                self.feed(local, peer, data);
                while let Ok((local, peer, data)) = self.mdns_rx.try_recv() {
                    self.mdns_received += 1;
                    self.feed(local, peer, data);
                }
            }
            Woke::Stream(input) => self.feed_stream(input),
            Woke::Timer => {}
        }
        // The engine's timers; one that fails is the connection's to report (its states).
        let now = self.runtime.now();
        let _ = self.pc.handle_timeout(now);
        self.sockets
            .retain(|s| s.close_at.is_none_or(|close_at| close_at > now));
        self.flush()
    }

    fn feed(&mut self, local: SocketAddr, peer: SocketAddr, data: Vec<u8>) {
        // A datagram the engine cannot take (a stray, a late one) is its business, not the
        // driver's: it goes on.
        let _ = self.pc.handle_read(TaggedBytesMut {
            now: self.runtime.now(),
            transport: TransportContext {
                local_addr: local,
                peer_addr: peer,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(&data[..]),
        });
    }

    fn feed_stream(&mut self, input: DriverInput) {
        let now = self.runtime.now();
        match input {
            DriverInput::Event(event) => {
                let _ = self.pc.handle_stream_event(now, event);
            }
            DriverInput::Read { id, data } => {
                let _ = self.pc.handle_stream_read(now, id, &data);
            }
            DriverInput::Accepted(accepted) => {
                if let Some(id) = self.pc.handle_stream_accepted(
                    now,
                    accepted.listener,
                    accepted.local,
                    accepted.remote,
                ) {
                    self.streams.adopt(id, accepted);
                }
            }
        }
    }

    /// Sends a datagram of the engine on the socket of its local address, marked with the
    /// DSCP and ECN codepoint the engine gives it (`RTCPeerConnection::traffic_class`: RFC 8837
    /// Table 1 by flow and priority, RFC 8835 section 4.2): the socket's `IP_TOS` /
    /// `IPV6_TCLASS` is set before the datagram when it differs from the last one set.
    fn send(&mut self, datagram: TaggedBytesMut) {
        if datagram.transport.transport_protocol != TransportProtocol::UDP {
            return;
        }
        let local = datagram.transport.local_addr;
        if local.port() == MDNS_PORT && !self.sockets.iter().any(|s| s.local == local) {
            if !self.mdns_egress.push(datagram) {
                self.unsent += 1;
            }
            return;
        }
        let traffic_class = self.pc.traffic_class(&datagram);
        let Some(host) = self.sockets.iter_mut().find(|s| s.local == local) else {
            self.unsent += 1;
            return;
        };
        // UDP: a datagram the socket cannot take now is lost, as on the wire.
        let sent = host
            .socket
            .try_send(&Transmit {
                destination: datagram.transport.peer_addr,
                contents: &datagram.message,
                traffic_class,
                segment_size: None,
                source: None,
            })
            .is_ok();
        // The platform does not mark (RFC 8835 4.2: "appropriate to depart ... on platforms
        // where QoS marking is not implemented"): counted once per socket.
        let unmarked = host.socket.unmarked();
        if unmarked && !host.counted_unmarked {
            host.counted_unmarked = true;
            self.unmarked_sockets += 1;
        }
        if sent {
            let applied = if unmarked { 0 } else { traffic_class };
            *self.sent_by_traffic_class.entry(applied).or_default() += 1;
        } else {
            self.unsent += 1;
        }
    }

    /// Sends the held mDNS datagrams the budget lets go at `now`, binding the mDNS sockets at
    /// the first, each on the interface of the address the engine names for it
    /// ([`MdnsSockets::routes`]). A datagram no socket could send is unsent; a send the system
    /// refuses counts against its family ([`Self::mdns_send_result`]).
    fn send_mdns(&mut self, now: Instant) {
        while let Some(datagram) = self.mdns_egress.pop_ready(now) {
            self.ensure_mdns(now, false);
            let Some(sockets) = self.mdns_sockets.as_ref() else {
                self.unsent += 1;
                continue;
            };
            let routes = sockets.routes(
                datagram.transport.local_addr.ip(),
                datagram.transport.peer_addr,
            );
            let mut results = Vec::new();
            for (destination, source) in routes {
                let family = if destination.is_ipv6() {
                    &sockets.v6
                } else {
                    &sockets.v4
                };
                if let Some((socket, _)) = &family.socket {
                    let result = socket.try_send(&Transmit {
                        destination,
                        contents: &datagram.message,
                        traffic_class: 0,
                        segment_size: None,
                        source,
                    });
                    results.push((destination.is_ipv6(), result));
                }
            }
            let mut sent = false;
            for (ipv6, result) in results {
                sent |= self.mdns_send_result(ipv6, result, now);
            }
            if sent {
                self.mdns_sent += 1;
            } else {
                self.unsent += 1;
            }
        }
    }

    /// Books one mDNS send of a family: a success makes the family available again (told
    /// once); a refusal counts, and declares the family unavailable at once when the error
    /// says there is no route or no permission, or after a few in a row. A full send buffer
    /// (`WouldBlock`) is a lost datagram, as on the wire, not a failure.
    fn mdns_send_result(&mut self, ipv6: bool, result: io::Result<usize>, now: Instant) -> bool {
        let Some(sockets) = self.mdns_sockets.as_mut() else {
            return false;
        };
        let family = if ipv6 {
            &mut sockets.v6
        } else {
            &mut sockets.v4
        };
        match result {
            Ok(_) => {
                family.failures = 0;
                if family.unavailable {
                    family.unavailable = false;
                    family.backoff = MDNS_RETRY_FIRST;
                    self.driver_events
                        .push_back(PeerDriverEvent::MdnsAvailable { ipv6 });
                    self.refresh_mdns_publishing();
                }
                true
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => {
                self.mdns_send_failures += 1;
                family.failures += 1;
                if decisive(&e) || family.failures >= MDNS_FAILURES_BEFORE_UNAVAILABLE {
                    self.mdns_unavailable(ipv6, MdnsStage::Send, &e, now);
                }
                false
            }
        }
    }

    /// A family's mDNS cannot be used: its socket is closed (bound again at the next try),
    /// the next try waits a back-off, the application is told (once until it works again),
    /// and the connection learns that the family's names cannot be published.
    fn mdns_unavailable(&mut self, ipv6: bool, stage: MdnsStage, error: &io::Error, now: Instant) {
        let Some(sockets) = self.mdns_sockets.as_mut() else {
            return;
        };
        let family = if ipv6 {
            &mut sockets.v6
        } else {
            &mut sockets.v4
        };
        family.close();
        family.failures = 0;
        family.retry_at = Some(now + family.backoff);
        family.backoff = (family.backoff * 2).min(MDNS_RETRY_MAX);
        if !family.unavailable {
            family.unavailable = true;
            self.driver_events
                .push_back(PeerDriverEvent::MdnsUnavailable(MdnsFailure::new(
                    ipv6, stage, error,
                )));
        }
        self.refresh_mdns_publishing();
    }

    /// The host's mDNS sockets (none with [`PeerDriverConfig::mdns_sockets`] off): each family
    /// without a socket is bound now when it never was, when `force` (a gathering), or when
    /// its back-off has passed. Each socket is joined to its group on the interface of every
    /// configured address of its family (RFC 6762 section 14: a name is answered, and a peer's
    /// asked for, on the link of its address). A bind that fails is reported
    /// ([`PeerDriverEvent::MdnsUnavailable`]) and tried again later.
    fn ensure_mdns(&mut self, now: Instant, force: bool) {
        let skips_loopback_v4 = self.config.skips_loopback_mdns_v4();
        let addresses = mdns_addresses(&self.config.addresses, skips_loopback_v4);
        if self.mdns_sockets.is_none() {
            let mut v4 = MdnsFamily::new(one_per_interface(&addresses, true));
            if addresses.len() < self.config.addresses.len() {
                note_loopback_mdns_skipped();
                // Only loopback IPv4 addresses: no IPv4 socket at all (one with no interface
                // would join and send on the system's default one).
                v4.off = !addresses.iter().any(IpAddr::is_ipv4);
            }
            let v6 = MdnsFamily::new(one_per_interface(&addresses, false));
            let companions = v6
                .links
                .iter()
                .filter_map(|ip6| {
                    let name = runtime::interface_name(*ip6)?;
                    let ip4 = v4
                        .links
                        .iter()
                        .find(|ip4| runtime::interface_name(**ip4).as_deref() == Some(&name))?;
                    Some((*ip6, *ip4))
                })
                .collect();
            self.mdns_sockets = Some(MdnsSockets {
                v4,
                v6,
                companions,
                skips_loopback_v4,
            });
        }
        if !self.config.mdns_sockets {
            return;
        }
        for ipv6 in [false, true] {
            let Some(sockets) = self.mdns_sockets.as_ref() else {
                return;
            };
            let family = if ipv6 { &sockets.v6 } else { &sockets.v4 };
            if family.off
                || family.socket.is_some()
                || !(force || family.retry_at.is_none_or(|at| now >= at))
            {
                continue;
            }
            let config = if ipv6 {
                mdns_v6(addresses.clone())
            } else {
                mdns_v4(addresses.clone())
            };
            let bound = self
                .runtime
                .bind_udp_multicast(&config)
                .and_then(|socket| Ok((socket.local_addr()?, socket)));
            match bound {
                Ok((local, socket)) => {
                    let tx = self.mdns_tx.clone();
                    let dropped = self.mdns_dropped.clone();
                    let reader = self.runtime.spawn(Box::pin(read_loop(
                        socket.clone(),
                        local,
                        true,
                        move |received| match tx.force_send(received) {
                            Ok(None) => true,
                            Ok(Some(_)) => {
                                dropped.fetch_add(1, Ordering::Relaxed);
                                true
                            }
                            Err(_) => false,
                        },
                        MDNS_MAX_DATAGRAM,
                    )));
                    if let Some(sockets) = self.mdns_sockets.as_mut() {
                        let family = if ipv6 {
                            &mut sockets.v6
                        } else {
                            &mut sockets.v4
                        };
                        family.socket = Some((socket, reader));
                    }
                }
                Err(e) => {
                    self.mdns_bind_failures += 1;
                    self.mdns_unavailable(ipv6, MdnsStage::Bind, &e, now);
                }
            }
        }
        self.refresh_mdns_publishing();
    }

    /// Before the connection's host candidates, with `QueryAndGather`: binds the mDNS sockets
    /// (again, for a family that failed) and tells the connection for which address families
    /// its names can be published (draft-ietf-mmusic-mdns-ice-candidates section 3.1.1 step 4).
    fn prepare_mdns_publishing(&mut self) {
        if self.pc.multicast_dns_mode() != MulticastDnsMode::QueryAndGather {
            return;
        }
        let now = self.runtime.now();
        self.ensure_mdns(now, true);
        if self.mdns_publishing_told.is_none() {
            let publishing = self.mdns_publishing();
            self.mdns_publishing_told = Some(publishing);
            self.pc.set_multicast_dns_publishing(publishing);
        }
    }

    /// What is actually sent: an IPv4 record's messages need the IPv4 socket; an IPv6 record's
    /// leave on the IPv6 group, or on the IPv4 group of its interface.
    fn mdns_publishing(&self) -> MulticastDnsPublishing {
        let usable = |f: &MdnsFamily| f.socket.is_some() && !f.unavailable;
        self.mdns_sockets.as_ref().map_or(
            MulticastDnsPublishing {
                ipv4: false,
                ipv6: false,
            },
            |m| MulticastDnsPublishing {
                ipv4: usable(&m.v4),
                ipv6: usable(&m.v6) || (usable(&m.v4) && !m.companions.is_empty()),
            },
        )
    }

    /// Tells the connection again when what can be published changed, once it was told.
    fn refresh_mdns_publishing(&mut self) {
        let Some(told) = self.mdns_publishing_told else {
            return;
        };
        let now = self.mdns_publishing();
        if now != told {
            self.mdns_publishing_told = Some(now);
            self.pc.set_multicast_dns_publishing(now);
        }
    }

    /// With `QueryAndGather`, tells the connection which of the addresses it gathers on the
    /// operating system flags as RFC 4941 temporary IPv6 addresses
    /// (`RTCPeerConnection::set_temporary_ipv6_addresses`), so that
    /// `with_multicast_dns_expose_temporary_ipv6_addresses` can leave those unwrapped
    /// (draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.3). Read from the interface list
    /// at each gathering (`shared::ifaces::temporary_ipv6_addresses`: Linux, Android, macOS
    /// and iOS report the flag; Windows and other systems mark nothing); where it cannot be
    /// read, nothing is marked and every address stays hidden.
    fn mark_temporary_addresses(&mut self) {
        if self.pc.multicast_dns_mode() != MulticastDnsMode::QueryAndGather {
            return;
        }
        let temporary: Vec<std::net::Ipv6Addr> = shared::ifaces::temporary_ipv6_addresses()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| self.config.addresses.contains(&IpAddr::V6(*t)))
            .collect();
        self.pc.set_temporary_ipv6_addresses(temporary);
    }

    fn on_event(&mut self, event: &RTCPeerConnectionEvent) -> Result<()> {
        match event {
            RTCPeerConnectionEvent::OnLocalCandidatesNeeded(needed) => {
                self.on_candidates_needed(needed)
            }
            RTCPeerConnectionEvent::OnSignalingStateChangeEvent(RTCSignalingState::Stable) => {
                self.match_sockets_to_candidates();
                Ok(())
            }
            RTCPeerConnectionEvent::OnTransportEvent(event) => match &event.event {
                RTCTransportEventKind::GatheringStateChange(RTCIceGatheringState::Gathering) => {
                    self.on_gathering_begins(event.ice_transport, event.dtls_transport)
                }
                RTCTransportEventKind::SelectedCandidatePairChange(pair) => {
                    let local = pair.local();
                    let on_retired = self.sockets.iter().any(|s| {
                        s.retired_for.is_some() && names_socket(&local.address, local.port, s.local)
                    });
                    if !on_retired {
                        self.release_after_linger(event.ice_transport);
                    }
                    Ok(())
                }
                RTCTransportEventKind::IceStateChange(RTCIceTransportState::Closed) => {
                    self.release(event.ice_transport);
                    Ok(())
                }
                _ => Ok(()),
            },
            _ => Ok(()),
        }
    }

    /// `OnLocalCandidatesNeeded`: new sockets for the transport, or (`DiscardedBySetting`,
    /// no address refused) the same sockets' candidates again.
    fn on_candidates_needed(&mut self, needed: &RTCLocalCandidatesNeededEvent) -> Result<()> {
        let Some(mid) = needed.mids.first().cloned() else {
            return Ok(());
        };
        let index = needed.sdp_mline_index;
        self.gathered.insert(needed.ice_transport);
        self.mark_temporary_addresses();
        if !needed.reason.needs_new_addresses() {
            let on: Vec<SocketAddr> = self
                .sockets
                .iter()
                .filter(|s| s.retired_for.is_none() && needed.mids.contains(&s.mid))
                .map(|s| s.local)
                .collect();
            if !on.is_empty() {
                for local in on {
                    self.pc
                        .add_local_candidate(host_candidate(local, &mid, index)?)?;
                }
                return self.end_of_candidates(&mid, index);
            }
            return self.gather_section(&mid, index);
        }
        for host in self
            .sockets
            .iter_mut()
            .filter(|s| needed.refused_addresses.contains(&s.local))
        {
            host.retired_for = Some(needed.ice_transport);
        }
        if needed.reason == RTCLocalCandidatesNeededReason::TransportReplaced {
            // The transport they served is closed: nothing travels over them any more.
            self.release(needed.ice_transport);
        }
        self.gather_section(&mid, index)
    }

    /// Back in the stable state, the sockets are matched against the candidates the
    /// transports hold. A local offer that is rolled back takes its ICE restart back (RFC
    /// 9429 section 5.7: "any resources or candidates that were allocated by the abandoned
    /// local description are discarded"), the `OnLocalCandidatesNeeded` it fired included: a
    /// socket retired for it whose candidate the transport holds again carries the
    /// transport's packets as before (it is no longer retired), and a socket bound for the
    /// abandoned generation, whose candidate the transport dropped, is closed. The answer to
    /// the peer's colliding offer, if it sets up a new association, fires its own event.
    fn match_sockets_to_candidates(&mut self) {
        let held: Vec<(String, u16)> = self
            .pc
            .dtls_transports()
            .iter()
            .flat_map(|t| t.ice_transport().get_local_candidates())
            .filter(|c| c.protocol == RTCIceProtocol::Udp)
            .map(|c| (c.address, c.port))
            .collect();
        let holds = |local: &SocketAddr| {
            held.iter()
                .any(|(address, port)| names_socket(address, *port, *local))
        };
        for host in self.sockets.iter_mut() {
            if host.retired_for.is_some() && holds(&host.local) {
                host.retired_for = None;
                host.close_at = None;
            }
        }
        self.sockets
            .retain(|s| s.retired_for.is_some() || holds(&s.local));
    }

    /// A transport begins gathering an ICE generation the driver was not told about: the
    /// first one (no socket of the transport yet: every section without one gets them), or a
    /// restart that kept the candidates (each is given to the new generation again).
    fn on_gathering_begins(
        &mut self,
        ice_transport: RTCTransportId,
        dtls_transport: RTCTransportId,
    ) -> Result<()> {
        if self.gathered.remove(&ice_transport) {
            return Ok(());
        }
        let Some(held) = self.pc.dtls_transport_by_id(dtls_transport).and_then(|t| {
            let ice = t.ice_transport();
            (ice.gathering_state() == RTCIceGatheringState::Gathering)
                .then(|| ice.get_local_candidates())
        }) else {
            return Ok(());
        };
        let kept: Vec<(SocketAddr, String)> = self
            .sockets
            .iter()
            .filter(|s| s.retired_for.is_none())
            .filter(|s| {
                held.iter()
                    .any(|c| names_socket(&c.address, c.port, s.local))
            })
            .map(|s| (s.local, s.mid.clone()))
            .collect();
        if kept.is_empty() {
            return self.gather();
        }
        let mid = kept[0].1.clone();
        for (local, _) in &kept {
            self.pc
                .add_local_candidate(host_candidate(*local, &mid, None)?)?;
        }
        self.end_of_candidates(&mid, None)
    }

    /// Host candidates for every transport section (`ice_transport_sections`) that has no
    /// socket of its own yet, each ended with the end of its generation.
    ///
    /// # Errors
    ///
    /// As [`flush`](Self::flush).
    pub fn gather(&mut self) -> Result<()> {
        for (mid, index) in self.pc.ice_transport_sections() {
            if self
                .sockets
                .iter()
                .any(|s| s.retired_for.is_none() && s.mid == mid)
            {
                continue;
            }
            self.gather_section(&mid, Some(index))?;
        }
        Ok(())
    }

    /// New sockets, one per configured address, for the transport of section `mid`: their
    /// host candidates, then the end of the generation.
    fn gather_section(&mut self, mid: &str, index: Option<u16>) -> Result<()> {
        self.prepare_mdns_publishing();
        self.mark_temporary_addresses();
        for ip in self.config.addresses.clone() {
            let (socket, local) = self.bind_unique_port(ip).map_err(io_error)?;
            let tx = self.datagrams_tx.clone();
            let reader = self.runtime.spawn(Box::pin(read_loop(
                socket.clone(),
                local,
                false,
                move |received| tx.try_send(received).is_ok(),
                2048,
            )));
            self.sockets.push(HostSocket {
                socket,
                local,
                mid: mid.to_owned(),
                retired_for: None,
                close_at: None,
                counted_unmarked: false,
                reader,
            });
            self.pc
                .add_local_candidate(host_candidate(local, mid, index)?)?;
        }
        self.end_of_candidates(mid, index)
    }

    /// A UDP socket on `ip`; with `QueryAndGather`, one whose port no other socket of the
    /// driver has: a `.local` candidate names its socket by port alone ([`names_socket`]), so
    /// ports are kept unique across the driver's addresses (the system gives each address its
    /// own ports, and a port-range cursor comes round again). Where the range has no such port
    /// left after [`MAX_PORT_ATTEMPTS`] binds, the last one is taken: two sockets then share a
    /// port, and a retired one may stay open until its transport closes.
    fn bind_unique_port(&self, ip: IpAddr) -> io::Result<(Arc<dyn AsyncUdpSocket>, SocketAddr)> {
        let unique = self.pc.multicast_dns_mode() == MulticastDnsMode::QueryAndGather;
        // Sockets refused for their port stay bound until the end, so that the next bind
        // cannot be given the same port again.
        let mut refused = Vec::new();
        for _ in 0..MAX_PORT_ATTEMPTS {
            let socket = match self.config.udp_port_range {
                Some(range) => sockets::bind_runtime_udp_in_range(self.runtime.as_ref(), ip, range),
                None => self.runtime.bind_udp(SocketAddr::new(ip, 0)),
            };
            let socket = match socket {
                Ok(socket) => socket,
                // The range is full now that the refused sockets hold their ports.
                Err(e) if !refused.is_empty() && e.kind() == io::ErrorKind::AddrInUse => break,
                Err(e) => return Err(e),
            };
            let local = socket.local_addr()?;
            if !unique || !self.sockets.iter().any(|s| s.local.port() == local.port()) {
                return Ok((socket, local));
            }
            refused.push((socket, local));
        }
        refused
            .pop()
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrInUse))
    }

    fn end_of_candidates(&mut self, mid: &str, index: Option<u16>) -> Result<()> {
        self.pc.add_local_candidate(RTCIceCandidateInit {
            sdp_mid: Some(mid.to_owned()),
            sdp_mline_index: index,
            ..Default::default()
        })
    }

    /// Closes the sockets retired for `transport` (it is closed: nothing travels over them).
    fn release(&mut self, transport: RTCTransportId) {
        self.sockets.retain(|s| s.retired_for != Some(transport));
    }

    /// `transport` selected a pair on a new socket: its retired sockets are closed after
    /// [`PeerDriverConfig::retired_socket_linger`], for what the peer still sends to them.
    fn release_after_linger(&mut self, transport: RTCTransportId) {
        let close_at = self.runtime.now() + self.config.retired_socket_linger;
        for host in self
            .sockets
            .iter_mut()
            .filter(|s| s.retired_for == Some(transport) && s.close_at.is_none())
        {
            host.close_at = Some(close_at);
        }
    }
}

/// What a driver dropped without [`PeerDriver::shutdown`] can do: an async driver on a runtime
/// of the application's choice cannot wait in `drop` (no runtime may be blocked there, and
/// none may be running any more), so it closes the connection and sends at once, without
/// waiting, what the connection then writes: the mDNS goodbyes the budget lets go now (the
/// rest is lost, and the neighbours' caches hold those names until their TTL ends), each
/// socket's last datagrams if the system takes them. The sockets close as the driver goes,
/// leaving the mDNS groups. Use `shutdown` to have every goodbye sent.
impl Drop for PeerDriver {
    fn drop(&mut self) {
        if self.shut_down {
            return;
        }
        let _ = self.pc.close();
        while let Some(datagram) = self.pc.poll_write() {
            self.send(datagram);
        }
        if self.mdns_sockets.is_some() {
            self.send_mdns(self.runtime.now());
        }
    }
}

/// How many binds [`PeerDriver::bind_unique_port`] tries for a port no other socket has.
const MAX_PORT_ATTEMPTS: usize = 16;

/// Whether a local candidate of `address` and `port` is the one of the socket at `local`. With
/// mDNS (`QueryAndGather`) the engine has replaced the candidate's address with a `.local` name
/// (draft-ietf-mmusic-mdns-ice-candidates section 3.1.1): the port tells the socket then, and
/// it tells exactly one, because no two sockets of a driver share a port
/// ([`PeerDriver::bind_unique_port`]).
fn names_socket(address: &str, port: u16, local: SocketAddr) -> bool {
    port == local.port()
        && (address == local.ip().to_string() || address.to_ascii_lowercase().ends_with(".local"))
}

fn io_error(e: io::Error) -> Error {
    Error::Io(IoError(e))
}

/// The host candidate of `local` for section `mid`.
fn host_candidate(local: SocketAddr, mid: &str, index: Option<u16>) -> Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local.ip().to_string(),
            port: local.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let mut init = RTCIceCandidate::from(&candidate).to_json()?;
    init.sdp_mid = Some(mid.to_owned());
    init.sdp_mline_index = index;
    Ok(init)
}

/// What woke a [`PeerDriver::step`].
enum Woke {
    Datagram(Received),
    Mdns(Received),
    Stream(DriverInput),
    Timer,
}

/// Whether an mDNS send error says sending cannot work (no route to the group, no
/// permission): the family is unavailable at once, without waiting for more failures.
fn decisive(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkDown
    )
}

/// Reads `socket` and hands each datagram to `deliver` (`false`: the driver is gone), with
/// `local` as its local address, or, with `destination`, the destination address of its IP
/// header where the socket reports it (else `local`'s: a socket bound to the mDNS group
/// receives only what was sent to the group).
async fn read_loop(
    socket: Arc<dyn AsyncUdpSocket>,
    local: SocketAddr,
    destination: bool,
    mut deliver: impl FnMut(Received) -> bool + Send + 'static,
    max_datagram: usize,
) {
    let mut buf = vec![0u8; max_datagram];
    loop {
        let received = std::future::poll_fn(|cx| {
            let mut meta = [runtime::RecvMeta::default()];
            let mut bufs = [std::io::IoSliceMut::new(&mut buf)];
            socket
                .poll_recv(cx, &mut bufs, &mut meta)
                .map_ok(|_| meta[0])
        })
        .await;
        match received {
            Ok(meta) => {
                let to = match meta.dst_ip {
                    Some(ip) if destination && !ip.is_unspecified() => {
                        SocketAddr::new(ip, local.port())
                    }
                    _ => local,
                };
                if !deliver((to, meta.addr, buf[..meta.len].to_vec())) {
                    return;
                }
            }
            // An ICMP error reported on the socket (Windows: a port unreachable) is not the
            // end of it.
            Err(_) => runtime::yield_now().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NIC: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn sockets(addresses: &[IpAddr], skips_loopback_v4: bool) -> MdnsSockets {
        let addresses = mdns_addresses(addresses, skips_loopback_v4);
        MdnsSockets {
            v4: MdnsFamily::new(one_per_interface(&addresses, true)),
            v6: MdnsFamily::new(one_per_interface(&addresses, false)),
            companions: vec![],
            skips_loopback_v4,
        }
    }

    // The 0.3.0 default on Windows: IPv4 loopback addresses get no mDNS interface; the others,
    // IPv6 loopback included (not measured to leave a route), keep theirs. With the setting (and
    // on other systems) nothing is taken out.
    #[test]
    fn ipv4_loopback_addresses_get_no_mdns_interface_when_skipped() {
        let all = [NIC, LO, IpAddr::V6(Ipv6Addr::LOCALHOST)];
        assert_eq!(
            mdns_addresses(&all, true),
            vec![NIC, IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
        assert_eq!(mdns_addresses(&all, false), all.to_vec());
    }

    // A message about the loopback address's name is sent nowhere on the group when skipped, and
    // on the loopback interface otherwise; a query leaves on the other interfaces only.
    #[test]
    fn a_loopback_record_leaves_on_no_group_when_skipped() {
        let group = SocketAddr::new(MDNS_MULTICAST_IPV4.into(), MDNS_PORT);
        let skipped = sockets(&[NIC, LO], true);
        assert!(skipped.routes(LO, group).is_empty());
        assert_eq!(skipped.routes(NIC, group), vec![(group, Some(NIC))]);
        assert_eq!(
            skipped.routes(Ipv4Addr::UNSPECIFIED.into(), group),
            vec![(group, Some(NIC))],
            "the query leaves on the network interface only"
        );
        let asked = sockets(&[NIC, LO], false);
        assert_eq!(asked.routes(LO, group), vec![(group, Some(LO))]);
    }

    // The default decides on Windows only; the setting turns it off there.
    #[test]
    fn loopback_mdns_is_skipped_by_default_on_windows_only() {
        let config = PeerDriverConfig::on(vec![LO]);
        assert!(!config.mdns_on_loopback_on_windows, "the default");
        assert_eq!(config.skips_loopback_mdns_v4(), cfg!(windows));
        let asked = PeerDriverConfig {
            mdns_on_loopback_on_windows: true,
            ..config
        };
        assert!(!asked.skips_loopback_mdns_v4());
    }
}
