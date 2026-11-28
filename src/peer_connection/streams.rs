//! The peer connection's stream transports: the ICE-TCP candidates the engine gathers itself
//! and the TCP connections they use (RFC 6544), carried through `rtci_shared::stream`.
//!
//! The application (the *driver*) owns the sockets and nothing else: it listens, connects,
//! accepts, closes, reads and writes when the engine says so ([`RTCPeerConnection::poll_stream_command`],
//! [`RTCPeerConnection::poll_stream_transmit`]) and reports back
//! ([`RTCPeerConnection::handle_stream_event`], [`RTCPeerConnection::handle_stream_accepted`],
//! [`RTCPeerConnection::handle_stream_read`]). The engine gathers the TCP host candidates (a
//! passive and a simultaneous-open one on a listener each, and an active one) for every
//! address of a UDP host candidate the application adds, opens the connections its active and
//! simultaneous-open candidates need, frames every packet with RFC 4571, closes what ICE no
//! longer needs and reports failed connections to the ICE agent.
//!
//! A TCP candidate the application adds itself, and the connections it opens for one, stay the
//! application's (`handle_read` / `poll_write` with `TransportProtocol::TCP`, framed by the
//! application), as before.

use super::RTCPeerConnection;
use crate::peer_connection::handler::transport_set::TransportId;
use crate::peer_connection::transport::ice::candidate::RTCIceServerTransportProtocol;
use bytes::BytesMut;
use ice::TransportError;
use ice::candidate::{CandidateConfig, CandidateType, candidate_host::CandidateHostConfig};
use ice::network_type::NetworkType;
use ice::tcp_type::TcpType;
use log::{debug, trace};
use shared::error::{Error, Result};
use shared::stream::{
    Framing, ListenerId, StreamCommand, StreamConfig, StreamEvent, StreamId, StreamNotice,
    StreamOrigin, StreamState, StreamTable, StreamTransmit,
};
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// The stream-table tag of ICE-TCP connections and listeners.
pub(crate) const ICE_TCP: u32 = 1;
/// The stream-table tag of TURN-over-TCP / TLS connections.
pub(crate) const TURN: u32 = 2;
/// The stream-table tag of Binding connections to STUN servers (server-reflexive TCP
/// candidates).
pub(crate) const SRFLX: u32 = 3;
/// The stream-table tag of TURN-TCP data connections (RFC 6062 section 4.3): one peer's TCP
/// connection through a TCP allocation.
pub(crate) const TURN_DATA: u32 = 4;

/// The port an active TCP candidate is signalled with (RFC 6544 section 4.5).
const ACTIVE_PORT: u16 = 9;

/// What the engine does with TCP by itself. See the `SettingEngineBuilder` methods
/// `with_tcp_candidate_gathering`, `with_tcp_simultaneous_open`,
/// `with_tcp_close_unused_connections` and `with_stream_limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSettings {
    /// Gather TCP host candidates for each address of a UDP host candidate (RFC 6544 section
    /// 4.1, browsers' default). On by default.
    pub tcp_candidates: bool,
    /// With them, a simultaneous-open candidate on its own port (RFC 6544 section 5.1). On by
    /// default.
    pub simultaneous_open: bool,
    /// Close every ICE-TCP connection but the selected pair's once ICE has completed (RFC 6544
    /// section 8). On by default.
    pub close_unused_connections: bool,
    /// The stream table's window, queue and connection limits.
    pub limits: StreamConfig,
    /// Run the configuration's `turns:` and `turn:...?transport=tcp` servers (RFC 8656
    /// section 3.1). On by default.
    pub turn: bool,
    /// With them, relayed TCP candidates from a TCP allocation (RFC 6062, RFC 6544 section
    /// 5.5). On by default.
    pub turn_tcp_relay: bool,
    /// Who gathers server-reflexive candidates (RFC 8445 section 5.1.1.2): the engine by
    /// default.
    pub reflexive: super::srflx::ReflexiveGathering,
    /// Who gathers relayed candidates from `turn:` servers over UDP (RFC 8656, RFC 8445
    /// section 5.1.1.2): the engine by default.
    pub relay: super::turn_streams::RelayGathering,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            tcp_candidates: true,
            simultaneous_open: true,
            close_unused_connections: true,
            limits: StreamConfig::default(),
            turn: true,
            turn_tcp_relay: true,
            reflexive: super::srflx::ReflexiveGathering::Engine,
            relay: super::turn_streams::RelayGathering::Engine,
        }
    }
}

struct GatherListener {
    id: ListenerId,
    tcp_type: TcpType,
    bound: Option<SocketAddr>,
    failed: bool,
}

/// The TCP candidates of one local address of one transport (RFC 9429 section 5.2.1: each
/// transport gathers its own).
struct TcpGather {
    transport: TransportId,
    ip: IpAddr,
    listeners: Vec<GatherListener>,
    active_added: bool,
}

impl TcpGather {
    fn pending(&self) -> bool {
        self.listeners
            .iter()
            .any(|l| l.bound.is_none() && !l.failed)
    }
}

/// The peer connection's stream state.
pub(crate) struct EngineStreams {
    pub(crate) settings: StreamSettings,
    pub(crate) table: StreamTable,
    /// The application has used the stream interface: it drives streams.
    pub(crate) driver_seen: bool,
    gathers: Vec<TcpGather>,
    /// Addresses of the active candidates the engine added (port 9).
    active: HashSet<IpAddr>,
    /// Bases of the passive and simultaneous-open candidates the engine added.
    bound: HashSet<SocketAddr>,
    /// Connections an active candidate opened (its ephemeral port is not a candidate's).
    active_connections: HashSet<StreamId>,
    /// Connections that have delivered a message.
    answered: HashSet<StreamId>,
    /// The transport each ICE-TCP connection carries: the one whose check opened it, the
    /// one whose listener accepted it, or (a listening port shared by several transports)
    /// the one its first Binding request names.
    connection_transport: HashMap<StreamId, TransportId>,
    /// Two lite agents (RFC 6544 section 6.1): the pairs (transport, local, remote) whose
    /// connection this side opened when it selected them, once each.
    lite_connects: HashSet<(TransportId, SocketAddr, SocketAddr)>,
    /// Two lite agents, this side controlled: transports whose updated candidate exchange
    /// was applied, and whose connections opened in parallel with it are still to be matched
    /// against its pair (RFC 6544 section 6.1).
    pub(crate) lite_updates: HashSet<TransportId>,
    /// The transports whose end of gathering was signalled while their listeners or TURN
    /// allocations were still being made.
    end_of_gathering_deferred: HashSet<TransportId>,
    /// Writes for an engine candidate that no connection could take.
    pub(crate) unroutable: u64,
    /// The TURN-over-stream links.
    pub(crate) turn: super::turn_streams::EngineTurn,
    /// The engine's Binding requests to STUN servers.
    pub(crate) srflx: super::srflx::EngineSrflx,
}

impl EngineStreams {
    pub(crate) fn new(
        settings: StreamSettings,
        turn: super::turn_streams::EngineTurn,
        srflx: super::srflx::EngineSrflx,
    ) -> Self {
        Self {
            turn,
            srflx,
            settings,
            table: StreamTable::new(settings.limits),
            driver_seen: false,
            gathers: Vec::new(),
            active: HashSet::new(),
            bound: HashSet::new(),
            active_connections: HashSet::new(),
            answered: HashSet::new(),
            connection_transport: HashMap::new(),
            lite_connects: HashSet::new(),
            lite_updates: HashSet::new(),
            end_of_gathering_deferred: HashSet::new(),
            unroutable: 0,
        }
    }

    /// Whether `local` is the base of a TCP candidate the engine gathered.
    fn manages(&self, local: SocketAddr) -> bool {
        (local.port() == ACTIVE_PORT && self.active.contains(&local.ip()))
            || self.bound.contains(&local)
    }

    /// Whether the end of gathering of `transport` waits: for listeners and TURN links a
    /// driver serves, for TURN-over-DTLS links and for the server-reflexive probes (over UDP
    /// whatever the driver, a name only with one).
    fn end_of_gathering_waits(&self, transport: TransportId) -> bool {
        let driver = self.driver_seen;
        (driver && self.pending_listeners(transport))
            || self.turn.pending(transport, driver)
            || self.srflx.pending(transport, driver)
    }

    /// Whether a listener of `transport` is still being bound.
    fn pending_listeners(&self, transport: TransportId) -> bool {
        self.gathers
            .iter()
            .any(|g| g.transport == transport && g.pending())
    }

    /// The transport whose listener `listener` is, when no other transport's listener has
    /// the same address (a port the driver shares between transports).
    fn transport_of_listener(&self, listener: ListenerId) -> Option<TransportId> {
        let (gather, bound) = self.gathers.iter().find_map(|g| {
            g.listeners
                .iter()
                .find(|l| l.id == listener)
                .map(|l| (g, l.bound))
        })?;
        let shared = bound.is_some_and(|bound| {
            self.gathers.iter().any(|other| {
                other.transport != gather.transport
                    && other.listeners.iter().any(|l| l.bound == Some(bound))
            })
        });
        (!shared).then_some(gather.transport)
    }

    /// The local address the agent knows a connection by: an active candidate's (port 9) for
    /// one it opened, the bound address otherwise.
    fn agent_local(&self, id: StreamId, local: SocketAddr) -> SocketAddr {
        if self.active_connections.contains(&id) {
            SocketAddr::new(local.ip(), ACTIVE_PORT)
        } else {
            local
        }
    }

    /// The connection for a datagram the agent of `transport` sends from `local` to `remote`.
    /// A connection known to carry another transport is not it, and with `named_only` (a
    /// datagram that is not STUN, on a connection with several transports) neither is one
    /// whose transport is not known yet: its 5-tuple may be another transport's too.
    fn connection_for(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
        transport: TransportId,
        named_only: bool,
    ) -> Option<StreamId> {
        let active = local.port() == ACTIVE_PORT && self.active.contains(&local.ip());
        let mut connecting = None;
        for c in self.table.connections() {
            if c.tag != ICE_TCP || c.remote != remote || c.state == StreamState::Closing {
                continue;
            }
            match self.connection_transport.get(&c.id) {
                Some(t) if *t != transport => continue,
                None if named_only => continue,
                _ => {}
            }
            let fits = if active {
                self.active_connections.contains(&c.id) && c.local.ip() == local.ip()
            } else {
                !self.active_connections.contains(&c.id)
                    && (c.local == local || c.requested_local == local)
            };
            if fits {
                if c.state == StreamState::Open {
                    return Some(c.id);
                }
                connecting.get_or_insert(c.id);
            }
        }
        connecting
    }

    /// Opens a connection from the active candidate on `ip` (an ephemeral port of that
    /// interface, RFC 6544 section 7.1) to `remote`, for the agent of `on`.
    fn connect_active(
        &mut self,
        on: TransportId,
        ip: IpAddr,
        remote: SocketAddr,
    ) -> Option<StreamId> {
        let id = self
            .table
            .connect(
                SocketAddr::new(ip, 0),
                remote,
                Framing::Rfc4571,
                ICE_TCP,
                false,
                None,
            )
            .ok()?;
        self.active_connections.insert(id);
        self.connection_transport.insert(id, on);
        Some(id)
    }
}

/// RFC 7983's first-byte ranges for what may travel on an ICE-TCP connection: STUN, DTLS,
/// RTP / RTCP. Anything else means the RFC 4571 framing is lost (RFC 4571 section 2).
fn demultiplexable(first: u8) -> bool {
    matches!(first, 0..=3 | 20..=63 | 128..=191)
}

pub(crate) fn tcp_context(local: SocketAddr, peer: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr: local,
        peer_addr: peer,
        transport_protocol: TransportProtocol::TCP,
        ecn: None,
    }
}

impl RTCPeerConnection {
    /// The next thing the driver is to do with a socket: listen for, open, close or reset a
    /// TCP connection. Poll it, as `poll_write`, after each input. See
    /// [`rtci::shared::stream`](shared::stream) for the commands and the module documentation
    /// of `streams` for who owns what.
    pub fn poll_stream_command(&mut self) -> Option<StreamCommand> {
        self.streams.driver_seen = true;
        self.release_removed_transports();
        self.start_turn_links();
        // Permissions for remote candidates learned since (relayed TCP candidates).
        if self.streams.turn.has_tcp_relay() {
            let now = self.pipeline_context.now;
            self.turn_tcp_permissions(now);
            self.pump_turn(now);
        }
        self.open_lite_tcp_connections();
        self.settle_lite_tcp_updates();
        self.route_stream_writes();
        self.close_unused_tcp_connections();
        self.close_settled_srflx_connections();
        self.close_settled_turn_links();
        self.streams.table.poll_command()
    }

    /// The next bytes to write on one of the engine's connections, after every earlier
    /// transmit of that connection. Report what reached the socket with
    /// [`StreamEvent::Written`]: it is the back-pressure signal.
    pub fn poll_stream_transmit(&mut self) -> Option<StreamTransmit> {
        self.streams.driver_seen = true;
        self.route_stream_writes();
        let dscp = self.stream_dscp();
        self.streams.table.poll_transmit().map(|mut transmit| {
            transmit.dscp = dscp;
            transmit
        })
    }

    /// What the driver did: a listener bound or failed, a connection established or failed,
    /// bytes written, a connection closed or reset.
    ///
    /// # Errors
    ///
    /// An error of a connection's security layer.
    pub fn handle_stream_event(&mut self, now: Instant, event: StreamEvent) -> Result<()> {
        self.streams.driver_seen = true;
        self.pipeline_context.observe(now);
        let result = self.streams.table.handle_event(event);
        self.process_stream_notices(now);
        result
    }

    /// The driver accepted a connection from `remote` on `listener`, arriving on `local`.
    /// Returns the connection's id, or `None` when the engine does not take it: the driver
    /// closes the socket then.
    pub fn handle_stream_accepted(
        &mut self,
        now: Instant,
        listener: ListenerId,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Option<StreamId> {
        self.streams.driver_seen = true;
        self.pipeline_context.observe(now);
        if self.is_closed() {
            return None;
        }
        // A connection from a source the embedder's address policy refuses is not taken: the
        // driver closes the socket, and nothing it would carry reaches the ICE agent.
        if !self.address_allowed(remote, ice::AddressPurpose::InboundDatagramSource) {
            debug!("refused a connection on {listener} from {remote}: the address policy");
            return None;
        }
        let id = self.streams.table.accept(listener, local, remote);
        trace!("accepted {id:?} on {listener} from {remote}");
        if let Some(id) = id
            && let Some(transport) = self.streams.transport_of_listener(listener)
        {
            self.streams.connection_transport.insert(id, transport);
        }
        id
    }

    /// Bytes the driver read from a connection, in whatever piece the socket gave them.
    ///
    /// # Errors
    ///
    /// [`Error::ErrUnknownStream`]; the connection's stream is not of its framing or its
    /// layer failed (the connection is then reset).
    pub fn handle_stream_read(&mut self, now: Instant, id: StreamId, data: &[u8]) -> Result<()> {
        self.streams.driver_seen = true;
        self.pipeline_context.observe(now);
        let info = self.streams.table.info(id).ok_or(Error::ErrUnknownStream)?;
        let messages = match self.streams.table.read(id, data) {
            Ok(messages) => messages,
            Err(err) => {
                self.process_stream_notices(now);
                return Err(err);
            }
        };
        if info.tag == TURN {
            self.turn_messages(now, id, messages);
            self.process_stream_notices(now);
            return Ok(());
        }
        if info.tag == SRFLX {
            self.srflx_messages(now, id, messages);
            self.process_stream_notices(now);
            return Ok(());
        }
        if info.tag == TURN_DATA {
            self.turn_data_messages(now, id, messages);
            self.process_stream_notices(now);
            return Ok(());
        }
        if info.tag != ICE_TCP {
            return Ok(());
        }
        // ICE-TCP data from a source the embedder's address policy refuses (one it refused
        // after the connection was made): dropped, and the connection reset.
        if !self.address_allowed(info.remote, ice::AddressPurpose::InboundDatagramSource) {
            debug!(
                "{id}: data from {}: the address policy refuses the source, reset",
                info.remote
            );
            self.streams.table.reset(id);
            self.process_stream_notices(now);
            return Ok(());
        }
        let local = self.streams.agent_local(id, info.local);
        for message in messages {
            // A null packet (RFC 4571 section 2) carries nothing.
            let Some(&first) = message.first() else {
                continue;
            };
            let transport = tcp_context(local, info.remote);
            // The connection's transport; for one accepted on a port several transports
            // share, the one its first check names (RFC 8445 section 7.2.2).
            // Only what names its transport ties the connection to one: anything else on a
            // port several transports share (DTLS on a connection the peer reopened, RFC 6544
            // section 11.1) could be either's, and waits for a check to name it.
            let on = match self.streams.connection_transport.get(&id) {
                Some(on) => *on,
                None => match self
                    .pipeline_context
                    .transports
                    .route_named(&transport, &message)
                {
                    Some(on) => {
                        self.streams.connection_transport.insert(id, on);
                        on
                    }
                    None => {
                        debug!("{id}: a frame before a check names its transport: dropped");
                        self.streams.unroutable += 1;
                        continue;
                    }
                },
            };
            // Two lite agents: the peer's active candidate opened this connection for the
            // selected pair; the agent knows that peer by the candidate's address (port 9),
            // not by the connection's ephemeral port (RFC 6544 section 6.1).
            let transport = self
                .lite_pair_peer(on, id)
                .map_or(transport, |peer| tcp_context(local, peer));
            if !demultiplexable(first) {
                debug!("{id}: a frame that is neither STUN, DTLS nor RTP: framing lost, reset");
                self.streams.table.reset(id);
                self.with_transport(on, |pc| {
                    pc.ice_transport_mut().agent.handle_transport_error(
                        now,
                        transport,
                        TransportError::NotStun,
                    )
                });
                break;
            }
            let first_answer =
                self.streams.answered.insert(id) && info.origin == StreamOrigin::Connected;
            self.read_on_transport(
                on,
                TaggedBytesMut {
                    now,
                    transport,
                    message: BytesMut::from(&message[..]),
                },
            );
            // RFC 6544 section 7.1: on a connection this agent opened, a first answer that is
            // not STUN closes it (the agent has failed the pairs of that remote candidate).
            // Two lite agents send no connectivity check (RFC 8445 section 6.1.1): the first
            // thing the peer sends on the connection is DTLS, and that is no failed check.
            let lite_lite = {
                let agent = &self.ice_transport_of(on).agent;
                agent.is_lite() && agent.is_remote_lite()
            };
            if first_answer && first > 3 && !lite_lite {
                debug!("{id}: the first answer is not STUN, the connection is closed");
                self.streams.table.reset(id);
                break;
            }
        }
        self.process_stream_notices(now);
        Ok(())
    }

    /// The ICE username fragment the peer's checks address this connection by (RFC 8445
    /// section 7.2.2: a Binding request's USERNAME is `<this ufrag>:<the peer's>`). A driver
    /// that shares one UDP port or one ICE-TCP listening port between peer connections routes
    /// by it (`rtci-stream-driver`'s `UfragMux`); read it again after each local description,
    /// since an ICE restart changes it. During a restart the previous one stays in use until
    /// the restart completes.
    pub fn ice_username_fragment(&self) -> String {
        self.ice_transport()
            .agent
            .get_local_credentials()
            .ufrag
            .clone()
    }

    /// The ICE username fragment of every transport of the connection, the default one's
    /// first: a connection with sections outside a BUNDLE group has a transport, with its
    /// own ufrag, per section or group (RFC 9429 section 5.2.1). A driver that shares a port
    /// between peer connections registers each of them for this connection; the engine then
    /// gives what arrives on the shared port to the transport its checks name.
    pub fn ice_username_fragments(&self) -> Vec<String> {
        let default = self.pipeline_context.transports.default_id();
        let mut ids = self.pipeline_context.transports.ids();
        ids.sort_by_key(|id| *id != default);
        ids.into_iter()
            .map(|id| {
                self.ice_transport_of(id)
                    .agent
                    .get_local_credentials()
                    .ufrag
                    .clone()
            })
            .collect()
    }

    /// Requests the TCP candidates of the address of a UDP host candidate the application just
    /// added (`candidate_value`), or adds them again when they are bound already (a new ICE
    /// generation re-gathering the same addresses).
    /// The candidate is of the active transport (the default one, or the one
    /// [`Self::with_transport`] names), and so are its TCP candidates.
    pub(crate) fn gather_tcp_candidates(&mut self, candidate_value: &str) {
        if !self.streams.settings.tcp_candidates || self.is_closed() {
            return;
        }
        let on = self.pipeline_context.transports.active_id();
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        if candidate.candidate_type() != CandidateType::Host || candidate.network_type().is_tcp() {
            return;
        }
        let Ok(ip) = candidate.address().parse::<IpAddr>() else {
            return;
        };
        let accepted = self
            .ice_transport()
            .agent
            .get_local_candidates()
            .iter()
            .any(|c| c.addr() == candidate.addr() && !c.network_type().is_tcp());
        let network = if ip.is_ipv4() {
            NetworkType::Tcp4
        } else {
            NetworkType::Tcp6
        };
        let types = &self.setting_engine.candidates.ice_network_types;
        if !accepted || (!types.is_empty() && !types.contains(&network)) {
            return;
        }
        if let Some(gather) = self
            .streams
            .gathers
            .iter()
            .find(|g| g.transport == on && g.ip == ip)
        {
            let bound: Vec<(SocketAddr, TcpType)> = gather
                .listeners
                .iter()
                .filter_map(|l| l.bound.map(|a| (a, l.tcp_type)))
                .collect();
            let active = gather.active_added;
            for (addr, tcp_type) in bound {
                self.add_engine_tcp_candidate(on, addr, tcp_type);
                // A new ICE generation asks the STUN servers again (`srflx::EngineSrflx::add`).
                self.gather_srflx_tcp(on, addr, tcp_type);
            }
            if active {
                self.add_engine_tcp_candidate(
                    on,
                    SocketAddr::new(ip, ACTIVE_PORT),
                    TcpType::Active,
                );
            }
            return;
        }
        let any = SocketAddr::new(ip, 0);
        let mut listeners = vec![GatherListener {
            id: self
                .streams
                .table
                .listen(any, Framing::Rfc4571, ICE_TCP, false),
            tcp_type: TcpType::Passive,
            bound: None,
            failed: false,
        }];
        if self.streams.settings.simultaneous_open {
            listeners.push(GatherListener {
                id: self
                    .streams
                    .table
                    .listen(any, Framing::Rfc4571, ICE_TCP, true),
                tcp_type: TcpType::SimultaneousOpen,
                bound: None,
                failed: false,
            });
        }
        self.streams.gathers.push(TcpGather {
            transport: on,
            ip,
            listeners,
            active_added: false,
        });
    }

    /// The end-of-gathering sentinel of the default transport: held back while the engine's
    /// listeners are being bound for a driver that serves them, so their candidates are not
    /// refused (RFC 8838 section 13); given at once otherwise.
    pub(crate) fn finish_local_gathering_after_streams(&mut self) {
        if !self.defer_end_of_gathering() {
            self.release_unserved_tcp_listeners();
            self.finish_local_gathering();
        }
    }

    /// The end of candidates of the active transport came before the application first
    /// served the stream interface (no `poll_stream_command` or `handle_stream_*` yet): the
    /// engine cannot know a driver will bind its listeners, so the end of gathering does not
    /// wait for them, and a TCP candidate made once one is bound would follow the
    /// end-of-candidates indication, which RFC 8838 section 13 forbids ("an agent MUST NOT
    /// convey any more candidates after it has conveyed an end-of-candidates indication").
    /// Those listeners would listen for connections no candidate announces: they are
    /// released (a driver that polls later sees each `Listen` followed by its
    /// `StopListening`) and the application is told, at warn level, what to do instead. An
    /// ICE restart gathers them afresh.
    fn release_unserved_tcp_listeners(&mut self) {
        if self.streams.driver_seen {
            return;
        }
        let on = self.pipeline_context.transports.active_id();
        let unserved: Vec<ListenerId> = self
            .streams
            .gathers
            .iter()
            .filter(|g| g.transport == on)
            .flat_map(|g| g.listeners.iter().map(|l| l.id))
            .collect();
        if unserved.is_empty() {
            return;
        }
        log::warn!(
            "end of candidates before the stream interface was first served: the engine's TCP \
             candidates are not gathered ({} listener(s) released); poll `poll_stream_command` \
             before adding the end of candidates to have them (RFC 8838 section 13)",
            unserved.len()
        );
        for listener in unserved {
            self.streams.table.stop_listening(listener);
        }
        self.streams.gathers.retain(|g| g.transport != on);
    }

    /// Whether the end of gathering of the active transport waits for the engine's listeners
    /// and TURN allocations of that transport; it is then given once they are settled
    /// ([`Self::finish_deferred_gathering`]).
    pub(crate) fn defer_end_of_gathering(&mut self) -> bool {
        let on = self.pipeline_context.transports.active_id();
        let wait = self.streams.end_of_gathering_waits(on);
        if wait {
            self.streams.end_of_gathering_deferred.insert(on);
        }
        wait
    }

    /// Adds a candidate the engine gathered for `transport`: as the application's own on the
    /// default transport, through that transport's path on another one.
    pub(crate) fn add_engine_local_candidate(
        &mut self,
        transport: TransportId,
        value: &str,
        url: Option<&str>,
        relay_protocol: Option<RTCIceServerTransportProtocol>,
    ) -> Result<()> {
        if self
            .pipeline_context
            .transports
            .transport(transport)
            .is_none()
        {
            return Ok(());
        }
        // One path for every transport (mt-4): the candidate is the active transport's.
        self.with_transport(transport, |pc| {
            pc.add_ice_local_candidate(value, url, relay_protocol)
        })
    }

    fn add_engine_tcp_candidate(
        &mut self,
        transport: TransportId,
        addr: SocketAddr,
        tcp_type: TcpType,
    ) {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: addr.ip().to_string(),
                port: addr.port(),
                component: 1,
                ..Default::default()
            },
            tcp_type,
        }
        .new_candidate_host();
        let value = candidate
            .and_then(|c| crate::peer_connection::transport::RTCIceCandidate::from(&c).to_json())
            .map(|init| {
                init.candidate
                    .strip_prefix("candidate:")
                    .unwrap_or(&init.candidate)
                    .to_owned()
            });
        let value = match value {
            Ok(value) => value,
            Err(err) => {
                debug!("TCP candidate {addr} not made: {err}");
                return;
            }
        };
        match tcp_type {
            TcpType::Active => {
                self.streams.active.insert(addr.ip());
            }
            _ => {
                self.streams.bound.insert(addr);
            }
        }
        if let Err(err) = self.add_engine_local_candidate(transport, &value, None, None) {
            debug!("TCP candidate {addr} not added: {err}");
        }
    }

    fn process_stream_notices(&mut self, now: Instant) {
        while let Some(notice) = self.streams.table.poll_notice() {
            match notice {
                StreamNotice::Listening {
                    listener,
                    tag: ICE_TCP,
                    local,
                } => {
                    let mut add = vec![];
                    if let Some(gather) = self
                        .streams
                        .gathers
                        .iter_mut()
                        .find(|g| g.listeners.iter().any(|l| l.id == listener))
                    {
                        if let Some(l) = gather.listeners.iter_mut().find(|l| l.id == listener) {
                            l.bound = Some(local);
                            add.push((gather.transport, local, l.tcp_type));
                        }
                        if !gather.active_added {
                            gather.active_added = true;
                            add.push((
                                gather.transport,
                                SocketAddr::new(gather.ip, ACTIVE_PORT),
                                TcpType::Active,
                            ));
                        }
                    }
                    for (transport, addr, tcp_type) in add {
                        self.add_engine_tcp_candidate(transport, addr, tcp_type);
                        // Its server-reflexive candidates (RFC 6544 section 5.2).
                        self.gather_srflx_tcp(transport, addr, tcp_type);
                    }
                }
                StreamNotice::ListenFailed {
                    listener,
                    tag: ICE_TCP,
                    ..
                } => {
                    let mut active = None;
                    if let Some(gather) = self
                        .streams
                        .gathers
                        .iter_mut()
                        .find(|g| g.listeners.iter().any(|l| l.id == listener))
                    {
                        if let Some(l) = gather.listeners.iter_mut().find(|l| l.id == listener) {
                            l.failed = true;
                        }
                        // The active candidate needs no listener.
                        if !gather.active_added {
                            gather.active_added = true;
                            active =
                                Some((gather.transport, SocketAddr::new(gather.ip, ACTIVE_PORT)));
                        }
                    }
                    if let Some((transport, addr)) = active {
                        self.add_engine_tcp_candidate(transport, addr, TcpType::Active);
                    }
                }
                StreamNotice::ConnectFailed {
                    id,
                    tag: ICE_TCP,
                    local,
                    remote,
                } => {
                    // RFC 6544 section 7.1: the pair's check has failed.
                    let local = self.streams.agent_local(id, local);
                    self.streams.active_connections.remove(&id);
                    debug!("{id} from {local} to {remote} could not be established");
                    self.stream_transport_error(id, tcp_context(local, remote));
                }
                StreamNotice::Closed {
                    id,
                    tag: ICE_TCP,
                    local,
                    remote,
                    reset,
                } => {
                    let local = self.streams.agent_local(id, local);
                    self.streams.active_connections.remove(&id);
                    self.streams.answered.remove(&id);
                    debug!("{id} from {local} to {remote} ended (reset: {reset})");
                    // A check still waiting on it will not be answered there. A valid pair is
                    // left to consent: an active or simultaneous-open side reopens its
                    // connection with the next write (RFC 6544 section 11.1).
                    self.stream_transport_error(id, tcp_context(local, remote));
                }
                StreamNotice::Connected {
                    id,
                    tag: TURN,
                    local,
                    remote,
                } => self.turn_connected(now, id, local, remote),
                StreamNotice::ConnectFailed { id, tag: TURN, .. }
                | StreamNotice::Closed { id, tag: TURN, .. } => self.turn_connection_ended(now, id),
                StreamNotice::ConnectFailed { id, tag: SRFLX, .. }
                | StreamNotice::Closed { id, tag: SRFLX, .. } => {
                    self.srflx_connection_ended(now, id)
                }
                StreamNotice::Connected {
                    id,
                    tag: TURN_DATA,
                    local,
                    ..
                } => self.turn_data_connected(now, id, local),
                StreamNotice::ConnectFailed {
                    id, tag: TURN_DATA, ..
                }
                | StreamNotice::Closed {
                    id, tag: TURN_DATA, ..
                } => self.turn_data_ended(now, id),
                StreamNotice::Resolved { query, addresses } => {
                    self.name_resolved(query, None, &addresses)
                }
                StreamNotice::ResolvedFamily {
                    query,
                    ipv6,
                    addresses,
                } => self.name_resolved(query, Some(ipv6), &addresses),
                StreamNotice::ResolvedRecords { query, records } => {
                    self.records_resolved(query, &records)
                }
                _ => {}
            }
        }
        self.finish_deferred_gathering();
    }

    /// Records the engine asked the driver for: a TURN link's or a server-reflexive probe's.
    fn records_resolved(&mut self, query: u64, records: &[shared::stream::DnsRecord]) {
        if !self.turn_records(query, records) {
            self.srflx_records(query, records);
        }
    }

    /// A name the engine asked the driver for: a server-reflexive probe's or a TURN link's.
    fn name_resolved(&mut self, query: u64, ipv6: Option<bool>, addresses: &[SocketAddr]) {
        if !self.srflx_resolved(query, ipv6, addresses) {
            self.turn_resolved(query, ipv6, addresses);
        }
    }

    /// RFC 6544 section 7.1: a connection that failed or ended fails the checks waiting on it,
    /// on the agent of its transport (every agent when it is not known yet: a pair of another
    /// agent does not match the 5-tuple).
    fn stream_transport_error(&mut self, id: StreamId, transport: TransportContext) {
        let now = self.pipeline_context.now;
        let on = match self.streams.connection_transport.remove(&id) {
            Some(on) => vec![on],
            None => self.pipeline_context.transports.ids(),
        };
        for t in on {
            self.with_transport(t, |pc| {
                pc.ice_transport_mut().agent.handle_transport_error(
                    now,
                    transport,
                    TransportError::ConnectionFailed,
                )
            });
        }
    }

    /// The ends of gathering held back for the engine's listeners and TURN allocations, each
    /// once those of its transport are settled.
    pub(crate) fn finish_deferred_gathering(&mut self) {
        let ready: Vec<TransportId> = self
            .streams
            .end_of_gathering_deferred
            .iter()
            .copied()
            .filter(|t| !self.streams.end_of_gathering_waits(*t))
            .collect();
        for t in ready {
            self.streams.end_of_gathering_deferred.remove(&t);
            if self.pipeline_context.transports.transport(t).is_none() {
                continue;
            }
            // `finish_local_gathering` does nothing for a transport that has finished.
            self.with_transport(t, |pc| pc.finish_local_gathering());
        }
    }

    /// Stops the listeners and closes the connections of transports a description removed
    /// (RFC 9143 section 7: a bundled section's own transport is released).
    pub(crate) fn release_removed_transports(&mut self) {
        let ids = self.pipeline_context.transports.ids();
        let gone: Vec<ListenerId> = self
            .streams
            .gathers
            .iter()
            .filter(|g| !ids.contains(&g.transport))
            .flat_map(|g| g.listeners.iter().map(|l| l.id))
            .collect();
        for listener in gone {
            self.streams.table.stop_listening(listener);
        }
        self.streams.gathers.retain(|g| ids.contains(&g.transport));
        self.streams
            .end_of_gathering_deferred
            .retain(|t| ids.contains(t));
        let closed: Vec<StreamId> = self
            .streams
            .connection_transport
            .iter()
            .filter(|(_, t)| !ids.contains(t))
            .map(|(id, _)| *id)
            .collect();
        for id in closed {
            self.streams.connection_transport.remove(&id);
            self.streams.table.close(id);
        }
        self.release_removed_turn_links();
    }

    /// Moves the queued datagrams for the engine's TCP candidates onto their connections.
    pub(crate) fn route_stream_writes(&mut self) {
        if self.streams.active.is_empty()
            && self.streams.bound.is_empty()
            && self.streams.turn.relays().is_empty()
        {
            return;
        }
        self.flush_writes();
        let mut kept = std::collections::VecDeque::new();
        while let Some(msg) = self.pipeline_context.write_outs.pop_front() {
            if let Some(msg) = self.route_stream_write(msg) {
                kept.push_back(msg);
            }
        }
        self.pipeline_context.write_outs = kept;
    }

    /// Takes `msg` when it leaves from an engine TCP candidate (and returns `None`), else
    /// returns it for `poll_write`.
    pub(crate) fn route_stream_write(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        let local = msg.transport.local_addr;
        if msg.transport.transport_protocol == TransportProtocol::UDP
            && let Some(index) = self.streams.turn.link_of_relay(local)
        {
            // From a relayed candidate the engine allocated: through its TURN link.
            self.send_via_turn(index, msg);
            return None;
        }
        // From a relayed TCP candidate: onto the data connection to its peer (RFC 6062).
        let msg = self.turn_tcp_write(msg)?;
        // Not known to come from one transport: the one its check names, or that knows the
        // peer.
        let on = self
            .pipeline_context
            .transports
            .route_outbound(&msg.transport, &msg.message)
            .unwrap_or_else(|| self.pipeline_context.transports.default_id());
        self.take_tcp_write(on, msg)
    }

    /// Takes `msg`, which the agent of `on` sends, when it leaves from an engine TCP
    /// candidate: onto the connection of that transport (opened when an active or
    /// simultaneous-open candidate needs one). Returns it otherwise.
    pub(crate) fn take_tcp_write(
        &mut self,
        on: TransportId,
        msg: TaggedBytesMut,
    ) -> Option<TaggedBytesMut> {
        let local = msg.transport.local_addr;
        if msg.transport.transport_protocol != TransportProtocol::TCP
            || !self.streams.manages(local)
        {
            return Some(msg);
        }
        let remote = msg.transport.peer_addr;
        let named_only = msg.message.first().is_none_or(|first| *first > 3)
            && self.pipeline_context.transports.ids().len() > 1;
        let id = match self
            .streams
            .connection_for(local, remote, on, named_only)
            .or_else(|| self.lite_pair_connection(on, local, remote))
        {
            Some(id) => Some(id),
            None if local.port() == ACTIVE_PORT && self.streams.active.contains(&local.ip()) => {
                // RFC 6544 section 7.1: an active candidate opens its connection from that
                // interface, on an ephemeral port, when its check is sent.
                self.streams.connect_active(on, local.ip(), remote)
            }
            None if self
                .streams
                .gathers
                .iter()
                .flat_map(|g| g.listeners.iter())
                .any(|l| l.tcp_type == TcpType::SimultaneousOpen && l.bound == Some(local)) =>
            {
                // A simultaneous-open candidate connects from its own port (RFC 6544
                // section 7.1), beside its listener.
                let id = self
                    .streams
                    .table
                    .connect(local, remote, Framing::Rfc4571, ICE_TCP, true, None)
                    .ok();
                if let Some(id) = id {
                    self.streams.connection_transport.insert(id, on);
                }
                id
            }
            // A passive candidate only answers on connections it accepted.
            None => None,
        };
        // A check or its answer from this transport's agent names the connection its own.
        if let Some(id) = id
            && !named_only
            && !self.streams.connection_transport.contains_key(&id)
            && self.pipeline_context.transports.ids().len() > 1
        {
            self.streams.connection_transport.insert(id, on);
        }
        let sent =
            id.is_some_and(|id| matches!(self.streams.table.send(id, &msg.message), Ok(true)));
        if !sent {
            self.streams.unroutable += 1;
            trace!("no TCP connection takes a datagram from {local} to {remote}");
        }
        None
    }

    /// RFC 6544 section 8: once ICE has completed, the connections that do not carry the
    /// selected pair are closed, for each transport on its own. A connection whose transport
    /// is not known yet (accepted, nothing read) is closed once every transport has completed.
    ///
    /// The connection of the path an ICE restart replaced stays open while the agent still
    /// takes data on it (`Agent::retired_media_path`, a few seconds after the new pair was
    /// selected): the peer selects on its own and goes on sending on that path until it does
    /// (RFC 8445 section 12.2: be "prepared to receive data on any of the candidates provided
    /// in the most recent candidate exchange"). Closed at once, what it had sent and the
    /// packets it sends meanwhile are lost (seen as one RTP packet lost per SRTP re-keying
    /// when the call ran over ICE-TCP).
    fn close_unused_tcp_connections(&mut self) {
        if !self.streams.settings.close_unused_connections || self.is_closed() {
            return;
        }
        let ids = self.pipeline_context.transports.ids();
        let mut completed: Vec<(TransportId, Vec<StreamId>)> = vec![];
        for t in &ids {
            let agent = &self.ice_transport_of(*t).agent;
            // Completed: a pair is selected (RFC 8445 section 6.1.2.1), and the agent has not
            // failed.
            if agent.get_selected_candidate_pair().is_none()
                || agent.state() == ice::state::ConnectionState::Failed
                // Two lite agents: the pair is the controlling agent's, still to come; a
                // connection it opened in parallel waits for it (RFC 6544 section 6.1).
                || agent.awaits_lite_update()
            {
                continue;
            }
            let Some(path) = agent.media_path() else {
                continue;
            };
            let mut keep = vec![];
            if path.transport_protocol == TransportProtocol::TCP {
                // The selected pair's connection is gone: the peer may be reopening it (RFC
                // 6544 section 11.1), on a connection this side has not tied to the pair yet.
                // Nothing of this transport is closed until the pair has one again.
                match self
                    .streams
                    .connection_for(path.local_addr, path.peer_addr, *t, false)
                    .or_else(|| self.lite_pair_connection(*t, path.local_addr, path.peer_addr))
                {
                    Some(id) => keep.push(id),
                    None => continue,
                }
            }
            if let Some(retired) = agent
                .retired_media_path()
                .filter(|retired| retired.transport_protocol == TransportProtocol::TCP)
                && let Some(id) =
                    self.streams
                        .connection_for(retired.local_addr, retired.peer_addr, *t, false)
            {
                keep.push(id);
            }
            completed.push((*t, keep));
        }
        if completed.is_empty() {
            return;
        }
        let all = completed.len() == ids.len();
        let unused: Vec<StreamId> = self
            .streams
            .table
            .connections()
            .filter(|c| c.tag == ICE_TCP && c.state != StreamState::Closing)
            .filter(|c| match self.streams.connection_transport.get(&c.id) {
                Some(t) => completed
                    .iter()
                    .any(|(done, keep)| done == t && !keep.contains(&c.id)),
                None => all && !completed.iter().any(|(_, keep)| keep.contains(&c.id)),
            })
            .map(|c| c.id)
            .collect();
        for id in unused {
            debug!("{id} carries no selected pair: closed");
            self.streams.table.close(id);
        }
    }

    /// Two lite agents, the selected pair of `on` from this agent's passive TCP candidate to
    /// the peer's active one: the connection the peer opened for it (RFC 6544 section 6.1),
    /// and the addresses the agent knows the pair by (the peer by its active candidate's,
    /// port 9). It is a connection accepted on the pair's local candidate from the active
    /// candidate's IP address, from any port ("from any of the IP addresses the offerer
    /// listed"); no connectivity check names it, since two lite agents send none.
    fn lite_pair(&self, on: TransportId) -> Option<(StreamId, SocketAddr, SocketAddr)> {
        let agent = &self.ice_transport_of(on).agent;
        if !(agent.is_lite() && agent.is_remote_lite()) {
            return None;
        }
        let (local, remote) = agent.get_selected_candidate_pair()?;
        if local.tcp_type() != TcpType::Passive || remote.tcp_type() != TcpType::Active {
            return None;
        }
        let (local, peer) = (local.base_addr(), remote.addr());
        let mut found = None;
        for c in self.streams.table.connections() {
            if c.tag != ICE_TCP
                || c.state == StreamState::Closing
                || !matches!(c.origin, StreamOrigin::Accepted(_))
                || c.local != local
                || c.remote.ip() != peer.ip()
                || self
                    .streams
                    .connection_transport
                    .get(&c.id)
                    .is_some_and(|t| *t != on)
            {
                continue;
            }
            if c.state == StreamState::Open {
                return Some((c.id, local, peer));
            }
            found.get_or_insert((c.id, local, peer));
        }
        found
    }

    /// [`Self::lite_pair`]'s connection, when the agent of `on` sends from `local` to `peer`.
    fn lite_pair_connection(
        &self,
        on: TransportId,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Option<StreamId> {
        self.lite_pair(on)
            .filter(|(_, l, p)| *l == local && *p == peer)
            .map(|(id, _, _)| id)
    }

    /// [`Self::lite_pair`]'s peer address, when `id` is its connection.
    fn lite_pair_peer(&self, on: TransportId, id: StreamId) -> Option<SocketAddr> {
        self.lite_pair(on)
            .filter(|(pair_id, _, _)| *pair_id == id)
            .map(|(_, _, peer)| peer)
    }

    /// RFC 6544 section 6.1: "If both agents are using the lite mode and if the offerer uses
    /// the a=setup:active attribute [RFC4145] in the new offer, the offerer MAY initiate the
    /// TCP connection on the selected pair in parallel with the new offer". The TCP role is
    /// the pair's (`a=setup` is DTLS's in WebRTC, RFC 8842): the side whose candidate of the
    /// selected pair is active opens its connection, before anything is sent on it, once for
    /// each pair. The controlling agent does at once, in parallel with its updated offer; the
    /// controlled one once its pair is final (the update taken, or a single pair).
    fn open_lite_tcp_connections(&mut self) {
        for on in self.pipeline_context.transports.ids() {
            let agent = &self.ice_transport_of(on).agent;
            if !(agent.is_lite() && agent.is_remote_lite()) || agent.awaits_lite_update() {
                continue;
            }
            let Some((local, remote)) = agent.get_selected_candidate_pair() else {
                continue;
            };
            if local.tcp_type() != TcpType::Active || remote.tcp_type() != TcpType::Passive {
                continue;
            }
            let (local, remote) = (local.base_addr(), remote.addr());
            if !self.streams.manages(local)
                || !self.streams.lite_connects.insert((on, local, remote))
                || self
                    .streams
                    .connection_for(local, remote, on, false)
                    .is_some()
            {
                continue;
            }
            debug!("lite-lite: connecting the selected pair {local} -> {remote}");
            self.streams.connect_active(on, local.ip(), remote);
        }
    }

    /// RFC 6544 section 6.1, the answerer of two lite agents, once the updated offer was
    /// applied and its pair selected: "If the answerer receives the new offer matching the
    /// candidate pair where a connection was already created in parallel with the new offer,
    /// it MUST accept the offer and respond to it while keeping the already-created
    /// connection. If the connection that was created in parallel with the new offer does
    /// not match the candidate pair in the new offer, the connection MUST be closed, and ICE
    /// restart SHOULD be performed." A connection that matches the pair stays and any other
    /// the peer opened is closed; connections of which none matches are closed and ICE
    /// restarts (`restart_ice`). Until a connection is accepted (the update came first) the
    /// transport waits; a pair of another kind (UDP, or this side's candidate active) has no
    /// parallel connection to match.
    fn settle_lite_tcp_updates(&mut self) {
        if self.streams.lite_updates.is_empty() {
            return;
        }
        let pending: Vec<TransportId> = self.streams.lite_updates.iter().copied().collect();
        for on in pending {
            if !self.pipeline_context.transports.ids().contains(&on) {
                self.streams.lite_updates.remove(&on);
                continue;
            }
            let agent = &self.ice_transport_of(on).agent;
            let Some((local, remote)) = agent.get_selected_candidate_pair() else {
                continue;
            };
            if local.tcp_type() != TcpType::Passive || remote.tcp_type() != TcpType::Active {
                self.streams.lite_updates.remove(&on);
                continue;
            }
            let kept = self.lite_pair(on).map(|(id, _, _)| id);
            let others: Vec<StreamId> = self
                .streams
                .table
                .connections()
                .filter(|c| {
                    c.tag == ICE_TCP
                        && c.state != StreamState::Closing
                        && matches!(c.origin, StreamOrigin::Accepted(_))
                        && Some(c.id) != kept
                        && self
                            .streams
                            .connection_transport
                            .get(&c.id)
                            .is_none_or(|t| *t == on)
                })
                .map(|c| c.id)
                .collect();
            if kept.is_none() && others.is_empty() {
                continue;
            }
            self.streams.lite_updates.remove(&on);
            for id in &others {
                debug!("lite-lite: {id} does not match the pair of the new offer: closed");
                self.streams.table.close(*id);
            }
            if kept.is_none() {
                debug!("lite-lite: no connection matches the pair of the new offer: ICE restart");
                self.restart_ice();
            }
        }
    }

    /// `close()`: what is queued goes out, then every connection closes and every listener
    /// stops.
    pub(crate) fn close_streams(&mut self) {
        self.route_stream_writes();
        let ids: Vec<StreamId> = self.streams.table.connections().map(|c| c.id).collect();
        for id in ids {
            self.streams.table.close(id);
        }
        let listeners: Vec<ListenerId> = self.streams.table.listeners().map(|l| l.0).collect();
        for listener in listeners {
            self.streams.table.stop_listening(listener);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::RTCPeerConnectionBuilder;

    fn binding_request(username: &str) -> Vec<u8> {
        let mut attribute = vec![0x00, 0x06];
        attribute.extend_from_slice(&(username.len() as u16).to_be_bytes());
        attribute.extend_from_slice(username.as_bytes());
        attribute.resize(attribute.len().next_multiple_of(4), 0);
        let mut message = vec![0x00, 0x01];
        message.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
        message.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        message.extend_from_slice(&[7; 12]);
        message.extend_from_slice(&attribute);
        message
    }

    fn framed(message: &[u8]) -> Vec<u8> {
        Framing::Rfc4571.encode(message).unwrap()
    }

    /// Two transports whose passive candidates share one port (a driver's shared listener):
    /// a connection accepted there that brings DTLS before any check (an active side
    /// reopening it, RFC 6544 section 11.1) is tied to no transport by a guess from the
    /// peer's address; the check that follows names its transport (RFC 8445 section 7.2.2).
    #[test]
    fn a_frame_before_a_check_on_a_shared_port_ties_the_connection_to_no_transport() {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
                    .with_unique_transport_credentials(true)
                    .build(),
            )
            .build(now)
            .expect("a default peer connection builds");
        let default = pc.pipeline_context.transports.default_id();
        let other = pc.add_transport().expect("a second transport");
        let shared: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        for id in [default, other] {
            pc.with_transport(id, |pc| {
                let candidate = ice::candidate::unmarshal_candidate(
                    "candidate:1 1 tcp 2128609279 10.0.0.1 7000 typ host tcptype passive",
                )
                .unwrap();
                pc.ice_transport_mut()
                    .add_local_candidate(candidate)
                    .expect("the shared passive candidate is added")
            });
        }
        let listener = pc
            .streams
            .table
            .listen(shared, Framing::Rfc4571, ICE_TCP, false);
        pc.handle_stream_event(
            now,
            StreamEvent::Listening {
                listener,
                local: shared,
            },
        )
        .unwrap();
        let peer: SocketAddr = "10.0.0.2:50000".parse().unwrap();
        let id = pc
            .handle_stream_accepted(now, listener, shared, peer)
            .expect("the connection is taken");

        pc.handle_stream_read(now, id, &framed(&[0x16, 0xfe, 0xfd, 0, 0]))
            .unwrap();
        assert_eq!(
            pc.streams.connection_transport.get(&id),
            None,
            "DTLS names no transport"
        );
        assert_eq!(pc.streams.unroutable, 1, "and is given to none");

        let ufrag = pc
            .ice_transport_of(other)
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        pc.handle_stream_read(now, id, &framed(&binding_request(&format!("{ufrag}:peer"))))
            .unwrap();
        assert_eq!(pc.streams.connection_transport.get(&id), Some(&other));
    }

    /// The same shared passive port with the default, shared ICE credentials: the receiver's
    /// ufrag of a check names both transports, so what ties a connection to one is the rest of
    /// the USERNAME (a remote with credentials of its own per transport), or the tie-breaker
    /// the remote agent's earlier checks were routed with (rule 4 of `TransportSet::route`);
    /// a check neither settles ties the connection to no transport.
    #[test]
    fn a_shared_passive_port_with_shared_credentials_is_tied_by_the_full_username_or_tie_breaker() {
        let now = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(now)
            .expect("a default peer connection builds");
        let default = pc.pipeline_context.transports.default_id();
        let other = pc.add_transport().expect("a second transport");
        let shared: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        for id in [default, other] {
            pc.with_transport(id, |pc| {
                let candidate = ice::candidate::unmarshal_candidate(
                    "candidate:1 1 tcp 2128609279 10.0.0.1 7000 typ host tcptype passive",
                )
                .unwrap();
                pc.ice_transport_mut()
                    .add_local_candidate(candidate)
                    .expect("the shared passive candidate is added")
            });
        }
        let ufrag = pc
            .ice_transport_of(default)
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        assert_eq!(
            ufrag,
            pc.ice_transport_of(other)
                .agent
                .get_local_credentials()
                .ufrag
        );
        let listener = pc
            .streams
            .table
            .listen(shared, Framing::Rfc4571, ICE_TCP, false);
        pc.handle_stream_event(
            now,
            StreamEvent::Listening {
                listener,
                local: shared,
            },
        )
        .unwrap();
        let accept = |pc: &mut RTCPeerConnection, port: u16| {
            let peer: SocketAddr = format!("10.0.0.2:{port}").parse().unwrap();
            pc.handle_stream_accepted(now, listener, shared, peer)
                .expect("the connection is taken")
        };
        let check = |sender: &str, tie_breaker: Option<u64>| {
            let mut message = binding_request(&format!("{ufrag}:{sender}"));
            if let Some(tie_breaker) = tie_breaker {
                message.extend_from_slice(&[0x80, 0x2a, 0x00, 0x08]);
                message.extend_from_slice(&tie_breaker.to_be_bytes());
                let length = u16::from_be_bytes([message[2], message[3]]) + 12;
                message[2..4].copy_from_slice(&length.to_be_bytes());
            }
            framed(&message)
        };

        // Nothing tells the two apart: the connection is tied to none.
        let first = accept(&mut pc, 50000);
        pc.handle_stream_read(now, first, &check("rem", None))
            .unwrap();
        assert_eq!(pc.streams.connection_transport.get(&first), None);

        // A remote with credentials of its own per transport: the sender's part names one.
        for (id, remote) in [(default, "remA"), (other, "remB")] {
            pc.with_transport(id, |pc| {
                pc.ice_transport_mut()
                    .agent
                    .set_remote_credentials(remote.to_owned(), "p".repeat(22))
                    .expect("remote credentials")
            });
        }
        let second = accept(&mut pc, 50001);
        pc.handle_stream_read(now, second, &check("remB", Some(42)))
            .unwrap();
        assert_eq!(pc.streams.connection_transport.get(&second), Some(&other));

        // The remote shares its credentials too; a datagram check that was settled (by the
        // remote candidate it came from) taught the transport the remote agent's tie-breaker,
        // and a connection whose first check carries it is that transport's.
        for id in [default, other] {
            pc.with_transport(id, |pc| {
                pc.ice_transport_mut()
                    .agent
                    .set_remote_credentials("rem".to_owned(), "p".repeat(22))
                    .expect("remote credentials")
            });
        }
        pc.with_transport(default, |pc| {
            let candidate = ice::candidate::unmarshal_candidate(
                "candidate:2 1 udp 2130706431 10.0.0.2 6000 typ host",
            )
            .unwrap();
            pc.ice_transport_mut()
                .add_remote_candidate(candidate)
                .expect("the remote candidate is added")
        });
        for id in [default, other] {
            pc.with_transport(id, |pc| {
                let candidate = ice::candidate::unmarshal_candidate(
                    "candidate:3 1 udp 2130706431 10.0.0.1 7000 typ host",
                )
                .unwrap();
                pc.ice_transport_mut()
                    .add_local_candidate(candidate)
                    .expect("the shared UDP candidate is added")
            });
        }
        let udp = TransportContext {
            local_addr: shared,
            peer_addr: "10.0.0.2:6000".parse().unwrap(),
            ..Default::default()
        };
        let mut datagram = check("rem", Some(7));
        datagram.drain(..2);
        assert_eq!(
            pc.pipeline_context.transports.route(&udp, &datagram),
            Some(default)
        );
        let third = accept(&mut pc, 50002);
        pc.handle_stream_read(now, third, &check("rem", Some(7)))
            .unwrap();
        assert_eq!(pc.streams.connection_transport.get(&third), Some(&default));
    }
}
