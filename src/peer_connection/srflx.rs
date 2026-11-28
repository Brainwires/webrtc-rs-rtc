//! Server-reflexive candidates gathered by the engine (RFC 8445 section 5.1.1.2): a STUN
//! Binding request to each `stun:` / `stuns:` server of the configuration, from each host
//! candidate's base, on each transport (RFC 9429 section 5.2.1).
//!
//! - Over UDP, from every UDP host candidate the application adds: the request leaves through
//!   `poll_write` from the candidate's address and the response is taken out of `handle_read`
//!   before ICE sees it (by its transaction id). Retransmissions follow RFC 8489 section
//!   6.2.1 (`rtci_stun::client`).
//! - Over TCP and TLS (`stun:` and `stuns:`, RFC 7064), from the engine's passive and
//!   simultaneous-open ICE-TCP candidates: a connection from the listener's own port
//!   (`reuse_address`, RFC 6544 Appendix B) carries one Binding request, sent once and
//!   failed after Ti (RFC 8489 section 6.2.2); over TLS the server's certificate is checked
//!   as for TURN (RFC 8489 section 6.2.3, ALPN `stun.nat-discovery`, RFC 7443). The mapped
//!   address is a server-reflexive passive or simultaneous-open candidate, and its address
//!   on port 9 a server-reflexive active one (RFC 6544 section 5.2).
//!
//! A server's name is resolved through the driver ([`StreamCommand::Resolve`]); the
//! addresses race with Happy Eyeballs (RFC 8305, RFC 8656 section 3.9), a Binding
//! transaction per address started every Connection Attempt Delay, the first answer winning.
//! New transactions start no faster than one every Ta (RFC 8445 section 5.1.1.2). The end of
//! gathering waits for every probe to be answered or to fail.
//!
//! [`StreamCommand::Resolve`]: shared::stream::StreamCommand::Resolve

use super::RTCPeerConnection;
use super::servers_in_force::{ServersInForce, same_url};
use super::streams::{SRFLX, tcp_context};
use super::turn_tls::TlsLayer;
use crate::peer_connection::handler::transport_set::TransportId;
use bytes::BytesMut;
use ice::candidate::CandidateConfig;
use ice::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use ice::tcp_type::TcpType;
use ice::url::{SchemeType, Url};
use log::debug;
use sansio::Protocol;
use shared::stream::happy_eyeballs::{CONNECTION_ATTEMPT_DELAY, HappyEyeballs, sort_addresses};
use shared::stream::{Framing, StreamId, StreamLayer};
use shared::{TaggedBytesMut, TransportProtocol};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::agent::StunEvent;
use stun::client::{Client, ClientBuilder, TaggedMessage};
use stun::message::{BINDING_REQUEST, CLASS_SUCCESS_RESPONSE, Getter, Message, Setter};
use stun::xoraddr::XorMappedAddress;

/// The `stun:` / `stuns:` URLs of `urls`.
fn stun_servers(urls: &[Url]) -> Vec<Url> {
    urls.iter()
        .filter(|u| matches!(u.scheme, SchemeType::Stun | SchemeType::Stuns))
        .cloned()
        .collect()
}

/// The ALPN protocol id of STUN NAT discovery over TLS (RFC 7443 section 3).
pub const ALPN_STUN_NAT_DISCOVERY: &[u8] = b"stun.nat-discovery";

/// RFC 8445 section 14.2: the default pacing of gathering transactions.
const TA: Duration = Duration::from_millis(50);

/// The port an active TCP candidate is signalled with (RFC 6544 section 4.5).
const ACTIVE_PORT: u16 = 9;

/// Who gathers server-reflexive candidates. See
/// `SettingEngineBuilder::with_server_reflexive_gathering`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ReflexiveGathering {
    /// The engine, from the configuration's `stun:` / `stuns:` servers (RFC 8445 section
    /// 5.1.1.2: gathering is implemented and on unless configured off). A base for which the
    /// application adds a server-reflexive candidate itself is left to it.
    #[default]
    Engine,
    /// The application: the engine sends no Binding request to a server.
    Application,
}

/// What a probe's mapped address becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// A UDP host candidate's address.
    Udp,
    /// A passive or simultaneous-open ICE-TCP listener's address.
    Tcp(TcpType),
}

/// One Binding transaction to one address of the server.
struct Attempt {
    server: SocketAddr,
    client: Client,
    /// The request's transaction id.
    transaction: [u8; 12],
    /// The connection, over TCP / TLS.
    stream: Option<StreamId>,
    /// Over TCP / TLS: this is the new connection opened after one whose transaction failed
    /// (RFC 8489 section 6.2.2: RST, then a new connection), so a second failure fails it.
    retried: bool,
}

/// How an attempt's transaction ended.
enum Outcome {
    /// A success response with the reflexive address.
    Mapped(SocketAddr),
    /// No response within the transaction's time (Ti over TCP).
    TimedOut,
    /// An error response, a response without an address, or another end.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeState {
    Pending,
    /// NAPTR / SRV records are being looked up (a URI without a port, RFC 8489 section 8).
    Discovering(u64),
    Resolving(u64),
    Racing,
    Done,
}

/// One server-reflexive candidate on its way: a base, a server, a transport.
struct Probe {
    transport: TransportId,
    base: SocketAddr,
    kind: Base,
    url: Url,
    tls: bool,
    state: ProbeState,
    race: Option<HappyEyeballs>,
    attempts: Vec<Attempt>,
    /// The name's query, while its answers may still come.
    query: Option<u64>,
    /// The address the server reported.
    mapped: Option<SocketAddr>,
    /// The SRV discovery of a server whose URI gives no port.
    discovery: Option<crate::peer_connection::dns_discovery::Discovery>,
    /// The ICE generation (local ufrag) the probe gathers for: a new one asks again.
    ufrag: String,
    /// Over TCP / TLS, the Binding connection that answered and the server's address: kept
    /// open while the mapped address may be used (RFC 8489 section 6.2.2), until ICE of its
    /// transport has completed.
    kept: Option<(StreamId, SocketAddr)>,
    /// The last error response a server address gave (code, reason), for `icecandidateerror`.
    error: Option<(u16, String)>,
}

impl Probe {
    fn url_string(&self) -> String {
        let host = if self.url.host.contains(':') {
            format!("[{}]", self.url.host)
        } else {
            self.url.host.clone()
        };
        let scheme = if self.tls { "stuns" } else { "stun" };
        format!("{scheme}:{host}:{}", self.url.port)
    }
}

/// The engine's server-reflexive gathering.
pub(crate) struct EngineSrflx {
    /// The `stun:` / `stuns:` servers, as each ICE generation took them
    /// (`RTCPeerConnection::set_configuration` gives the next generations a new list).
    servers: ServersInForce,
    pub(crate) mode: ReflexiveGathering,
    probes: Vec<Probe>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Bases the application gathers server-reflexive candidates for itself.
    application_bases: Vec<SocketAddr>,
    /// When the last transaction started (Ta pacing).
    last_start: Option<Instant>,
    /// Mapped addresses announced: transport, address, base kind, ICE ufrag.
    announced: Vec<(TransportId, SocketAddr, Base, String)>,
    /// Servers gathering rejected and has not reported yet (`stuns:` with an IP address).
    rejected: Vec<String>,
}

/// RFC 8489 section 8.1: "A 'stuns' URI containing an IP address MUST be rejected" (the
/// server's certificate cannot be checked against a name; "a future STUN extension or usage
/// may relax this requirement, provided it demonstrates how to authenticate the STUN server").
fn rejected_by_rfc8489(url: &Url) -> bool {
    url.scheme == SchemeType::Stuns && url.host.parse::<IpAddr>().is_ok()
}

impl EngineSrflx {
    pub(crate) fn new(
        urls: &[Url],
        mode: ReflexiveGathering,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) -> Self {
        let servers = ServersInForce::new(stun_servers(urls));
        let tls_config = tls.map(|config| {
            let mut config = (*config).clone();
            config.alpn_protocols = vec![ALPN_STUN_NAT_DISCOVERY.to_vec()];
            Arc::new(config)
        });
        Self {
            servers,
            mode,
            probes: vec![],
            tls_config,
            application_bases: vec![],
            last_start: None,
            announced: vec![],
            rejected: vec![],
        }
    }

    /// The configuration's new servers: the ICE generations that begin from now on gather
    /// from them (W3C webrtc-pc "set the configuration", RFC 9429 section 4.1.18).
    pub(crate) fn set_servers(&mut self, urls: &[Url]) {
        self.servers.set(stun_servers(urls));
    }

    /// Whether a probe of `transport` is still on its way. A name waits for the driver only
    /// when one serves the stream interface (`resolving_counts`).
    pub(crate) fn pending(&self, transport: TransportId, resolving_counts: bool) -> bool {
        self.probes.iter().any(|p| {
            p.transport == transport
                && match p.state {
                    ProbeState::Pending | ProbeState::Racing => true,
                    ProbeState::Resolving(_) | ProbeState::Discovering(_) => resolving_counts,
                    ProbeState::Done => false,
                }
        })
    }

    /// Probes from `base` on `transport` for the ICE generation `ufrag`, one per server;
    /// returns what earlier probes of the same generation found. A new generation (an ICE
    /// restart) asks each server again: the NAT's mapping may have changed with the path that
    /// made the restart necessary, so a cached address is not announced for it.
    fn add(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        kind: Base,
        ufrag: &str,
    ) -> Vec<(SocketAddr, String)> {
        let mut found = vec![];
        if self.mode != ReflexiveGathering::Engine || self.application_bases.contains(&base) {
            return found;
        }
        let (servers, new_phase) = self.servers.for_generation(transport, ufrag);
        if new_phase {
            // A server of an earlier list that this generation does not take: its probes of
            // the earlier generation end, so that a late answer is not announced for this one.
            for p in self.probes.iter_mut().filter(|p| {
                p.transport == transport
                    && p.ufrag != ufrag
                    && !servers.iter().any(|u| same_url(u, &p.url))
            }) {
                p.state = ProbeState::Done;
                p.attempts.clear();
                p.race = None;
            }
        }
        for url in &servers {
            if rejected_by_rfc8489(url) {
                let text = url.to_string();
                if !self.rejected.contains(&text) {
                    self.rejected.push(text);
                }
                continue;
            }
            let tls = url.scheme == SchemeType::Stuns;
            // `stuns:` is TLS over TCP (RFC 7064); STUN over DTLS is not run here.
            if tls && kind == Base::Udp {
                continue;
            }
            if let Some(p) = self.probes.iter_mut().find(|p| {
                p.transport == transport && p.base == base && p.url.to_string() == url.to_string()
            }) {
                if p.ufrag == ufrag {
                    if let Some(mapped) = p.mapped {
                        found.push((mapped, p.url_string()));
                    }
                } else {
                    p.ufrag = ufrag.to_owned();
                    // One still on its way answers for the new generation; one that is done
                    // starts over, from the name (RFC 8445 section 9: the new generation's
                    // candidates are gathered anew).
                    if p.state == ProbeState::Done {
                        p.state = ProbeState::Pending;
                        p.mapped = None;
                        p.race = None;
                        p.query = None;
                        p.discovery = None;
                    }
                }
                continue;
            }
            self.probes.push(Probe {
                transport,
                base,
                kind,
                url: url.clone(),
                tls,
                state: ProbeState::Pending,
                race: None,
                attempts: vec![],
                query: None,
                mapped: None,
                discovery: None,
                ufrag: ufrag.to_owned(),
                kept: None,
                error: None,
            });
        }
        found
    }

    /// The application gathers for `base` itself: the engine's probes from it stop.
    pub(crate) fn application_gathers(&mut self, base: SocketAddr) {
        if !self.application_bases.contains(&base) {
            self.application_bases.push(base);
        }
        for p in self.probes.iter_mut().filter(|p| p.base == base) {
            p.state = ProbeState::Done;
            p.attempts.clear();
        }
    }

    /// The UDP bases `bases` of `transport` were refused (a new DTLS association runs on new
    /// transport addresses, RFC 8842 section 5.1): their probes end, so that no mapped address
    /// of the previous association's socket is announced for the new generation. Probes from
    /// the new bases the application adds start as for any host candidate.
    pub(crate) fn forget_bases(&mut self, transport: TransportId, bases: &[SocketAddr]) {
        self.probes.retain(|p| {
            !(p.transport == transport && p.kind == Base::Udp && bases.contains(&p.base))
        });
    }

    /// The Binding connections kept open: probe index, connection.
    fn kept_streams(&self) -> Vec<(usize, StreamId)> {
        self.probes
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.kept.map(|(id, _)| (i, id)))
            .collect()
    }

    fn probe_of_stream(&self, id: StreamId) -> Option<(usize, usize)> {
        self.probes.iter().enumerate().find_map(|(i, p)| {
            p.attempts
                .iter()
                .position(|a| a.stream == Some(id))
                .map(|j| (i, j))
        })
    }
}

/// A Binding request (RFC 8489 section 6; no attribute an RFC 5389 server would not know),
/// with the SOFTWARE attribute when `software` is given (RFC 8489 section 14.14: "This
/// attribute SHOULD be used by clients ... in all Binding requests"; RFC 5389 section 15.10
/// knows it too).
fn binding_request(software: Option<&str>) -> shared::error::Result<Message> {
    let mut message = Message::new();
    let mut setters: Vec<Box<dyn Setter>> = vec![
        Box::new(stun::message::TransactionId::new()),
        Box::new(BINDING_REQUEST),
    ];
    if let Some(software) = software {
        setters.push(Box::new(stun::textattrs::Software::new(
            stun::attributes::ATTR_SOFTWARE,
            software.to_owned(),
        )));
    }
    message.build(&setters)?;
    Ok(message)
}

/// The reflexive address a success response carries: XOR-MAPPED-ADDRESS, or MAPPED-ADDRESS
/// from a server of RFC 3489 (RFC 8489 section 5, backwards compatibility).
fn mapped_address(response: &Message) -> Option<SocketAddr> {
    if response.typ.class != CLASS_SUCCESS_RESPONSE {
        return None;
    }
    let mut xor = XorMappedAddress::default();
    if xor.get_from(response).is_ok() {
        return Some(SocketAddr::new(xor.ip, xor.port));
    }
    let mut plain = stun::addr::MappedAddress::default();
    plain
        .get_from(response)
        .ok()
        .map(|()| SocketAddr::new(plain.ip, plain.port))
}

impl RTCPeerConnection {
    /// Whether the engine gathers server-reflexive candidates at all: servers are configured,
    /// it is asked to, and the policy allows them.
    fn srflx_wanted(&self) -> bool {
        self.streams.srflx.servers.any()
            && self.streams.srflx.mode == ReflexiveGathering::Engine
            && !self.setting_engine.candidates.ice_lite
            && self.configuration.ice_transport_policy
                != crate::peer_connection::configuration::RTCIceTransportPolicy::Relay
            && !self.is_closed()
    }

    /// The local ufrag of `transport`'s current ICE generation.
    fn ice_username_fragment_of(&self, transport: TransportId) -> String {
        self.ice_transport_of(transport)
            .agent
            .get_local_credentials()
            .ufrag
            .clone()
    }

    /// Probes for a UDP host candidate the application just added (`candidate_value`) on the
    /// active transport; a server-reflexive candidate the application adds marks its base as
    /// the application's.
    pub(crate) fn gather_srflx_for(&mut self, candidate_value: &str) {
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        match candidate.candidate_type() {
            ice::candidate::CandidateType::ServerReflexive => {
                // The engine's own, coming back through a transport's path.
                let own = self
                    .streams
                    .srflx
                    .announced
                    .iter()
                    .any(|(_, mapped, _, _)| *mapped == candidate.addr());
                if !own
                    && let Some(related) = candidate.related_address()
                    && let Ok(ip) = related.address.parse::<IpAddr>()
                {
                    self.streams
                        .srflx
                        .application_gathers(SocketAddr::new(ip, related.port));
                }
                return;
            }
            ice::candidate::CandidateType::Host if !candidate.network_type().is_tcp() => {}
            _ => return,
        }
        if !self.srflx_wanted() {
            return;
        }
        // The servers RFC 8489 section 8.1 rejects are reported when gathering would use
        // them, whether or not this base would have asked them.
        self.report_rejected_srflx_servers_after(|pc| pc.gather_srflx_for_base(&candidate));
    }

    /// [`Self::gather_srflx_for`] once `candidate` is a UDP host candidate to probe from.
    fn gather_srflx_for_base(&mut self, candidate: &ice::candidate::Candidate) {
        let on = self.pipeline_context.transports.active_id();
        let base = candidate.addr();
        // A base whose host candidate the agent withheld (mDNS fails closed,
        // `with_multicast_dns_fail_closed`) still gets its server-reflexive candidates: they
        // carry the public address only (draft-ietf-mmusic-mdns-ice-candidates section
        // 3.1.2.2).
        let agent = &self.ice_transport().agent;
        let accepted = agent.multicast_dns_withholds(base.ip())
            || agent
                .get_local_candidates()
                .iter()
                .any(|c| c.addr() == base && !c.network_type().is_tcp());
        if accepted {
            let ufrag = self.ice_username_fragment_of(on);
            for (mapped, url) in self.streams.srflx.add(on, base, Base::Udp, &ufrag) {
                self.announce_srflx(on, base, Base::Udp, mapped, &url);
            }
            self.drive_srflx(self.pipeline_context.now);
        }
    }

    /// Runs `gather`, then reports each server it rejected (RFC 8489 section 8.1) as W3C
    /// 4.8.3 has a failed server reported: an `icecandidateerror` of code 701, "If no host
    /// candidate can reach the server" (none is asked), without a local address (none was
    /// used), once per server URL while gathering (`report_ice_candidate_error`).
    fn report_rejected_srflx_servers_after(&mut self, gather: impl FnOnce(&mut Self)) {
        gather(self);
        for url in std::mem::take(&mut self.streams.srflx.rejected) {
            let error = crate::peer_connection::event::RTCPeerConnectionIceErrorEvent {
                url,
                error_code: crate::peer_connection::event::ICE_SERVER_UNREACHABLE,
                error_text: "a stuns: URI whose host is an IP address is rejected \
                             (RFC 8489 section 8.1)"
                    .to_owned(),
                ..Default::default()
            };
            if let Err(err) = self.report_ice_candidate_error(error) {
                debug!("srflx: the rejected server is not reported: {err}");
            }
        }
    }

    /// The active transport's UDP bases were refused (a new DTLS association,
    /// `IceTransport::previous_association_addresses`): the engine's probes from them end
    /// ([`EngineSrflx::forget_bases`]).
    pub(crate) fn forget_srflx_of_refused_bases(&mut self) {
        let on = self.pipeline_context.transports.active_id();
        let bases = self.ice_transport().previous_association_addresses.clone();
        if !bases.is_empty() {
            self.streams.srflx.forget_bases(on, &bases);
        }
    }

    /// Probes over TCP / TLS from an engine ICE-TCP listener that is now bound.
    pub(crate) fn gather_srflx_tcp(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        tcp_type: TcpType,
    ) {
        if !self.srflx_wanted() || tcp_type == TcpType::Active {
            return;
        }
        self.report_rejected_srflx_servers_after(|pc| {
            let ufrag = pc.ice_username_fragment_of(transport);
            for (mapped, url) in pc
                .streams
                .srflx
                .add(transport, base, Base::Tcp(tcp_type), &ufrag)
            {
                pc.announce_tcp_srflx(transport, base, tcp_type, mapped, &url);
            }
            pc.drive_srflx(pc.pipeline_context.now);
        });
    }

    /// Starts what is due: names to resolve, races to start, transactions at most one per Ta.
    pub(crate) fn drive_srflx(&mut self, now: Instant) {
        let ids = self.pipeline_context.transports.ids();
        let gone: Vec<StreamId> = self
            .streams
            .srflx
            .probes
            .iter()
            .filter(|p| !ids.contains(&p.transport))
            .flat_map(|p| {
                p.attempts
                    .iter()
                    .filter_map(|a| a.stream)
                    .chain(p.kept.map(|(id, _)| id))
            })
            .collect();
        for id in gone {
            self.streams.table.close(id);
        }
        self.streams
            .srflx
            .probes
            .retain(|p| ids.contains(&p.transport));
        for index in 0..self.streams.srflx.probes.len() {
            let probe = &mut self.streams.srflx.probes[index];
            if probe.state != ProbeState::Pending {
                continue;
            }
            match probe.url.host.parse::<IpAddr>() {
                Ok(ip) => {
                    probe.race = Some(HappyEyeballs::new(
                        vec![SocketAddr::new(ip, probe.url.port)],
                        CONNECTION_ATTEMPT_DELAY,
                    ));
                    probe.state = ProbeState::Racing;
                }
                // RFC 8489 section 8 / RFC 7064 section 3.2: without a port, SRV finds it.
                Err(_) if !probe.url.explicit_port => {
                    let srv = match (probe.kind, probe.tls) {
                        (Base::Udp, _) => "_stun._udp",
                        (_, false) => "_stun._tcp",
                        (_, true) => "_stuns._tcp",
                    };
                    let discovery = crate::peer_connection::dns_discovery::Discovery::new(
                        &probe.url.host,
                        probe.url.port,
                        None,
                        srv,
                    );
                    let first = discovery.start();
                    probe.discovery = Some(discovery);
                    self.srflx_discovery_next(index, first, now);
                }
                Err(_) => {
                    let (host, port) = (probe.url.host.clone(), probe.url.port);
                    let query = self.streams.table.resolve(host, port);
                    let probe = &mut self.streams.srflx.probes[index];
                    probe.state = ProbeState::Resolving(query);
                    probe.query = Some(query);
                }
            }
        }
        for index in 0..self.streams.srflx.probes.len() {
            if self.streams.srflx.probes[index].state != ProbeState::Racing {
                continue;
            }
            loop {
                if self
                    .streams
                    .srflx
                    .last_start
                    .is_some_and(|last| now < last + TA)
                {
                    break;
                }
                let base_ip = self.streams.srflx.probes[index].base.ip();
                let Some(server) = self.streams.srflx.probes[index]
                    .race
                    .as_mut()
                    .and_then(|r| r.next_attempt(now))
                else {
                    break;
                };
                // A server of the other family cannot be reached from this base; one the
                // embedder's address policy refuses is never sent anything.
                if server.is_ipv4() != base_ip.is_ipv4()
                    || !self.address_allowed(server, ice::AddressPurpose::StunTurnServer)
                {
                    if let Some(r) = self.streams.srflx.probes[index].race.as_mut() {
                        r.failed();
                    }
                    continue;
                }
                self.streams.srflx.last_start = Some(now);
                self.start_srflx_attempt(now, index, server);
            }
            let probe = &mut self.streams.srflx.probes[index];
            if probe.race.as_ref().is_some_and(HappyEyeballs::exhausted) {
                // The next SRV target, when there is one (RFC 2782).
                if let Some(next) = probe.discovery.as_mut().map(|d| d.next_target()) {
                    self.srflx_discovery_next(index, next, now);
                } else {
                    debug!(
                        "{}: no server-reflexive address from {}",
                        probe.url, probe.base
                    );
                    probe.state = ProbeState::Done;
                    // W3C webrtc-pc 4.8.3: the server's error code, or 701 when no address
                    // of it answered.
                    let (code, text) = probe.error.clone().unwrap_or((
                        crate::peer_connection::event::ICE_SERVER_UNREACHABLE,
                        "no address of the server answered".to_owned(),
                    ));
                    let (transport, base, url) = (probe.transport, probe.base, probe.url_string());
                    self.report_engine_gathering_error(transport, Some(base), url, code, text);
                }
            }
        }
        self.finish_deferred_gathering();
    }

    fn start_srflx_attempt(&mut self, now: Instant, index: usize, server: SocketAddr) {
        self.start_srflx_attempt_on(now, index, server, false);
    }

    /// Starts a Binding transaction to `server`: over UDP from the base; over TCP / TLS on the
    /// connection kept open from an earlier answer of that server (RFC 8489 section 6.2.2-4:
    /// several transactions may share one), or on a new connection (`retried`: one that
    /// replaces a connection whose transaction failed).
    fn start_srflx_attempt_on(
        &mut self,
        now: Instant,
        index: usize,
        server: SocketAddr,
        retried: bool,
    ) {
        let (base, kind, tls, host) = {
            let p = &self.streams.srflx.probes[index];
            (p.base, p.kind, p.tls, p.url.host.clone())
        };
        // The connection an earlier answer left open, when it is to this server and open.
        let reuse = match self.streams.srflx.probes[index].kept {
            Some((id, to))
                if to == server
                    && self
                        .streams
                        .table
                        .info(id)
                        .is_some_and(|c| c.state == shared::stream::StreamState::Open) =>
            {
                self.streams.srflx.probes[index].kept = None;
                Some(id)
            }
            _ => None,
        };
        let protocol = if kind == Base::Udp {
            TransportProtocol::UDP
        } else {
            TransportProtocol::TCP
        };
        let software = self.setting_engine.srflx_software();
        let started = (|| -> shared::error::Result<Attempt> {
            let mut client = ClientBuilder::new().build(now, base, server, protocol)?;
            let request = binding_request(software.as_deref())?;
            let transaction = request.transaction_id.0;
            client.handle_write(TaggedMessage {
                now,
                message: request,
            })?;
            let stream = if kind == Base::Udp {
                None
            } else if let Some(id) = reuse {
                Some(id)
            } else {
                let layer: Option<Box<dyn StreamLayer>> = if tls {
                    let config = self.streams.srflx.tls_config.clone().ok_or_else(|| {
                        shared::error::Error::Other(
                            "stuns: server without roots or a verifier to check it".to_owned(),
                        )
                    })?;
                    Some(Box::new(TlsLayer::new(config, &host)?))
                } else {
                    None
                };
                // RFC 6544 Appendix B: from the candidate's own port, beside its listener.
                Some(
                    self.streams
                        .table
                        .connect(base, server, Framing::Turn, SRFLX, true, layer)?,
                )
            };
            Ok(Attempt {
                server,
                client,
                transaction,
                stream,
                retried,
            })
        })();
        match started {
            Ok(attempt) => {
                self.streams.srflx.probes[index].attempts.push(attempt);
                self.pump_srflx_attempt(
                    now,
                    index,
                    self.streams.srflx.probes[index].attempts.len() - 1,
                );
            }
            Err(err) => {
                debug!("Binding request to {server} from {base}: {err}");
                if let Some(r) = self.streams.srflx.probes[index].race.as_mut() {
                    r.failed();
                }
            }
        }
    }

    /// Sends what an attempt's client has to send and acts on its events.
    fn pump_srflx_attempt(&mut self, now: Instant, index: usize, attempt: usize) {
        let mut outcome: Option<Outcome> = None;
        {
            let probe = &mut self.streams.srflx.probes[index];
            let a = &mut probe.attempts[attempt];
            while let Some(transmit) = a.client.poll_write() {
                match a.stream {
                    None => self.pipeline_context.write_outs.push_back(transmit),
                    Some(id) => {
                        let _ = self.streams.table.send(id, &transmit.message);
                    }
                }
            }
            while let Some(event) = a.client.poll_event() {
                outcome = Some(match event {
                    StunEvent::Message(response) => match mapped_address(&response) {
                        Some(mapped) => Outcome::Mapped(mapped),
                        None => {
                            debug!("{}: Binding error or no mapped address", a.server);
                            let mut code = stun::error_code::ErrorCodeAttribute::default();
                            if stun::message::Getter::get_from(&mut code, &response).is_ok() {
                                probe.error = Some((
                                    code.code.0,
                                    String::from_utf8_lossy(&code.reason).into_owned(),
                                ));
                            }
                            Outcome::Failed
                        }
                    },
                    StunEvent::TransactionTimeOut => {
                        debug!("{}: Binding transaction timed out", a.server);
                        Outcome::TimedOut
                    }
                    other => {
                        debug!("{}: Binding transaction ended: {other:?}", a.server);
                        Outcome::Failed
                    }
                });
            }
        }
        match outcome {
            None => {}
            Some(Outcome::Mapped(mapped)) => self.srflx_won(now, index, attempt, mapped),
            Some(Outcome::TimedOut) => self.srflx_attempt_timed_out(now, index, attempt),
            Some(Outcome::Failed) => self.srflx_attempt_failed(now, index, attempt),
        }
    }

    /// RFC 8489 section 6.2.2: a transaction that failed on a connection that does not work
    /// any more is answered with a RST and a new connection, once; over UDP (and on the new
    /// connection) the attempt has failed.
    fn srflx_attempt_timed_out(&mut self, now: Instant, index: usize, attempt: usize) {
        let a = &self.streams.srflx.probes[index].attempts[attempt];
        let Some(id) = a.stream.filter(|_| !a.retried) else {
            return self.srflx_attempt_failed(now, index, attempt);
        };
        let server = a.server;
        self.streams.srflx.probes[index].attempts.remove(attempt);
        debug!("{server}: no answer on the Binding connection: RST and a new connection");
        self.streams.table.reset(id);
        self.start_srflx_attempt_on(now, index, server, true);
    }

    /// An attempt failed: its connection is closed and the race goes on with the server's
    /// next address (or its next SRV target).
    fn srflx_attempt_failed(&mut self, now: Instant, index: usize, attempt: usize) {
        let a = self.streams.srflx.probes[index].attempts.remove(attempt);
        if let Some(id) = a.stream {
            self.streams.table.close(id);
        }
        if let Some(r) = self.streams.srflx.probes[index].race.as_mut() {
            r.failed();
        }
        self.drive_srflx(now);
    }

    /// The first answer: the race is over, the candidate is announced.
    fn srflx_won(&mut self, now: Instant, index: usize, attempt: usize, mapped: SocketAddr) {
        let probe = &mut self.streams.srflx.probes[index];
        if let Some(r) = probe.race.as_mut() {
            r.succeeded();
        }
        probe.state = ProbeState::Done;
        probe.mapped = Some(mapped);
        let winner = probe.attempts.remove(attempt);
        let losers: Vec<Attempt> = std::mem::take(&mut probe.attempts);
        let (transport, base, kind, url) =
            (probe.transport, probe.base, probe.kind, probe.url_string());
        // RFC 8489 section 6.2.2: the client keeps the connection open while it may use the
        // mapped address learned over it (the NAT binding lives as long as the connection),
        // so the winner's stays open until ICE of its transport has completed
        // (`close_settled_srflx_connections`); the others are done.
        let previous = probe.kept.take();
        probe.kept = winner.stream.map(|id| (id, winner.server));
        for id in losers
            .iter()
            .filter_map(|a| a.stream)
            .chain(previous.map(|(id, _)| id))
            .filter(|id| Some(*id) != winner.stream)
        {
            self.streams.table.close(id);
        }
        match kind {
            Base::Udp => self.announce_srflx(transport, base, kind, mapped, &url),
            Base::Tcp(tcp_type) => self.announce_tcp_srflx(transport, base, tcp_type, mapped, &url),
        }
        self.drive_srflx(now);
    }

    /// A passive or simultaneous-open server-reflexive candidate, and (RFC 6544 section 5.2)
    /// an active one on the same address, its base the host active candidate.
    fn announce_tcp_srflx(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        tcp_type: TcpType,
        mapped: SocketAddr,
        url: &str,
    ) {
        self.announce_srflx(transport, base, Base::Tcp(tcp_type), mapped, url);
        self.announce_srflx(
            transport,
            SocketAddr::new(base.ip(), ACTIVE_PORT),
            Base::Tcp(TcpType::Active),
            SocketAddr::new(mapped.ip(), ACTIVE_PORT),
            url,
        );
    }

    fn announce_srflx(
        &mut self,
        transport: TransportId,
        base: SocketAddr,
        kind: Base,
        mapped: SocketAddr,
        url: &str,
    ) {
        let ufrag = self
            .ice_transport_of(transport)
            .agent
            .get_local_credentials()
            .ufrag
            .clone();
        let key = (transport, mapped, kind, ufrag);
        // RFC 8445 section 5.1.3: one equal to its base (no NAT) is redundant, with the base's
        // host candidate written with its address. In `QueryAndGather` that host candidate
        // carries an mDNS name instead, and draft-ietf-mmusic-mdns-ice-candidates section
        // 3.1.2.2 says: "Regardless of whether the address turns out to be public or private,
        // a server-reflexive candidate will be generated; [...] and as such MUST NOT be
        // considered redundant per the guidance in [RFC8445], Section 5.1.3". So it goes to
        // the agent, which applies 5.1.3 with what it holds: kept (raddr 0.0.0.0 / ::, rport
        // 9) beside a `.local` host candidate, dropped beside one that carries the address
        // (the fixed-IP mode's other addresses, or one unwrapped by
        // `with_multicast_dns_expose_known_public_addresses`, which takes its evidence from
        // it). libwebrtc keeps it the same way (p2p/base/stun_port.cc,
        // UDPPort::OnStunBindingRequestSucceeded: the reflected address equal to the local
        // one is discarded only when "mDNS obfuscation is not enabled").
        let hidden_base =
            self.setting_engine.multicast_dns.mode == ice::mdns::MulticastDnsMode::QueryAndGather;
        if (mapped == base && !hidden_base) || self.streams.srflx.announced.contains(&key) {
            return;
        }
        self.streams.srflx.announced.push(key);
        let network = if kind == Base::Udp { "udp" } else { "tcp" };
        let candidate = CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: network.to_owned(),
                address: mapped.ip().to_string(),
                port: mapped.port(),
                component: 1,
                ..Default::default()
            },
            rel_addr: base.ip().to_string(),
            rel_port: base.port(),
            url: Some(url.to_owned()),
        }
        .new_candidate_server_reflexive()
        .and_then(|mut c| {
            if let Base::Tcp(tcp_type) = kind {
                c.set_tcp_type(tcp_type);
            }
            crate::peer_connection::transport::RTCIceCandidate::from(&c).to_json()
        });
        match candidate {
            Ok(init) => {
                let value = init
                    .candidate
                    .strip_prefix("candidate:")
                    .unwrap_or(&init.candidate)
                    .to_owned();
                if let Err(err) =
                    self.add_engine_local_candidate(transport, &value, Some(url), None)
                {
                    debug!("server-reflexive candidate {mapped} not added: {err}");
                }
            }
            Err(err) => debug!("server-reflexive candidate {mapped} not made: {err}"),
        }
    }

    /// Takes a datagram that answers one of the engine's Binding requests over UDP; returns
    /// it otherwise, for ICE.
    pub(crate) fn take_srflx_response(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if msg.transport.transport_protocol != TransportProtocol::UDP
            || msg.message.len() < 20
            || msg.message[0] & 0xc0 != 0
            || self.streams.srflx.probes.is_empty()
        {
            return Some(msg);
        }
        let (local, peer) = (msg.transport.local_addr, msg.transport.peer_addr);
        let found = self
            .streams
            .srflx
            .probes
            .iter()
            .enumerate()
            .find_map(|(i, p)| {
                if p.base != local {
                    return None;
                }
                p.attempts
                    .iter()
                    .position(|a| {
                        a.stream.is_none()
                            && a.server == peer
                            && msg.message[8..20] == a.transaction
                    })
                    .map(|j| (i, j))
            });
        let Some((index, attempt)) = found else {
            return Some(msg);
        };
        let now = msg.now;
        let a = &mut self.streams.srflx.probes[index].attempts[attempt];
        if let Err(err) = a.client.handle_read(msg) {
            debug!("Binding response from {peer}: {err}");
        }
        self.pump_srflx_attempt(now, index, attempt);
        None
    }

    /// Messages read on a Binding connection.
    pub(crate) fn srflx_messages(&mut self, now: Instant, id: StreamId, messages: Vec<Vec<u8>>) {
        let Some((index, attempt)) = self.streams.srflx.probe_of_stream(id) else {
            return;
        };
        {
            let a = &mut self.streams.srflx.probes[index].attempts[attempt];
            let context = tcp_context(a.client.local_addr(), a.server);
            for message in messages {
                if let Err(err) = a.client.handle_read(TaggedBytesMut {
                    now,
                    transport: context,
                    message: BytesMut::from(&message[..]),
                }) {
                    debug!("Binding response from {}: {err}", a.server);
                }
            }
        }
        self.pump_srflx_attempt(now, index, attempt);
    }

    /// A Binding connection could not be made or ended before its answer (the race goes on
    /// with the server's next address), or a connection kept open after its answer ended.
    pub(crate) fn srflx_connection_ended(&mut self, now: Instant, id: StreamId) {
        for p in self.streams.srflx.probes.iter_mut() {
            if p.kept.is_some_and(|(kept, _)| kept == id) {
                p.kept = None;
            }
        }
        if let Some((index, attempt)) = self.streams.srflx.probe_of_stream(id) {
            self.streams.srflx.probes[index].attempts[attempt].stream = None;
            self.srflx_attempt_failed(now, index, attempt);
        }
    }

    /// Closes the Binding connections kept open (RFC 8489 section 6.2.2) once they are no
    /// longer needed: ICE of their transport has completed (a pair is selected: the mapped
    /// address has been used with the peer or will not be), or the connection is closing.
    pub(crate) fn close_settled_srflx_connections(&mut self) {
        let closed = self.is_closed();
        for (index, id) in self.streams.srflx.kept_streams() {
            let transport = self.streams.srflx.probes[index].transport;
            let settled = closed
                || self
                    .pipeline_context
                    .transports
                    .transport(transport)
                    .is_none()
                || self
                    .ice_transport_of(transport)
                    .agent
                    .get_selected_candidate_pair()
                    .is_some();
            if settled {
                self.streams.srflx.probes[index].kept = None;
                self.streams.table.close(id);
            }
        }
    }

    /// A name resolved for a probe: all its addresses at once (`ipv6` `None`) or one family.
    /// Returns whether the query was a probe's.
    pub(crate) fn srflx_resolved(
        &mut self,
        query: u64,
        ipv6: Option<bool>,
        addresses: &[SocketAddr],
    ) -> bool {
        let now = self.pipeline_context.now;
        let mut ours = false;
        for probe in self.streams.srflx.probes.iter_mut() {
            let waiting = probe.query == Some(query)
                && (probe.state == ProbeState::Resolving(query)
                    || (probe.state == ProbeState::Racing
                        && probe.race.as_ref().is_some_and(HappyEyeballs::awaiting)));
            if !waiting {
                continue;
            }
            ours = true;
            match ipv6 {
                None => {
                    probe.query = None;
                    let sorted = sort_addresses(addresses, true);
                    probe.race = Some(HappyEyeballs::new(sorted, CONNECTION_ATTEMPT_DELAY));
                }
                Some(ipv6) => {
                    let race = probe.race.get_or_insert_with(|| {
                        HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY)
                    });
                    race.answer(now, ipv6, addresses, true);
                }
            }
            probe.state = ProbeState::Racing;
        }
        if ours {
            self.drive_srflx(now);
        }
        ours
    }

    /// Acts on the next step of a probe's discovery.
    fn srflx_discovery_next(
        &mut self,
        index: usize,
        next: crate::peer_connection::dns_discovery::Next,
        now: Instant,
    ) {
        use crate::peer_connection::dns_discovery::Next;
        match next {
            Next::Records { name, kind } => {
                let query = self.streams.table.resolve_records(name, kind);
                let probe = &mut self.streams.srflx.probes[index];
                probe.state = ProbeState::Discovering(query);
                if let Some(d) = probe.discovery.as_mut() {
                    d.asked(query, now);
                }
            }
            Next::Address { host, port } => match host.parse::<IpAddr>() {
                Ok(ip) => {
                    let probe = &mut self.streams.srflx.probes[index];
                    probe.race = Some(HappyEyeballs::new(
                        vec![SocketAddr::new(ip, port)],
                        CONNECTION_ATTEMPT_DELAY,
                    ));
                    probe.state = ProbeState::Racing;
                }
                Err(_) => {
                    let query = self.streams.table.resolve(host, port);
                    let probe = &mut self.streams.srflx.probes[index];
                    probe.state = ProbeState::Resolving(query);
                    probe.query = Some(query);
                    probe.race = None;
                }
            },
            Next::Exhausted => self.streams.srflx.probes[index].state = ProbeState::Done,
        }
    }

    /// SRV records the driver looked up for a probe. Returns whether the query was a probe's.
    pub(crate) fn srflx_records(
        &mut self,
        query: u64,
        records: &[shared::stream::DnsRecord],
    ) -> bool {
        let now = self.pipeline_context.now;
        let Some(index) = self
            .streams
            .srflx
            .probes
            .iter()
            .position(|p| p.state == ProbeState::Discovering(query))
        else {
            return false;
        };
        let Some(next) = self.streams.srflx.probes[index]
            .discovery
            .as_mut()
            .map(|d| d.on_records(records))
        else {
            return false;
        };
        self.srflx_discovery_next(index, next, now);
        self.drive_srflx(now);
        true
    }

    /// The probes' next timer: a retransmission, Ti, the next attempt or the Ta gate.
    pub(crate) fn srflx_poll_timeout(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        let gate = self.streams.srflx.last_start.map(|last| last + TA);
        for probe in self.streams.srflx.probes.iter_mut() {
            if let ProbeState::Discovering(_) = probe.state
                && let Some(t) = probe.discovery.as_ref().and_then(|d| d.poll_timeout())
            {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
            for a in probe.attempts.iter_mut() {
                if let Some(t) = a.client.poll_timeout() {
                    next = Some(next.map_or(t, |n| n.min(t)));
                }
            }
            if probe.state == ProbeState::Racing
                && let Some(race) = probe.race.as_ref()
            {
                // A first attempt held only by the Ta gate is due when the gate opens.
                let held = probe.attempts.is_empty() && !race.exhausted() && !race.awaiting();
                let due = race.poll_timeout().or(if held { gate } else { None });
                if let Some(t) = due {
                    let t = gate.map_or(t, |g| t.max(g));
                    next = Some(next.map_or(t, |n| n.min(t)));
                }
            }
        }
        next
    }

    /// Fires the probes' timers.
    pub(crate) fn srflx_handle_timeout(&mut self, now: Instant) {
        if self.streams.srflx.probes.is_empty() {
            return;
        }
        for index in 0..self.streams.srflx.probes.len() {
            for attempt in (0..self.streams.srflx.probes[index].attempts.len()).rev() {
                if index >= self.streams.srflx.probes.len()
                    || attempt >= self.streams.srflx.probes[index].attempts.len()
                {
                    continue;
                }
                let a = &mut self.streams.srflx.probes[index].attempts[attempt];
                if a.client.poll_timeout().is_some_and(|t| t <= now)
                    && let Err(err) = a.client.handle_timeout(now)
                {
                    debug!("Binding transaction timer: {err}");
                }
                self.pump_srflx_attempt(now, index, attempt);
            }
        }
        // A records query the driver did not answer counts as empty.
        let unanswered: Vec<u64> = self
            .streams
            .srflx
            .probes
            .iter()
            .filter_map(|p| match p.state {
                ProbeState::Discovering(q)
                    if p.discovery.as_ref().is_some_and(|d| d.timed_out(now)) =>
                {
                    Some(q)
                }
                _ => None,
            })
            .collect();
        for query in unanswered {
            self.srflx_records(query, &[]);
        }
        self.drive_srflx(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use crate::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    use crate::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceServer};
    use crate::peer_connection::event::RTCPeerConnectionEvent;
    use crate::peer_connection::transport::RTCIceCandidateInit;
    use crate::peer_connection::turn_tls::{TurnTlsConfig, rustls_provider};
    use shared::stream::{StreamCommand, StreamEvent};
    use std::io::{Read, Write};

    fn tls_server(name: &str) -> (Arc<rustls::ServerConfig>, Arc<rustls::RootCertStore>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = cert.der().clone();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(rustls_provider().unwrap())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![der],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = vec![ALPN_STUN_NAT_DISCOVERY.to_vec()];
        (Arc::new(config), Arc::new(roots))
    }

    /// RFC 7064 / RFC 8489 section 6.2.3: a `stuns:` server is asked over TLS from the
    /// passive listener's port, its certificate checked against the URI's host with the
    /// configured roots, ALPN `stun.nat-discovery` (RFC 7443); the mapped address is a
    /// server-reflexive TCP candidate carrying the `stuns:` URL. No UDP request goes to it.
    #[test]
    fn a_stuns_server_is_asked_over_tls_and_its_answer_is_a_tcp_candidate() {
        let now = Instant::now();
        let (server_config, roots) = tls_server("stun.rtc.test");
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec!["stuns:stun.rtc.test:5349".to_owned()],
                        ..Default::default()
                    }])
                    .build(),
            )
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_tcp_simultaneous_open(false)
                    .with_turn_tls(TurnTlsConfig {
                        roots: Some(roots),
                        ..Default::default()
                    })
                    .build(),
            )
            .build(now)
            .unwrap();
        pc.create_data_channel("stuns", None).unwrap();
        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(now, offer).unwrap();
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host".to_owned(),
            ..Default::default()
        })
        .unwrap();
        let mut commands = vec![];
        let drain = |pc: &mut RTCPeerConnection, commands: &mut Vec<StreamCommand>| {
            while let Some(c) = pc.poll_stream_command() {
                commands.push(c);
            }
        };
        drain(&mut pc, &mut commands);
        assert!(
            pc.poll_write().is_none(),
            "no STUN over UDP to a stuns: server"
        );
        let listener = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Listen { listener, .. } => Some(*listener),
                _ => None,
            })
            .unwrap();
        let bound: SocketAddr = "10.0.0.1:7000".parse().unwrap();
        pc.handle_stream_event(
            now,
            StreamEvent::Listening {
                listener,
                local: bound,
            },
        )
        .unwrap();
        drain(&mut pc, &mut commands);
        let query = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Resolve { query, .. } => Some(*query),
                _ => None,
            })
            .expect("the server's name goes to the driver");
        let server: SocketAddr = "192.0.2.10:5349".parse().unwrap();
        pc.handle_stream_event(
            now,
            StreamEvent::Resolved {
                query,
                addresses: vec![server],
            },
        )
        .unwrap();
        drain(&mut pc, &mut commands);
        let id = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Connect {
                    id,
                    local,
                    remote,
                    reuse_address: true,
                } if *local == bound && *remote == server => Some(*id),
                _ => None,
            })
            .expect("a connection from the listener's port");
        pc.handle_stream_event(now, StreamEvent::Connected { id, local: bound })
            .unwrap();

        let mut tls = rustls::ServerConnection::new(server_config).unwrap();
        let mut request = None;
        for _ in 0..20 {
            while let Some(t) = pc.poll_stream_transmit() {
                assert_eq!(t.id, id);
                tls.read_tls(&mut &t.data[..]).unwrap();
                tls.process_new_packets().unwrap();
            }
            let mut plain = vec![];
            let _ = tls.reader().read_to_end(&mut plain);
            if !plain.is_empty() {
                let mut m = Message::new();
                m.unmarshal_binary(&plain).unwrap();
                request = Some(m);
            }
            let mut out = vec![];
            while tls.wants_write() {
                tls.write_tls(&mut out).unwrap();
            }
            if !out.is_empty() {
                pc.handle_stream_read(now, id, &out).unwrap();
            }
            if request.is_some() {
                break;
            }
        }
        let request = request.expect("the Binding request over TLS");
        assert_eq!(request.typ, BINDING_REQUEST);
        assert_eq!(tls.alpn_protocol(), Some(ALPN_STUN_NAT_DISCOVERY));
        let mut response = Message::new();
        let setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(stun::message::BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: "203.0.113.5".parse().unwrap(),
                port: 62000,
            }),
        ];
        response.build(&setters).unwrap();
        tls.writer().write_all(&response.raw).unwrap();
        let mut out = vec![];
        while tls.wants_write() {
            tls.write_tls(&mut out).unwrap();
        }
        pc.handle_stream_read(now, id, &out).unwrap();

        let mut found = None;
        while let Some(e) = pc.poll_event() {
            if let RTCPeerConnectionEvent::OnIceCandidateEvent(ev) = e
                && let Some(init) = ev.candidate.as_ref().and_then(|c| c.to_json().ok())
                && init.candidate.contains("typ srflx")
                && init.candidate.contains("tcptype passive")
            {
                found = Some((init.candidate, ev.url));
            }
        }
        let (candidate, url) = found.expect("a server-reflexive passive TCP candidate");
        assert!(
            candidate.contains("203.0.113.5 62000 typ srflx raddr 10.0.0.1 rport 7000"),
            "{candidate}"
        );
        assert_eq!(url.as_deref(), Some("stuns:stun.rtc.test:5349"));
    }

    /// RFC 8489 section 6.2.2: the client keeps the connection open until it "has no plans to
    /// use any resources (such as a mapped address ...) that were learned though STUN requests
    /// sent over that connection" and, "if using that learned port with a remote peer, has
    /// established communications with that remote peer". The engine's Binding connection
    /// stays open after its answer and closes once ICE of its transport has completed.
    #[test]
    fn the_binding_connection_stays_open_until_ice_has_completed() {
        use crate::peer_connection::transport::RTCDtlsRole;
        use crate::peer_connection::util_test::{Pair, new_pair, signal_pair};
        let now = Instant::now();
        let (_, mut answerer) = new_pair().unwrap();
        let mut offerer = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec!["stun:192.0.2.10:3478".to_owned()],
                        ..Default::default()
                    }])
                    .build(),
            )
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_answering_dtls_role(RTCDtlsRole::Server)
                    .with_tcp_simultaneous_open(false)
                    .build(),
            )
            .build(now)
            .unwrap();
        offerer.create_data_channel("kept", None).unwrap();
        offerer
            .add_local_candidate(RTCIceCandidateInit {
                candidate: format!(
                    "candidate:1 1 udp 2130706431 127.0.0.1 {} typ host",
                    crate::peer_connection::util_test::OFFERER_ADDR
                        .parse::<SocketAddr>()
                        .unwrap()
                        .port()
                ),
                ..Default::default()
            })
            .unwrap();
        let mut commands = vec![];
        let drain = |pc: &mut RTCPeerConnection, commands: &mut Vec<StreamCommand>| {
            while let Some(c) = pc.poll_stream_command() {
                commands.push(c);
            }
        };
        drain(&mut offerer, &mut commands);
        let listener = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Listen { listener, .. } => Some(*listener),
                _ => None,
            })
            .unwrap();
        let bound: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        offerer
            .handle_stream_event(
                now,
                StreamEvent::Listening {
                    listener,
                    local: bound,
                },
            )
            .unwrap();
        // The TCP transaction waits one Ta behind the UDP one.
        offerer.handle_timeout(now + TA).unwrap();
        drain(&mut offerer, &mut commands);
        let server: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let id = commands
            .iter()
            .find_map(|c| match c {
                StreamCommand::Connect {
                    id, local, remote, ..
                } if *local == bound && *remote == server => Some(*id),
                _ => None,
            })
            .expect("the Binding connection");
        offerer
            .handle_stream_event(now + TA, StreamEvent::Connected { id, local: bound })
            .unwrap();
        let mut wire = vec![];
        while let Some(t) = offerer.poll_stream_transmit() {
            wire.extend(t.data);
        }
        let mut request = Message::new();
        request.unmarshal_binary(&wire).unwrap();
        let mut response = Message::new();
        let setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(stun::message::BINDING_SUCCESS),
            Box::new(XorMappedAddress {
                ip: "203.0.113.5".parse().unwrap(),
                port: 62000,
            }),
        ];
        response.build(&setters).unwrap();
        offerer
            .handle_stream_read(now + TA, id, &response.raw)
            .unwrap();
        drain(&mut offerer, &mut commands);
        let closed = |commands: &[StreamCommand]| {
            commands.iter().any(|c| {
                matches!(c, StreamCommand::Close { id: c } | StreamCommand::Reset { id: c } if *c == id)
            })
        };
        assert!(!closed(&commands), "open after the answer, while ICE runs");

        signal_pair(&mut offerer, &mut answerer).unwrap();
        let mut pair = Pair::new(offerer, answerer);
        pair.connect().unwrap();
        drain(&mut pair.offerer, &mut commands);
        assert!(closed(&commands), "closed once ICE has completed");
    }

    /// The SOFTWARE attribute of the first server-reflexive Binding request the engine's
    /// gatherer sends over UDP from a host candidate to the configured STUN server, under
    /// `software` (`None`: `with_ice_software` not called).
    fn srflx_request_software(software: Option<Option<String>>) -> Option<String> {
        let now = Instant::now();
        let server: SocketAddr = "192.0.2.10:3478".parse().unwrap();
        let mut setting_engine = SettingEngineBuilder::new();
        if let Some(software) = software {
            setting_engine = setting_engine.with_ice_software(software);
        }
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(vec![RTCIceServer {
                        urls: vec![format!("stun:{server}")],
                        ..Default::default()
                    }])
                    .build(),
            )
            .with_setting_engine(setting_engine.build())
            .build(now)
            .unwrap();
        pc.create_data_channel("software", None).unwrap();
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host".to_owned(),
            ..Default::default()
        })
        .unwrap();
        for step in 0..10u32 {
            while let Some(t) = pc.poll_write() {
                if t.transport.peer_addr != server {
                    continue;
                }
                let mut m = Message::new();
                m.unmarshal_binary(&t.message).unwrap();
                assert_eq!(m.typ, BINDING_REQUEST);
                return stun::textattrs::Software::get_from_as(&m, stun::attributes::ATTR_SOFTWARE)
                    .ok()
                    .map(|s| s.to_string());
            }
            pc.handle_timeout(now + TA * step).unwrap();
        }
        panic!("no Binding request reached the STUN server");
    }

    /// RFC 8489 section 8.1: "A 'stuns' URI containing an IP address MUST be rejected". Given
    /// such a server (as a configuration that takes the URL gives it, the half
    /// `a_url_no_check_refuses_is_accepted` covers; set directly here so that this half does
    /// not depend on it), gathering does not use it, from a UDP base nor from the engine's passive ICE-TCP
    /// listener, which is bound here as a driver would (the base a `stuns:` server is asked
    /// from): nothing is sent and no connection is opened to it, it is reported once with an
    /// `icecandidateerror` of code 701 (W3C 4.8.3: the server cannot be reached; no local
    /// address was used, so none is given), and once the application ends gathering it
    /// completes (nothing is left waiting for the server).
    #[test]
    fn a_stuns_server_whose_host_is_an_ip_address_is_not_asked_and_is_reported() {
        let now = Instant::now();
        // Roots to check a server with: without them a `stuns:` attempt fails before any
        // connection is opened ("stuns: server without roots or a verifier to check it"), and
        // an engine that asked the server would go unnoticed by the connection assertion.
        let (_, roots) = tls_server("stun.rtc.test");
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_tcp_simultaneous_open(false)
                    .with_turn_tls(TurnTlsConfig {
                        roots: Some(roots),
                        ..Default::default()
                    })
                    .build(),
            )
            .build(now)
            .unwrap();
        pc.streams
            .srflx
            .set_servers(&[Url::parse_url_lenient("stuns:192.0.2.1:5349").unwrap()]);
        pc.create_data_channel("d", None).unwrap();
        let offer = pc.create_offer(None).unwrap();
        pc.set_local_description(now, offer).unwrap();
        pc.add_local_candidate(RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 10.0.0.1 4000 typ host".to_owned(),
            ..Default::default()
        })
        .unwrap();
        let server: SocketAddr = "192.0.2.1:5349".parse().unwrap();
        let mut commands = vec![];
        let mut errors = vec![];
        let mut bound = 0u16;
        for step in 0..10u32 {
            while let Some(t) = pc.poll_write() {
                assert_ne!(t.transport.peer_addr, server, "nothing is sent to it");
            }
            let mut listeners = vec![];
            while let Some(command) = pc.poll_stream_command() {
                if let StreamCommand::Listen { listener, .. } = &command {
                    listeners.push(*listener);
                }
                commands.push(command);
            }
            for listener in listeners {
                bound += 1;
                pc.handle_stream_event(
                    now,
                    StreamEvent::Listening {
                        listener,
                        local: SocketAddr::new("10.0.0.1".parse().unwrap(), 7000 + bound),
                    },
                )
                .unwrap();
            }
            while let Some(event) = pc.poll_event() {
                if let RTCPeerConnectionEvent::OnIceCandidateErrorEvent(e) = event {
                    errors.push(e);
                }
            }
            pc.handle_timeout(now + TA * step).unwrap();
        }
        assert!(
            bound > 0,
            "the passive listener was asked for and bound: {commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|c| matches!(c, StreamCommand::Connect { remote, .. } if *remote == server)),
            "no connection is opened to it: {commands:?}"
        );
        assert_eq!(errors.len(), 1, "reported once per server URL: {errors:?}");
        assert_eq!(errors[0].url, "stuns:192.0.2.1:5349");
        assert_eq!(
            errors[0].error_code,
            crate::peer_connection::event::ICE_SERVER_UNREACHABLE
        );
        assert_eq!((errors[0].address.as_str(), errors[0].port), ("", 0));

        pc.add_local_candidate(RTCIceCandidateInit::default())
            .unwrap();
        while pc.poll_event().is_some() {}
        assert_eq!(
            pc.ice_gathering_state(),
            crate::peer_connection::state::RTCIceGatheringState::Complete,
            "gathering waits for nothing of the rejected server"
        );
    }

    /// RFC 8489 section 14.14: "This attribute SHOULD be used by clients and servers. ... in
    /// all Binding requests". By default the gatherer's request carries the ICE agent's
    /// SOFTWARE, as the connectivity checks do.
    #[test]
    fn by_default_the_srflx_binding_request_carries_the_rtc_ice_software() {
        assert_eq!(
            srflx_request_software(None).as_deref(),
            Some(ice::agent::DEFAULT_SOFTWARE)
        );
    }

    /// RFC 8489 section 16.1.2: SOFTWARE is a configurable option. `with_ice_software(None)`
    /// takes it off the gatherer's request too; `Some(text)` sends that text.
    #[test]
    fn with_ice_software_the_srflx_binding_request_carries_that_text_or_none() {
        assert_eq!(srflx_request_software(Some(None)), None);
        assert_eq!(
            srflx_request_software(Some(Some("probe 1.0".to_owned()))).as_deref(),
            Some("probe 1.0")
        );
        assert_eq!(srflx_request_software(Some(Some(String::new()))), None);
    }
}
