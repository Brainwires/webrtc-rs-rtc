//! TURN over TCP and over TLS built into the engine (RFC 8656 section 3.1; `turns:` and
//! `turn:...?transport=tcp` servers of the configuration), through the stream interface.
//!
//! For each such server the engine asks its driver to resolve the name
//! ([`StreamCommand::Resolve`](shared::stream::StreamCommand::Resolve)) unless it is an
//! address, orders the addresses by Happy Eyeballs (RFC 8305) and connects to them staggered
//! by the Connection Attempt Delay, keeping the first that connects. Over TLS (rustls,
//! sans-I/O, ALPN `stun.turn`) it verifies the server with the roots or verifier the
//! application gave. It then runs the TURN client over the connection (TURN's own framing,
//! RFC 8656 section 12.5), allocates, announces the relayed candidate with its
//! `relayProtocol` (`tcp` or `tls`), creates permissions as the agent sends, and relays the
//! agent's datagrams both ways. The relayed transport itself is UDP (RFC 8656).
//!
//! A `turns:...?transport=udp` server is reached over DTLS (RFC 7350): a client-role
//! `rtci-dtls` association from a UDP host candidate's base, on the application's socket. Its
//! records leave through `poll_write` and are taken out of `handle_read` before ICE sees them
//! (by the server's address on that base); the server's certificate is checked against the
//! URI's host with the same roots or verifier as TLS. The TURN client runs over it with UDP's
//! retransmissions (RFC 7350 section 4), and the relayed candidate's `relayProtocol` is
//! `dtls`.
//!
//! A plain `turn:` server over UDP (`turn:...?transport=udp`, the default transport) is run
//! the same way on the application's socket unless the application gathers its relayed
//! candidates itself (`SettingEngineBuilder::with_relay_gathering`): from each transport's
//! first UDP host candidate's base of the server's family, the engine sends the Allocate
//! through `poll_write` and takes the server's answers out of `handle_read` (by the
//! transactions it has open, and Data indications and ChannelData on its allocation). The
//! server's addresses race as RFC 8656 section 3.9 says for UDP: an unauthenticated Allocate
//! to each, staggered by the Connection Attempt Delay; the first answered keeps going, a later
//! 401 is dropped, and an allocation a later answer made is deleted with a Refresh of LIFETIME
//! 0. Permissions, channel bindings, refreshes and the 401 / 438 paths are the TURN client's
//! (`rtci_turn::client`); the relayed candidate's `relayProtocol` is `udp`.

use super::RTCPeerConnection;
use super::streams::{TURN, tcp_context};
use super::turn_tls::{TlsLayer, TurnTlsConfig};
use crate::peer_connection::handler::transport_set::TransportId;
use crate::peer_connection::servers_in_force::{ServersInForce, same_url};
use crate::peer_connection::transport::ice::candidate::RTCIceServerTransportProtocol;
use bytes::BytesMut;
use ice::url::{ProtoType, SchemeType, Url};
use log::debug;
use sansio::Protocol;
use shared::stream::happy_eyeballs::{CONNECTION_ATTEMPT_DELAY, HappyEyeballs, sort_addresses};
use shared::stream::{Framing, StreamId, StreamLayer};
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod tcp_relay;

/// ALTERNATE-SERVER redirects followed per resolution.
const MAX_REDIRECTS: u8 = 3;

/// How long an Allocate that lost a UDP race (RFC 8656 section 3.9) is waited on past its
/// client's next timer, for an answer that would leave an allocation to delete.
const LOSER_GRACE: Duration = Duration::from_secs(40);

/// Datagrams held per peer address while their permission is being created.
const MAX_HELD_PER_PEER: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkState {
    /// Not started.
    Pending,
    /// The driver is looking up the server's NAPTR or SRV records (RFC 5928 section 3).
    Discovering(u64),
    /// The driver is resolving the host name.
    Resolving(u64),
    /// Connection attempts are racing.
    Connecting,
    /// Connected; the TURN client runs on it.
    Open(StreamId),
    /// The DTLS association is up (`TurnLink::dtls`); the TURN client runs on it.
    OpenDtls,
    /// Over UDP: an address answered first (`TurnLink::client` runs from `link_local` to
    /// `server` on the application's socket).
    OpenUdp,
    /// Given up: no address connected, TLS failed, the allocation failed or the connection
    /// ended.
    Failed,
    /// Closed once ICE had completed without its relayed candidate (RFC 6544 section 11.2);
    /// a new ICE generation allocates again.
    Released,
}

/// What carries a link's TURN messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrier {
    /// TCP (`turn:...?transport=tcp`).
    Tcp,
    /// TLS over TCP (`turns:`).
    Tls,
    /// DTLS over the application's UDP socket (`turns:...?transport=udp`, RFC 7350).
    Dtls,
    /// Plain UDP on the application's socket (`turn:`, `turn:...?transport=udp`).
    Udp,
}

/// An unauthenticated Allocate racing to one address of a `turn:` server over UDP (RFC 8656
/// section 3.9), from a UDP base of the transport.
pub(crate) struct UdpAttempt {
    /// The link's URL (`TurnLink::url_string`).
    url: String,
    remote: SocketAddr,
    base: SocketAddr,
    client: turn::client::Client,
    /// Its Allocate has gone out. Not yet while the engine is deleting an allocation of the
    /// same 5-tuple (`EngineTurn::five_tuple_in_release`): the request waits for that release
    /// to end.
    sent: bool,
}

/// Who gathers relayed candidates from `turn:` servers over UDP. See
/// `SettingEngineBuilder::with_relay_gathering`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RelayGathering {
    /// The engine, on the application's UDP socket, for each transport and each `turn:` server
    /// over UDP of the configuration (as browsers do). A server for which the application adds
    /// a relayed candidate itself is left to it.
    #[default]
    Engine,
    /// The application: the engine sends nothing to a `turn:` server over UDP.
    ///
    /// The application runs the TURN client and adds the relayed candidate
    /// (`add_local_candidate`, with `url` set to the server). The engine then treats the
    /// relayed address as a local address of its own, and the application carries datagrams
    /// between it and the allocation, as the engine does for an allocation it runs itself:
    ///
    /// - **In**: a datagram the allocation relayed (the payload of a Data indication or of
    ///   ChannelData) goes to `handle_read` with `local_addr` = the relayed address (the relay
    ///   candidate's address, the XOR-RELAYED-ADDRESS of the Allocate response) and
    ///   `peer_addr` = the peer (XOR-PEER-ADDRESS, or the channel's peer). Not the address of
    ///   the socket that talks to the TURN server: the ICE agent matches `local_addr` exactly
    ///   against its local candidates (RFC 8445 section 7.3.1.4), and a datagram on any other
    ///   address is discarded ("Discarded message, not a valid local candidate").
    /// - **Out**: a datagram from `poll_write` whose `transport.local_addr` is the relayed
    ///   address leaves through the allocation (a Send indication, or ChannelData on a bound
    ///   channel, to `transport.peer_addr`; RFC 8656 sections 11 and 12), not from a socket.
    ///
    /// ```text
    /// // in: what the TURN client unwrapped
    /// pc.handle_read(TaggedBytesMut { now, message: payload, transport: TransportContext {
    ///     local_addr: relayed_addr,  // the relay candidate's address
    ///     peer_addr: peer,           // XOR-PEER-ADDRESS / the channel's peer
    ///     transport_protocol: TransportProtocol::UDP, ecn: None } })?;
    /// // out
    /// while let Some(msg) = pc.poll_write() {
    ///     if msg.transport.local_addr == relayed_addr {
    ///         turn.send_to(&msg.message, msg.transport.peer_addr)?;  // Send / ChannelData
    ///     } else {
    ///         socket_for(msg.transport.local_addr).send_to(&msg.message, msg.transport.peer_addr)?;
    ///     }
    /// }
    /// ```
    Application,
}

/// An allocation over UDP the engine is letting go, or an Allocate still under way when it
/// stopped needing it: its client runs on until the transaction is done (RFC 8656 section 8
/// with RFC 8489 section 6.2.1: the Refresh of LIFETIME 0 is retransmitted, a 438 answered with
/// the new nonce), after `close()` too.
pub(crate) struct UdpRelease {
    url: String,
    base: SocketAddr,
    server: SocketAddr,
    client: turn::client::Client,
    /// The allocation being deleted; `None` while an Allocate is under way.
    relay: Option<SocketAddr>,
    /// The Allocate under way carries the credential (its success is an allocation, which is
    /// deleted at once); otherwise it is the first, unauthenticated one: a 401 to it ends it,
    /// and the request it asks for is not sent.
    signed: bool,
    done: bool,
}

/// A DTLS association to one address of a `turns:...?transport=udp` server, from a UDP base.
pub(crate) struct DtlsAttempt {
    remote: SocketAddr,
    base: SocketAddr,
    endpoint: dtls::endpoint::Endpoint,
}

impl DtlsAttempt {
    /// Moves the association's records onto the application's socket (`poll_write`).
    fn flush(&mut self, out: &mut std::collections::VecDeque<TaggedBytesMut>) {
        while let Some(t) = self.endpoint.poll_transmit() {
            out.push_back(t);
        }
    }
}

pub(crate) struct TurnLink {
    /// The transport the relayed candidate is gathered for: each transport allocates on its
    /// own (RFC 9429 section 5.2.1).
    transport: TransportId,
    url: Url,
    carrier: Carrier,
    /// Over DTLS: the handshakes racing, one per server address.
    dtls_attempts: Vec<DtlsAttempt>,
    /// Over DTLS: the association that won.
    dtls: Option<DtlsAttempt>,
    /// Over UDP: the Allocates racing, one per server address.
    udp_attempts: Vec<UdpAttempt>,
    /// A TCP allocation (RFC 6062): relayed TCP candidates, peers on data connections.
    relay_tcp: bool,
    /// Its peers' data connections.
    data: Vec<tcp_relay::DataConn>,
    /// The peer addresses it has created a permission for.
    permitted: HashSet<IpAddr>,
    state: LinkState,
    race: Option<HappyEyeballs>,
    attempts: Vec<StreamId>,
    client: Option<turn::client::Client>,
    server: Option<SocketAddr>,
    link_local: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    /// The ICE generation (local ufrag) the relayed candidate was last announced for.
    announced_ufrag: Option<String>,
    /// The name's query, while its per-family answers may still come.
    query: Option<u64>,
    /// The NAPTR / SRV discovery of a server whose URI gives no port.
    discovery: Option<crate::peer_connection::dns_discovery::Discovery>,
    held: HashMap<IpAddr, Vec<(SocketAddr, Vec<u8>)>>,
    /// The ICE generation (local ufrag) the link last started for: a failed or released link
    /// starts over, from the resolution, for a new one (RFC 5928 section 3).
    generation: Option<String>,
    /// ALTERNATE-SERVER redirects followed in this resolution (RFC 8489 section 10: at most
    /// a few, against loops).
    redirects: u8,
    /// A link whose server left the list a new ICE generation took (new credentials, say)
    /// while its relayed candidate carried the data: kept, refreshed and relaying, until the
    /// agent no longer uses that path (RFC 8445 section 9: "during the restart, data can
    /// continue to be sent using existing data sessions"; section 5.1.1.4), then released.
    retiring: bool,
}

impl TurnLink {
    fn settled(&self) -> bool {
        matches!(self.state, LinkState::Failed | LinkState::Released) || self.relay.is_some()
    }

    fn url_string(&self) -> String {
        let (scheme, transport) = match self.carrier {
            Carrier::Tcp => ("turn", "tcp"),
            Carrier::Tls => ("turns", "tcp"),
            Carrier::Dtls => ("turns", "udp"),
            Carrier::Udp => ("turn", "udp"),
        };
        format!(
            "{scheme}:{}:{}?transport={transport}",
            host_for_url(&self.url.host),
            self.url.port
        )
    }

    fn protocol(&self) -> RTCIceServerTransportProtocol {
        match self.carrier {
            Carrier::Tcp => RTCIceServerTransportProtocol::Tcp,
            Carrier::Tls => RTCIceServerTransportProtocol::Tls,
            Carrier::Dtls => RTCIceServerTransportProtocol::Dtls,
            Carrier::Udp => RTCIceServerTransportProtocol::Udp,
        }
    }

    /// Whether the link runs on the application's UDP socket (DTLS or plain UDP).
    fn on_datagrams(&self) -> bool {
        matches!(self.carrier, Carrier::Dtls | Carrier::Udp)
    }

    fn tls(&self) -> bool {
        self.carrier == Carrier::Tls
    }

    /// The DTLS association (racing or won) to `remote` from `base`.
    fn dtls_to(&mut self, base: SocketAddr, remote: SocketAddr) -> Option<&mut DtlsAttempt> {
        self.dtls
            .iter_mut()
            .chain(self.dtls_attempts.iter_mut())
            .find(|a| a.base == base && a.remote == remote)
    }
}

/// Whether the URL an application gave a relayed candidate names `server` (scheme, host and
/// port; `turn:host` without a port is 3478).
/// The `turn:` / `turns:` URLs of `urls`: `turns:` over UDP is DTLS (RFC 7350 section 4);
/// `turn:` over UDP runs unless the application gathers its relayed candidates itself
/// (`relay_gathering`).
fn turn_servers(urls: &[Url]) -> Vec<Url> {
    urls.iter()
        .filter(|u| matches!(u.scheme, SchemeType::Turn | SchemeType::Turns))
        .cloned()
        .collect()
}

fn same_server(url: &str, server: &Url) -> bool {
    Url::parse_url(url).is_ok_and(|u| {
        u.scheme == server.scheme
            && u.proto == server.proto
            && u.host.eq_ignore_ascii_case(&server.host)
            && u.port == server.port
    })
}

fn host_for_url(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// The engine's TURN-over-stream links.
pub(crate) struct EngineTurn {
    /// The servers each transport allocates on: `turn:...?transport=tcp` and `turns:` URLs
    /// (`turns:...?transport=udp` over DTLS), and `turn:` over UDP; as each ICE generation of
    /// each transport took them (`RTCPeerConnection::set_configuration` gives the next
    /// generations a new list).
    servers: ServersInForce,
    /// The bases of the UDP host candidates of each transport: where a DTLS link starts.
    udp_bases: Vec<(TransportId, SocketAddr)>,
    /// The transports whose links were made (once each, failed ones are not made again).
    made_for: HashSet<TransportId>,
    links: Vec<TurnLink>,
    pub(crate) enabled: bool,
    tls: TurnTlsConfig,
    tls_config: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// Relayed TCP candidates from a TCP allocation beside the UDP one, for each server over
    /// TCP or TLS (RFC 6544 section 5.5).
    pub(crate) tcp_relay: bool,
    /// The addresses of the remote TCP candidates signalled per transport (for the
    /// permissions of the TCP allocations).
    remote_tcp_ips: Vec<(TransportId, IpAddr)>,
    /// Server addresses not to be used before an instant: an Allocate answered 486 or 508
    /// (one minute) or 437 (two minutes), RFC 8656 section 7.4 with RFC 5928 section 3 ("MUST
    /// NOT be used for the specified duration, even if returned by a subsequent resolution").
    held_back: Vec<(SocketAddr, Instant)>,
    /// Who gathers from `turn:` servers over UDP.
    pub(crate) relay_gathering: RelayGathering,
    /// Allocates that lost a UDP race (RFC 8656 section 3.9), kept until their answer: a 401
    /// drops them, a success has the allocation deleted.
    udp_losers: Vec<UdpAttempt>,
    /// The relayed candidates the application added itself over UDP: the transport and the
    /// `url` it gave (`None`: any server).
    application_relays: Vec<(TransportId, Option<String>)>,
    /// Allocations being let go and Allocates nobody needs any more (`UdpRelease`).
    releases: Vec<UdpRelease>,
    /// 5-tuples an Allocate was refused with 437 on (RFC 8656 section 7.4): (base, server,
    /// until). A link does not allocate from such a base to that server again for two
    /// minutes.
    mismatched: Vec<(SocketAddr, SocketAddr, Instant)>,
    /// 5-tuples whose release ended: (base, server, the instant a new Allocate may leave from
    /// it: the end plus `SettingEngine::turn_reallocation_delay`).
    freed: Vec<(SocketAddr, SocketAddr, Instant)>,
}

impl EngineTurn {
    /// The links of the `turn:...?transport=tcp` and `turns:` URLs among `urls`.
    pub(crate) fn new(urls: &[Url], enabled: bool, tls: TurnTlsConfig) -> Self {
        let servers = ServersInForce::new(turn_servers(urls));
        let tls_config = tls.client_config().ok().flatten();
        Self {
            servers,
            udp_bases: vec![],
            made_for: HashSet::new(),
            links: vec![],
            enabled,
            tls,
            tls_config,
            tcp_relay: true,
            remote_tcp_ips: vec![],
            held_back: vec![],
            relay_gathering: RelayGathering::Engine,
            udp_losers: vec![],
            application_relays: vec![],
            releases: vec![],
            mismatched: vec![],
            freed: vec![],
        }
    }

    /// Whether the engine runs links over `carrier`: over UDP when it gathers relayed
    /// candidates itself, over the others when it runs TURN over streams and DTLS.
    fn runs(&self, carrier: Carrier) -> bool {
        match carrier {
            Carrier::Udp => self.relay_gathering == RelayGathering::Engine,
            _ => self.enabled,
        }
    }

    /// Whether the application added a relayed candidate itself for `link`'s server on its
    /// transport (by the candidate's `url`, or any relayed candidate without one).
    fn left_to_application(&self, link: &TurnLink) -> bool {
        link.carrier == Carrier::Udp
            && self.application_relays.iter().any(|(t, url)| {
                *t == link.transport && url.as_deref().is_none_or(|u| same_server(u, &link.url))
            })
    }

    /// Whether an Allocate from `base` to `server` was refused with 437 less than two minutes
    /// before `now`.
    fn is_mismatched(&self, base: SocketAddr, server: SocketAddr, now: Instant) -> bool {
        self.mismatched
            .iter()
            .any(|(b, s, until)| *b == base && *s == server && now < *until)
    }

    /// Whether an allocation of the 5-tuple (`base`, `server`) is being deleted at `now`: a
    /// release of it is under way (`UdpRelease`), or ended less than the reallocation delay
    /// before. Until the server has answered the Refresh of LIFETIME 0 the allocation is the
    /// 5-tuple's, and an Allocate on it would be refused with 437 (RFC 8656 section 7.2, step
    /// 2), after which the client leaves the server alone for two minutes (section 7.4).
    fn five_tuple_in_release(&self, base: SocketAddr, server: SocketAddr, now: Instant) -> bool {
        self.releases
            .iter()
            .any(|r| !r.done && r.base == base && r.server == server)
            || self
                .freed
                .iter()
                .any(|(b, s, at)| *b == base && *s == server && now < *at)
    }

    /// Whether `server` is held back at `now`.
    fn is_held_back(&self, server: SocketAddr, now: Instant) -> bool {
        self.held_back
            .iter()
            .any(|(a, until)| *a == server && now < *until)
    }

    /// The configuration's new servers: the ICE generations that begin from now on allocate
    /// on them (W3C webrtc-pc "set the configuration", RFC 9429 section 4.1.18).
    pub(crate) fn set_servers(&mut self, urls: &[Url]) {
        self.servers.set(turn_servers(urls));
    }

    /// The links of `transport` for its generation `ufrag`, one per server of the list that
    /// generation takes: made once per transport, and when a later generation takes another
    /// list, the links of servers no longer in it are returned (to be closed) and links for
    /// the new servers are made.
    fn make_links(&mut self, transport: TransportId, ufrag: &str) -> Vec<TurnLink> {
        let (servers, new_phase) = self.servers.for_generation(transport, ufrag);
        let first = self.made_for.insert(transport);
        if !first && !new_phase {
            return vec![];
        }
        let mut dropped = vec![];
        if !first {
            let mut i = 0;
            while i < self.links.len() {
                if self.links[i].transport == transport
                    && !self.links[i].retiring
                    && !servers.iter().any(|u| same_url(u, &self.links[i].url))
                {
                    dropped.push(self.links.remove(i));
                } else {
                    i += 1;
                }
            }
        }
        for url in &servers {
            if !first
                && self
                    .links
                    .iter()
                    .any(|l| l.transport == transport && !l.retiring && same_url(&l.url, url))
            {
                continue;
            }
            let carrier = match (url.scheme, url.proto) {
                (SchemeType::Turns, ProtoType::Udp) => Carrier::Dtls,
                (SchemeType::Turns, _) => Carrier::Tls,
                (_, ProtoType::Udp) => Carrier::Udp,
                _ => Carrier::Tcp,
            };
            if !self.runs(carrier) {
                continue;
            }
            // Over TCP and TLS also a TCP allocation, on a control connection of its own (an
            // allocation is its 5-tuple's, RFC 8656 section 2.2), for relayed TCP candidates.
            let kinds: &[bool] = if self.tcp_relay && matches!(carrier, Carrier::Tcp | Carrier::Tls)
            {
                &[false, true]
            } else {
                &[false]
            };
            for &relay_tcp in kinds {
                self.links.push(TurnLink {
                    transport,
                    url: url.clone(),
                    carrier,
                    dtls_attempts: vec![],
                    dtls: None,
                    udp_attempts: vec![],
                    relay_tcp,
                    data: vec![],
                    permitted: HashSet::new(),
                    state: LinkState::Pending,
                    race: None,
                    attempts: vec![],
                    client: None,
                    server: None,
                    link_local: None,
                    relay: None,
                    announced_ufrag: None,
                    query: None,
                    discovery: None,
                    held: HashMap::new(),
                    generation: None,
                    redirects: 0,
                    retiring: false,
                });
            }
        }
        dropped
    }

    /// Whether a link of `transport` is still on its way to a relayed candidate. A link over
    /// a stream waits for the driver (`driver`: one serves the stream interface); a DTLS link
    /// needs it only to resolve a name.
    pub(crate) fn pending(&self, transport: TransportId, driver: bool) -> bool {
        self.links.iter().any(|l| {
            self.runs(l.carrier)
                && l.transport == transport
                && l.state != LinkState::Pending
                && !l.settled()
                && (driver
                    || (l.on_datagrams()
                        && !matches!(l.state, LinkState::Resolving(_) | LinkState::Discovering(_))))
        })
    }

    /// A UDP host candidate's base of `transport`: DTLS links of the transport can start.
    pub(crate) fn note_udp_base(&mut self, transport: TransportId, base: SocketAddr) {
        if !self.udp_bases.contains(&(transport, base)) {
            self.udp_bases.push((transport, base));
        }
    }

    /// The first UDP base of `transport` of the family of `server` that is `usable`.
    fn udp_base(
        &self,
        transport: TransportId,
        server: SocketAddr,
        usable: impl Fn(SocketAddr) -> bool,
    ) -> Option<SocketAddr> {
        self.udp_bases
            .iter()
            .find(|(t, b)| *t == transport && b.is_ipv4() == server.is_ipv4() && usable(*b))
            .map(|(_, b)| *b)
    }

    /// The UDP link whose client runs, or one of whose Allocates races, from `base` to
    /// `remote`.
    fn link_of_udp(&self, base: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.links.iter().position(|l| {
            l.carrier == Carrier::Udp
                && ((l.state == LinkState::OpenUdp
                    && l.link_local == Some(base)
                    && l.server == Some(remote))
                    || l.udp_attempts
                        .iter()
                        .any(|a| a.base == base && a.remote == remote))
        })
    }

    /// The DTLS link (and whether its association has won) that `(base, remote)` is one of.
    fn link_of_dtls(&self, base: SocketAddr, remote: SocketAddr) -> Option<usize> {
        self.links.iter().position(|l| {
            l.dtls
                .iter()
                .chain(l.dtls_attempts.iter())
                .any(|a| a.base == base && a.remote == remote)
        })
    }

    fn link_of_stream(&self, id: StreamId) -> Option<usize> {
        self.links
            .iter()
            .position(|l| l.state == LinkState::Open(id) || l.attempts.contains(&id))
    }

    /// Whether a TCP allocation has its relayed address.
    pub(crate) fn has_tcp_relay(&self) -> bool {
        self.links.iter().any(|l| l.relay_tcp && l.relay.is_some())
    }

    /// The link whose relayed UDP address is `addr`.
    pub(crate) fn link_of_relay(&self, addr: SocketAddr) -> Option<usize> {
        self.links
            .iter()
            .position(|l| !l.relay_tcp && l.relay == Some(addr))
    }

    /// The links and their relayed addresses, for diagnostics.
    pub(crate) fn relays(&self) -> Vec<SocketAddr> {
        self.links.iter().filter_map(|l| l.relay).collect()
    }

    pub(crate) fn tls_config(&self) -> &TurnTlsConfig {
        &self.tls
    }
}

/// Lets go of what a UDP link holds: its allocation is deleted with a Refresh of LIFETIME 0
/// (RFC 8656 section 8), run as a transaction of its own (`UdpRelease`), and an Allocate still
/// under way (one racing, or the request with the credential) is followed to its answer, a
/// success deleted. The link keeps no client.
fn release_udp_allocation(
    link: &mut TurnLink,
    now: Instant,
    out: &mut std::collections::VecDeque<TaggedBytesMut>,
    releases: &mut Vec<UdpRelease>,
) {
    if link.carrier != Carrier::Udp {
        return;
    }
    let url = link.url_string();
    // An Allocate that never left (it waited for a release of its 5-tuple) has nothing to
    // follow.
    for a in link.udp_attempts.drain(..).filter(|a| a.sent) {
        releases.push(UdpRelease {
            url: a.url,
            base: a.base,
            server: a.remote,
            client: a.client,
            relay: None,
            signed: false,
            done: false,
        });
    }
    if link.state != LinkState::OpenUdp {
        return;
    }
    let (Some(base), Some(server)) = (link.link_local, link.server) else {
        return;
    };
    let Some(mut client) = link.client.take() else {
        return;
    };
    let relay = link.relay;
    if let Some(relay) = relay
        && let Ok(mut r) = client.relay(relay)
    {
        let _ = r.close(now);
    }
    while let Some(t) = client.poll_write() {
        out.push_back(TaggedBytesMut {
            now,
            transport: udp_context(base, server),
            message: t.message,
        });
    }
    releases.push(UdpRelease {
        url,
        base,
        server,
        client,
        relay,
        signed: true,
        done: false,
    });
}

fn udp_context(local: SocketAddr, peer: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr: local,
        peer_addr: peer,
        transport_protocol: TransportProtocol::UDP,
        ecn: None,
    }
}

/// The STUN class of a datagram that is a STUN message (RFC 8489 section 5): 0 request, 1
/// indication, 2 success response, 3 error response.
fn stun_class(datagram: &[u8]) -> Option<u8> {
    if datagram.len() < 20 || datagram[0] & 0xc0 != 0 || datagram[4..8] != [0x21, 0x12, 0xa4, 0x42]
    {
        return None;
    }
    let t = u16::from_be_bytes([datagram[0], datagram[1]]);
    Some((((t >> 7) & 0x2) | ((t >> 4) & 0x1)) as u8)
}

fn any_of_family(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

impl RTCPeerConnection {
    /// Starts the links not started yet, once there is a local description, and announces
    /// the relayed candidates again for a new ICE generation.
    pub(crate) fn start_turn_links(&mut self) {
        if !(self.streams.turn.enabled
            || self.streams.turn.relay_gathering == RelayGathering::Engine)
            || self.is_closed()
            || self.local_description().is_none()
        {
            return;
        }
        self.release_retired_turn_links();
        // Again for the links already retiring: an ICE restart taken back
        // (`Agent::revert_restart`) restores a session as it was before the withdrawal.
        let retiring: Vec<(TransportId, SocketAddr, bool)> = self
            .streams
            .turn
            .links
            .iter()
            .filter(|l| l.retiring)
            .filter_map(|l| l.relay.map(|r| (l.transport, r, l.relay_tcp)))
            .collect();
        for (transport, relay, tcp) in retiring {
            self.withdraw_relay_candidate(transport, relay, tcp);
        }
        let mut dropped = vec![];
        for transport in self.pipeline_context.transports.ids() {
            let ufrag = self
                .ice_transport_of(transport)
                .agent
                .get_local_credentials()
                .ufrag
                .clone();
            dropped.extend(self.streams.turn.make_links(transport, &ufrag));
        }
        // A dropped link whose relayed candidate carries the data stays until the restart has
        // its own path (RFC 8445 section 9); the others close.
        let mut closed = vec![];
        for mut link in dropped {
            if self.turn_relay_carries_data(&link) {
                debug!(
                    "{}: kept while its relayed candidate carries the data",
                    link.url
                );
                // Its relayed candidate is the previous path's only: a restart that keeps the
                // local candidates would carry it into the new session, which would pair (and
                // nominate) it, and the allocation of the credentials just replaced would never
                // be let go (`Agent::withdraw_local_candidate`).
                if let Some(relay) = link.relay {
                    self.withdraw_relay_candidate(link.transport, relay, link.relay_tcp);
                }
                link.retiring = true;
                self.streams.turn.links.push(link);
            } else {
                closed.push(link);
            }
        }
        self.close_turn_links(closed);
        let now = self.pipeline_context.now;
        let driver = self.streams.driver_seen;
        for index in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[index];
            // A link over a stream starts for a driver that serves the stream interface; a
            // DTLS or UDP link from a UDP host candidate's base, once the transport has one.
            // A UDP link for a server the application gathers from itself never starts.
            if link.state != LinkState::Pending
                || self.streams.turn.left_to_application(link)
                || (!link.on_datagrams() && !driver)
                || (link.on_datagrams()
                    && !self
                        .streams
                        .turn
                        .udp_bases
                        .iter()
                        .any(|(t, b)| *t == link.transport && self.turn_base_usable(*t, *b)))
            {
                continue;
            }
            let generation = self
                .ice_transport_of(self.streams.turn.links[index].transport)
                .agent
                .get_local_credentials()
                .ufrag
                .clone();
            let link = &mut self.streams.turn.links[index];
            link.generation = Some(generation);
            link.redirects = 0;
            match link.url.host.parse::<IpAddr>() {
                Ok(ip) => {
                    let addr = SocketAddr::new(ip, link.url.port);
                    link.race = Some(HappyEyeballs::new(vec![addr], CONNECTION_ATTEMPT_DELAY));
                    link.state = LinkState::Connecting;
                }
                // RFC 5928 section 3: without a port, S-NAPTR and SRV find the server.
                Err(_) if !link.url.explicit_port => {
                    // RFC 5928 section 3 and RFC 7350 section 4.2: the S-NAPTR tag and SRV
                    // service of the transport.
                    let (tag, srv) = match link.carrier {
                        Carrier::Tcp => ("turn.tcp", "_turn._tcp"),
                        Carrier::Tls => ("turn.tls", "_turns._tcp"),
                        Carrier::Dtls => ("turn.dtls", "_turns._udp"),
                        Carrier::Udp => ("turn.udp", "_turn._udp"),
                    };
                    let discovery = crate::peer_connection::dns_discovery::Discovery::new(
                        &link.url.host,
                        link.url.port,
                        Some(tag),
                        srv,
                    );
                    let first = discovery.start();
                    link.discovery = Some(discovery);
                    self.turn_discovery_next(index, first, now);
                }
                Err(_) => {
                    let query = self
                        .streams
                        .table
                        .resolve(link.url.host.clone(), link.url.port);
                    let link = &mut self.streams.turn.links[index];
                    link.state = LinkState::Resolving(query);
                    link.query = Some(query);
                }
            }
        }
        // A link released once ICE had completed allocates again for a new ICE generation.
        for i in 0..self.streams.turn.links.len() {
            let l = &self.streams.turn.links[i];
            if l.retiring || !matches!(l.state, LinkState::Released | LinkState::Failed) {
                continue;
            }
            let ufrag = self
                .ice_transport_of(l.transport)
                .agent
                .get_local_credentials()
                .ufrag
                .clone();
            // RFC 5928 section 3: "After an allocation succeeds or all the allocations fail,
            // the resolution context MUST be discarded, and the resolution algorithm MUST be
            // restarted from the beginning for any subsequent allocation."
            let last = if l.state == LinkState::Released {
                l.announced_ufrag.as_ref()
            } else {
                l.generation.as_ref()
            };
            if last.is_some_and(|g| *g != ufrag) {
                let l = &mut self.streams.turn.links[i];
                l.state = LinkState::Pending;
                l.race = None;
                l.query = None;
                l.discovery = None;
                l.announced_ufrag = None;
            }
        }
        self.drive_turn_races(now);
        let again: Vec<usize> = self
            .streams
            .turn
            .links
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                let ufrag = &self
                    .ice_transport_of(l.transport)
                    .agent
                    .get_local_credentials()
                    .ufrag;
                !l.retiring && l.relay.is_some() && l.announced_ufrag.as_ref() != Some(ufrag)
            })
            .map(|(i, _)| i)
            .collect();
        for index in again {
            self.announce_relay_candidate(index);
        }
    }

    /// Starts the connection attempts that are due.
    pub(crate) fn drive_turn_races(&mut self, now: Instant) {
        for index in 0..self.streams.turn.links.len() {
            if self.streams.turn.links[index].state != LinkState::Connecting {
                continue;
            }
            while let Some(addr) = self.streams.turn.links[index]
                .race
                .as_mut()
                .and_then(|r| r.next_attempt(now))
            {
                if !self.address_allowed(addr, ice::AddressPurpose::StunTurnServer) {
                    debug!("TURN server {addr}: the address policy refuses it, not used");
                    if let Some(r) = self.streams.turn.links[index].race.as_mut() {
                        r.failed();
                    }
                    continue;
                }
                if self.streams.turn.is_held_back(addr, now) {
                    debug!("TURN server {addr} is held back: not used");
                    if let Some(r) = self.streams.turn.links[index].race.as_mut() {
                        r.failed();
                    }
                    continue;
                }
                if self.streams.turn.links[index].carrier == Carrier::Udp {
                    if !self.start_udp_attempt(now, index, addr)
                        && let Some(r) = self.streams.turn.links[index].race.as_mut()
                    {
                        r.failed();
                    }
                    if self.streams.turn.links[index].state == LinkState::Failed {
                        break;
                    }
                    continue;
                }
                if self.streams.turn.links[index].carrier == Carrier::Dtls {
                    if !self.start_dtls_attempt(now, index, addr)
                        && let Some(r) = self.streams.turn.links[index].race.as_mut()
                    {
                        r.failed();
                    }
                    if self.streams.turn.links[index].state == LinkState::Failed {
                        break;
                    }
                    continue;
                }
                let tls = self.streams.turn.links[index].tls();
                let layer: Option<Box<dyn StreamLayer>> = if tls {
                    let Some(config) = self.streams.turn.tls_config.clone() else {
                        debug!("turns: server without roots or a verifier to check it: not used");
                        self.streams.turn.links[index].state = LinkState::Failed;
                        break;
                    };
                    match TlsLayer::new(config, &self.streams.turn.links[index].url.host) {
                        Ok(layer) => Some(Box::new(layer)),
                        Err(err) => {
                            debug!("TURN TLS: {err}");
                            self.streams.turn.links[index].state = LinkState::Failed;
                            break;
                        }
                    }
                } else {
                    None
                };
                match self.streams.table.connect(
                    any_of_family(addr),
                    addr,
                    Framing::Turn,
                    TURN,
                    false,
                    layer,
                ) {
                    Ok(id) => self.streams.turn.links[index].attempts.push(id),
                    Err(_) => {
                        if let Some(r) = self.streams.turn.links[index].race.as_mut() {
                            r.failed();
                        }
                    }
                }
            }
            if self.streams.turn.links[index]
                .race
                .as_ref()
                .is_some_and(HappyEyeballs::exhausted)
            {
                // RFC 5928 section 3: the next SRV target, when there is one.
                if let Some(next) = self.streams.turn.links[index]
                    .discovery
                    .as_mut()
                    .map(|d| d.next_target())
                {
                    self.turn_discovery_next(index, next, now);
                } else {
                    debug!(
                        "TURN server {}: no address connected",
                        self.streams.turn.links[index].url
                    );
                    self.streams.turn.links[index].state = LinkState::Failed;
                    // W3C webrtc-pc 4.8.3: "If no host candidate can reach the server,
                    // errorCode will be set to the value 701".
                    let l = &self.streams.turn.links[index];
                    let (transport, url) = (l.transport, l.url_string());
                    self.report_engine_gathering_error(
                        transport,
                        None,
                        url,
                        crate::peer_connection::event::ICE_SERVER_UNREACHABLE,
                        "no address of the server answered".to_owned(),
                    );
                }
            }
        }
    }

    /// Acts on the next step of a link's discovery.
    fn turn_discovery_next(
        &mut self,
        index: usize,
        next: crate::peer_connection::dns_discovery::Next,
        now: Instant,
    ) {
        use crate::peer_connection::dns_discovery::Next;
        match next {
            Next::Records { name, kind } => {
                let query = self.streams.table.resolve_records(name, kind);
                let link = &mut self.streams.turn.links[index];
                link.state = LinkState::Discovering(query);
                if let Some(d) = link.discovery.as_mut() {
                    d.asked(query, now);
                }
            }
            Next::Address { host, port } => match host.parse::<IpAddr>() {
                Ok(ip) => {
                    let link = &mut self.streams.turn.links[index];
                    link.race = Some(HappyEyeballs::new(
                        vec![SocketAddr::new(ip, port)],
                        CONNECTION_ATTEMPT_DELAY,
                    ));
                    link.state = LinkState::Connecting;
                }
                Err(_) => {
                    let query = self.streams.table.resolve(host, port);
                    let link = &mut self.streams.turn.links[index];
                    link.state = LinkState::Resolving(query);
                    link.query = Some(query);
                    link.race = None;
                }
            },
            Next::Exhausted => {
                debug!(
                    "TURN server {}: no target connected",
                    self.streams.turn.links[index].url
                );
                self.streams.turn.links[index].state = LinkState::Failed;
            }
        }
    }

    /// The NAPTR or SRV records the driver looked up for a link (`None`: the query timed out).
    /// Returns whether the query was a link's.
    pub(crate) fn turn_records(
        &mut self,
        query: u64,
        records: &[shared::stream::DnsRecord],
    ) -> bool {
        let now = self.pipeline_context.now;
        let Some(index) = self
            .streams
            .turn
            .links
            .iter()
            .position(|l| l.state == LinkState::Discovering(query))
        else {
            return false;
        };
        let Some(next) = self.streams.turn.links[index]
            .discovery
            .as_mut()
            .map(|d| d.on_records(records))
        else {
            return false;
        };
        self.turn_discovery_next(index, next, now);
        self.drive_turn_races(now);
        true
    }

    /// A name the driver resolved: every address at once (`ipv6` `None`), or one family's
    /// as it arrived (RFC 8305 section 3: the race starts on the first answer, and a late one
    /// joins it).
    pub(crate) fn turn_resolved(
        &mut self,
        query: u64,
        ipv6: Option<bool>,
        addresses: &[SocketAddr],
    ) {
        let now = self.pipeline_context.now;
        if let Some(link) = self.streams.turn.links.iter_mut().find(|l| {
            l.query == Some(query)
                && (l.state == LinkState::Resolving(query)
                    || (l.state == LinkState::Connecting
                        && l.race.as_ref().is_some_and(HappyEyeballs::awaiting)))
        }) {
            match ipv6 {
                None => {
                    link.query = None;
                    // No address: an exhausted race, which moves on to the next SRV target
                    // or fails the link (`drive_turn_races`).
                    let sorted = sort_addresses(addresses, true);
                    link.race = Some(HappyEyeballs::new(sorted, CONNECTION_ATTEMPT_DELAY));
                    link.state = LinkState::Connecting;
                }
                Some(ipv6) => {
                    link.race
                        .get_or_insert_with(|| {
                            HappyEyeballs::awaiting_answers(CONNECTION_ATTEMPT_DELAY)
                        })
                        .answer(now, ipv6, addresses, true);
                    link.state = LinkState::Connecting;
                }
            }
        }
        self.drive_turn_races(now);
    }

    /// A TURN connection attempt connected: the race is won, the client starts.
    pub(crate) fn turn_connected(
        &mut self,
        now: Instant,
        id: StreamId,
        local: SocketAddr,
        remote: SocketAddr,
    ) {
        let Some(index) = self.streams.turn.link_of_stream(id) else {
            return;
        };
        if self.streams.turn.links[index].state != LinkState::Connecting {
            return;
        }
        let losers: Vec<StreamId> = self.streams.turn.links[index]
            .attempts
            .iter()
            .copied()
            .filter(|a| *a != id)
            .collect();
        for loser in losers {
            self.streams.table.reset(loser);
        }
        let Some(provider) = self.setting_engine.crypto_provider.clone() else {
            self.streams.turn.links[index].state = LinkState::Failed;
            return;
        };
        let link = &mut self.streams.turn.links[index];
        if let Some(race) = link.race.as_mut() {
            race.succeeded();
        }
        link.attempts = vec![id];
        link.state = LinkState::Open(id);
        link.server = Some(remote);
        link.link_local = Some(local);
        let config = turn::client::ClientConfig {
            stun_serv_addr: remote.to_string(),
            turn_serv_addr: remote.to_string(),
            local_addr: local,
            transport_protocol: TransportProtocol::TCP,
            username: link.url.username.clone(),
            password: link.url.password.clone(),
            realm: String::new(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: self
                .setting_engine
                .turn_allocation_refresh_interval_cap,
            software: self.setting_engine.turn_software(),
            ..Default::default()
        };
        let tcp = link.relay_tcp;
        match turn::client::Client::new(config, provider).and_then(|mut client| {
            if tcp {
                // RFC 6062 section 4.1: REQUESTED-TRANSPORT TCP.
                client.allocate_with(now, tcp_relay::tcp_allocation())?;
            } else {
                client.allocate(now)?;
            }
            Ok(client)
        }) {
            Ok(client) => link.client = Some(client),
            Err(err) => {
                debug!("TURN client for {}: {err}", link.url);
                link.state = LinkState::Failed;
            }
        }
        self.pump_turn(now);
    }

    /// A TURN connection attempt failed, or a TURN connection ended.
    pub(crate) fn turn_connection_ended(&mut self, now: Instant, id: StreamId) {
        let Some(index) = self.streams.turn.link_of_stream(id) else {
            return;
        };
        let link = &mut self.streams.turn.links[index];
        link.attempts.retain(|a| *a != id);
        match link.state {
            LinkState::Connecting => {
                if let Some(race) = link.race.as_mut() {
                    race.failed();
                }
                self.drive_turn_races(now);
            }
            LinkState::Open(open) if open == id => {
                // RFC 8656 section 3.1: the allocation lives as long as its connection.
                debug!(
                    "TURN connection to {} ended: its allocation is gone",
                    link.url
                );
                self.turn_allocation_lost(now, index);
            }
            _ => {}
        }
    }

    /// A link's allocation is gone with its connection (or DTLS association). RFC 6544 section
    /// 11.2: when the session uses an address that server allocated, the client "SHOULD
    /// reconnect to the TURN server, obtain a new allocation, and restart ICE": the link starts
    /// over and ICE is restarted (`restart_ice`: the next offer has new credentials, and the
    /// new generation announces the new relayed candidate). A link whose candidate is not in
    /// use has failed.
    pub(crate) fn turn_allocation_lost(&mut self, now: Instant, index: usize) {
        let in_use = self.relay_in_use(index);
        let link = &mut self.streams.turn.links[index];
        for conn in std::mem::take(&mut link.data) {
            if let Some(id) = conn.stream() {
                self.streams.table.close(id);
            }
        }
        let link = &mut self.streams.turn.links[index];
        link.client = None;
        link.relay = None;
        link.dtls = None;
        link.udp_attempts.clear();
        link.permitted.clear();
        link.attempts.clear();
        if in_use {
            debug!(
                "{}: reconnecting for a new allocation; ICE restarts",
                link.url
            );
            link.state = LinkState::Pending;
            link.race = None;
            link.query = None;
            link.discovery = None;
            link.announced_ufrag = None;
            self.restart_ice();
            self.start_turn_links();
        } else {
            link.state = LinkState::Failed;
        }
        let _ = now;
    }

    /// An Allocate of link `index` was refused (RFC 8656 section 7.4). A 300 (Try Alternate)
    /// is followed: the ALTERNATE-SERVER is tried before any other (7.4-3). A 486 or 508 holds
    /// the server back for a minute, a 437 for two (RFC 5928 section 3: also against later
    /// resolutions). Any refusal is the failure of that server: the resolution goes on with
    /// its next SRV target, and when there is none the link has failed until a new ICE
    /// generation restarts the resolution.
    fn turn_allocate_refused(
        &mut self,
        now: Instant,
        index: usize,
        err: turn::client::RequestError,
    ) {
        use stun::error_code::ErrorCode;
        let link = &mut self.streams.turn.links[index];
        let server = link.server;
        let base = link.link_local;
        let code = err.code();
        let (url, carrier, transport) = (link.url_string(), link.carrier, link.transport);
        if let Some(ErrorCode(c)) = code {
            self.pipeline_context.event_outs.push_back(
                crate::peer_connection::event::RTCPeerConnectionEvent::OnTurnRequestRejected {
                    url: url.clone(),
                    relay: None,
                    method: "Allocate",
                    error_code: c,
                },
            );
            // W3C webrtc-pc 4.8.3: gathering from the server failed with its error code.
            let reason = match &err {
                turn::client::RequestError::Rejected(r) => r.reason.clone(),
                other => format!("{other:?}"),
            };
            self.report_engine_gathering_error(transport, base, url, c, reason);
        }
        // RFC 8656 section 7.4, 437: "The client SHOULD pick another client transport address
        // and retry the Allocate request [...] The client SHOULD try three different client
        // transport addresses before giving up on this server." Over UDP the engine has the
        // application's sockets only: another UDP base of the transport, if there is one.
        if code == Some(ErrorCode(437))
            && carrier == Carrier::Udp
            && let (Some(base), Some(server)) = (base, server)
        {
            self.streams
                .turn
                .mismatched
                .retain(|(_, _, until)| now < *until);
            self.streams
                .turn
                .mismatched
                .push((base, server, now + Duration::from_secs(120)));
            let tried = self
                .streams
                .turn
                .mismatched
                .iter()
                .filter(|(_, s, _)| *s == server)
                .count();
            let other = self
                .streams
                .turn
                .udp_base(transport, server, |b| {
                    self.turn_base_usable(transport, b)
                        && !self.streams.turn.is_mismatched(b, server, now)
                })
                .is_some();
            if other && tried < 3 {
                debug!("{server}: 437 on {base}; allocating from another base");
                let link = &mut self.streams.turn.links[index];
                link.client = None;
                link.server = None;
                link.link_local = None;
                link.race = Some(HappyEyeballs::new(vec![server], CONNECTION_ATTEMPT_DELAY));
                link.state = LinkState::Connecting;
                self.drive_turn_races(now);
                return;
            }
        }
        // The connection (or association) to the refusing server is of no further use.
        let link = &mut self.streams.turn.links[index];
        if let LinkState::Open(id) = link.state {
            self.streams.table.close(id);
        }
        let link = &mut self.streams.turn.links[index];
        if let Some(mut dtls) = link.dtls.take() {
            let r = dtls.remote;
            let _ = dtls.endpoint.stop(now, r);
            dtls.flush(&mut self.pipeline_context.write_outs);
        }
        let link = &mut self.streams.turn.links[index];
        link.client = None;
        link.attempts.clear();
        for conn in std::mem::take(&mut link.data) {
            if let Some(id) = conn.stream() {
                self.streams.table.close(id);
            }
        }
        let hold = match code {
            Some(ErrorCode(486)) | Some(ErrorCode(508)) => Some(Duration::from_secs(60)),
            Some(ErrorCode(437)) => Some(Duration::from_secs(120)),
            _ => None,
        };
        if let (Some(hold), Some(server)) = (hold, server) {
            debug!("TURN server {server} held back for {hold:?}");
            self.streams
                .turn
                .held_back
                .retain(|(a, until)| *a != server && now < *until);
            self.streams.turn.held_back.push((server, now + hold));
        }
        let link = &mut self.streams.turn.links[index];
        if code == Some(ErrorCode(300))
            && link.redirects < MAX_REDIRECTS
            && let turn::client::RequestError::Rejected(response) = &err
            && let Some(alternate) = response.alternate_server
        {
            debug!("{}: trying the alternate server {alternate}", link.url);
            link.redirects += 1;
            link.race = Some(HappyEyeballs::new(
                vec![alternate],
                CONNECTION_ATTEMPT_DELAY,
            ));
            link.state = LinkState::Connecting;
            self.drive_turn_races(now);
            return;
        }
        if let Some(next) = link.discovery.as_mut().map(|d| d.next_target()) {
            link.state = LinkState::Connecting;
            self.turn_discovery_next(index, next, now);
            self.drive_turn_races(now);
        } else {
            link.state = LinkState::Failed;
        }
    }

    /// Whether the selected pair of the link's transport has its relayed candidate as the
    /// local one.
    fn relay_in_use(&self, index: usize) -> bool {
        let link = &self.streams.turn.links[index];
        let Some(relay) = link.relay else {
            return false;
        };
        self.ice_transport_of(link.transport)
            .agent
            .get_selected_candidate_pair()
            .is_some_and(|(local, _)| {
                let addr = local.addr();
                addr == relay || (link.relay_tcp && addr.ip() == relay.ip() && addr.port() == 9)
            })
    }

    /// RFC 6544 section 11.2: once ICE of a transport has completed, the connection to a TURN
    /// server whose relayed candidate the selected pair does not use is closed (it "MUST be
    /// kept open ... if a relayed candidate from the TURN server was selected"). Its
    /// allocation goes with it; a later ICE generation allocates again.
    pub(crate) fn close_settled_turn_links(&mut self) {
        for index in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[index];
            let LinkState::Open(id) = link.state else {
                continue;
            };
            if link.retiring {
                continue;
            }
            let completed = self
                .ice_transport_of(link.transport)
                .agent
                .get_selected_candidate_pair()
                .is_some();
            if !completed || link.relay.is_none() || self.relay_in_use(index) {
                continue;
            }
            debug!(
                "{}: ICE completed without its relayed candidate: closed",
                link.url
            );
            let link = &mut self.streams.turn.links[index];
            for conn in std::mem::take(&mut link.data) {
                if let Some(id) = conn.stream() {
                    self.streams.table.close(id);
                }
            }
            let link = &mut self.streams.turn.links[index];
            link.state = LinkState::Released;
            link.client = None;
            link.relay = None;
            link.attempts.clear();
            link.permitted.clear();
            self.streams.table.close(id);
        }
    }

    /// TURN messages read from a link.
    pub(crate) fn turn_messages(&mut self, now: Instant, id: StreamId, messages: Vec<Vec<u8>>) {
        let Some(index) = self.streams.turn.link_of_stream(id) else {
            return;
        };
        let link = &mut self.streams.turn.links[index];
        let (Some(server), Some(local)) = (link.server, link.link_local) else {
            return;
        };
        if let Some(client) = link.client.as_mut() {
            for message in messages {
                if let Err(err) = client.handle_read(TaggedBytesMut {
                    now,
                    transport: tcp_context(local, server),
                    message: BytesMut::from(&message[..]),
                }) {
                    debug!("TURN message from {server}: {err}");
                }
            }
        }
        self.pump_turn(now);
    }

    /// Moves what the TURN clients have to send onto their connections and acts on their
    /// events.
    pub(crate) fn pump_turn(&mut self, now: Instant) {
        self.pump_udp_attempts(now);
        let mut inbound = vec![];
        let mut announce = vec![];
        let mut peers_ready = vec![];
        let mut failed_peers = vec![];
        let mut refused = vec![];
        let mut rejected = vec![];
        for index in 0..self.streams.turn.links.len() {
            let link = &mut self.streams.turn.links[index];
            let id = match link.state {
                LinkState::Open(id) => Some(id),
                LinkState::OpenDtls | LinkState::OpenUdp => None,
                _ => continue,
            };
            let link_url = link.url_string();
            let Some(client) = link.client.as_mut() else {
                continue;
            };
            let mut granted = vec![];
            while let Some(event) = client.poll_event() {
                match event {
                    turn::client::Event::AllocateResponse(_, relayed) => {
                        link.relay = Some(relayed);
                        announce.push(index);
                    }
                    turn::client::Event::AllocateError(_, err) => {
                        debug!("TURN allocation on {} refused: {err:?}", link.url);
                        refused.push((index, err));
                    }
                    // Before the allocation the only request out is the Allocate: one that
                    // timed out (a silent server, or one whose only answer was an unsigned
                    // 400, RFC 8489 section 9.2.5) is that server's failure, as a refusal is.
                    turn::client::Event::TransactionTimeout(_) if link.relay.is_none() => {
                        debug!("TURN allocation on {} timed out", link.url);
                        refused.push((
                            index,
                            turn::client::RequestError::Failed(shared::error::Error::ErrTimeout),
                        ));
                    }
                    turn::client::Event::AllocationLost(_, err) => {
                        debug!("TURN allocation on {} lost: {err:?}", link.url);
                        rejected.push((link_url.clone(), link.relay, "Refresh", err.code()));
                        link.state = LinkState::Failed;
                        link.relay = None;
                    }
                    turn::client::Event::RefreshError(relay, err) => {
                        debug!("TURN Refresh on {} refused: {err:?}", link.url);
                        rejected.push((link_url.clone(), Some(relay), "Refresh", err.code()));
                    }
                    turn::client::Event::PermissionLost(relay, _, err) => {
                        rejected.push((
                            link_url.clone(),
                            Some(relay),
                            "CreatePermission",
                            err.code(),
                        ));
                    }
                    turn::client::Event::ChannelBindError(relay, _, err) => {
                        rejected.push((link_url.clone(), Some(relay), "ChannelBind", err.code()));
                    }
                    turn::client::Event::CreatePermissionResponse(_, peer) => {
                        granted.push(peer.ip());
                    }
                    turn::client::Event::CreatePermissionError(_, err) => {
                        debug!("TURN permission refused: {err:?}");
                        rejected.push((
                            link_url.clone(),
                            link.relay,
                            "CreatePermission",
                            err.code(),
                        ));
                    }
                    turn::client::Event::DataIndicationOrChannelData(_, peer, data) => {
                        if let Some(relay) = link.relay {
                            inbound.push((link.transport, relay, peer, data));
                        }
                    }
                    turn::client::Event::ConnectResponse(_, peer, connection_id) => {
                        peers_ready.push((index, peer, connection_id, false));
                    }
                    turn::client::Event::ConnectionAttempt(_, peer, connection_id) => {
                        peers_ready.push((index, peer, connection_id, true));
                    }
                    turn::client::Event::ConnectError(_, peer, err) => {
                        debug!("TURN Connect to {peer}: {err:?}");
                        failed_peers.push((index, peer));
                    }
                    _ => {}
                }
            }
            if let (Some(relay), Some(client)) = (link.relay, link.client.as_mut()) {
                for ip in granted {
                    for (peer, data) in link.held.remove(&ip).unwrap_or_default() {
                        if let Ok(mut r) = client.relay(relay) {
                            let _ = r.send_to(now, &data, peer);
                        }
                    }
                }
            }
            if let Some(client) = link.client.as_mut() {
                while let Some(transmit) = client.poll_write() {
                    match (id, link.dtls.as_mut()) {
                        (Some(id), _) => {
                            let _ = self.streams.table.send(id, &transmit.message);
                        }
                        (None, Some(dtls)) => {
                            let remote = dtls.remote;
                            if let Err(err) = dtls.endpoint.write(now, remote, &transmit.message) {
                                debug!("TURN over DTLS to {remote}: {err}");
                            }
                            dtls.flush(&mut self.pipeline_context.write_outs);
                        }
                        (None, None) if link.carrier == Carrier::Udp => {
                            if let (Some(base), Some(server)) = (link.link_local, link.server) {
                                self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                                    now,
                                    transport: udp_context(base, server),
                                    message: transmit.message,
                                });
                            }
                        }
                        (None, None) => {}
                    }
                }
            }
        }
        for index in announce {
            self.announce_relay_candidate(index);
        }
        for (index, peer, connection_id, attempt) in peers_ready {
            self.turn_tcp_peer_ready(index, peer, connection_id, attempt);
        }
        for (index, peer) in failed_peers {
            self.turn_tcp_connect_failed(now, index, peer);
        }
        // A request the server finally refused (the client retried a 401 / 438 already):
        // the application hears of it, a REST credential that expired, say.
        for (url, relay, method, code) in rejected {
            if let Some(code) = code {
                self.pipeline_context.event_outs.push_back(
                    crate::peer_connection::event::RTCPeerConnectionEvent::OnTurnRequestRejected {
                        url,
                        relay,
                        method,
                        error_code: code.0,
                    },
                );
            }
        }
        for (index, err) in refused {
            self.turn_allocate_refused(now, index, err);
        }
        for index in 0..self.streams.turn.links.len() {
            self.pump_turn_data(now, index);
        }
        for (transport, relay, peer, data) in inbound {
            // On the transport the relayed candidate is of.
            self.pipeline_context.observe(now);
            self.read_on_transport(
                transport,
                TaggedBytesMut {
                    now,
                    transport: TransportContext {
                        local_addr: relay,
                        peer_addr: peer,
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: data,
                },
            );
        }
        self.finish_deferred_gathering();
    }

    fn announce_relay_candidate(&mut self, index: usize) {
        let link = &self.streams.turn.links[index];
        let (Some(relay), Some(local)) = (link.relay, link.link_local) else {
            return;
        };
        let (url, protocol, transport) = (link.url_string(), link.protocol(), link.transport);
        // A TCP allocation: a passive relayed candidate, and on port 9 an active one (RFC
        // 6544 sections 4.5 and 5.5).
        let kinds: Vec<(&str, u16, Option<ice::tcp_type::TcpType>)> = if link.relay_tcp {
            vec![
                ("tcp", relay.port(), Some(ice::tcp_type::TcpType::Passive)),
                ("tcp", 9, Some(ice::tcp_type::TcpType::Active)),
            ]
        } else {
            vec![("udp", relay.port(), None)]
        };
        for (network, port, tcp_type) in kinds {
            let candidate = ice::candidate::candidate_relay::CandidateRelayConfig {
                base_config: ice::candidate::CandidateConfig {
                    network: network.to_owned(),
                    address: relay.ip().to_string(),
                    port,
                    component: 1,
                    ..Default::default()
                },
                rel_addr: local.ip().to_string(),
                rel_port: local.port(),
                ..Default::default()
            }
            .new_candidate_relay()
            .and_then(|mut c| {
                if let Some(tcp_type) = tcp_type {
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
                    if let Err(err) = self.add_engine_local_candidate(
                        transport,
                        &value,
                        Some(&url),
                        Some(protocol),
                    ) {
                        debug!("relayed candidate {relay} not added: {err}");
                    }
                    let ufrag = self
                        .ice_transport_of(transport)
                        .agent
                        .get_local_credentials()
                        .ufrag
                        .clone();
                    self.streams.turn.links[index].announced_ufrag = Some(ufrag);
                }
                Err(err) => debug!("relayed candidate {relay} not made: {err}"),
            }
        }
    }

    /// Sends a datagram the agent wrote from a relayed candidate through its TURN link: at
    /// once with a permission for the peer, else after one is created (RFC 8656 section 9).
    pub(crate) fn send_via_turn(&mut self, index: usize, msg: TaggedBytesMut) {
        let now = msg.now.max(self.pipeline_context.now);
        let peer = msg.transport.peer_addr;
        let link = &mut self.streams.turn.links[index];
        let (Some(relay), Some(client)) = (link.relay, link.client.as_mut()) else {
            return;
        };
        let Ok(mut r) = client.relay(relay) else {
            return;
        };
        match r.send_to(now, &msg.message, peer) {
            Ok(()) => {}
            Err(shared::error::Error::ErrNoPermission) => {
                let first = !link.held.contains_key(&peer.ip());
                let held = link.held.entry(peer.ip()).or_default();
                if held.len() < MAX_HELD_PER_PEER {
                    held.push((peer, msg.message.to_vec()));
                }
                if first && let Ok(mut r) = client.relay(relay) {
                    let _ = r.create_permission(now, peer);
                }
            }
            Err(err) => debug!("TURN send to {peer}: {err}"),
        }
        self.pump_turn(now);
    }

    /// A new DTLS association needs a new 3-tuple (RFC 8842 section 5.1), the relayed one
    /// included: each link of the active transport that holds an allocation deletes it (over
    /// UDP a Refresh of LIFETIME 0, RFC 8656 section 8; over TCP, TLS and DTLS its connection
    /// closes) and starts over, so that the new ICE generation announces the relayed
    /// candidate of a new allocation.
    pub(crate) fn reallocate_turn_links_of_active_transport(&mut self, now: Instant) {
        let transport = self.pipeline_context.transports.active_id();
        let mut ended = vec![];
        let out = &mut self.pipeline_context.write_outs;
        let releases = &mut self.streams.turn.releases;
        for l in self
            .streams
            .turn
            .links
            .iter_mut()
            .filter(|l| l.transport == transport && l.relay.is_some())
        {
            ended.extend(
                std::mem::take(&mut l.data)
                    .iter()
                    .filter_map(|c| c.stream()),
            );
            if let Some(a) = l.dtls.as_mut() {
                let _ = a.endpoint.close(now);
                a.flush(out);
            }
            release_udp_allocation(l, now, out, releases);
            if let LinkState::Open(id) = l.state {
                ended.push(id);
            }
            debug!("{}: a new DTLS association: allocating again", l.url);
            l.client = None;
            l.relay = None;
            l.dtls = None;
            l.udp_attempts.clear();
            l.permitted.clear();
            l.attempts.clear();
            l.state = LinkState::Pending;
            l.race = None;
            l.query = None;
            l.discovery = None;
            l.announced_ufrag = None;
        }
        for id in ended {
            self.streams.table.close(id);
        }
    }

    /// Closes links taken out of the engine (their server left the list a new generation
    /// took): their connections end, a DTLS association says close_notify, an allocation
    /// over UDP is deleted.
    fn close_turn_links(&mut self, mut links: Vec<TurnLink>) {
        let now = self.pipeline_context.now;
        let out = &mut self.pipeline_context.write_outs;
        let releases = &mut self.streams.turn.releases;
        let mut ended = vec![];
        for l in links.iter_mut() {
            ended.extend(l.attempts.iter().copied());
            ended.extend(l.data.iter().filter_map(|c| c.stream()));
            for a in l.dtls.iter_mut().chain(l.dtls_attempts.iter_mut()) {
                let _ = a.endpoint.close(now);
                a.flush(out);
            }
            release_udp_allocation(l, now, out, releases);
        }
        for id in ended {
            self.streams.table.close(id);
        }
    }

    /// Drops the links of transports a description removed, and their connections.
    pub(crate) fn release_removed_turn_links(&mut self) {
        let ids = self.pipeline_context.transports.ids();
        let mut ended = vec![];
        let now = self.pipeline_context.now;
        let out = &mut self.pipeline_context.write_outs;
        let releases = &mut self.streams.turn.releases;
        self.streams.turn.links.retain_mut(|l| {
            let kept = ids.contains(&l.transport);
            if !kept {
                ended.extend(l.attempts.iter().copied());
                ended.extend(l.data.iter().filter_map(|c| c.stream()));
                // A DTLS association says close_notify; an allocation over UDP is deleted.
                for a in l.dtls.iter_mut().chain(l.dtls_attempts.iter_mut()) {
                    let _ = a.endpoint.close(now);
                    a.flush(out);
                }
                release_udp_allocation(l, now, out, releases);
            }
            kept
        });
        self.streams.turn.made_for.retain(|t| ids.contains(t));
        self.streams.turn.servers.retain_transports(&ids);
        self.streams.turn.udp_bases.retain(|(t, _)| ids.contains(t));
        for id in ended {
            self.streams.table.close(id);
        }
    }

    /// The TURN clients' and races' next timer.
    pub(crate) fn turn_poll_timeout(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        for link in self.streams.turn.links.iter_mut() {
            let t = match link.state {
                LinkState::Discovering(_) => link.discovery.as_ref().and_then(|d| d.poll_timeout()),
                LinkState::Connecting => link
                    .race
                    .as_ref()
                    .and_then(HappyEyeballs::poll_timeout)
                    .into_iter()
                    .chain(
                        link.dtls_attempts
                            .iter()
                            .filter_map(|a| a.endpoint.poll_timeout(&a.remote)),
                    )
                    .chain(
                        link.udp_attempts
                            .iter_mut()
                            .filter_map(|a| a.client.poll_timeout()),
                    )
                    .min(),
                LinkState::Open(_) | LinkState::OpenUdp => {
                    link.client.as_mut().and_then(|c| c.poll_timeout())
                }
                LinkState::OpenDtls => link
                    .client
                    .as_mut()
                    .and_then(|c| c.poll_timeout())
                    .into_iter()
                    .chain(
                        link.dtls
                            .as_ref()
                            .and_then(|a| a.endpoint.poll_timeout(&a.remote)),
                    )
                    .min(),
                _ => None,
            };
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        }
        if let Some(t) = self.turn_data_poll_timeout() {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        if let Some(t) = self.turn_releases_poll_timeout() {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        // The end of a reallocation delay an Allocate waits for.
        let turn = &self.streams.turn;
        let waits = |base: SocketAddr, server: SocketAddr| {
            turn.links.iter().any(|l| {
                l.udp_attempts
                    .iter()
                    .any(|a| !a.sent && a.base == base && a.remote == server)
            })
        };
        if let Some(t) = turn
            .freed
            .iter()
            .filter(|(b, s, _)| waits(*b, *s))
            .map(|(_, _, at)| *at)
            .min()
        {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        next
    }

    /// Fires the TURN clients' and races' timers.
    pub(crate) fn turn_handle_timeout(&mut self, now: Instant) {
        // A DTLS link whose base was added before the local description starts now.
        self.start_turn_links();
        self.turn_releases_handle_timeout(now);
        self.start_waiting_udp_attempts(now);
        if self.streams.turn.links.is_empty() {
            return;
        }
        for link in self.streams.turn.links.iter_mut() {
            if let (LinkState::Open(_) | LinkState::OpenDtls | LinkState::OpenUdp, Some(client)) =
                (link.state, link.client.as_mut())
                && let Err(err) = client.handle_timeout(now)
            {
                debug!("TURN client timer: {err}");
            }
            for a in link.udp_attempts.iter_mut() {
                if a.client.poll_timeout().is_some_and(|t| t <= now)
                    && let Err(err) = a.client.handle_timeout(now)
                {
                    debug!("TURN Allocate to {}: {err}", a.remote);
                }
            }
        }
        // An Allocate that lost its race and was never answered is forgotten.
        self.streams.turn.udp_losers.retain_mut(|l| {
            l.client
                .poll_timeout()
                .is_some_and(|t| t + LOSER_GRACE > now)
        });
        self.turn_dtls_timeouts(now);
        self.turn_data_handle_timeout(now);
        // A records query the driver did not answer counts as empty.
        let unanswered: Vec<u64> = self
            .streams
            .turn
            .links
            .iter()
            .filter_map(|l| match l.state {
                LinkState::Discovering(q)
                    if l.discovery.as_ref().is_some_and(|d| d.timed_out(now)) =>
                {
                    Some(q)
                }
                _ => None,
            })
            .collect();
        for query in unanswered {
            self.turn_records(query, &[]);
        }
        self.drive_turn_races(now);
        self.pump_turn(now);
        self.release_retired_turn_links();
    }

    /// Raises `icecandidateerror` (W3C webrtc-pc 4.8.3) for a server the engine gathers from
    /// itself: `base`, the local address it used (left out when no candidate exposes it),
    /// the server's URL, its STUN error code or 701.
    pub(crate) fn report_engine_gathering_error(
        &mut self,
        transport: TransportId,
        base: Option<SocketAddr>,
        url: String,
        error_code: u16,
        error_text: String,
    ) {
        let error = crate::peer_connection::event::RTCPeerConnectionIceErrorEvent {
            address: base.map(|b| b.ip().to_string()).unwrap_or_default(),
            port: base.map_or(0, |b| b.port()),
            url,
            error_code,
            error_text,
            ice_transport: Some(self.ice_transport_of(transport).id),
        };
        if let Err(err) = self.report_ice_candidate_error(error) {
            debug!("icecandidateerror not raised: {err}");
        }
    }

    /// Whether the relayed candidate of `link` is the local end of the path the agent of its
    /// transport sends data on, or still takes data on (the path an ICE restart replaced, for
    /// `RETIRED_MEDIA_PATH_GRACE` after the restart selected its pair).
    fn turn_relay_carries_data(&self, link: &TurnLink) -> bool {
        let Some(relay) = link.relay else {
            return false;
        };
        let agent = &self.ice_transport_of(link.transport).agent;
        [agent.media_path(), agent.retired_media_path()]
            .into_iter()
            .flatten()
            .any(|p| {
                p.local_addr == relay
                    || (link.relay_tcp
                        && p.local_addr.ip() == relay.ip()
                        && p.local_addr.port() == 9)
            })
    }

    /// Withdraws the relayed candidate(s) of `relay` from the agent of `transport` (UDP, or
    /// the passive and active TCP candidates of a TCP allocation).
    fn withdraw_relay_candidate(&mut self, transport: TransportId, relay: SocketAddr, tcp: bool) {
        let now = self.pipeline_context.now;
        let targets: Vec<(SocketAddr, TransportProtocol)> = if tcp {
            vec![
                (relay, TransportProtocol::TCP),
                (SocketAddr::new(relay.ip(), 9), TransportProtocol::TCP),
            ]
        } else {
            vec![(relay, TransportProtocol::UDP)]
        };
        self.with_transport(transport, |pc| {
            for (addr, protocol) in targets {
                pc.ice_transport_mut()
                    .agent
                    .withdraw_local_candidate(now, addr, protocol);
            }
        });
    }

    /// Releases the retiring links whose relayed candidate no longer carries data (the
    /// restart's pair is selected and the previous path's grace is over) or whose allocation is
    /// gone: an allocation over UDP is deleted with a Refresh of LIFETIME 0 (RFC 8656 section
    /// 7), a DTLS association says close_notify, a connection closes. The links are dropped.
    pub(crate) fn release_retired_turn_links(&mut self) {
        for i in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[i];
            if link.retiring
                && link.client.is_some()
                && link.state != LinkState::Failed
                && !self.turn_relay_carries_data(link)
            {
                debug!(
                    "{}: the data left its relayed candidate: released",
                    link.url
                );
                self.release_turn_link_in_place(i);
            }
        }
        self.streams
            .turn
            .links
            .retain(|l| !(l.retiring && (l.client.is_none() || l.state == LinkState::Failed)));
    }

    /// Releases link `i` where it is (its index stays valid): its connections end, a DTLS
    /// association says close_notify, an allocation over UDP is deleted with a Refresh of
    /// LIFETIME 0; it holds no client or relayed address afterwards.
    fn release_turn_link_in_place(&mut self, i: usize) {
        let now = self.pipeline_context.now;
        let out = &mut self.pipeline_context.write_outs;
        let link = &mut self.streams.turn.links[i];
        let mut ended: Vec<StreamId> = std::mem::take(&mut link.attempts);
        ended.extend(
            std::mem::take(&mut link.data)
                .iter()
                .filter_map(|c| c.stream()),
        );
        if let LinkState::Open(id) = link.state {
            ended.push(id);
        }
        for a in link.dtls.iter_mut().chain(link.dtls_attempts.iter_mut()) {
            let _ = a.endpoint.close(now);
            a.flush(out);
        }
        release_udp_allocation(link, now, out, &mut self.streams.turn.releases);
        link.client = None;
        link.relay = None;
        link.dtls = None;
        link.dtls_attempts.clear();
        link.udp_attempts.clear();
        link.permitted.clear();
        link.held.clear();
        link.state = LinkState::Released;
        for id in ended {
            self.streams.table.close(id);
        }
    }

    /// The UDP base of `transport` a new link to `server` starts from: one no other link holds
    /// an allocation or a DTLS association from to that address, since an allocation is its
    /// 5-tuple's (RFC 8656 section 2.2: a second allocation "must" use "a different 5-tuple";
    /// an Allocate on one in use is answered 437, section 7.2). When every base is taken by a
    /// retiring link (one socket, the same server), that link is released first and its base
    /// is used: break before make.
    fn turn_free_udp_base(
        &mut self,
        transport: TransportId,
        server: SocketAddr,
    ) -> Option<SocketAddr> {
        let taken = |links: &[TurnLink], base: SocketAddr| {
            links.iter().any(|l| {
                l.on_datagrams()
                    && l.client.is_some()
                    && l.link_local == Some(base)
                    && l.server == Some(server)
            })
        };
        let now = self.pipeline_context.now;
        if let Some(base) = self.streams.turn.udp_base(transport, server, |base| {
            self.turn_base_usable(transport, base)
                && !taken(&self.streams.turn.links, base)
                && !self.streams.turn.is_mismatched(base, server, now)
        }) {
            return Some(base);
        }
        let base = self.turn_udp_base(transport, server)?;
        for i in 0..self.streams.turn.links.len() {
            let l = &self.streams.turn.links[i];
            if l.retiring
                && l.client.is_some()
                && l.link_local == Some(base)
                && l.server == Some(server)
            {
                debug!(
                    "{}: its 5-tuple ({base} to {server}) is needed by a new allocation: released first",
                    l.url
                );
                let url = l.url_string();
                self.release_turn_link_in_place(i);
                self.pipeline_context.event_outs.push_back(
                    crate::peer_connection::event::RTCPeerConnectionEvent::OnTurnAllocationReplacedInPlace {
                        url,
                        local_address: base,
                    },
                );
            }
        }
        Some(base)
    }
}

impl RTCPeerConnection {
    /// A UDP host candidate the application added (`candidate_value`), on the active
    /// transport: its base is where that transport's DTLS links start (RFC 7350). Whether ICE
    /// took the candidate does not matter (with the `relay` policy it does not): the socket is
    /// the application's either way.
    pub(crate) fn note_udp_base_for_turn(&mut self, candidate_value: &str) {
        if !(self.streams.turn.enabled
            || self.streams.turn.relay_gathering == RelayGathering::Engine)
            || self.is_closed()
        {
            return;
        }
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        if candidate.candidate_type() != ice::candidate::CandidateType::Host
            || candidate.network_type().is_tcp()
        {
            return;
        }
        let Ok(ip) = candidate.address().parse::<IpAddr>() else {
            return;
        };
        let on = self.pipeline_context.transports.active_id();
        self.streams
            .turn
            .note_udp_base(on, SocketAddr::new(ip, candidate.port()));
        self.start_turn_links();
    }

    /// The DTLS client configuration of a link to `host` (RFC 7350 section 4, RFC 8656
    /// section 3.1): the server's certificate is checked against the URI's host with the roots
    /// or the verifier of `with_turn_tls`; only forward-secret AEAD suites (BCP 195, RFC 7350
    /// 4-2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 among them). `None` when nothing could
    /// verify a server.
    fn turn_dtls_config(&self, host: &str) -> Option<Arc<dtls::config::HandshakeConfig>> {
        use dtls::cipher_suite::CipherSuiteId;
        let provider = self.setting_engine.crypto_provider.clone()?;
        let tls = self.streams.turn.tls_config();
        let mut builder = dtls::config::ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_server_name(host.to_owned())
            .with_cipher_suites(vec![
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
                CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256,
                CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Aes_256_Gcm_Sha384,
                CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
            ])
            .with_extended_master_secret(dtls::config::ExtendedMasterSecretType::Request);
        if let Some(verifier) = &tls.verifier {
            builder = builder.with_server_cert_verifier(verifier.clone());
        } else if let Some(roots) = &tls.roots {
            builder = builder.with_roots_cas((**roots).clone());
        } else if tls.webpki_roots {
            #[cfg(feature = "turn-tls-webpki-roots")]
            {
                builder = builder.with_roots_cas(rustls::RootCertStore {
                    roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
                });
            }
            #[cfg(not(feature = "turn-tls-webpki-roots"))]
            {
                return None;
            }
        } else {
            return None;
        }
        if tls.disable_tls12 {
            builder = builder.with_protocol_versions(
                dtls::config::DtlsVersion::Dtls1_3,
                dtls::config::DtlsVersion::Dtls1_3,
            );
        }
        match builder.build(true, None) {
            Ok(config) => Some(Arc::new(config)),
            Err(err) => {
                debug!("TURN DTLS configuration: {err}");
                None
            }
        }
    }

    /// Whether a link of `transport` may start from the UDP base `base`: not when it is a
    /// transport address of a DTLS association a new one replaced (RFC 8842 section 5.1: the
    /// new association's 3-tuple is a new one, the relayed one included, so its allocation
    /// is made from a base the application gathered for it).
    fn turn_base_usable(&self, transport: TransportId, base: SocketAddr) -> bool {
        !self
            .ice_transport_of(transport)
            .previous_association_addresses
            .contains(&base)
    }

    /// The UDP base of `transport` of the family of `server` a link starts from
    /// ([`Self::turn_base_usable`]).
    fn turn_udp_base(&self, transport: TransportId, server: SocketAddr) -> Option<SocketAddr> {
        self.streams.turn.udp_base(transport, server, |base| {
            self.turn_base_usable(transport, base)
        })
    }

    /// Starts a DTLS handshake to `addr` for link `index`, from the transport's UDP base of
    /// that family. Returns whether it started; a link nothing can verify has failed.
    fn start_dtls_attempt(&mut self, now: Instant, index: usize, addr: SocketAddr) -> bool {
        let (transport, host) = {
            let l = &self.streams.turn.links[index];
            (l.transport, l.url.host.clone())
        };
        let Some(base) = self.turn_free_udp_base(transport, addr) else {
            debug!("TURN over DTLS to {addr}: no UDP base of that family");
            return false;
        };
        let Some(config) = self.turn_dtls_config(&host) else {
            debug!("turns: DTLS server without roots or a verifier to check it: not used");
            self.streams.turn.links[index].state = LinkState::Failed;
            return false;
        };
        let mut endpoint = dtls::endpoint::Endpoint::new(base, TransportProtocol::UDP, None);
        if let Err(err) = endpoint.connect(now, addr, config, None) {
            debug!("TURN over DTLS to {addr}: {err}");
            return false;
        }
        let mut attempt = DtlsAttempt {
            remote: addr,
            base,
            endpoint,
        };
        attempt.flush(&mut self.pipeline_context.write_outs);
        self.streams.turn.links[index].dtls_attempts.push(attempt);
        true
    }

    /// Takes a datagram of a DTLS link (from a server's address to the base an association
    /// runs on) before ICE sees it; returns anything else.
    pub(crate) fn take_turn_dtls(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if msg.transport.transport_protocol != TransportProtocol::UDP
            || !msg.message.first().is_some_and(|b| (20..=63).contains(b))
        {
            return Some(msg);
        }
        let (base, remote) = (msg.transport.local_addr, msg.transport.peer_addr);
        let Some(index) = self.streams.turn.link_of_dtls(base, remote) else {
            return Some(msg);
        };
        let now = msg.now;
        let won = self.streams.turn.links[index]
            .dtls
            .as_ref()
            .is_some_and(|a| a.base == base && a.remote == remote);
        let link = &mut self.streams.turn.links[index];
        let Some(attempt) = link.dtls_to(base, remote) else {
            return Some(msg);
        };
        let result = attempt
            .endpoint
            .read(now, remote, msg.transport.ecn, msg.message);
        attempt.flush(&mut self.pipeline_context.write_outs);
        match result {
            Err(err) => {
                debug!("TURN over DTLS from {remote}: {err}");
                let failed = attempt.endpoint.is_connection_failed(&remote)
                    || attempt.endpoint.get_connection_state(remote).is_none();
                if failed {
                    self.turn_dtls_ended(now, index, base, remote, won);
                }
            }
            Ok(events) => {
                for event in events {
                    match event {
                        dtls::endpoint::EndpointEvent::HandshakeComplete if !won => {
                            self.turn_dtls_won(now, index, base, remote);
                        }
                        dtls::endpoint::EndpointEvent::ApplicationData(data) => {
                            let link = &mut self.streams.turn.links[index];
                            if let Some(client) = link.client.as_mut()
                                && let Err(err) = client.handle_read(TaggedBytesMut {
                                    now,
                                    transport: TransportContext {
                                        local_addr: base,
                                        peer_addr: remote,
                                        transport_protocol: TransportProtocol::UDP,
                                        ecn: None,
                                    },
                                    message: data,
                                })
                            {
                                debug!("TURN message from {remote}: {err}");
                            }
                        }
                        dtls::endpoint::EndpointEvent::PeerClosed => {
                            self.turn_dtls_ended(now, index, base, remote, won);
                        }
                        _ => {}
                    }
                }
            }
        }
        self.pump_turn(now);
        None
    }

    /// A DTLS handshake of link `index` completed: the race is won, the TURN client starts
    /// over the association, with UDP's retransmissions (RFC 7350 section 4).
    fn turn_dtls_won(&mut self, now: Instant, index: usize, base: SocketAddr, remote: SocketAddr) {
        let link = &mut self.streams.turn.links[index];
        if link.state != LinkState::Connecting {
            return;
        }
        let Some(position) = link
            .dtls_attempts
            .iter()
            .position(|a| a.base == base && a.remote == remote)
        else {
            return;
        };
        let winner = link.dtls_attempts.remove(position);
        for mut loser in std::mem::take(&mut link.dtls_attempts) {
            let r = loser.remote;
            let _ = loser.endpoint.stop(now, r);
            loser.flush(&mut self.pipeline_context.write_outs);
        }
        if let Some(race) = link.race.as_mut() {
            race.succeeded();
        }
        link.dtls = Some(winner);
        link.state = LinkState::OpenDtls;
        link.server = Some(remote);
        link.link_local = Some(base);
        let Some(provider) = self.setting_engine.crypto_provider.clone() else {
            link.state = LinkState::Failed;
            return;
        };
        let config = turn::client::ClientConfig {
            stun_serv_addr: remote.to_string(),
            turn_serv_addr: remote.to_string(),
            local_addr: base,
            transport_protocol: TransportProtocol::UDP,
            username: link.url.username.clone(),
            password: link.url.password.clone(),
            realm: String::new(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: self
                .setting_engine
                .turn_allocation_refresh_interval_cap,
            software: self.setting_engine.turn_software(),
            ..Default::default()
        };
        match turn::client::Client::new(config, provider).and_then(|mut client| {
            client.allocate(now)?;
            Ok(client)
        }) {
            Ok(client) => link.client = Some(client),
            Err(err) => {
                debug!("TURN client for {}: {err}", link.url);
                link.state = LinkState::Failed;
            }
        }
    }

    /// A DTLS association of link `index` failed or was closed: a racing one fails its
    /// address; the one that won takes the allocation with it.
    fn turn_dtls_ended(
        &mut self,
        now: Instant,
        index: usize,
        base: SocketAddr,
        remote: SocketAddr,
        won: bool,
    ) {
        if won {
            debug!("TURN over DTLS to {remote} ended: its allocation is gone");
            // RFC 6544 section 11.2: "Similar measures SHOULD apply also to other types of
            // relaying servers".
            self.turn_allocation_lost(now, index);
            return;
        }
        let link = &mut self.streams.turn.links[index];
        link.dtls_attempts
            .retain(|a| !(a.base == base && a.remote == remote));
        if link.state == LinkState::Connecting {
            if let Some(race) = link.race.as_mut() {
                race.failed();
            }
            self.drive_turn_races(now);
        }
    }

    /// The DTLS associations' timers: handshake retransmissions and give-up.
    fn turn_dtls_timeouts(&mut self, now: Instant) {
        let mut ended = vec![];
        for (index, link) in self.streams.turn.links.iter_mut().enumerate() {
            let won = link.dtls.as_mut().map(|a| (a, true));
            let racing = link.dtls_attempts.iter_mut().map(|a| (a, false));
            for (a, won) in won.into_iter().chain(racing) {
                let remote = a.remote;
                if !a.endpoint.poll_timeout(&remote).is_some_and(|t| t <= now) {
                    continue;
                }
                let result = a.endpoint.handle_timeout(remote, now);
                a.flush(&mut self.pipeline_context.write_outs);
                if let Err(err) = result {
                    debug!("TURN over DTLS to {remote}: {err}");
                    ended.push((index, a.base, remote, won));
                }
            }
        }
        for (index, base, remote, won) in ended {
            self.turn_dtls_ended(now, index, base, remote, won);
        }
    }

    /// `close()`: every DTLS association says close_notify, every allocation over UDP is
    /// deleted (a Refresh of LIFETIME 0, RFC 8656 section 8).
    pub(crate) fn close_turn_dtls(&mut self) {
        let now = self.pipeline_context.now;
        for link in self.streams.turn.links.iter_mut() {
            for a in link.dtls.iter_mut().chain(link.dtls_attempts.iter_mut()) {
                let _ = a.endpoint.close(now);
                a.flush(&mut self.pipeline_context.write_outs);
            }
            release_udp_allocation(
                link,
                now,
                &mut self.pipeline_context.write_outs,
                &mut self.streams.turn.releases,
            );
        }
        // The Allocates that lost a race and are still unanswered: an answer that is an
        // allocation has it deleted.
        for loser in std::mem::take(&mut self.streams.turn.udp_losers) {
            self.streams.turn.releases.push(UdpRelease {
                url: loser.url,
                base: loser.base,
                server: loser.remote,
                client: loser.client,
                relay: None,
                signed: false,
                done: false,
            });
        }
        self.pump_turn_releases(now);
    }

    /// Moves the releases on (`UdpRelease`): what their clients send leaves from their base,
    /// an Allocate success is deleted at once, and a release that is done is dropped with an
    /// `OnTurnAllocationReleased`: its Refresh of LIFETIME 0 was answered (or 437) or timed
    /// out, or the Allocate was answered without an allocation, refused, or timed out.
    pub(crate) fn pump_turn_releases(&mut self, now: Instant) {
        for r in self.streams.turn.releases.iter_mut() {
            while let Some(event) = r.client.poll_event() {
                match event {
                    turn::client::Event::AllocateResponse(_, relay) => {
                        debug!("{}: an allocation nobody needs ({relay}): deleted", r.url);
                        if let Ok(mut x) = r.client.relay(relay) {
                            let _ = x.close(now);
                        }
                        r.relay = Some(relay);
                        r.signed = true;
                    }
                    turn::client::Event::AllocationReleased(_) => r.done = true,
                    turn::client::Event::AllocateError(..)
                    | turn::client::Event::TransactionTimeout(_)
                        if r.relay.is_none() =>
                    {
                        r.done = true
                    }
                    _ => {}
                }
            }
            while let Some(t) = r.client.poll_write() {
                if r.done {
                    continue;
                }
                self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                    now,
                    transport: udp_context(r.base, r.server),
                    message: t.message,
                });
            }
            // Nothing under way any more (no allocation was ever asked with the credential).
            if r.relay.is_none() && r.client.poll_timeout().is_none() {
                r.done = true;
            }
        }
        let delay = self.setting_engine.turn_reallocation_delay;
        self.streams.turn.freed.retain(|(_, _, at)| now < *at);
        let mut ended = false;
        let mut i = 0;
        while i < self.streams.turn.releases.len() {
            if !self.streams.turn.releases[i].done {
                i += 1;
                continue;
            }
            let r = self.streams.turn.releases.remove(i);
            debug!("{}: released from {}", r.url, r.base);
            ended = true;
            if !delay.is_zero() {
                self.streams
                    .turn
                    .freed
                    .push((r.base, r.server, now + delay));
            }
            self.pipeline_context.event_outs.push_back(
                crate::peer_connection::event::RTCPeerConnectionEvent::OnTurnAllocationReleased {
                    url: r.url,
                    local_address: r.base,
                    relayed_address: r.relay,
                },
            );
        }
        // An Allocate that waited for one of these 5-tuples leaves now.
        if ended {
            self.start_waiting_udp_attempts(now);
        }
    }

    /// The releases' next timer (all a closed peer connection still has).
    pub(crate) fn turn_releases_poll_timeout(&mut self) -> Option<Instant> {
        self.streams
            .turn
            .releases
            .iter_mut()
            .filter_map(|r| r.client.poll_timeout())
            .min()
    }

    /// Fires the releases' timers (retransmissions, transaction timeouts).
    pub(crate) fn turn_releases_handle_timeout(&mut self, now: Instant) {
        for r in self.streams.turn.releases.iter_mut() {
            if r.client.poll_timeout().is_some_and(|t| t <= now)
                && let Err(err) = r.client.handle_timeout(now)
            {
                debug!("TURN release timer: {err}");
            }
        }
        self.pump_turn_releases(now);
    }

    /// An answer to one of the releases' transactions (taken out of `handle_read` before
    /// anything else sees it), or `msg` back.
    pub(crate) fn take_turn_release(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if self.streams.turn.releases.is_empty() || !matches!(stun_class(&msg.message), Some(2 | 3))
        {
            return Some(msg);
        }
        let (base, remote) = (msg.transport.local_addr, msg.transport.peer_addr);
        let mut id = [0u8; 12];
        id.copy_from_slice(&msg.message[8..20]);
        let tid = stun::message::TransactionId(id);
        let now = msg.now;
        let Some(r) = self.streams.turn.releases.iter_mut().find(|r| {
            !r.done && r.base == base && r.server == remote && r.client.has_transaction(&tid)
        }) else {
            return Some(msg);
        };
        if let Err(err) = r.client.handle_read(msg) {
            debug!("TURN message from {remote}: {err}");
        }
        if !r.signed {
            // The answer to the unauthenticated Allocate. A 401 made nothing: the request with
            // the credential it asks for is not sent. A success (a server that does not
            // authenticate) is an allocation, deleted (`pump_turn_releases`).
            while r.client.poll_write().is_some() {}
            let made = std::iter::from_fn(|| r.client.poll_event()).find_map(|e| match e {
                turn::client::Event::AllocateResponse(_, relay) => Some(relay),
                _ => None,
            });
            match made {
                Some(relay) => {
                    if let Ok(mut x) = r.client.relay(relay) {
                        let _ = x.close(now);
                    }
                    r.relay = Some(relay);
                    r.signed = true;
                }
                None => r.done = true,
            }
        }
        self.pump_turn_releases(now);
        None
    }

    /// Starts an unauthenticated Allocate to `addr` for the UDP link `index`, from the
    /// transport's UDP base of that family (RFC 8656 section 3.9). Returns whether it started.
    fn start_udp_attempt(&mut self, now: Instant, index: usize, addr: SocketAddr) -> bool {
        let transport = self.streams.turn.links[index].transport;
        let Some(base) = self.turn_free_udp_base(transport, addr) else {
            debug!("TURN over UDP to {addr}: no UDP base of that family");
            return false;
        };
        let Some(provider) = self.setting_engine.crypto_provider.clone() else {
            return false;
        };
        let link = &self.streams.turn.links[index];
        let url = link.url_string();
        let config = turn::client::ClientConfig {
            stun_serv_addr: addr.to_string(),
            turn_serv_addr: addr.to_string(),
            local_addr: base,
            transport_protocol: TransportProtocol::UDP,
            username: link.url.username.clone(),
            password: link.url.password.clone(),
            realm: String::new(),
            rto_in_ms: 0,
            allocation_refresh_interval_cap: self
                .setting_engine
                .turn_allocation_refresh_interval_cap,
            software: self.setting_engine.turn_software(),
            ..Default::default()
        };
        // The 5-tuple's previous allocation is still being deleted: the Allocate waits for
        // the release to end (`start_waiting_udp_attempts`).
        let sent = !self.streams.turn.five_tuple_in_release(base, addr, now);
        let mut client = match turn::client::Client::new(config, provider).and_then(|mut c| {
            if sent {
                c.allocate(now)?;
            }
            Ok(c)
        }) {
            Ok(client) => client,
            Err(err) => {
                debug!("TURN client for {addr}: {err}");
                return false;
            }
        };
        if !sent {
            debug!(
                "TURN over UDP to {addr}: the allocation from {base} is being deleted; the Allocate waits"
            );
        }
        while let Some(t) = client.poll_write() {
            self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                now,
                transport: udp_context(base, addr),
                message: t.message,
            });
        }
        self.streams.turn.links[index]
            .udp_attempts
            .push(UdpAttempt {
                url,
                remote: addr,
                base,
                client,
                sent,
            });
        true
    }

    /// Sends the Allocates that waited for a release of their 5-tuple, once it has ended (and
    /// the reallocation delay after it is over). One that cannot be sent fails its address.
    pub(crate) fn start_waiting_udp_attempts(&mut self, now: Instant) {
        if self.is_closed() {
            return;
        }
        let mut failed = false;
        for index in 0..self.streams.turn.links.len() {
            let mut i = 0;
            while i < self.streams.turn.links[index].udp_attempts.len() {
                let a = &self.streams.turn.links[index].udp_attempts[i];
                if a.sent
                    || self
                        .streams
                        .turn
                        .five_tuple_in_release(a.base, a.remote, now)
                {
                    i += 1;
                    continue;
                }
                let a = &mut self.streams.turn.links[index].udp_attempts[i];
                if let Err(err) = a.client.allocate(now) {
                    debug!("TURN client for {}: {err}", a.remote);
                    self.streams.turn.links[index].udp_attempts.remove(i);
                    if let Some(race) = self.streams.turn.links[index].race.as_mut() {
                        race.failed();
                    }
                    failed = true;
                    continue;
                }
                a.sent = true;
                debug!(
                    "TURN over UDP to {}: the 5-tuple is free; Allocate sent",
                    a.remote
                );
                while let Some(t) = a.client.poll_write() {
                    self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                        now,
                        transport: udp_context(a.base, a.remote),
                        message: t.message,
                    });
                }
                i += 1;
            }
        }
        if failed {
            self.drive_turn_races(now);
        }
    }

    /// The racing Allocates over UDP: their retransmissions leave, and one that timed out (or
    /// failed before any answer) fails its address: the next one starts at once.
    fn pump_udp_attempts(&mut self, now: Instant) {
        let mut failed = vec![];
        for index in 0..self.streams.turn.links.len() {
            let link = &mut self.streams.turn.links[index];
            if link.udp_attempts.is_empty() {
                continue;
            }
            let mut lost = vec![];
            for (i, a) in link.udp_attempts.iter_mut().enumerate() {
                while let Some(t) = a.client.poll_write() {
                    self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                        now,
                        transport: udp_context(a.base, a.remote),
                        message: t.message,
                    });
                }
                while let Some(event) = a.client.poll_event() {
                    if matches!(
                        event,
                        turn::client::Event::TransactionTimeout(_)
                            | turn::client::Event::AllocateError(..)
                    ) {
                        debug!("TURN Allocate to {}: no answer", a.remote);
                        lost.push(i);
                    }
                }
            }
            lost.dedup();
            for i in lost.into_iter().rev() {
                link.udp_attempts.remove(i);
                if let Some(race) = link.race.as_mut() {
                    race.failed();
                }
                failed.push(index);
            }
        }
        if !failed.is_empty() {
            self.drive_turn_races(now);
        }
    }

    /// Takes a datagram of a UDP link (from a server's address to the base it runs on) before
    /// ICE sees it: an answer to one of its transactions, or a Data indication or ChannelData
    /// on its allocation; returns anything else (the application's own TURN client may share
    /// the socket).
    pub(crate) fn take_turn_udp(&mut self, msg: TaggedBytesMut) -> Option<TaggedBytesMut> {
        if msg.transport.transport_protocol != TransportProtocol::UDP
            || (self.streams.turn.links.is_empty()
                && self.streams.turn.udp_losers.is_empty()
                && self.streams.turn.releases.is_empty())
        {
            return Some(msg);
        }
        let msg = self.take_turn_release(msg)?;
        let class = stun_class(&msg.message);
        let channel_data = msg.message.len() >= 4 && (0x40..=0x4f).contains(&msg.message[0]);
        if class.is_none() && !channel_data {
            return Some(msg);
        }
        let (base, remote) = (msg.transport.local_addr, msg.transport.peer_addr);
        let now = msg.now;
        let response = matches!(class, Some(2 | 3));
        let tid = (msg.message.len() >= 20).then(|| {
            let mut id = [0u8; 12];
            id.copy_from_slice(&msg.message[8..20]);
            stun::message::TransactionId(id)
        });
        // The answer to an Allocate that lost its race.
        if response
            && let Some(tid) = tid
            && let Some(i) = self.streams.turn.udp_losers.iter().position(|l| {
                l.base == base && l.remote == remote && l.client.has_transaction(&tid)
            })
        {
            let mut loser = self.streams.turn.udp_losers.remove(i);
            self.turn_udp_loser_answered(now, &mut loser, msg);
            return None;
        }
        let Some(index) = self.streams.turn.link_of_udp(base, remote) else {
            return Some(msg);
        };
        let link = &mut self.streams.turn.links[index];
        if link.state == LinkState::OpenUdp {
            let ours = match (class, tid) {
                (Some(2 | 3), Some(tid)) => link
                    .client
                    .as_ref()
                    .is_some_and(|c| c.has_transaction(&tid)),
                // A Data indication; ChannelData.
                (Some(1), _) | (None, _) => link.relay.is_some(),
                _ => false,
            };
            if !ours {
                return Some(msg);
            }
            if let Some(client) = link.client.as_mut()
                && let Err(err) = client.handle_read(msg)
            {
                debug!("TURN message from {remote}: {err}");
            }
            self.pump_turn(now);
            return None;
        }
        // The first answer of the race (a 401, or a success from a server that does not
        // authenticate) wins it (RFC 8656 section 3.9).
        let Some(tid) = tid.filter(|_| response) else {
            return Some(msg);
        };
        let Some(position) = link
            .udp_attempts
            .iter()
            .position(|a| a.base == base && a.remote == remote && a.client.has_transaction(&tid))
        else {
            return Some(msg);
        };
        if let Err(err) = link.udp_attempts[position].client.handle_read(msg) {
            debug!("TURN message from {remote}: {err}");
        }
        self.turn_udp_won(now, index, position);
        self.pump_turn(now);
        None
    }

    /// Attempt `position` of UDP link `index` was answered first: its client runs on, the
    /// others lose (kept until their answer: `turn_udp_loser_answered`).
    fn turn_udp_won(&mut self, now: Instant, index: usize, position: usize) {
        let link = &mut self.streams.turn.links[index];
        if link.state != LinkState::Connecting {
            return;
        }
        let winner = link.udp_attempts.remove(position);
        self.streams.turn.udp_losers.extend(
            std::mem::take(&mut link.udp_attempts)
                .into_iter()
                .filter(|a| a.sent),
        );
        if let Some(race) = link.race.as_mut() {
            race.succeeded();
        }
        link.state = LinkState::OpenUdp;
        link.server = Some(winner.remote);
        link.link_local = Some(winner.base);
        link.client = Some(winner.client);
        let _ = now;
    }

    /// The answer to an Allocate that lost its race (RFC 8656 section 3.9): a 401 is dropped
    /// (the connection "silently abandoned"), an allocation a server without authentication
    /// made is deleted with a Refresh of LIFETIME 0.
    fn turn_udp_loser_answered(
        &mut self,
        now: Instant,
        loser: &mut UdpAttempt,
        msg: TaggedBytesMut,
    ) {
        let _ = loser.client.handle_read(msg);
        // What the answer made the client send (the signed request after a 401) stays unsent.
        while loser.client.poll_write().is_some() {}
        let mut relayed = None;
        while let Some(event) = loser.client.poll_event() {
            if let turn::client::Event::AllocateResponse(_, addr) = event {
                relayed = Some(addr);
            }
        }
        let Some(relayed) = relayed else {
            return;
        };
        debug!(
            "TURN over UDP: the allocation {relayed} on {} lost the race; deleted",
            loser.remote
        );
        if let Ok(mut relay) = loser.client.relay(relayed) {
            let _ = relay.close(now);
        }
        while let Some(t) = loser.client.poll_write() {
            self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                now,
                transport: udp_context(loser.base, loser.remote),
                message: t.message,
            });
        }
    }

    /// A relayed candidate the application added itself (`candidate_value`, `url`) on the
    /// active transport: the engine's UDP links for that server (any, without a `url`) on that
    /// transport are left to it. One whose relayed candidate the engine has not announced yet
    /// stops (an allocation it holds is deleted); one already announced stays, since a
    /// signalled candidate cannot be taken back.
    pub(crate) fn note_application_relay(&mut self, candidate_value: &str, url: Option<&str>) {
        let Ok(candidate) = ice::candidate::unmarshal_candidate(candidate_value) else {
            return;
        };
        if candidate.candidate_type() != ice::candidate::CandidateType::Relay
            || candidate.network_type().is_tcp()
            || self.streams.turn.link_of_relay(candidate.addr()).is_some()
        {
            return;
        }
        let on = self.pipeline_context.transports.active_id();
        let url = url.map(str::to_owned);
        if !self
            .streams
            .turn
            .application_relays
            .contains(&(on, url.clone()))
        {
            self.streams.turn.application_relays.push((on, url));
        }
        let now = self.pipeline_context.now;
        for index in 0..self.streams.turn.links.len() {
            let link = &self.streams.turn.links[index];
            if !self.streams.turn.left_to_application(link) || link.announced_ufrag.is_some() {
                continue;
            }
            debug!(
                "{}: the application gathers from it; the engine stops",
                link.url
            );
            let link = &mut self.streams.turn.links[index];
            release_udp_allocation(
                link,
                now,
                &mut self.pipeline_context.write_outs,
                &mut self.streams.turn.releases,
            );
            link.client = None;
            link.relay = None;
            link.race = None;
            link.state = LinkState::Failed;
        }
        self.finish_deferred_gathering();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8656 section 3.1, RFC 7350 section 4.1: `turn:...?transport=tcp` (TCP), `turns:`
    /// (TLS over TCP), `turns:...?transport=udp` (DTLS) and `turn:` over UDP servers get a link
    /// per transport; with `RelayGathering::Application` a `turn:` server over UDP gets none.
    #[test]
    fn turn_servers_get_a_link_per_transport_over_udp_only_when_the_engine_gathers() {
        let urls: Vec<Url> = [
            "turn:192.0.2.1:3478?transport=tcp",
            "turns:turn.example:5349",
            "turns:192.0.2.1:5349?transport=tcp",
            "turn:192.0.2.1:3478",
            "turns:192.0.2.1:5349?transport=udp",
            "stun:192.0.2.1:3478",
        ]
        .iter()
        .map(|u| Url::parse_url(u).unwrap())
        .collect();
        let mut turn = EngineTurn::new(&urls, true, TurnTlsConfig::default());
        // The TCP allocations beside: `a_tcp_or_tls_server_gets_a_tcp_allocation_link_too`.
        turn.tcp_relay = false;
        assert!(
            turn.links.is_empty(),
            "no link before a transport needs one"
        );
        let first = TransportId::default();
        turn.make_links(first, "u1");
        turn.make_links(first, "u1");
        let links: Vec<(String, RTCIceServerTransportProtocol)> = turn
            .links
            .iter()
            .map(|l| (l.url_string(), l.protocol()))
            .collect();
        assert_eq!(
            links,
            vec![
                (
                    "turn:192.0.2.1:3478?transport=tcp".to_owned(),
                    RTCIceServerTransportProtocol::Tcp
                ),
                (
                    "turns:turn.example:5349?transport=tcp".to_owned(),
                    RTCIceServerTransportProtocol::Tls
                ),
                (
                    "turns:192.0.2.1:5349?transport=tcp".to_owned(),
                    RTCIceServerTransportProtocol::Tls
                ),
                (
                    "turn:192.0.2.1:3478?transport=udp".to_owned(),
                    RTCIceServerTransportProtocol::Udp
                ),
                (
                    "turns:192.0.2.1:5349?transport=udp".to_owned(),
                    RTCIceServerTransportProtocol::Dtls
                ),
            ]
        );
        // Nothing started: nothing pending for the end of gathering.
        assert!(!turn.pending(first, true));
        // Another transport gets links of its own, once.
        turn.make_links(TransportId(1), "u1");
        assert_eq!(turn.links.len(), 10);
        assert!(
            turn.links[5..]
                .iter()
                .all(|l| l.transport == TransportId(1))
        );
        // The application gathers from `turn:` over UDP: no link for it.
        let mut turn = EngineTurn::new(&urls, true, TurnTlsConfig::default());
        turn.tcp_relay = false;
        turn.relay_gathering = RelayGathering::Application;
        turn.make_links(first, "u1");
        assert_eq!(turn.links.len(), 4);
        assert!(turn.links.iter().all(|l| l.carrier != Carrier::Udp));
    }

    /// RFC 6062 section 4.1 with RFC 6544 section 5.5: a server over TCP or TLS gets a second
    /// link for a TCP allocation (its own control connection: an allocation is its 5-tuple's);
    /// one over DTLS none (a TCP allocation needs TCP or TLS to the server).
    #[test]
    fn a_tcp_or_tls_server_gets_a_tcp_allocation_link_too() {
        let urls: Vec<Url> = [
            "turn:192.0.2.1:3478?transport=tcp",
            "turns:192.0.2.1:5349?transport=tcp",
            "turns:192.0.2.1:5349?transport=udp",
        ]
        .iter()
        .map(|u| Url::parse_url(u).unwrap())
        .collect();
        let mut turn = EngineTurn::new(&urls, true, TurnTlsConfig::default());
        turn.make_links(TransportId::default(), "u1");
        let links: Vec<(RTCIceServerTransportProtocol, bool)> = turn
            .links
            .iter()
            .map(|l| (l.protocol(), l.relay_tcp))
            .collect();
        assert_eq!(
            links,
            vec![
                (RTCIceServerTransportProtocol::Tcp, false),
                (RTCIceServerTransportProtocol::Tcp, true),
                (RTCIceServerTransportProtocol::Tls, false),
                (RTCIceServerTransportProtocol::Tls, true),
                (RTCIceServerTransportProtocol::Dtls, false),
            ]
        );
    }
}
