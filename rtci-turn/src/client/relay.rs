use log::{debug, warn};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::ops::Add;
use std::time::{Duration, Instant};
use stun::error_code::*;
use stun::fingerprint::*;
use stun::message::*;

use super::permission::*;
use super::transaction::*;
use crate::proto;

use crate::client::binding::{BINDING_REFRESH_AGE, BindingManager, BindingState};
use crate::client::credential::Credential;
use crate::client::data_connection::{DataConnection, DataConnectionConfig};
use crate::client::error::RequestError;
use crate::client::{Client, Event, RelayTransport, RelayedAddr, Response};
use crate::proto::connid::ConnectionId;
use shared::error::{Error, Result};
use std::sync::Arc;

const PERM_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
// https://datatracker.ietf.org/doc/html/rfc8656#name-permissions-2
// The Permission Lifetime MUST be 300 seconds (= 5 minutes).
const PERM_LIFETIME: Duration = Duration::from_secs(300);
const MAX_RETRY_ATTEMPTS: u16 = 3;
/// How often the bindings of an allocation are looked over for ones to rebind.
const BINDING_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// How long a ChannelBind the server refused is not sent again. The data goes as Send
/// indications meanwhile, so this only bounds how often a server that keeps refusing is asked.
const CHANNEL_BIND_RETRY_INTERVAL: Duration = Duration::from_secs(60);
/// Most peer addresses one CreatePermission names. A refresh of more permissions is split into
/// several requests, which keeps each well inside one UDP datagram (an IPv6 XOR-PEER-ADDRESS is
/// 24 bytes) and far from the 64 KiB a STUN length field can describe.
pub(crate) const MAX_PEERS_PER_CREATE_PERMISSION: usize = 16;
/// Smallest step the allocation-refresh timer may advance by.
///
/// The timer advances by a fixed cadence from its own previous value, which keeps the refresh
/// schedule drift-free. That only works while the step is positive. `lifetime` is assigned
/// straight from the server's LIFETIME attribute, and a refresh carrying `LIFETIME=0` — how
/// RFC 8656 §8 deallocates, and what [`Relay::close`] sends — makes `lifetime / 2` zero. The timer
/// then freezes on an already-expired instant and `poll_timeout` reports that same instant
/// forever. A caller that treats an expired deadline as "handle it and go round again" spins
/// on it without ever reaching its socket reads, which is
/// [webrtc#862](https://github.com/webrtc-rs/webrtc/issues/862).
const MIN_ALLOC_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

fn allocation_refresh_interval(lifetime: Duration, interval_cap: Option<Duration>) -> Duration {
    let half_lifetime = lifetime / 2;
    interval_cap
        .map_or(half_lifetime, |cap| half_lifetime.min(cap))
        .max(MIN_ALLOC_REFRESH_INTERVAL)
}

// RelayState is a set of params use by Relay
pub(crate) struct RelayState {
    /// The address the allocation is kept under: the first relayed address it was given.
    pub(crate) relayed_addr: RelayedAddr,
    /// The relayed addresses the allocation has now: one, or an IPv4 and an IPv6 one after
    /// ADDITIONAL-ADDRESS-FAMILY (RFC 8656 §7.1), IPv4 first.
    pub(crate) addrs: Vec<RelayedAddr>,
    /// The XOR-MAPPED-ADDRESS of the Allocate success response: the client's
    /// server-reflexive address.
    pub(crate) mapped_addr: Option<SocketAddr>,
    /// The RESERVATION-TOKEN of the Allocate success response.
    pub(crate) reservation_token: Option<proto::rsrvtoken::ReservationToken>,
    /// Why the server did not allocate one of the two families asked for.
    pub(crate) address_error: Option<proto::addrerror::AddressErrorCode>,
    /// Whether the server took an Allocate with DONT-FRAGMENT, so supports it.
    pub(crate) dont_fragment: bool,
    /// What the allocation relays: UDP datagrams, or TCP connections (RFC 6062).
    pub(crate) transport: RelayTransport,
    /// Peers a Connect request is outstanding for: never two for one peer address
    /// (RFC 6062 §4.3).
    pub(crate) connecting: HashSet<SocketAddr>,
    /// Peers the server could not connect to (447), and when each may be tried again.
    connect_hold: HashMap<SocketAddr, Instant>,
    /// The long-term credential requests for the allocation are made with, as the server's
    /// last challenge left it: none for an allocation a server gave without asking for one.
    pub(crate) credential: Arc<Credential>,
    pub(crate) lifetime: Duration,
    /// When the server deletes the allocation unless a Refresh reaches it first: the lifetime
    /// it last returned, counted from that response.
    pub(crate) expires_at: Instant,
    /// Whether the application released the allocation ([`Relay::close`]). Nothing is sent
    /// for it any more but the Refresh with LIFETIME 0 and its retries.
    pub(crate) releasing: bool,
    allocation_refresh_interval_cap: Option<Duration>,
    /// Permissions by peer IP address: a permission covers every port on that address
    /// (RFC 8656 §9).
    pub(crate) perm_map: HashMap<IpAddr, Permission>,
    /// The allocation's channel bindings. They are the allocation's own and end with it
    /// (RFC 8656 §12).
    pub(crate) binding_mgr: BindingManager,
    refresh_alloc_timer: Instant,
    refresh_perms_timer: Instant,
    /// When the bindings are next looked over; `None` while no binding is live.
    bindings_timer: Option<Instant>,
}

impl RelayState {
    pub(super) fn new(
        now: Instant,
        relayed_addr: RelayedAddr,
        credential: Arc<Credential>,
        lifetime: Duration,
        allocation_refresh_interval_cap: Option<Duration>,
    ) -> Self {
        debug!("initial lifetime: {} seconds", lifetime.as_secs());

        Self {
            relayed_addr,
            addrs: vec![relayed_addr],
            mapped_addr: None,
            reservation_token: None,
            address_error: None,
            dont_fragment: false,
            transport: RelayTransport::Udp,
            connecting: HashSet::new(),
            connect_hold: HashMap::new(),
            credential,
            lifetime,
            expires_at: now.add(lifetime),
            releasing: false,
            allocation_refresh_interval_cap,
            perm_map: HashMap::new(),
            binding_mgr: BindingManager::new(),
            refresh_alloc_timer: now.add(allocation_refresh_interval(
                lifetime,
                allocation_refresh_interval_cap,
            )),
            refresh_perms_timer: now.add(PERM_REFRESH_INTERVAL),
            bindings_timer: None,
        }
    }

    /// Whether requests for this allocation are signed. An allocation a server gave without
    /// asking for a credential (RFC 8656 §7.2 step 1) has none.
    pub(crate) fn is_signed(&self) -> bool {
        self.credential.is_established()
    }

    /// Whether the allocation has a relayed address of `peer`'s family. A peer of another
    /// family cannot be reached through it: the server answers 443 (RFC 8656 §10.2, §12.2).
    pub(crate) fn relays_family_of(&self, peer: &IpAddr) -> bool {
        self.addrs
            .iter()
            .any(|addr| addr.is_ipv4() == peer.is_ipv4())
    }

    /// The address events name the allocation by: its first relayed address.
    pub(crate) fn name(&self) -> RelayedAddr {
        self.addrs.first().copied().unwrap_or(self.relayed_addr)
    }

    /// Whether the client holds a permission for `ip`, asked for or installed, that has not
    /// run out at `now`: data from an address without one is not relayed by the server
    /// (RFC 8656 §11.4, §12.6).
    pub(crate) fn expects_data_from(&self, ip: &IpAddr, now: Instant) -> bool {
        self.perm_map
            .get(ip)
            .is_some_and(|perm| perm.state() == PermState::Idle || perm.is_permitted(now))
    }

    /// Drops the permission for `ip` after a CreatePermission the application asked for failed,
    /// unless the server installed it meanwhile: a permission is per IP address (RFC 8656 §9),
    /// so another request for the same address (another port) may have been granted while this
    /// one was outstanding, and the refusal of one request takes nothing from the other.
    pub(crate) fn forget_unless_permitted(&mut self, ip: IpAddr, now: Instant) {
        if self
            .perm_map
            .get(&ip)
            .is_some_and(|perm| !perm.is_permitted(now))
        {
            self.perm_map.remove(&ip);
        }
    }
}

/// A borrowed handle to one live allocation on the TURN server.
///
/// Obtained from [`Client::relay`](crate::client::Client::relay). Sending to a peer requires
/// a permission for it first — see [`Self::create_permission`].
pub struct Relay<'a> {
    pub(crate) relayed_addr: RelayedAddr,
    pub(crate) client: &'a mut Client,
}

impl Relay<'_> {
    /// Asks the server to permit traffic to and from `peer_addr`.
    ///
    /// The relay silently drops data for peers with no permission, and permissions expire after
    /// five minutes unless refreshed. A permission is for the peer's IP address, whatever the
    /// port (RFC 8656 §9), so one covers every port on that address. Returns the transaction id
    /// to match against the resulting [`Event`], or `None` if a permission is already in place.
    ///
    /// # Errors
    ///
    /// Fails if the allocation no longer exists or was released, if `peer_addr` is not of
    /// the family of a relayed address of the allocation (RFC 8656 §10.1), or if the request
    /// cannot be encoded.
    pub fn create_permission(
        &mut self,
        now: Instant,
        peer_addr: SocketAddr,
    ) -> Result<Option<TransactionId>> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            if relay.releasing {
                return Err(Error::ErrConnClosed);
            }
            if !relay.relays_family_of(&peer_addr.ip()) {
                return Err(peer_family_mismatch(peer_addr));
            }
            relay
                .perm_map
                .entry(peer_addr.ip())
                .or_insert_with(Permission::default);
            if let Some(perm) = relay.perm_map.get(&peer_addr.ip())
                && !perm.is_permitted(now)
            {
                return Ok(Some(self.create_permissions(
                    now,
                    &[peer_addr],
                    Some(peer_addr),
                    Retry::default(),
                )?));
            }
            Ok(None)
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        let relay = self.client.relays.get(&self.relayed_addr)?;
        if relay.releasing {
            // Only the release is outstanding, and its transaction has its own deadline.
            return None;
        }
        let mut deadline = relay.refresh_alloc_timer.min(relay.refresh_perms_timer);
        if let Some(bindings_timer) = relay.bindings_timer {
            deadline = deadline.min(bindings_timer);
        }
        Some(deadline)
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return;
        };
        if relay.releasing {
            return;
        }

        let refresh_alloc = if relay.refresh_alloc_timer <= now {
            // Floored so the timer always moves. A zero step would leave it pinned to an
            // instant already in the past — see `MIN_ALLOC_REFRESH_INTERVAL`.
            let step =
                allocation_refresh_interval(relay.lifetime, relay.allocation_refresh_interval_cap);
            relay.refresh_alloc_timer = now.add(step);
            Some(relay.lifetime)
        } else {
            None
        };

        let refresh_perms = if relay.refresh_perms_timer <= now {
            relay.refresh_perms_timer = now.add(PERM_REFRESH_INTERVAL);
            true
        } else {
            false
        };

        // A binding lasts 10 minutes from its last ChannelBind (RFC 8656 §12). One that
        // carried data since then is rebound before a send would do it, so a channel the
        // client only receives on does not run out.
        let mut rebind = vec![];
        if relay.bindings_timer.is_some_and(|at| at <= now) {
            let mut any_live = false;
            for b in relay.binding_mgr.iter_mut() {
                if !b.is_live(now) {
                    continue;
                }
                any_live = true;
                if b.state() == BindingState::Ready
                    && b.used
                    && now.saturating_duration_since(b.refreshed_at()) + BINDING_SWEEP_INTERVAL
                        >= BINDING_REFRESH_AGE
                {
                    b.set_state(BindingState::Refresh);
                    rebind.push(b.addr);
                }
            }
            relay.bindings_timer = any_live.then(|| now.add(BINDING_SWEEP_INTERVAL));
        }

        if let Some(lifetime) = refresh_alloc {
            let _ = self.refresh_allocation(now, lifetime);
        }
        if refresh_perms {
            let _ = self.refresh_permissions(now);
        }
        for bind_addr in rebind {
            if self
                .rebind_channel(now, bind_addr, Retry::default())
                .is_err()
                && let Some(relay) = self.client.relays.get_mut(&self.relayed_addr)
                && let Some(b) = relay.binding_mgr.get_by_addr(&bind_addr)
            {
                b.set_state(BindingState::Ready);
            }
        }
    }

    /// Sends `p` to `peer_addr` through the relay.
    ///
    /// Uses ChannelData framing once a channel is bound for that peer, and a Send indication
    /// until then. A channel is bound for every peer address sent to, as long as channel
    /// numbers are free; without one the data keeps going as Send indications.
    ///
    /// # Errors
    ///
    /// Fails if the allocation is gone or was released, if no permission is in place for
    /// `peer_addr` (none was created, the server refused it, or its 300 s ran out without a
    /// refresh), or if `p` is longer than the message that would carry it can say (65 535
    /// bytes of ChannelData).
    pub fn send_to(&mut self, now: Instant, p: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        if relay.releasing {
            return Err(Error::ErrConnClosed);
        }
        if relay.transport == RelayTransport::Tcp {
            return Err(not_a_udp_allocation());
        }
        // check if we have a permission for the destination IP addr
        if !relay
            .perm_map
            .get(&peer_addr.ip())
            .is_some_and(|perm| perm.is_permitted(now))
        {
            return Err(Error::ErrNoPermission);
        }
        // The peer of a channel binding is of the relayed address's family (RFC 8656 §12.1).
        if !relay.relays_family_of(&peer_addr.ip()) {
            return Err(peer_family_mismatch(peer_addr));
        }

        self.send(now, p, peer_addr)
    }

    /// Sends `p` to `peer_addr` in a Send indication carrying DONT-FRAGMENT, which asks the
    /// server to set the DF bit on the datagram it sends the peer (RFC 8656 §11.1). The data
    /// never goes as ChannelData, which cannot say so.
    ///
    /// # Errors
    ///
    /// As [`Self::send_to`]; and if the allocation was not made with
    /// [`AllocateOptions::dont_fragment`](crate::client::AllocateOptions), or the server
    /// answered that request with 420: the server is not known to support the attribute
    /// (RFC 8656 §7.1).
    pub fn send_to_dont_fragment(
        &mut self,
        now: Instant,
        p: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        if relay.releasing {
            return Err(Error::ErrConnClosed);
        }
        if relay.transport == RelayTransport::Tcp {
            return Err(not_a_udp_allocation());
        }
        if !relay.dont_fragment {
            return Err(Error::Other(
                "DONT-FRAGMENT is not known to be supported for this allocation".to_owned(),
            ));
        }
        if !relay
            .perm_map
            .get(&peer_addr.ip())
            .is_some_and(|perm| perm.is_permitted(now))
        {
            return Err(Error::ErrNoPermission);
        }
        if !relay.relays_family_of(&peer_addr.ip()) {
            return Err(peer_family_mismatch(peer_addr));
        }
        self.send_indication(now, p, peer_addr, true)
    }

    /// The relayed addresses of the allocation: one, or an IPv4 and an IPv6 address when it
    /// was made with [`AllocateOptions::additional_ipv6`](crate::client::AllocateOptions)
    /// and the server gave both. Peers of either family can then be reached through it.
    #[must_use]
    pub fn relayed_addrs(&self) -> Vec<RelayedAddr> {
        self.state()
            .map_or_else(Vec::new, |relay| relay.addrs.clone())
    }

    /// The client's address as the server saw the Allocate request arrive from: its
    /// server-reflexive address (RFC 8656 §7.3), from the response's XOR-MAPPED-ADDRESS.
    #[must_use]
    pub fn mapped_addr(&self) -> Option<SocketAddr> {
        self.state()?.mapped_addr
    }

    /// The lifetime the server last granted the allocation.
    #[must_use]
    pub fn lifetime(&self) -> Option<Duration> {
        self.state().map(|relay| relay.lifetime)
    }

    /// The RESERVATION-TOKEN of the Allocate success response: the port the server holds for
    /// a later allocation, after an EVEN-PORT that asked for it (RFC 8656 §7.1).
    #[must_use]
    pub fn reservation_token(&self) -> Option<proto::rsrvtoken::ReservationToken> {
        self.state()?.reservation_token.clone()
    }

    /// Whether the server supports DONT-FRAGMENT: the allocation was made with it and the
    /// server took it.
    #[must_use]
    pub fn dont_fragment(&self) -> bool {
        self.state().is_some_and(|relay| relay.dont_fragment)
    }

    /// The ADDRESS-ERROR-CODE of the Allocate success response: which of the two address
    /// families asked for the server did not allocate, and why (RFC 8656 §7.3).
    #[must_use]
    pub fn address_error(&self) -> Option<proto::addrerror::AddressErrorCode> {
        self.state()?.address_error.clone()
    }

    /// What the allocation relays: UDP datagrams, or TCP connections (RFC 6062).
    #[must_use]
    pub fn transport(&self) -> RelayTransport {
        self.state()
            .map_or(RelayTransport::Udp, |relay| relay.transport)
    }

    /// Asks the server to open a TCP connection from the relayed address to `peer_addr`
    /// (RFC 6062 §4.3), with a Connect request on the control connection. Returns the id that
    /// [`Event::ConnectResponse`], [`Event::ConnectError`] or [`Event::TransactionTimeout`]
    /// will name. The server answers when the peer accepted, or after it gave up (about 30
    /// seconds).
    ///
    /// Connect requests to different peers can be outstanding together.
    ///
    /// # Errors
    ///
    /// Fails, with nothing sent, if the allocation is gone, was released, or relays UDP; if
    /// `peer_addr` is not of the family of its relayed address; if a Connect to `peer_addr`
    /// is still outstanding (RFC 6062 §4.3: never two for one peer address); or if the server
    /// answered 447 for `peer_addr` less than ten seconds ago.
    pub fn connect(&mut self, now: Instant, peer_addr: SocketAddr) -> Result<TransactionId> {
        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        if relay.releasing {
            return Err(Error::ErrConnClosed);
        }
        if relay.transport != RelayTransport::Tcp {
            return Err(Error::Other(
                "Connect is for a TCP allocation (RFC 6062); this one relays UDP".to_owned(),
            ));
        }
        if !relay.relays_family_of(&peer_addr.ip()) {
            return Err(peer_family_mismatch(peer_addr));
        }
        if relay.connecting.contains(&peer_addr) {
            return Err(Error::Other(format!(
                "a Connect to {peer_addr} is already outstanding"
            )));
        }
        if let Some(until) = relay.connect_hold.get(&peer_addr) {
            if now < *until {
                return Err(Error::Other(format!(
                    "the server could not connect to {peer_addr}; not again within {}s",
                    CONNECT_RETRY_WAIT.as_secs()
                )));
            }
            relay.connect_hold.remove(&peer_addr);
        }
        relay.connecting.insert(peer_addr);
        match self.connect_with(now, peer_addr, Retry::default()) {
            Ok(id) => Ok(id),
            Err(err) => {
                if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
                    relay.connecting.remove(&peer_addr);
                }
                Err(err)
            }
        }
    }

    fn connect_with(
        &mut self,
        now: Instant,
        peer_addr: SocketAddr,
        retry: Retry,
    ) -> Result<TransactionId> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        let msg = self.client.build_request(
            METHOD_CONNECT,
            vec![Box::new(proto::peeraddr::PeerAddress {
                ip: peer_addr.ip(),
                port: peer_addr.port(),
            })],
            relay,
        )?;
        let credential = Some(relay.credential.clone());
        self.client.perform_transaction(
            now,
            &msg,
            self.client.turn_server_addr_or_err()?,
            TransactionType::ConnectRequest(self.relayed_addr, peer_addr, retry),
            credential,
        )
    }

    pub(super) fn handle_connect_response(
        &mut self,
        now: Instant,
        res: Response,
        peer_addr: SocketAddr,
        retry: Retry,
    ) -> Result<()> {
        if !self.client.relays.contains_key(&self.relayed_addr) {
            return Ok(());
        }
        let id = retry.report_id(res.transaction_id);

        let err = if res.typ.class == CLASS_ERROR_RESPONSE {
            let mut err = res.error();
            if self.take_challenge(&res) {
                if !retry.stale_nonce
                    && self
                        .connect_with(now, peer_addr, retry.after_stale_nonce(res.transaction_id))
                        .is_ok()
                {
                    // The same peer again, with the new nonce and a new transaction id.
                    return Ok(());
                }
                err = RequestError::Failed(Error::ErrTryAgain);
            }
            err
        } else {
            let mut connection_id = ConnectionId::default();
            match connection_id.get_from(&res) {
                Ok(()) => {
                    if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
                        relay.connecting.remove(&peer_addr);
                    }
                    self.client.events.push_back(Event::ConnectResponse(
                        id,
                        peer_addr,
                        connection_id,
                    ));
                    return Ok(());
                }
                Err(err) => RequestError::Failed(err),
            }
        };

        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            relay.connecting.remove(&peer_addr);
            // 447 (Connection Timeout or Failure): the peer may be tried again, but not
            // within ten seconds (RFC 6062 §4.3).
            if err.is(CODE_CONN_TIMEOUT_OR_FAILURE) {
                relay
                    .connect_hold
                    .insert(peer_addr, now.add(CONNECT_RETRY_WAIT));
            }
        }
        // 437: the allocation no longer exists (RFC 8656 §5).
        let allocation_gone = err.is(CODE_ALLOC_MISMATCH);
        self.client
            .events
            .push_back(Event::ConnectError(id, peer_addr, err));
        if allocation_gone {
            self.lose(res.error());
        }
        Ok(())
    }

    /// The protocol side of a new TCP connection to the server that is to carry the peer
    /// connection `connection_id`: from [`Event::ConnectResponse`] for a connection this
    /// client asked for, from [`Event::ConnectionAttempt`] for one a peer made (RFC 6062
    /// §4.3, §4.4).
    ///
    /// The application opens the connection itself, to the server address the control
    /// connection goes to ([`DataConnection::server_addr`]) and from `local_addr`, which must
    /// not be the control connection's local address. The returned [`DataConnection`] has the
    /// ConnectionBind request queued, with the CONNECTION-ID and the credential of the
    /// control connection; the server waits 30 seconds for it.
    ///
    /// # Errors
    ///
    /// Fails if the allocation is gone, was released, or relays UDP, or if `local_addr` is
    /// the control connection's.
    pub fn data_connection(
        &mut self,
        now: Instant,
        connection_id: ConnectionId,
        local_addr: SocketAddr,
    ) -> Result<DataConnection> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        if relay.releasing {
            return Err(Error::ErrConnClosed);
        }
        if relay.transport != RelayTransport::Tcp {
            return Err(Error::Other(
                "a data connection is for a TCP allocation (RFC 6062); this one relays UDP"
                    .to_owned(),
            ));
        }
        if local_addr == self.client.local_addr {
            return Err(Error::Other(
                "a data connection is made from another local address than the control \
                 connection's (RFC 6062 section 4.3)"
                    .to_owned(),
            ));
        }
        DataConnection::new(
            now,
            DataConnectionConfig {
                crypto_provider: self.client.crypto_provider.clone(),
                server_addr: self.client.turn_server_addr_or_err()?,
                local_addr,
                connection_id,
                software: self.client.software.clone(),
                credential: relay.credential.clone(),
            },
        )
    }

    fn state(&self) -> Option<&RelayState> {
        self.client.relays.get(&self.relayed_addr)
    }

    /// The address events name this allocation by.
    fn name(&self) -> RelayedAddr {
        self.state().map_or(self.relayed_addr, RelayState::name)
    }

    /// Deletes the relayed address of one family from an allocation that has two, with a
    /// Refresh of LIFETIME 0 naming the family (RFC 8656 §8.1). The other address, with its
    /// permissions and channel bindings, stays. [`Event::AllocationReleased`] names the
    /// address when the server confirms. For an allocation with one address this is
    /// [`Self::close`].
    ///
    /// # Errors
    ///
    /// Fails if the allocation is gone or was released, or has no relayed address of
    /// `family`: REQUESTED-ADDRESS-FAMILY may only name a family the allocation holds.
    pub fn release_family(
        &mut self,
        now: Instant,
        family: proto::reqfamily::RequestedAddressFamily,
    ) -> Result<()> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        if relay.releasing {
            return Err(Error::ErrConnClosed);
        }
        let ipv6 = family == proto::reqfamily::REQUESTED_FAMILY_IPV6;
        if (family != proto::reqfamily::REQUESTED_FAMILY_IPV4 && !ipv6)
            || !relay.addrs.iter().any(|addr| addr.is_ipv6() == ipv6)
        {
            return Err(Error::Other(format!(
                "the allocation has no {family} relayed address"
            )));
        }
        if relay.addrs.len() == 1 {
            return self.close(now);
        }
        self.release_family_with(now, family, Retry::default())
    }

    pub(super) fn release_family_with(
        &mut self,
        now: Instant,
        family: proto::reqfamily::RequestedAddressFamily,
        retry: Retry,
    ) -> Result<()> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        let msg = self.client.build_request(
            METHOD_REFRESH,
            vec![
                Box::new(proto::lifetime::Lifetime(Duration::ZERO)),
                Box::new(family),
            ],
            relay,
        )?;
        let credential = Some(relay.credential.clone());
        let _ = self.client.perform_transaction(
            now,
            &msg,
            self.client.turn_server_addr_or_err()?,
            TransactionType::FamilyRelease(self.relayed_addr, family.0, retry),
            credential,
        );
        Ok(())
    }

    /// Handles the response to the Refresh that deletes the relayed address of `family`.
    pub(super) fn handle_family_release_response(
        &mut self,
        now: Instant,
        res: Response,
        family: u8,
        retry: Retry,
    ) -> Result<()> {
        let family = proto::reqfamily::RequestedAddressFamily(family);
        let ipv6 = family == proto::reqfamily::REQUESTED_FAMILY_IPV6;
        if res.typ.class == CLASS_ERROR_RESPONSE {
            let mut err = res.error();
            if self.take_challenge(&res) {
                if !retry.stale_nonce {
                    return self.release_family_with(
                        now,
                        family,
                        retry.after_stale_nonce(res.transaction_id),
                    );
                }
                err = RequestError::Failed(Error::ErrTryAgain);
            }
            if err.is(CODE_ALLOC_MISMATCH) {
                self.lose(err);
                return Ok(());
            }
            // 443 (Peer Address Family Mismatch): the server holds no address of that
            // family (RFC 8656 §8.2), so there is none to keep here. Anything else leaves
            // the address where it was.
            if !err.is(CODE_PEER_ADDR_FAMILY_MISMATCH) {
                let name = self.name();
                self.client.events.push_back(Event::RefreshError(name, err));
                return Ok(());
            }
        }

        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return Ok(());
        };
        // The other family's address, permissions and channel bindings are untouched.
        let gone: Vec<RelayedAddr> = relay
            .addrs
            .iter()
            .copied()
            .filter(|addr| addr.is_ipv6() == ipv6)
            .collect();
        relay.addrs.retain(|addr| addr.is_ipv6() != ipv6);
        relay.perm_map.retain(|ip, _| ip.is_ipv6() != ipv6);
        let bound: Vec<SocketAddr> = relay
            .binding_mgr
            .iter()
            .map(|b| b.addr)
            .filter(|addr| addr.is_ipv6() == ipv6)
            .collect();
        for addr in bound {
            relay.binding_mgr.delete_by_addr(&addr);
        }
        if relay.addrs.is_empty() {
            self.released();
            return Ok(());
        }
        for addr in gone {
            self.client
                .events
                .push_back(Event::AllocationReleased(addr));
        }
        Ok(())
    }

    fn send(&mut self, now: Instant, p: &[u8], peer_addr: SocketAddr) -> Result<()> {
        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };

        // What to do about the channel for this peer: bind it, rebind it, or neither; and
        // whether the data can go on it.
        let mut bind = None;
        let mut channel = None;
        if relay.binding_mgr.find_by_addr(&peer_addr).is_none() {
            // Out of channel numbers: binding is optional (RFC 8656 §12), the data goes as a
            // Send indication.
            let _ = relay.binding_mgr.create(now, peer_addr);
        }
        if let Some(b) = relay.binding_mgr.get_by_addr(&peer_addr) {
            if b.state() == BindingState::Failed && b.retry_at.is_none_or(|at| at <= now) {
                b.set_state(BindingState::Idle);
            }
            match b.state() {
                BindingState::Idle => {
                    b.set_state(BindingState::Request);
                    bind = Some(b.number);
                }
                BindingState::Request | BindingState::Failed => {}
                BindingState::Ready | BindingState::Refresh => {
                    if !b.is_live(now) {
                        // The binding ran out on the server, which now drops ChannelData on
                        // that number: bind it again, the same number to the same peer.
                        if b.state() == BindingState::Ready {
                            b.set_state(BindingState::Request);
                            bind = Some(b.number);
                        }
                    } else {
                        if b.state() == BindingState::Ready
                            && now.saturating_duration_since(b.refreshed_at()) > BINDING_REFRESH_AGE
                        {
                            b.set_state(BindingState::Refresh);
                            bind = Some(b.number);
                        }
                        channel = Some(b.number);
                    }
                }
            }
        }

        if let Some(channel_number) = channel
            && p.len() > usize::from(u16::MAX)
        {
            // Refused before anything is sent for it, the rebind included.
            if bind.is_some()
                && let Some(b) = relay.binding_mgr.get_by_addr(&peer_addr)
            {
                b.set_state(BindingState::Ready);
            }
            debug!(
                "{} bytes do not fit ChannelData on {channel_number}",
                p.len()
            );
            return Err(Error::ErrBadChannelDataLength);
        }

        if let Some(bind_number) = bind {
            let credential = relay.credential.clone();
            self.channel_bind(
                now,
                self.relayed_addr,
                peer_addr,
                bind_number,
                credential,
                Retry::default(),
            )?;
        }

        match channel {
            Some(channel_number) => {
                if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr)
                    && let Some(b) = relay.binding_mgr.get_by_addr(&peer_addr)
                {
                    b.used = true;
                }
                self.send_channel_data(now, p, channel_number)
            }
            None => self.send_indication(now, p, peer_addr, false),
        }
    }

    /// Sends `p` to `peer_addr` in a Send indication (RFC 8656 §11.1).
    fn send_indication(
        &mut self,
        now: Instant,
        p: &[u8],
        peer_addr: SocketAddr,
        dont_fragment: bool,
    ) -> Result<()> {
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(METHOD_SEND, CLASS_INDICATION)),
            Box::new(proto::data::Data(p.to_vec())),
            Box::new(proto::peeraddr::PeerAddress {
                ip: peer_addr.ip(),
                port: peer_addr.port(),
            }),
        ];
        if dont_fragment {
            setters.push(Box::new(proto::dontfrag::DontFragmentAttr));
        }
        // RFC 8489 Section 6.1: "Indications MAY include a SOFTWARE attribute"; only when the
        // application asked for it (`ClientConfig::software_in_indications`).
        if self.client.software_in_indications && !self.client.software.text.is_empty() {
            setters.push(Box::new(self.client.software.clone()));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut msg = Message::new();
        msg.build(&setters)?;

        // indication has no transaction (fire-and-forget)
        self.client
            .write_to(now, &msg.raw, self.client.turn_server_addr_or_err()?);
        Ok(())
    }

    // Close closes the connection.
    // Any blocked ReadFrom or write_to operations will be unblocked and return errors.
    /// Releases the allocation by refreshing it with a zero lifetime (RFC 8656 §8).
    ///
    /// From here on the allocation is not refreshed and nothing can be sent through it,
    /// whatever becomes of the request. [`Event::AllocationReleased`] follows when the server
    /// confirms, answers 437 (it no longer had the allocation), or never answers; in that last
    /// case the server drops the allocation when its lifetime runs out.
    ///
    /// # Re-allocating on the same socket after a release
    ///
    /// An allocation is its 5-tuple's (RFC 8656 §2.2): an [`allocate`](Client::allocate) from
    /// the same local address to the same server before [`Event::AllocationReleased`] can be
    /// refused with 437 (Allocation Mismatch, §7.2). On a 437 the client "SHOULD pick another
    /// client transport address and retry", tries three, and then "SHOULD NOT try to create
    /// another allocation on the server for 2 minutes" (§7.4): never retry on the refused
    /// 5-tuple. RFC 8656 §8.2 has the server delete the allocation when it answers; coturn
    /// keeps it for one second more and answers 437 meanwhile, so wait about two seconds after
    /// [`Event::AllocationReleased`] (or use another socket) before allocating there again.
    ///
    /// # Errors
    ///
    /// Fails if the refresh request cannot be sent.
    pub fn close(&mut self, now: Instant) -> Result<()> {
        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        if relay.releasing {
            return Ok(());
        }
        relay.releasing = true;
        // Whatever else is under way for the allocation no longer matters.
        let relayed_addr = self.relayed_addr;
        self.client
            .tr_map
            .delete_where(|tr| tr.relay() == Some(relayed_addr));
        self.refresh_allocation(now, Duration::from_secs(0))
    }

    /// Forgets the allocation and everything under way for it.
    fn forget(&mut self) {
        let relayed_addr = self.relayed_addr;
        self.client.relays.remove(&relayed_addr);
        self.client
            .tr_map
            .delete_where(|tr| tr.relay() == Some(relayed_addr));
    }

    /// The server no longer holds the allocation: the client drops its copy, with its
    /// permissions and channel bindings, and says so.
    pub(super) fn lose(&mut self, err: RequestError) {
        let name = self.name();
        debug!("allocation {name} lost: {err}");
        self.forget();
        self.client
            .events
            .push_back(Event::AllocationLost(name, err));
    }

    /// The allocation the application released is done with.
    pub(super) fn released(&mut self) {
        let name = self.name();
        debug!("allocation released; relay {name} dropped");
        self.forget();
        self.client
            .events
            .push_back(Event::AllocationReleased(name));
    }

    fn create_permissions(
        &mut self,
        now: Instant,
        peer_addrs: &[SocketAddr],
        peer_addr_opt: Option<SocketAddr>,
        retry: Retry,
    ) -> Result<TransactionId> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        let attrs: Vec<Box<dyn Setter>> = peer_addrs
            .iter()
            .map(|addr| {
                Box::new(proto::peeraddr::PeerAddress {
                    ip: addr.ip(),
                    port: addr.port(),
                }) as Box<dyn Setter>
            })
            .collect();
        let msg = self
            .client
            .build_request(METHOD_CREATE_PERMISSION, attrs, relay)?;
        let credential = Some(relay.credential.clone());
        self.client.perform_transaction(
            now,
            &msg,
            self.client.turn_server_addr_or_err()?,
            TransactionType::CreatePermissionRequest(
                self.relayed_addr,
                peer_addr_opt,
                peer_addrs.to_vec(),
                retry,
            ),
            credential,
        )
    }

    /// Whether the error response `res` is one the request can be sent again after, and takes
    /// what that needs from it (RFC 8489 §9.2.5, RFC 8656 §4.4): the nonce of a 438 (Stale
    /// Nonce), with its realm, password algorithms and user name form, or the same of a 401
    /// (Unauthenticated) to a request that carried no credential because the server had not
    /// asked for one when it made the allocation, or that names another realm.
    ///
    /// Not after a response whose nonce cookie announces PASSWORD-ALGORITHMS when it has none
    /// (a bid-down), not when none of the offered algorithms is supported, and not after a
    /// 401 to the very credentials the request carried.
    fn take_challenge(&mut self, res: &Response) -> bool {
        let mut code = ErrorCodeAttribute::default();
        if code.get_from(res).is_err()
            || (code.code != CODE_STALE_NONCE && code.code != CODE_UNAUTHORIZED)
        {
            return false;
        }
        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return false;
        };
        match relay.credential.challenged(
            &res.request(),
            &res.msg,
            self.client.crypto_provider.crypto(),
        ) {
            Ok(credential) => {
                relay.credential = Arc::new(credential);
                debug!("{}: took the server's realm and nonce", code.code.0);
                true
            }
            Err(refused) => {
                warn!("{} is not answered: {refused}", code.code.0);
                false
            }
        }
    }

    pub(super) fn handle_create_permission_response(
        &mut self,
        now: Instant,
        res: Response,
        peer_addr_opt: Option<SocketAddr>,
        peer_addrs: Vec<SocketAddr>,
        retry: Retry,
    ) -> Result<()> {
        if !self.client.relays.contains_key(&self.relayed_addr) {
            return Ok(());
        }
        let id = retry.report_id(res.transaction_id);

        if res.typ.class != CLASS_ERROR_RESPONSE {
            let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
                return Ok(());
            };
            // The server installed or refreshed every permission the request named, for 300 s
            // from now (RFC 8656 §9, §10.3).
            let until = now.add(PERM_LIFETIME);
            if let Some(peer_addr) = peer_addr_opt {
                if let Some(perm) = relay.perm_map.get_mut(&peer_addr.ip()) {
                    perm.permit_until(until);
                    self.client
                        .events
                        .push_back(Event::CreatePermissionResponse(id, peer_addr));
                }
            } else {
                for peer_addr in &peer_addrs {
                    if let Some(perm) = relay.perm_map.get_mut(&peer_addr.ip())
                        && perm.state() == PermState::Permitted
                    {
                        perm.permit_until(until);
                    }
                }
            }
            return Ok(());
        }

        let mut err = res.error();
        if self.take_challenge(&res) {
            if !retry.stale_nonce {
                // The same peers again, with the new nonce and a new transaction id.
                self.create_permissions(
                    now,
                    &peer_addrs,
                    peer_addr_opt,
                    retry.after_stale_nonce(res.transaction_id),
                )?;
                return Ok(());
            }
            err = RequestError::Failed(Error::ErrTryAgain);
        }

        // 437 (Allocation Mismatch) to anything but an Allocate: the allocation no longer
        // exists (RFC 8656 §5).
        let allocation_gone = err.is(CODE_ALLOC_MISMATCH);
        if let Some(peer_addr) = peer_addr_opt {
            if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
                relay.forget_unless_permitted(peer_addr.ip(), now);
            }
            self.client
                .events
                .push_back(Event::CreatePermissionError(id, err));
            if allocation_gone {
                self.lose(res.error());
            }
        } else if allocation_gone {
            self.lose(err);
        } else if !res.msg.is_authenticated()
            && self
                .client
                .relays
                .get(&self.relayed_addr)
                .is_some_and(RelayState::is_signed)
        {
            // An unsigned 401 or 438 is all a server can say about a credential or nonce it
            // does not accept, and all anyone else can forge. It ends this refresh, not the
            // permissions: they last what the server last granted, and are asked for again.
            debug!("permission refresh failed ({err}); the permissions keep their time");
        } else if peer_addrs.len() > 1 {
            // The server refuses a request for one address it will not permit, and with it
            // the refresh of every other address the request named. Each is asked for on its
            // own, so only the refused ones end.
            debug!("permission refresh refused ({err}); refreshing each address on its own");
            for peer_addr in &peer_addrs {
                self.create_permissions(now, &[*peer_addr], None, Retry::default())?;
            }
        } else if let Some(peer_addr) = peer_addrs.first() {
            // The permission is not refreshed: it ends on the server within 300 s of its last
            // refresh, and here now, so nothing more is sent to a peer the server will drop.
            if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
                relay.perm_map.remove(&peer_addr.ip());
            }
            let name = self.name();
            self.client
                .events
                .push_back(Event::PermissionLost(name, peer_addr.ip(), err));
        }

        Ok(())
    }

    pub(super) fn refresh_allocation(&mut self, now: Instant, lifetime: Duration) -> Result<()> {
        self.refresh_allocation_with(now, lifetime, Retry::default())
    }

    pub(super) fn refresh_allocation_with(
        &mut self,
        now: Instant,
        lifetime: Duration,
        retry: Retry,
    ) -> Result<()> {
        let Some(relay) = self.client.relays.get(&self.relayed_addr) else {
            return Err(Error::ErrConnClosed);
        };
        let msg = self.client.build_request(
            METHOD_REFRESH,
            vec![Box::new(proto::lifetime::Lifetime(lifetime))],
            relay,
        )?;
        let credential = Some(relay.credential.clone());
        let _ = self.client.perform_transaction(
            now,
            &msg,
            self.client.turn_server_addr_or_err()?,
            TransactionType::RefreshRequest(self.relayed_addr, lifetime, retry),
            credential,
        );
        Ok(())
    }

    /// Handles a Refresh response as if it answered a first request for the current lifetime.
    #[cfg(test)]
    pub(super) fn handle_refresh_allocation_response(
        &mut self,
        now: Instant,
        res: Message,
    ) -> Result<()> {
        let lifetime = self
            .client
            .relays
            .get(&self.relayed_addr)
            .map_or(Duration::ZERO, |relay| relay.lifetime);
        self.handle_refresh_response(now, Response::unchecked(&res), lifetime, Retry::default())
    }

    /// Handles the response to a Refresh that asked for `lifetime`.
    pub(super) fn handle_refresh_response(
        &mut self,
        now: Instant,
        res: Response,
        lifetime: Duration,
        retry: Retry,
    ) -> Result<()> {
        if !self.client.relays.contains_key(&self.relayed_addr) {
            return Ok(());
        }

        if res.typ.class == CLASS_ERROR_RESPONSE {
            let mut err = res.error();
            if self.take_challenge(&res) {
                if !retry.stale_nonce {
                    // The same LIFETIME again (zero for a release), with the new nonce and a
                    // new transaction id.
                    return self.refresh_allocation_with(
                        now,
                        lifetime,
                        retry.after_stale_nonce(res.transaction_id),
                    );
                }
                err = RequestError::Failed(Error::ErrTryAgain);
            }
            self.refresh_failed(now, lifetime, err);
            return Ok(());
        }

        // Getting lifetime from response
        let mut updated_lifetime = proto::lifetime::Lifetime::default();
        if let Err(err) = updated_lifetime.get_from(&res) {
            // A success that does not say for how long: nothing to extend the allocation by.
            self.refresh_failed(now, lifetime, RequestError::Failed(err));
            return Ok(());
        }

        // A zero lifetime is the server confirming deallocation — the reply to the refresh
        // `close()` sends. The allocation no longer exists, so neither should the relay:
        // leaving it in the map means it keeps reporting refresh deadlines for something that
        // is gone, and keeps trying to refresh it.
        if updated_lifetime.0.is_zero() {
            if lifetime.is_zero() {
                self.released();
            } else {
                self.lose(RequestError::Failed(Error::ErrFailedToRefreshAllocation));
            }
            return Ok(());
        }

        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            relay.lifetime = updated_lifetime.0;
            relay.expires_at = now.add(relay.lifetime);
            relay.refresh_alloc_timer = now.add(allocation_refresh_interval(
                relay.lifetime,
                relay.allocation_refresh_interval_cap,
            ));
            debug!("updated lifetime: {} seconds", relay.lifetime.as_secs());
        }

        Ok(())
    }

    /// A Refresh that asked for `lifetime` got no usable answer, or an error other than a
    /// challenge it could be sent again after.
    pub(super) fn refresh_failed(&mut self, now: Instant, lifetime: Duration, err: RequestError) {
        let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
            return;
        };

        if lifetime.is_zero() || relay.releasing {
            // The application released the allocation, so it is not refreshed again whatever
            // the server said: a 437 means it was gone already (RFC 8656 §8.3), and after
            // anything else, or silence, the server drops it when its lifetime runs out.
            if matches!(err, RequestError::Rejected(_)) && !err.is(CODE_ALLOC_MISMATCH) {
                let name = relay.name();
                self.client.events.push_back(Event::RefreshError(name, err));
            }
            self.released();
            return;
        }

        // 437 (Allocation Mismatch): the allocation no longer exists (RFC 8656 §5, §8.3). So
        // it does, for the client, once its lifetime ran out with no Refresh answered.
        if err.is(CODE_ALLOC_MISMATCH) || now >= relay.expires_at {
            self.lose(err);
            return;
        }

        // The allocation still has time: the next Refresh does not wait for the usual
        // interval, which may end at the expiry itself.
        let remaining = relay.expires_at.saturating_duration_since(now);
        let sooner = now.add((remaining / 2).max(MIN_ALLOC_REFRESH_INTERVAL));
        if sooner < relay.refresh_alloc_timer {
            relay.refresh_alloc_timer = sooner;
        }
        let name = relay.name();
        self.client.events.push_back(Event::RefreshError(name, err));
    }

    pub(super) fn refresh_permissions(&mut self, now: Instant) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            // The port of an XOR-PEER-ADDRESS in a CreatePermission is ignored (RFC 8656 §9.1).
            let addrs: Vec<SocketAddr> = relay
                .perm_map
                .keys()
                .map(|ip| SocketAddr::new(*ip, 0))
                .collect();
            if addrs.is_empty() {
                debug!("no permission to refresh");
                return Ok(());
            }
            for peers in addrs.chunks(MAX_PEERS_PER_CREATE_PERMISSION) {
                let _ = self.create_permissions(now, peers, None, Retry::default())?;
            }
            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    #[allow(clippy::too_many_arguments)] // the retry state rides with the request it repeats
    fn channel_bind(
        &mut self,
        now: Instant,
        relayed_addr: RelayedAddr,
        bind_addr: SocketAddr,
        bind_number: u16,
        credential: Arc<Credential>,
        retry: Retry,
    ) -> Result<()> {
        let msg = self.client.build_request_with(
            METHOD_CHANNEL_BIND,
            vec![
                Box::new(proto::peeraddr::PeerAddress {
                    ip: bind_addr.ip(),
                    port: bind_addr.port(),
                }),
                Box::new(proto::channum::ChannelNumber(bind_number)),
            ],
            &credential,
        )?;
        let turn_server_addr = self.client.turn_server_addr_or_err()?;

        if let Some(relay) = self.client.relays.get_mut(&relayed_addr)
            && let Some(b) = relay.binding_mgr.get_by_addr(&bind_addr)
        {
            // From here on the server may hold the binding, whatever comes back.
            b.last_request_at = Some(now);
        }

        debug!("UDPConn.bind call PerformTransaction 1");
        let _ = self.client.perform_transaction(
            now,
            &msg,
            turn_server_addr,
            TransactionType::ChannelBindRequest(relayed_addr, bind_addr, retry),
            Some(credential),
        );

        Ok(())
    }

    /// Sends the ChannelBind for `bind_addr` again, on the channel number it already has and
    /// with the allocation's current nonce and key.
    pub(super) fn rebind_channel(
        &mut self,
        now: Instant,
        bind_addr: SocketAddr,
        retry: Retry,
    ) -> Result<()> {
        let relay = self
            .client
            .relays
            .get(&self.relayed_addr)
            .ok_or(Error::ErrConnClosed)?;
        let bind_number = relay
            .binding_mgr
            .find_by_addr(&bind_addr)
            .map(|b| b.number)
            .ok_or(Error::ErrChannelBindNotFound)?;
        let credential = relay.credential.clone();
        self.channel_bind(
            now,
            self.relayed_addr,
            bind_addr,
            bind_number,
            credential,
            retry,
        )
    }

    pub(super) fn handle_channel_bind_response(
        &mut self,
        now: Instant,
        res: Response,
        bind_addr: SocketAddr,
        retry: Retry,
    ) -> Result<()> {
        if !self.client.relays.contains_key(&self.relayed_addr) {
            return Ok(());
        }

        if res.typ.class != CLASS_ERROR_RESPONSE {
            let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) else {
                return Ok(());
            };
            if let Some(b) = relay.binding_mgr.get_by_addr(&bind_addr) {
                b.set_refreshed_at(now);
                b.set_state(BindingState::Ready);
                b.bound = true;
                b.used = false;
                b.retry_at = None;
                debug!("channel binding successful: {}", bind_addr);
                if relay.bindings_timer.is_none() {
                    relay.bindings_timer = Some(now.add(BINDING_SWEEP_INTERVAL));
                }
            }
            // A ChannelBind also installs or refreshes the permission for the peer's address
            // (RFC 8656 §12.3).
            if let Some(perm) = relay.perm_map.get_mut(&bind_addr.ip()) {
                perm.permit_until(now.add(PERM_LIFETIME));
            }
            return Ok(());
        }

        let mut err = res.error();
        if self.take_challenge(&res) {
            if !retry.stale_nonce
                && self
                    .rebind_channel(now, bind_addr, retry.after_stale_nonce(res.transaction_id))
                    .is_ok()
            {
                // Sent again with the new nonce; the binding keeps waiting on it.
                return Ok(());
            }
            err = RequestError::Failed(Error::ErrTryAgain);
        }
        self.channel_bind_failed(now, bind_addr, err);
        Ok(())
    }

    /// A ChannelBind for `bind_addr` failed with `err`: an error response, or responses the
    /// client could not accept.
    pub(super) fn channel_bind_failed(
        &mut self,
        now: Instant,
        bind_addr: SocketAddr,
        err: RequestError,
    ) {
        warn!("ChannelBind for {bind_addr} failed: {err}");

        // The data keeps going as Send indications, and the ChannelBind is not sent again
        // with every one of them.
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr)
            && let Some(b) = relay.binding_mgr.get_by_addr(&bind_addr)
        {
            b.set_state(BindingState::Failed);
            b.retry_at = Some(now.add(CHANNEL_BIND_RETRY_INTERVAL));
        }

        // 437: the allocation no longer exists (RFC 8656 §5). 400: the client's channels and
        // the server's are out of step, and RFC 8656 §12.3 recommends deleting the allocation
        // and starting afresh.
        let allocation_gone = err.is(CODE_ALLOC_MISMATCH);
        let out_of_step = err.is(CODE_BAD_REQUEST);
        let again = match &err {
            RequestError::Rejected(response) => RequestError::Rejected(response.clone()),
            RequestError::Failed(_) => RequestError::Failed(Error::ErrTryAgain),
        };
        let name = self.name();
        self.client
            .events
            .push_back(Event::ChannelBindError(name, bind_addr, err));
        if allocation_gone {
            self.lose(again);
        } else if out_of_step {
            // Released on the server and dropped here at once: its state cannot be trusted.
            let credential = self
                .client
                .relays
                .get(&self.relayed_addr)
                .map(|relay| relay.credential.clone());
            if let Some(credential) = credential {
                let _ = self.client.release_orphan(now, &credential);
            }
            self.lose(again);
        }
    }

    /// A ChannelBind for `bind_addr` and the one sent after it both went unanswered: the next
    /// send to that peer binds it again.
    pub(super) fn channel_bind_timed_out(&mut self, bind_addr: SocketAddr) {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr)
            && let Some(b) = relay.binding_mgr.get_by_addr(&bind_addr)
        {
            b.set_state(BindingState::Idle);
        }
    }

    fn send_channel_data(&mut self, now: Instant, data: &[u8], channel_number: u16) -> Result<()> {
        let mut ch_data = proto::chandata::ChannelData {
            data: data.to_vec(),
            number: proto::channum::ChannelNumber(channel_number),
            ..Default::default()
        };
        ch_data.encode()?;

        self.client
            .write_to(now, &ch_data.raw, self.client.turn_server_addr_or_err()?);

        Ok(())
    }
}

/// How long after a 447 the same peer is not connected to again (RFC 6062 §4.3: "at least 10
/// seconds").
const CONNECT_RETRY_WAIT: Duration = Duration::from_secs(10);

/// The error for datagram sends on a TCP allocation, whose data goes over data connections.
fn not_a_udp_allocation() -> Error {
    Error::Other(
        "this is a TCP allocation (RFC 6062): data goes over a data connection per peer".to_owned(),
    )
}

/// The error for a peer no relayed address of the allocation can reach.
fn peer_family_mismatch(peer_addr: SocketAddr) -> Error {
    Error::Other(format!(
        "{peer_addr} is not of the address family of a relayed address of the allocation"
    ))
}
