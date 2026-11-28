//! An in-memory TURN server over UDP (RFC 8656) that behaves like coturn where the tests need
//! it: allocations are kept per 5-tuple (a second Allocate on one in use is 437, a request on
//! none is 437), a request on an allocation with a username other than the allocation's is
//! 441, permissions last 300 s and channel bindings 600 s, a Refresh of LIFETIME 0 deletes the
//! allocation, and with a REST secret (draft-uberti-behave-turn-rest-00, coturn's
//! `use-auth-secret`) the username's timestamp is checked on EVERY authenticated request: an
//! expired one is answered 401, as coturn does.
//!
//! `release_linger` models what coturn does with a Refresh of LIFETIME 0 (RFC 8656 section 8.2
//! has the server delete the allocation at once): coturn answers it with success but floors
//! the lifetime at one second (`refresh_relay_connection` in `src/server/ns_turn_server.c`:
//! `if (lifetime < 1) lifetime = 1;`), so the allocation lives on until that timer fires, and an
//! Allocate on its 5-tuple meanwhile is answered 437 before any authentication
//! (`handle_turn_command`: "Mismatched allocation: wrong transaction ID").
//!
//! No sockets: the test hands it what a client sent to one of its addresses (`client_sent`) and
//! what a peer sent to a relayed address (`peer_sent`), and takes what it sends from `out`.
//! Time is the test's virtual clock.

#![allow(dead_code)]

use anyhow::Result;
use base64::Engine;
use rtci::crypto::HmacAlgorithm;
use rtci::stun::attributes::{ATTR_MESSAGE_INTEGRITY, ATTR_NONCE, ATTR_REALM, ATTR_USERNAME};
use rtci::stun::error_code::{
    CODE_ALLOC_MISMATCH, CODE_BAD_REQUEST, CODE_UNAUTHORIZED, CODE_WRONG_CREDENTIALS, ErrorCode,
    ErrorCodeAttribute,
};
use rtci::stun::fingerprint::FINGERPRINT;
use rtci::stun::integrity::MessageIntegrity;
use rtci::stun::message::{
    CLASS_ERROR_RESPONSE, CLASS_INDICATION, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, Getter,
    METHOD_ALLOCATE, METHOD_CHANNEL_BIND, METHOD_CREATE_PERMISSION, METHOD_DATA, METHOD_REFRESH,
    METHOD_SEND, Message, MessageClass, MessageType, Method, Setter, TransactionId,
};
use rtci::stun::textattrs::{Nonce, Realm, TextAttribute};
use rtci::stun::xoraddr::XorMappedAddress;
use rtci::turn::proto::chandata::ChannelData;
use rtci::turn::proto::channum::ChannelNumber;
use rtci::turn::proto::data::Data;
use rtci::turn::proto::lifetime::Lifetime;
use rtci::turn::proto::peeraddr::PeerAddress;
use rtci::turn::proto::relayaddr::RelayedAddress;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const REALM: &str = "rtc.test";
const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
const DEFAULT_LIFETIME: Duration = Duration::from_secs(600);
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// How the server checks credentials.
pub enum Auth {
    /// Fixed long-term credentials: username to password.
    Static(Vec<(String, String)>),
    /// coturn `use-auth-secret`: the password is base64(HMAC-SHA1(secret, username)) and the
    /// username is `<expiry unix time>[:<id>]`.
    Rest { secret: String },
}

/// The REST password of `username` under `secret` (draft-uberti-behave-turn-rest-00 2.2).
pub fn rest_password(secret: &str, username: &str) -> Result<String> {
    let provider = rtci::crypto::default_provider()?;
    let mut mac = provider
        .crypto()
        .new_hmac(HmacAlgorithm::Sha1, secret.as_bytes())?;
    let mut tag = vec![0u8; mac.output_len()];
    mac.sign(&[username.as_bytes()], &mut tag)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(tag))
}

pub struct Allocation {
    pub username: String,
    pub relayed: SocketAddr,
    pub expires: Instant,
    permissions: HashMap<IpAddr, Instant>,
    channels: HashMap<u16, (SocketAddr, Instant)>,
    allocate_tid: TransactionId,
}

/// A request the server answered with an error: (method, code, username).
pub type Rejection = (Method, u16, String);

pub struct TurnServer {
    pub auth: Auth,
    /// The server's addresses (where clients send).
    pub addresses: Vec<SocketAddr>,
    /// The IP relayed addresses are on.
    relay_ip: IpAddr,
    next_port: u16,
    /// Virtual time `start` is the unix time `start_unix`.
    start: Instant,
    start_unix: u64,
    /// Allocations by 5-tuple: (client address, server address).
    pub allocations: HashMap<(SocketAddr, SocketAddr), Allocation>,
    /// What the server sends: (from, to, bytes). From a server address to a client, or from a
    /// relayed address to a peer.
    pub out: Vec<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// Every request answered with an error.
    pub rejections: Vec<Rejection>,
    /// Every request received, by 5-tuple: (client, server, method, username, lifetime asked).
    pub requests: Vec<(SocketAddr, SocketAddr, Method, String, Option<Duration>)>,
    /// Allocations deleted by a Refresh of LIFETIME 0: (client, server, relayed, when).
    pub deleted: Vec<(SocketAddr, SocketAddr, SocketAddr, Instant)>,
    /// Datagrams relayed each way: (relayed, peer, client to peer?).
    pub relayed: Vec<(SocketAddr, SocketAddr, bool, Instant)>,
    /// Refreshes of LIFETIME 0 to lose (as if the datagram never arrived), the next ones.
    pub lose_releases: usize,
    /// The next authenticated request is answered 438 (Stale Nonce) with a new nonce.
    pub stale_nonce_next: bool,
    /// While set, what the server sends waits in `held` instead of `out`.
    pub hold: bool,
    pub held: Vec<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// coturn's Refresh of LIFETIME 0 (see the module text): answered, the allocation kept
    /// this long, and an Allocate on its 5-tuple answered 437 before authentication.
    pub release_linger: Option<Duration>,
}

impl TurnServer {
    pub fn new(auth: Auth, addresses: Vec<SocketAddr>, relay_ip: IpAddr, start: Instant) -> Self {
        Self {
            auth,
            addresses,
            relay_ip,
            next_port: 50000,
            start,
            start_unix: 1_800_000_000,
            allocations: HashMap::new(),
            out: vec![],
            rejections: vec![],
            requests: vec![],
            deleted: vec![],
            relayed: vec![],
            lose_releases: 0,
            stale_nonce_next: false,
            hold: false,
            held: vec![],
            release_linger: None,
        }
    }

    /// The virtual instant the server's clock starts at.
    pub fn start(&self) -> Instant {
        self.start
    }

    /// The unix time at virtual instant `now`.
    pub fn unix(&self, now: Instant) -> u64 {
        self.start_unix + now.saturating_duration_since(self.start).as_secs()
    }

    /// A REST username that expires `valid` after `now`.
    pub fn rest_username(&self, now: Instant, valid: Duration, id: &str) -> String {
        format!("{}:{id}", self.unix(now) + valid.as_secs())
    }

    /// Whether `addr` is a relayed address of a live allocation.
    pub fn is_relayed(&self, addr: SocketAddr) -> bool {
        self.allocations.values().any(|a| a.relayed == addr)
    }

    fn password(&self, username: &str, now: Instant) -> Option<String> {
        match &self.auth {
            Auth::Static(users) => users
                .iter()
                .find(|(u, _)| u == username)
                .map(|(_, p)| p.clone()),
            Auth::Rest { secret } => {
                let expiry: u64 = username.split(':').next()?.parse().ok()?;
                if expiry < self.unix(now) {
                    return None;
                }
                rest_password(secret, username).ok()
            }
        }
    }

    fn key(username: &str, password: &str) -> Result<Vec<u8>> {
        let provider = rtci::crypto::default_provider()?;
        Ok(MessageIntegrity::long_term_integrity_key(
            username.to_owned(),
            REALM.to_owned(),
            password.to_owned(),
            provider.crypto(),
        )?)
    }

    fn build(
        request: &Message,
        class: MessageClass,
        attrs: Vec<Box<dyn Setter>>,
        key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let provider = rtci::crypto::default_provider()?;
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(request.transaction_id),
            Box::new(MessageType::new(request.typ.method, class)),
        ];
        setters.extend(attrs);
        if let Some(key) = key {
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                key.to_vec(),
                provider.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        let mut m = Message::new();
        m.build(&setters)?;
        Ok(m.raw)
    }

    fn error(
        &mut self,
        request: &Message,
        code: ErrorCode,
        username: &str,
        key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        self.rejections
            .push((request.typ.method, code.0, username.to_owned()));
        let mut attrs: Vec<Box<dyn Setter>> = vec![Box::new(ErrorCodeAttribute {
            code,
            reason: b"rejected".to_vec(),
        })];
        if code == CODE_UNAUTHORIZED {
            attrs.push(Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())));
            attrs.push(Box::new(Realm::new(ATTR_REALM, REALM.to_owned())));
        }
        Self::build(request, CLASS_ERROR_RESPONSE, attrs, key)
    }

    /// A datagram a client sent from `from` to the server address `to`.
    pub fn client_sent(
        &mut self,
        now: Instant,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        let tuple = (from, to);
        if ChannelData::is_channel_data(data) {
            let mut cd = ChannelData {
                raw: data.to_vec(),
                ..Default::default()
            };
            cd.decode()?;
            if let Some(a) = self.allocations.get(&tuple)
                && a.expires > now
                && let Some((peer, until)) = a.channels.get(&cd.number.0)
                && *until > now
                && a.permissions.get(&peer.ip()).is_some_and(|t| *t > now)
            {
                let (relayed, peer) = (a.relayed, *peer);
                self.relayed.push((relayed, peer, true, now));
                self.out.push((relayed, peer, cd.data));
            }
            return Ok(());
        }
        let mut m = Message::new();
        m.unmarshal_binary(data)?;
        if m.typ.class == CLASS_INDICATION {
            if m.typ.method == METHOD_SEND {
                let mut peer = PeerAddress::default();
                let mut payload = Data::default();
                if peer.get_from(&m).is_ok()
                    && payload.get_from(&m).is_ok()
                    && let Some(a) = self.allocations.get(&tuple)
                    && a.expires > now
                    && a.permissions.get(&peer.ip).is_some_and(|t| *t > now)
                {
                    let peer = SocketAddr::new(peer.ip, peer.port);
                    self.relayed.push((a.relayed, peer, true, now));
                    self.out.push((a.relayed, peer, payload.0));
                }
            }
            return Ok(());
        }
        if m.typ.class != CLASS_REQUEST {
            return Ok(());
        }
        let username = TextAttribute::get_from_as(&m, ATTR_USERNAME)
            .map(|u| u.text)
            .unwrap_or_default();
        let mut lifetime = Lifetime::default();
        let asked = lifetime.get_from(&m).ok().map(|_| lifetime.0);
        if m.typ.method == METHOD_REFRESH && asked == Some(Duration::ZERO) && self.lose_releases > 0
        {
            self.lose_releases -= 1;
            return Ok(());
        }
        self.requests
            .push((from, to, m.typ.method, username.clone(), asked));
        let lingering = self.release_linger.is_some()
            && m.typ.method == METHOD_ALLOCATE
            && self
                .allocations
                .get(&tuple)
                .is_some_and(|a| a.expires > now && a.allocate_tid != m.transaction_id);
        let reply = if lingering {
            self.error(&m, CODE_ALLOC_MISMATCH, &username, None)?
        } else {
            self.request(now, tuple, &mut m, &username, asked)?
        };
        if self.hold {
            self.held.push((to, from, reply));
        } else {
            self.out.push((to, from, reply));
        }
        Ok(())
    }

    /// Sends what `hold` kept back.
    pub fn release_held(&mut self) {
        self.hold = false;
        self.out.append(&mut self.held);
    }

    fn request(
        &mut self,
        now: Instant,
        tuple: (SocketAddr, SocketAddr),
        m: &mut Message,
        username: &str,
        asked: Option<Duration>,
    ) -> Result<Vec<u8>> {
        // Authentication on every request (coturn checks the REST timestamp each time).
        if !m.contains(ATTR_MESSAGE_INTEGRITY) {
            return self.error(m, CODE_UNAUTHORIZED, username, None);
        }
        let Some(password) = self.password(username, now) else {
            return self.error(m, CODE_UNAUTHORIZED, username, None);
        };
        let key = Self::key(username, &password)?;
        let provider = rtci::crypto::default_provider()?;
        if MessageIntegrity::check(m, &key, provider.crypto()).is_err() {
            return self.error(m, CODE_UNAUTHORIZED, username, None);
        }
        if self.stale_nonce_next {
            self.stale_nonce_next = false;
            self.rejections
                .push((m.typ.method, 438, username.to_owned()));
            return Self::build(
                m,
                CLASS_ERROR_RESPONSE,
                vec![
                    Box::new(ErrorCodeAttribute {
                        code: ErrorCode(438),
                        reason: b"Stale Nonce".to_vec(),
                    }),
                    Box::new(Nonce::new(ATTR_NONCE, "nonce-2".to_owned())),
                    Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
                ],
                None,
            );
        }
        let key = Some(&key[..]);
        self.allocations.retain(|_, a| a.expires > now);
        let method = m.typ.method;
        if method == METHOD_ALLOCATE {
            if let Some(a) = self.allocations.get(&tuple) {
                if a.allocate_tid == m.transaction_id {
                    let relayed = a.relayed;
                    return self.allocate_success(m, tuple, relayed, key);
                }
                return self.error(m, CODE_ALLOC_MISMATCH, username, key);
            }
            let relayed = SocketAddr::new(self.relay_ip, self.next_port);
            self.next_port += 1;
            let lifetime = asked.unwrap_or(DEFAULT_LIFETIME).min(MAX_LIFETIME);
            self.allocations.insert(
                tuple,
                Allocation {
                    username: username.to_owned(),
                    relayed,
                    expires: now + lifetime,
                    permissions: HashMap::new(),
                    channels: HashMap::new(),
                    allocate_tid: m.transaction_id,
                },
            );
            return self.allocate_success(m, tuple, relayed, key);
        }
        let Some(a) = self.allocations.get_mut(&tuple) else {
            return self.error(m, CODE_ALLOC_MISMATCH, username, key);
        };
        // RFC 8656 section 5: the allocation's own username only.
        if a.username != username {
            return self.error(m, CODE_WRONG_CREDENTIALS, username, key);
        }
        match method {
            METHOD_REFRESH => {
                let lifetime = asked.unwrap_or(DEFAULT_LIFETIME).min(MAX_LIFETIME);
                if lifetime.is_zero() {
                    let relayed = a.relayed;
                    match self.release_linger {
                        Some(linger) => a.expires = now + linger,
                        None => {
                            self.allocations.remove(&tuple);
                        }
                    }
                    self.deleted.push((tuple.0, tuple.1, relayed, now));
                } else {
                    a.expires = now + lifetime;
                }
                Self::build(
                    m,
                    CLASS_SUCCESS_RESPONSE,
                    vec![Box::new(Lifetime(lifetime))],
                    key,
                )
            }
            METHOD_CREATE_PERMISSION => {
                let mut peer = PeerAddress::default();
                if peer.get_from(m).is_err() {
                    return self.error(m, CODE_BAD_REQUEST, username, key);
                }
                a.permissions.insert(peer.ip, now + PERMISSION_LIFETIME);
                Self::build(m, CLASS_SUCCESS_RESPONSE, vec![], key)
            }
            METHOD_CHANNEL_BIND => {
                let mut peer = PeerAddress::default();
                let mut number = ChannelNumber::default();
                if peer.get_from(m).is_err() || number.get_from(m).is_err() {
                    return self.error(m, CODE_BAD_REQUEST, username, key);
                }
                let peer = SocketAddr::new(peer.ip, peer.port);
                a.channels.insert(number.0, (peer, now + CHANNEL_LIFETIME));
                a.permissions.insert(peer.ip(), now + PERMISSION_LIFETIME);
                Self::build(m, CLASS_SUCCESS_RESPONSE, vec![], key)
            }
            _ => self.error(m, CODE_BAD_REQUEST, username, key),
        }
    }

    fn allocate_success(
        &self,
        m: &Message,
        tuple: (SocketAddr, SocketAddr),
        relayed: SocketAddr,
        key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        Self::build(
            m,
            CLASS_SUCCESS_RESPONSE,
            vec![
                Box::new(RelayedAddress {
                    ip: relayed.ip(),
                    port: relayed.port(),
                }),
                Box::new(XorMappedAddress {
                    ip: tuple.0.ip(),
                    port: tuple.0.port(),
                }),
                Box::new(Lifetime(DEFAULT_LIFETIME)),
            ],
            key,
        )
    }

    /// A datagram a peer sent from `from` to the relayed address `to`: relayed to the client
    /// as ChannelData when a channel is bound to `from`, else as a Data indication, if the
    /// allocation has a permission for `from`'s IP.
    pub fn peer_sent(
        &mut self,
        now: Instant,
        from: SocketAddr,
        to: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        let Some((tuple, a)) = self
            .allocations
            .iter()
            .find(|(_, a)| a.relayed == to && a.expires > now)
        else {
            return Ok(());
        };
        if !a.permissions.get(&from.ip()).is_some_and(|t| *t > now) {
            return Ok(());
        }
        let (client, server) = *tuple;
        let channel = a
            .channels
            .iter()
            .find(|(_, (p, until))| *p == from && *until > now)
            .map(|(n, _)| *n);
        let bytes = match channel {
            Some(n) => {
                let mut cd = ChannelData {
                    data: data.to_vec(),
                    number: ChannelNumber(n),
                    ..Default::default()
                };
                cd.encode()?;
                cd.raw
            }
            None => {
                let mut m = Message::new();
                m.build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
                    Box::new(PeerAddress {
                        ip: from.ip(),
                        port: from.port(),
                    }),
                    Box::new(Data(data.to_vec())),
                    Box::new(FINGERPRINT),
                ])?;
                m.raw
            }
        };
        self.relayed.push((to, from, false, now));
        self.out.push((server, client, bytes));
        Ok(())
    }

    /// The requests of `method` received.
    pub fn count(&self, method: Method) -> usize {
        self.requests.iter().filter(|r| r.2 == method).count()
    }
}
