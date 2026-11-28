#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! TURN for the Sans-I/O WebRTC stack.
//!
//! Traversal Using Relays around NAT ([RFC 8656], which replaced RFC 5766 and RFC 6156). TURN
//! is ICE's fallback: when no direct path between two peers can be found, each relays its
//! media through a server, which allocates a public address on their behalf.
//!
//! The client covers the client role of RFC 8656: UDP relayed addresses of either family or
//! both (`REQUESTED-ADDRESS-FAMILY`, `ADDITIONAL-ADDRESS-FAMILY`), permissions, channels,
//! `DONT-FRAGMENT`, even and reserved ports, ICMP errors, and the long-term credential of
//! RFC 8489 (SHA-256 password algorithm, `USERHASH`, `MESSAGE-INTEGRITY-SHA256`, and RFC
//! 5389's MD5 for servers that have nothing else); and TCP allocations ([RFC 6062]):
//! `Connect`, `ConnectionAttempt`, and a data connection per peer. Requests are sent on the
//! retransmission timer of RFC 8489 section 6.2, and every received STUN message is read
//! through `rtci_stun::validated`. There is no TURN server here.
//!
//! # Structure
//!
//! * [`client`] — the Sans-I/O client: allocate a relayed address, create permissions,
//!   bind channels, and send or receive through the allocation. It owns no sockets.
//! * [`proto`] — the TURN-specific STUN attributes and methods (`ALLOCATE`,
//!   `CREATE-PERMISSION`, `CHANNEL-BIND`, `XOR-RELAYED-ADDRESS`, ChannelData framing),
//!   built on [`rtci-stun`].
//!
//! # Example
//!
//! A client is configured with the server to allocate from and the long-term credentials to
//! authenticate with; driving it is then a matter of feeding it datagrams and polling for
//! [`Event`](client::Event)s:
//!
//! ```
//! use rtci_turn::client::ClientConfig;
//! use shared::TransportProtocol;
//!
//! let config = ClientConfig {
//!     turn_serv_addr: "turn.example.com:3478".to_owned(),
//!     local_addr: "0.0.0.0:0".parse().unwrap(),
//!     transport_protocol: TransportProtocol::UDP,
//!     username: "user".to_owned(),
//!     password: "pass".to_owned(),
//!     realm: "example.com".to_owned(),
//!     stun_serv_addr: String::new(), // optional: only for Binding requests
//!     software: String::new(),
//!     rto_in_ms: 0, // 0 selects the default initial RTO, 500 ms
//!     allocation_refresh_interval_cap: None,
//!     ..Default::default()
//! };
//! assert_eq!(config.turn_serv_addr, "turn.example.com:3478");
//! ```
//!
//! The application owns the socket: it feeds what arrives to the client, sends what the client
//! queues, and adds the relayed address to its ICE agent as a relay candidate. The crate is
//! re-exported as `rtci::turn`.
//!
//! [RFC 8656]: https://datatracker.ietf.org/doc/html/rfc8656
//! [RFC 6062]: https://datatracker.ietf.org/doc/html/rfc6062
//! [`rtci-stun`]: https://docs.rs/rtc-stun

/// The Sans-I/O TURN client: allocate a relayed address and send through it.
/// The crypto provider API.
///
/// Re-exported because this crate's public constructors take an
/// [`Arc<dyn RTCCryptoProvider>`](crypto::RTCCryptoProvider), which a caller must be able to name
/// without adding — and version-matching — a direct `rtci-crypto` dependency.
pub use crypto;

pub mod client;
/// Entry points for stateful fuzz targets. Gated behind `cfg(fuzzing)`; not part of the
/// supported API.
#[cfg(all(fuzzing, any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
pub mod fuzzing;
/// The TURN-specific STUN attributes, methods and ChannelData framing.
pub mod proto;
pub mod rest;
