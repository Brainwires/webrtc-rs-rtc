//! Entry points for stateful fuzz targets.
//!
//! [`conn_handle_records`] runs a real DTLS handshake between two in-memory endpoints and lets
//! the fuzzer inject records into one of them at any point: before, during and after the
//! handshake. Records can be plaintext, or encrypted under the peer's actual keys, so they get
//! past record authentication to the fragment buffer, the handshake cache, epoch handling and the
//! CBC / GCM / CCM / ChaCha20 decrypt paths.
//!
//! Every input is replayed deterministically: randomness comes from a seeded provider, the key
//! exchange derives a fixed secret, the certificate is fixed and signatures are a hash of the
//! message, and the clock is `start` plus offsets the input chooses. Gated behind
//! `cfg(fuzzing)`; not part of the supported API.
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shared::TransportProtocol;

use crate::cipher_suite::CipherSuiteId;
use crate::config::{ClientAuthType, ConfigBuilder, ExtendedMasterSecretType, HandshakeConfig};
use crate::conn::DTLSConn;
use crate::content::ContentType;
use crate::crypto::{Certificate, CryptoPrivateKey};
use crate::endpoint::Endpoint;
use crate::record_layer::record_layer_header::{PROTOCOL_VERSION1_2, RecordLayerHeader};

/// A fixed P-256 key (PKCS#8) for the certificate suites. Not a secret: it exists only so the
/// fuzz harness presents the same certificate on every run.
const P256_PKCS8: [u8; 138] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x38, 0xab, 0xc5, 0x52, 0x0d, 0x73, 0x19, 0x27, 0x93, 0xe6, 0x9a, 0x76,
    0x5e, 0xd7, 0x9a, 0x27, 0x9f, 0xe2, 0x31, 0x24, 0x98, 0x6a, 0xbd, 0x9d, 0x5a, 0x34, 0x66, 0xe3,
    0x90, 0xfd, 0x10, 0x09, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x80, 0x16, 0xbf, 0xfc, 0xa7, 0xf7,
    0x96, 0x4c, 0xc4, 0xb7, 0x52, 0x0a, 0x4f, 0x95, 0x85, 0xeb, 0xde, 0x23, 0x5e, 0xc6, 0x65, 0x45,
    0x17, 0x6c, 0xac, 0x6e, 0x72, 0xb9, 0x32, 0x64, 0x28, 0x8e, 0x66, 0xaf, 0x19, 0x38, 0x34, 0xb7,
    0x73, 0x37, 0xe2, 0x30, 0x05, 0x70, 0xe6, 0x1f, 0xe7, 0xc4, 0x1f, 0xac, 0x39, 0x57, 0x3f, 0xd2,
    0xbc, 0x17, 0x4c, 0xa1, 0xe7, 0xee, 0x68, 0xde, 0x61, 0x1b,
];

/// A self-signed certificate for [`P256_PKCS8`], made once with rcgen. Generating one at run
/// time would sign it with a fresh ECDSA nonce, so each run would see different bytes.
const P256_CERT_DER: [u8; 354] = [
    0x30, 0x82, 0x01, 0x5e, 0x30, 0x82, 0x01, 0x04, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x29,
    0x3f, 0x13, 0x29, 0xf6, 0xc6, 0x3c, 0x65, 0xc6, 0x70, 0x97, 0x82, 0x1c, 0x80, 0x2e, 0xae, 0x65,
    0x24, 0xe7, 0x44, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x72, 0x63, 0x67, 0x65,
    0x6e, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x63, 0x65,
    0x72, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x37, 0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5a, 0x18, 0x0f, 0x34, 0x30, 0x39, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5a, 0x30, 0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x16, 0x72, 0x63, 0x67, 0x65, 0x6e, 0x20, 0x73, 0x65, 0x6c, 0x66, 0x20, 0x73, 0x69, 0x67, 0x6e,
    0x65, 0x64, 0x20, 0x63, 0x65, 0x72, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x80, 0x16, 0xbf, 0xfc, 0xa7, 0xf7, 0x96, 0x4c, 0xc4, 0xb7, 0x52, 0x0a, 0x4f, 0x95,
    0x85, 0xeb, 0xde, 0x23, 0x5e, 0xc6, 0x65, 0x45, 0x17, 0x6c, 0xac, 0x6e, 0x72, 0xb9, 0x32, 0x64,
    0x28, 0x8e, 0x66, 0xaf, 0x19, 0x38, 0x34, 0xb7, 0x73, 0x37, 0xe2, 0x30, 0x05, 0x70, 0xe6, 0x1f,
    0xe7, 0xc4, 0x1f, 0xac, 0x39, 0x57, 0x3f, 0xd2, 0xbc, 0x17, 0x4c, 0xa1, 0xe7, 0xee, 0x68, 0xde,
    0x61, 0x1b, 0xa3, 0x18, 0x30, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0d, 0x30,
    0x0b, 0x82, 0x09, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, 0x2e, 0x72, 0x73, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00,
    0xc6, 0x8e, 0x2f, 0xf9, 0x4d, 0xf6, 0xf6, 0x6d, 0x59, 0xc7, 0xb3, 0x75, 0xf5, 0xd9, 0xa0, 0x3a,
    0x71, 0xda, 0x5d, 0xca, 0x82, 0xd5, 0x82, 0xa9, 0x7a, 0x4d, 0xa1, 0x10, 0x1f, 0x41, 0x1f, 0xc7,
    0x02, 0x20, 0x1d, 0xc2, 0xde, 0xe3, 0x36, 0x5a, 0x85, 0xd1, 0xb4, 0x1a, 0xd7, 0x5b, 0xf6, 0xaf,
    0x87, 0xc4, 0xbb, 0x33, 0x76, 0x71, 0xd3, 0x87, 0x40, 0xa7, 0xa2, 0x4a, 0x5d, 0x39, 0xff, 0x07,
    0x20, 0x11,
];

/// The suites the fuzzer picks from: AEAD (GCM, CCM, ChaCha20) and CBC, certificate and PSK.
const SUITES: [CipherSuiteId; 6] = [
    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
    CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
    CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
    CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
];

/// How many datagrams each side remembers for the replay op.
const HISTORY: usize = 32;

fn deterministic_certificate(provider: &Arc<dyn crypto::RTCCryptoProvider>) -> Option<Certificate> {
    let signing_key = provider
        .crypto()
        .import_signing_key(crypto::SignatureScheme::EcdsaP256Sha256, &P256_PKCS8)
        .ok()?;
    Some(Certificate {
        certificate: vec![rustls::pki_types::CertificateDer::from(
            P256_CERT_DER.to_vec(),
        )],
        private_key: CryptoPrivateKey::from_signing_key(signing_key),
    })
}

fn handshake_config(
    provider: Arc<dyn crypto::RTCCryptoProvider>,
    is_client: bool,
    suite: CipherSuiteId,
    ems: ExtendedMasterSecretType,
    client_auth: bool,
) -> Option<Arc<HandshakeConfig>> {
    let is_psk = matches!(
        suite,
        CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256 | CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8
    );
    let mut builder = ConfigBuilder::default()
        .with_crypto_provider(provider.clone())
        .with_cipher_suites(vec![suite])
        .with_extended_master_secret(ems)
        .with_insecure_skip_verify(true);
    if is_psk {
        builder = builder.with_psk(Some(Arc::new(|_: &[u8]| Ok(vec![0xab, 0xcd, 0xef]))));
        if is_client {
            builder = builder.with_psk_identity_hint(Some(b"rtc-dtls-fuzz".to_vec()));
        }
    } else {
        if !is_client || client_auth {
            builder = builder.with_certificates(vec![deterministic_certificate(&provider)?]);
        }
        if !is_client && client_auth {
            builder = builder.with_client_auth(ClientAuthType::RequireAnyClientCert);
        }
    }
    builder.build(is_client, None).ok().map(Arc::new)
}

/// One side of the in-memory association.
struct Side {
    endpoint: Endpoint,
    addr: SocketAddr,
    /// Datagrams this side sent, oldest first, for the replay op.
    sent: VecDeque<BytesMut>,
}

impl Side {
    /// Moves everything this side has queued into `inbox`, remembering it for replay.
    fn flush(&mut self, inbox: &mut VecDeque<BytesMut>) {
        while let Some(transmit) = self.endpoint.poll_transmit() {
            if self.sent.len() == HISTORY {
                self.sent.pop_front();
            }
            self.sent.push_back(transmit.message.clone());
            inbox.push_back(transmit.message);
        }
    }
}

struct Harness {
    target: Side,
    peer: Side,
    /// Datagrams in flight to the target and to the peer.
    to_target: VecDeque<BytesMut>,
    to_peer: VecDeque<BytesMut>,
    now: Instant,
    target_connected: bool,
}

impl Harness {
    fn deliver_to_target(&mut self, datagram: BytesMut) {
        if let Ok(events) = self
            .target
            .endpoint
            .read(self.now, self.peer.addr, None, datagram)
        {
            for event in events {
                if matches!(event, crate::endpoint::EndpointEvent::HandshakeComplete) {
                    self.target_connected = true;
                }
            }
        }
        self.target.flush(&mut self.to_peer);
    }

    fn deliver_to_peer(&mut self, datagram: BytesMut) {
        let _ = self
            .peer
            .endpoint
            .read(self.now, self.target.addr, None, datagram);
        self.peer.flush(&mut self.to_target);
    }

    /// Delivers what is in flight right now, in both directions.
    fn pump_once(&mut self) {
        for datagram in std::mem::take(&mut self.to_target) {
            self.deliver_to_target(datagram);
        }
        for datagram in std::mem::take(&mut self.to_peer) {
            self.deliver_to_peer(datagram);
        }
    }

    fn advance(&mut self, by: Duration) {
        self.now += by;
        let _ = self
            .target
            .endpoint
            .handle_timeout(self.peer.addr, self.now);
        self.target.flush(&mut self.to_peer);
        let _ = self
            .peer
            .endpoint
            .handle_timeout(self.target.addr, self.now);
        self.peer.flush(&mut self.to_target);
    }

    fn peer_conn(&mut self) -> Option<&mut DTLSConn> {
        let target = self.target.addr;
        self.peer.endpoint.connection_mut(&target)
    }

    /// A record carrying `body`, as the peer would send it: with the peer's next sequence number
    /// (shifted by `seq_skip`) and, at a non-zero epoch, encrypted under the peer's keys.
    fn peer_record(
        &mut self,
        content_type: u8,
        epoch_shift: i8,
        seq_skip: u64,
        body: &[u8],
    ) -> Option<BytesMut> {
        let conn = self.peer_conn()?;
        let epoch = conn
            .state
            .local_epoch
            .saturating_add_signed(i16::from(epoch_shift));
        let index = epoch as usize;
        while conn.state.local_sequence_number.len() <= index {
            conn.state.local_sequence_number.push(0);
        }
        let seq = conn.state.local_sequence_number[index].saturating_add(seq_skip);
        conn.state.local_sequence_number[index] = seq.saturating_add(1);

        let header = RecordLayerHeader {
            content_type: ContentType::from(content_type),
            protocol_version: PROTOCOL_VERSION1_2,
            epoch,
            sequence_number: seq & crate::record_layer::record_layer_header::MAX_SEQUENCE_NUMBER,
            content_len: u16::try_from(body.len()).ok()?,
        };
        let mut raw = vec![];
        header.marshal(&mut raw).ok()?;
        // `ContentType` folds unknown values into `Invalid`; keep the byte the input chose.
        raw[0] = content_type;
        raw.extend_from_slice(body);

        if epoch != 0
            && let Some(cipher_suite) = conn.state.cipher_suite.as_mut()
            && cipher_suite.is_initialized()
        {
            raw = cipher_suite.encrypt(&header, &raw).ok()?;
        }
        Some(BytesMut::from(&raw[..]))
    }
}

/// Splits the next op argument off `data`: a one-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let len = usize::from(len).min(rest.len());
    let (arg, rest) = rest.split_at(len);
    *data = rest;
    arg
}

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Stateful target: a DTLS handshake between a fuzzed target endpoint and an honest in-memory
/// peer, with fuzzer-chosen records injected along the way.
///
/// The first byte picks the cipher suite, which side is the target (client or server), the
/// extended-master-secret policy and client authentication. The rest is a sequence of ops, each
/// an op byte followed by a length-prefixed argument:
///
/// - pump until the handshake completes (bounded), or deliver one round in each direction;
/// - a raw datagram to the target;
/// - a record from the peer, at its current epoch (or one either side), plaintext or encrypted
///   under the peer's keys, with a fuzzed content type, sequence skip and body;
/// - a handshake fragment with fuzzed header fields, wrapped the same way;
/// - a replay of one of the peer's earlier datagrams, optionally with one byte flipped;
/// - advancing the clock, which drives retransmission;
/// - application data written by the peer or the target, and a close.
pub fn conn_handle_records(data: &[u8], start: Instant) {
    run(data, start);
}

/// [`conn_handle_records`], reporting whether the target completed its handshake and the last
/// datagrams it sent.
fn run(mut data: &[u8], start: Instant) -> (bool, VecDeque<BytesMut>) {
    let Some((&config, rest)) = data.split_first() else {
        return (false, VecDeque::new());
    };
    data = rest;

    let suite = SUITES[usize::from(config) % SUITES.len()];
    let target_is_client = config & 0x08 != 0;
    let ems = match (config >> 4) & 0x03 {
        0 => ExtendedMasterSecretType::Request,
        1 => ExtendedMasterSecretType::Require,
        _ => ExtendedMasterSecretType::Disable,
    };
    let client_auth = config & 0x40 != 0;

    // Separate seeds: two peers drawing identical randoms would be a degenerate handshake.
    let (Ok(client_provider), Ok(server_provider)) = (
        crypto::fuzzing::deterministic_provider(1, true),
        crypto::fuzzing::deterministic_provider(2, true),
    ) else {
        return (false, VecDeque::new());
    };
    let (Some(client_config), Some(server_config)) = (
        handshake_config(client_provider, true, suite, ems, client_auth),
        handshake_config(server_provider, false, suite, ems, client_auth),
    ) else {
        return (false, VecDeque::new());
    };

    let client_addr = SocketAddr::from(([10, 0, 0, 1], 5000));
    let server_addr = SocketAddr::from(([10, 0, 0, 2], 5000));
    let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
    let server = Endpoint::new(server_addr, TransportProtocol::UDP, Some(server_config));
    if client
        .connect(start, server_addr, client_config, None)
        .is_err()
    {
        return (false, VecDeque::new());
    }

    let client = Side {
        endpoint: client,
        addr: client_addr,
        sent: VecDeque::new(),
    };
    let server = Side {
        endpoint: server,
        addr: server_addr,
        sent: VecDeque::new(),
    };
    let (target, peer) = if target_is_client {
        (client, server)
    } else {
        (server, client)
    };
    let mut h = Harness {
        target,
        peer,
        to_target: VecDeque::new(),
        to_peer: VecDeque::new(),
        now: start,
        target_connected: false,
    };
    h.target.flush(&mut h.to_peer);
    h.peer.flush(&mut h.to_target);

    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 10 {
            0 => {
                for _ in 0..32 {
                    if h.target_connected && h.to_target.is_empty() && h.to_peer.is_empty() {
                        break;
                    }
                    h.pump_once();
                    if h.to_target.is_empty() && h.to_peer.is_empty() && !h.target_connected {
                        h.advance(Duration::from_secs(1));
                    }
                }
            }
            1 => h.pump_once(),
            2 => h.deliver_to_target(BytesMut::from(arg)),
            3 => {
                let content_type = byte(arg, 0);
                let epoch_shift = (byte(arg, 1) % 3) as i8 - 1;
                let seq_skip = u64::from(byte(arg, 2));
                let body = arg.get(3..).unwrap_or(&[]);
                if let Some(record) = h.peer_record(content_type, epoch_shift, seq_skip, body) {
                    h.deliver_to_target(record);
                }
            }
            4 => {
                // A handshake fragment: type, message_seq, length and offset from the input.
                let mut body = vec![byte(arg, 0)];
                let total = u32::from(u16::from_be_bytes([byte(arg, 1), byte(arg, 2)]));
                let offset = u32::from(u16::from_be_bytes([byte(arg, 3), byte(arg, 4)]));
                let fragment = arg.get(7..).unwrap_or(&[]);
                body.extend_from_slice(&total.to_be_bytes()[1..]);
                body.extend_from_slice(&[byte(arg, 5), byte(arg, 6)]);
                body.extend_from_slice(&offset.to_be_bytes()[1..]);
                body.extend_from_slice(&(fragment.len() as u32).to_be_bytes()[1..]);
                body.extend_from_slice(fragment);
                let epoch_shift = if byte(arg, 0) & 0x80 != 0 { 0 } else { -1 };
                if let Some(record) = h.peer_record(22, epoch_shift, 0, &body) {
                    h.deliver_to_target(record);
                }
            }
            5 => {
                let sent = &h.peer.sent;
                if !sent.is_empty() {
                    let mut datagram = sent[usize::from(byte(arg, 0)) % sent.len()].clone();
                    if arg.len() >= 3 && !datagram.is_empty() {
                        let at = usize::from(byte(arg, 1)) % datagram.len();
                        datagram[at] ^= byte(arg, 2);
                    }
                    h.deliver_to_target(datagram);
                }
            }
            6 => h.advance(Duration::from_millis(u64::from(byte(arg, 0)) * 50)),
            7 => {
                let target = h.target.addr;
                if h.peer.endpoint.write(h.now, target, arg).is_ok() {
                    h.peer.flush(&mut h.to_target);
                }
            }
            8 => {
                let peer = h.peer.addr;
                if h.target.endpoint.write(h.now, peer, arg).is_ok() {
                    h.target.flush(&mut h.to_peer);
                }
            }
            _ => {
                let target = h.target.addr;
                let _ = h.peer.endpoint.stop(h.now, target);
                h.peer.flush(&mut h.to_target);
            }
        }
        // Exercise the accessors a caller reads after every input.
        let _ = h.target.endpoint.poll_timeout(&h.peer.addr);
        if let Some(state) = h.target.endpoint.get_connection_state(h.peer.addr) {
            let _ = state.cipher_suite().map(|cs| cs.id());
            if h.target_connected {
                let _ = state.export_keying_material("EXTRACTOR-dtls_srtp", &[], 60);
            }
        }
    }
    (h.target_connected, h.target.sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every suite completes the handshake with either side as the target, so the fuzzer's
    /// injected records reach a connected association.
    #[test]
    fn handshake_completes_for_every_configuration() {
        for config in 0..=0x7fu8 {
            if (config >> 4) & 0x03 == 3 {
                continue;
            }
            assert!(
                run(&[config, 0, 0], Instant::now()).0,
                "config {config:#04x}"
            );
        }
    }

    /// The same input produces the same bytes on the wire, run after run.
    #[test]
    fn runs_are_deterministic() {
        // Handshake, a peer write, a retransmission timeout, then a record at the next epoch.
        let input = [0x41, 0, 0, 7, 3, 1, 2, 3, 6, 1, 40, 3, 4, 23, 1, 0, 9];
        for config in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x49] {
            let mut input = input;
            input[0] = config;
            let start = Instant::now();
            let first = run(&input, start);
            let second = run(&input, start + Duration::from_secs(5));
            assert!(first.0, "config {config:#04x}");
            assert_eq!(first.1, second.1, "config {config:#04x}");
        }
    }
}
