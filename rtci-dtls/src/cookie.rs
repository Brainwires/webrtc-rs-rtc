//! The stateless cookie exchange of RFC 6347 4.2.1.
//!
//! A server answers a ClientHello that does not carry a valid cookie with a HelloVerifyRequest
//! and keeps nothing: the cookie is a MAC, under a secret only the server holds, over the
//! client's address and the ClientHello parameters that the second ClientHello must repeat.
//! Only a ClientHello that echoes it, which proves the client receives at the address it sends
//! from, gets an association. A spoofed source address therefore costs the server one small
//! datagram and no memory.

use crate::handshake::handshake_header::HANDSHAKE_HEADER_LENGTH;
use crate::handshake::handshake_message_client_hello::MAX_SESSION_ID_LENGTH;
use crate::handshake::handshake_random::HANDSHAKE_RANDOM_LENGTH;
use crate::record_layer::record_layer_header::{
    DTLS_VERSION_MAJOR, PROTOCOL_VERSION1_2, ProtocolVersion, RECORD_LAYER_HEADER_SIZE,
};
use crypto::{HmacAlgorithm, RTCCryptoProvider};
use shared::error::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// The length of a cookie: an HMAC-SHA-256 tag cut to 160 bits.
pub(crate) const STATELESS_COOKIE_LENGTH: usize = 20;
const COOKIE_SECRET_LENGTH: usize = 32;
/// How long a cookie secret signs new cookies. Cookies of the secret before it are still
/// accepted, so a cookie is valid for between one and two lifetimes.
pub(crate) const COOKIE_SECRET_LIFETIME: Duration = Duration::from_secs(60);

const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST: u8 = 3;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// What a server reads of a ClientHello before it keeps any state for the client: where the
/// record and the message sit in their sequences, the parameters the cookie covers, and the
/// cookie. Borrowed from the datagram.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientHelloPrefix<'a> {
    /// The record's sequence number, which the HelloVerifyRequest record repeats and the
    /// first ServerHello record starts from (RFC 6347 4.2.1).
    pub(crate) record_sequence: u64,
    /// The ClientHello's message_seq. The server's answer, HelloVerifyRequest or ServerHello,
    /// carries the same one (RFC 6347 4.2.2).
    pub(crate) message_sequence: u16,
    /// client_version, random and session_id, as encoded.
    pub(crate) version_random_session: &'a [u8],
    /// The cookie the ClientHello carries (empty in a first ClientHello).
    pub(crate) cookie: &'a [u8],
    /// cipher_suites and compression_methods, as encoded.
    pub(crate) suites_and_compression: &'a [u8],
}

impl<'a> ClientHelloPrefix<'a> {
    /// The ClientHello's random.
    pub(crate) fn random(&self) -> &'a [u8] {
        &self.version_random_session[2..2 + HANDSHAKE_RANDOM_LENGTH]
    }

    /// Reads the ClientHello that starts `datagram`, if one does: an epoch-0 handshake record
    /// whose first message is a ClientHello fragment at offset 0 that reaches at least to the
    /// end of the compression methods. (A ClientHello may be cut into several records; what
    /// the cookie covers sits in its first hundred bytes or so, ahead of the extensions.)
    pub(crate) fn parse(datagram: &'a [u8]) -> Option<Self> {
        let header = datagram.get(..RECORD_LAYER_HEADER_SIZE)?;
        if header[0] != CONTENT_TYPE_HANDSHAKE
            || header[1] != DTLS_VERSION_MAJOR
            || header[3..5] != [0, 0]
        {
            return None;
        }
        let mut record_sequence = [0u8; 8];
        record_sequence[2..].copy_from_slice(&header[5..11]);
        let record_len = u16::from_be_bytes([header[11], header[12]]) as usize;
        let record =
            datagram.get(RECORD_LAYER_HEADER_SIZE..RECORD_LAYER_HEADER_SIZE + record_len)?;

        let message = record.get(..HANDSHAKE_HEADER_LENGTH)?;
        if message[0] != HANDSHAKE_TYPE_CLIENT_HELLO || message[6..9] != [0, 0, 0] {
            return None;
        }
        let message_sequence = u16::from_be_bytes([message[4], message[5]]);
        let fragment_len = u32::from_be_bytes([0, message[9], message[10], message[11]]) as usize;
        let body = record.get(HANDSHAKE_HEADER_LENGTH..HANDSHAKE_HEADER_LENGTH + fragment_len)?;

        // client_version, random, session_id<0..32>.
        let mut at = 2 + HANDSHAKE_RANDOM_LENGTH;
        let session_id_len = *body.get(at)? as usize;
        if session_id_len > MAX_SESSION_ID_LENGTH {
            return None;
        }
        at += 1 + session_id_len;
        let version_random_session = body.get(..at)?;
        // cookie<0..255>.
        let cookie_len = *body.get(at)? as usize;
        let cookie = body.get(at + 1..at + 1 + cookie_len)?;
        at += 1 + cookie_len;
        // cipher_suites<2..2^16-2>, compression_methods<1..255>.
        let start = at;
        let suites_len = u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]) as usize;
        at += 2 + suites_len;
        let compression_len = *body.get(at)? as usize;
        at += 1 + compression_len;
        let suites_and_compression = body.get(start..at)?;

        Some(ClientHelloPrefix {
            record_sequence: u64::from_be_bytes(record_sequence),
            message_sequence,
            version_random_session,
            cookie,
            suites_and_compression,
        })
    }

    /// The HelloVerifyRequest datagram that answers this ClientHello with `cookie`.
    ///
    /// Its record carries the ClientHello's record sequence number, so that several
    /// HelloVerifyRequests never repeat one (RFC 6347 4.2.1), and its message the ClientHello's
    /// message_seq. `server_version` is the message's server_version field: DTLS 1.0 by
    /// default, as RFC 6347 4.2.1 advises whatever version is negotiated afterwards, or
    /// DTLS 1.2 when the configuration asks for it
    /// ([`ConfigBuilder::with_hello_verify_request_version`](crate::config::ConfigBuilder::with_hello_verify_request_version)).
    /// Clients are told to ignore the field either way. The record itself says DTLS 1.2, as
    /// every record of this stack does.
    pub(crate) fn hello_verify_request(
        &self,
        cookie: &[u8],
        server_version: ProtocolVersion,
    ) -> Vec<u8> {
        let body_len = 2 + 1 + cookie.len();
        let mut out =
            Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + HANDSHAKE_HEADER_LENGTH + body_len);
        out.extend_from_slice(&[
            CONTENT_TYPE_HANDSHAKE,
            PROTOCOL_VERSION1_2.major,
            PROTOCOL_VERSION1_2.minor,
            0,
            0,
        ]);
        out.extend_from_slice(&self.record_sequence.to_be_bytes()[2..]);
        out.extend_from_slice(&((HANDSHAKE_HEADER_LENGTH + body_len) as u16).to_be_bytes());

        let length = (body_len as u32).to_be_bytes();
        out.push(HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST);
        out.extend_from_slice(&length[1..]);
        out.extend_from_slice(&self.message_sequence.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(&length[1..]);

        out.extend_from_slice(&[server_version.major, server_version.minor]);
        out.push(cookie.len() as u8);
        out.extend_from_slice(cookie);
        out
    }
}

/// The secrets a server's cookies are made with: the current one and the one before it.
#[derive(Default)]
pub(crate) struct CookieSecrets {
    current: Option<([u8; COOKIE_SECRET_LENGTH], Instant)>,
    previous: Option<[u8; COOKIE_SECRET_LENGTH]>,
}

impl Drop for CookieSecrets {
    fn drop(&mut self) {
        // Overwritten in place on the way out, like every other secret here: taking the
        // value out of the `Option` would leave its bytes where they were.
        self.forget_current();
        self.forget_previous();
    }
}

impl CookieSecrets {
    fn forget_current(&mut self) {
        if let Some((secret, _)) = &mut self.current {
            secret.zeroize();
        }
        self.current = None;
    }

    fn forget_previous(&mut self) {
        if let Some(secret) = &mut self.previous {
            secret.zeroize();
        }
        self.previous = None;
    }

    /// Makes the first secret, or a new one once the current one has served its lifetime.
    fn rotate(&mut self, now: Instant, provider: &dyn RTCCryptoProvider) -> Result<()> {
        let age = self
            .current
            .as_ref()
            .map(|(_, since)| now.saturating_duration_since(*since));
        if age.is_none_or(|age| age >= COOKIE_SECRET_LIFETIME) {
            let mut secret = [0u8; COOKIE_SECRET_LENGTH];
            provider
                .random()
                .fill_secret(&mut secret)
                .map_err(|err| Error::Crypto(err.to_string()))?;
            // The secret before stays good for one more lifetime; one that has been idle for
            // two is too old to vouch for anything.
            let recent = age.is_some_and(|age| age < 2 * COOKIE_SECRET_LIFETIME);
            self.forget_previous();
            if recent && let Some((current, _)) = &self.current {
                self.previous = Some(*current);
            }
            self.forget_current();
            self.current = Some((secret, now));
            secret.zeroize();
        }
        Ok(())
    }

    /// The cookie for `hello` from `remote` under `secret`: HMAC-SHA-256 over the address and
    /// the ClientHello parameters RFC 6347 4.2.1 names (version, random, session_id,
    /// cipher_suites, compression_methods), each with its length in front.
    ///
    /// On a stack that is overwritten afterwards (`crypto::on_erased_stack`): the HMAC leaves
    /// the keyed hash states of the secret in the provider's frames (tests/key_residue.rs).
    fn mac(
        secret: &[u8],
        provider: &dyn RTCCryptoProvider,
        remote: SocketAddr,
        hello: &ClientHelloPrefix<'_>,
    ) -> Result<[u8; STATELESS_COOKIE_LENGTH]> {
        crypto::on_erased_stack(|| Self::keyed_mac(secret, provider, remote, hello))
    }

    fn keyed_mac(
        secret: &[u8],
        provider: &dyn RTCCryptoProvider,
        remote: SocketAddr,
        hello: &ClientHelloPrefix<'_>,
    ) -> Result<[u8; STATELESS_COOKIE_LENGTH]> {
        let address = match remote.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mut mac = provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, secret)
            .map_err(|err| Error::Crypto(err.to_string()))?;
        let mut tag = vec![0u8; mac.output_len()];
        mac.sign(
            &[
                &[address.len() as u8],
                &address,
                &remote.port().to_be_bytes(),
                &(hello.version_random_session.len() as u16).to_be_bytes(),
                hello.version_random_session,
                &(hello.suites_and_compression.len() as u32).to_be_bytes(),
                hello.suites_and_compression,
            ],
            &mut tag,
        )
        .map_err(|err| Error::Crypto(err.to_string()))?;
        let mut cookie = [0u8; STATELESS_COOKIE_LENGTH];
        cookie.copy_from_slice(&tag[..STATELESS_COOKIE_LENGTH]);
        Ok(cookie)
    }

    /// The secrets cookies are accepted under at `now`: the current one, which new cookies
    /// are made with, first, then the one before it. The DTLS 1.3 cookie exchange (RFC 9147
    /// section 5.1) shares them with the DTLS 1.2 one.
    pub(crate) fn secrets(
        &mut self,
        now: Instant,
        provider: &dyn RTCCryptoProvider,
    ) -> Result<Vec<crypto::SecretVec>> {
        self.rotate(now, provider)?;
        Ok(self
            .current
            .iter()
            .map(|(secret, _)| secret)
            .chain(self.previous.iter())
            .map(|secret| crypto::SecretVec::new(secret.to_vec()))
            .collect())
    }

    /// The cookie to send `remote` for `hello`, under the current secret.
    pub(crate) fn issue(
        &mut self,
        now: Instant,
        provider: &dyn RTCCryptoProvider,
        remote: SocketAddr,
        hello: &ClientHelloPrefix<'_>,
    ) -> Result<[u8; STATELESS_COOKIE_LENGTH]> {
        self.rotate(now, provider)?;
        let Some((secret, _)) = &self.current else {
            return Err(Error::Crypto("no cookie secret".to_owned()));
        };
        Self::mac(secret, provider, remote, hello)
    }

    /// Whether `hello` carries the cookie this server would send `remote` for it, under the
    /// current secret or the one before. Compared in constant time.
    pub(crate) fn verify(
        &mut self,
        now: Instant,
        provider: &dyn RTCCryptoProvider,
        remote: SocketAddr,
        hello: &ClientHelloPrefix<'_>,
    ) -> Result<bool> {
        if hello.cookie.len() != STATELESS_COOKIE_LENGTH {
            return Ok(false);
        }
        self.rotate(now, provider)?;
        let secrets = self
            .current
            .iter()
            .map(|(secret, _)| secret)
            .chain(self.previous.iter());
        let mut valid = false;
        for secret in secrets {
            let expected = Self::mac(secret, provider, remote, hello)?;
            valid |= crypto::constant_time_eq(&expected, hello.cookie);
        }
        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello datagram: `cookie`, one cipher suite, null compression, no extensions.
    fn client_hello(cookie: &[u8], session_id_len: usize, fragment_offset: u8) -> Vec<u8> {
        let mut body = vec![0xfe, 0xfd];
        body.extend_from_slice(&[0x42; 32]);
        body.push(session_id_len as u8);
        body.extend_from_slice(&vec![0x07; session_id_len]);
        body.push(cookie.len() as u8);
        body.extend_from_slice(cookie);
        body.extend_from_slice(&[0, 2, 0xc0, 0x2b, 1, 0]);
        let length = (body.len() as u32).to_be_bytes();
        let mut message = vec![1];
        message.extend_from_slice(&length[1..]);
        message.extend_from_slice(&[0, 3, 0, 0, fragment_offset]);
        message.extend_from_slice(&length[1..]);
        message.extend_from_slice(&body);
        let mut datagram = vec![22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 9];
        datagram.extend_from_slice(&(message.len() as u16).to_be_bytes());
        datagram.extend_from_slice(&message);
        datagram
    }

    #[test]
    fn the_prefix_of_a_client_hello_is_read_without_state() {
        let datagram = client_hello(&[0xaa; 20], 32, 0);
        let hello = ClientHelloPrefix::parse(&datagram).expect("a ClientHello");
        assert_eq!(hello.record_sequence, 9);
        assert_eq!(hello.message_sequence, 3);
        assert_eq!(hello.cookie, &[0xaa; 20]);
        assert_eq!(hello.random(), &[0x42; 32]);
        assert_eq!(hello.version_random_session.len(), 2 + 32 + 1 + 32);
        assert_eq!(hello.suites_and_compression, &[0, 2, 0xc0, 0x2b, 1, 0]);
    }

    #[test]
    fn what_is_not_the_start_of_a_client_hello_is_not_read() {
        let good = client_hello(&[], 0, 0);
        assert!(ClientHelloPrefix::parse(&good).is_some());

        // A later fragment, a session id past 32 bytes, another message, another content
        // type, a later epoch, and every truncation.
        assert!(ClientHelloPrefix::parse(&client_hello(&[], 0, 1)).is_none());
        assert!(ClientHelloPrefix::parse(&client_hello(&[], 33, 0)).is_none());
        let mut other = good.clone();
        other[13] = 2;
        assert!(ClientHelloPrefix::parse(&other).is_none());
        let mut other = good.clone();
        other[0] = 23;
        assert!(ClientHelloPrefix::parse(&other).is_none());
        let mut other = good.clone();
        other[4] = 1;
        assert!(ClientHelloPrefix::parse(&other).is_none());
        for len in 0..good.len() {
            assert!(
                ClientHelloPrefix::parse(&good[..len]).is_none(),
                "{len} bytes"
            );
        }
    }

    #[test]
    fn a_hello_verify_request_repeats_the_sequence_numbers_of_its_client_hello() {
        let datagram = client_hello(&[], 0, 0);
        let hello = ClientHelloPrefix::parse(&datagram).unwrap();
        let answer = hello.hello_verify_request(&[0x5c; 20], PROTOCOL_VERSION1_2);
        assert_eq!(&answer[..5], &[22, 0xfe, 0xfd, 0, 0]);
        assert_eq!(
            &answer[5..11],
            &[0, 0, 0, 0, 0, 9],
            "the record sequence number"
        );
        assert_eq!(answer.len(), 13 + 12 + 23);
        assert_eq!(&answer[13..17], &[3, 0, 0, 23]);
        assert_eq!(&answer[17..19], &[0, 3], "message_seq");
        assert_eq!(&answer[25..28], &[0xfe, 0xfd, 20]);
        assert_eq!(&answer[28..], &[0x5c; 20]);
        assert!(answer.len() < datagram.len());
    }
}
