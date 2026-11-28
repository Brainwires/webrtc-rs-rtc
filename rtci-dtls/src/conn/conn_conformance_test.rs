//! Handshake rules of RFC 5246 (as DTLS 1.2 inherits them), RFC 5746, RFC 5764, RFC 7627 and
//! RFC 8422, each driven through the production connection or flight code.
//!
//! Hellos a conforming peer could send but this crate never builds (a session id, no extensions
//! block, a signalling cipher suite, an MKI) are written here byte by byte, so the parser under
//! test is not also the encoder.

use super::*;
use crate::cipher_suite::CipherSuiteId;
use crate::config::{ClientAuthType, ConfigBuilder, ExtendedMasterSecretType};
use crate::crypto::Certificate;
use crate::curve::EllipticCurveType;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::flight::flight3::Flight3;
use crate::flight::flight6::Flight6;
use crate::handshake::handshake_message_server_hello_done::HandshakeMessageServerHelloDone;
use crate::handshake::handshake_message_server_key_exchange::HandshakeMessageServerKeyExchange;
use crate::signature_hash_algorithm::{
    HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm, SignatureScheme,
};

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

pub(crate) const ECDSA_GCM: u16 = 0xc02b;
const SCSV: u16 = 0x00ff;

const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_USE_SRTP: u16 = 14;
const EXT_ALPN: u16 = 16;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

const ALERT_FATAL: u8 = 2;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_ILLEGAL_PARAMETER: u8 = 47;
const ALERT_DECRYPT_ERROR: u8 = 51;

pub(crate) fn provider() -> Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

pub(crate) fn self_signed() -> Certificate {
    Certificate::generate_self_signed(vec!["localhost".to_owned()], provider().crypto())
        .expect("a self-signed certificate is generated")
}

pub(crate) fn builder() -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
}

pub(crate) fn client(builder: ConfigBuilder) -> DTLSConn {
    let config = builder
        .with_insecure_skip_verify(true)
        .build(true, None)
        .expect("a client configuration");
    DTLSConn::new(Arc::new(config), true, None)
}

pub(crate) fn server(builder: ConfigBuilder) -> DTLSConn {
    let config = builder
        .with_certificates(vec![self_signed()])
        .build(false, None)
        .expect("a server configuration");
    DTLSConn::new(Arc::new(config), false, None)
}

/// One received datagram, handled as `Endpoint::read` handles it.
pub(crate) fn feed(conn: &mut DTLSConn, now: Instant, datagram: &[u8]) -> Result<()> {
    conn.read(datagram)?;
    if !conn.is_handshake_completed() {
        conn.handshake(now)?;
        if conn.handle_incoming_queued_packets()? && !conn.is_handshake_completed() {
            conn.handshake(now)?;
        }
    }
    Ok(())
}

pub(crate) fn drain(conn: &mut DTLSConn) -> Vec<Vec<u8>> {
    let mut datagrams = vec![];
    while let Some(datagram) = conn.outgoing_raw_packet() {
        datagrams.push(datagram.to_vec());
    }
    datagrams
}

/// A client and a server driven against each other, with everything each sent.
pub(crate) struct Exchange {
    pub(crate) client: DTLSConn,
    pub(crate) server: DTLSConn,
    pub(crate) client_err: Option<Error>,
    pub(crate) server_err: Option<Error>,
    pub(crate) from_client: Vec<Vec<u8>>,
    pub(crate) from_server: Vec<Vec<u8>>,
}

impl Exchange {
    pub(crate) fn run(client: DTLSConn, server: DTLSConn) -> Self {
        Self::run_altering(client, server, |_| {}, |_| {})
    }

    /// As [`Self::run`], with every datagram passed through `to_server` or `to_client` on its
    /// way: what someone on the path can do to the unprotected part of a handshake.
    pub(crate) fn run_altering(
        mut client: DTLSConn,
        mut server: DTLSConn,
        mut to_server: impl FnMut(&mut Vec<u8>),
        mut to_client: impl FnMut(&mut Vec<u8>),
    ) -> Self {
        let now = Instant::now();
        let mut client_err = client.handshake(now).err();
        let mut server_err = None;
        let mut from_client = vec![];
        let mut from_server = vec![];
        for _ in 0..64 {
            let sent_by_client = drain(&mut client);
            for datagram in &sent_by_client {
                let mut datagram = datagram.clone();
                to_server(&mut datagram);
                if server_err.is_none()
                    && let Err(err) = feed(&mut server, now, &datagram)
                {
                    server_err = Some(err);
                }
            }
            let sent_by_server = drain(&mut server);
            for datagram in &sent_by_server {
                let mut datagram = datagram.clone();
                to_client(&mut datagram);
                if client_err.is_none()
                    && let Err(err) = feed(&mut client, now, &datagram)
                {
                    client_err = Some(err);
                }
            }
            let idle = sent_by_client.is_empty() && sent_by_server.is_empty();
            from_client.extend(sent_by_client);
            from_server.extend(sent_by_server);
            if idle {
                break;
            }
        }
        Exchange {
            client,
            server,
            client_err,
            server_err,
            from_client,
            from_server,
        }
    }

    pub(crate) fn completed(&self) -> bool {
        self.client_err.is_none()
            && self.server_err.is_none()
            && self.client.is_handshake_completed()
            && self.server.is_handshake_completed()
    }
}

/// The (level, description) of every plaintext alert record in `datagrams`.
pub(crate) fn plaintext_alerts(datagrams: &[Vec<u8>]) -> Vec<(u8, u8)> {
    let mut alerts = vec![];
    for datagram in datagrams {
        for record in unpack_datagram(datagram).expect("a datagram splits into records") {
            let epoch = u16::from_be_bytes([record[3], record[4]]);
            if record[0] == 21 && epoch == 0 && record.len() == RECORD_LAYER_HEADER_SIZE + 2 {
                alerts.push((record[13], record[14]));
            }
        }
    }
    alerts
}

/// The (type, body) of every unfragmented plaintext handshake message in `datagrams`.
pub(crate) fn plaintext_handshake_messages(datagrams: &[Vec<u8>]) -> Vec<(u8, Vec<u8>)> {
    let mut messages = vec![];
    for datagram in datagrams {
        for record in unpack_datagram(datagram).expect("a datagram splits into records") {
            let epoch = u16::from_be_bytes([record[3], record[4]]);
            if record[0] != 22 || epoch != 0 {
                continue;
            }
            let message = &record[RECORD_LAYER_HEADER_SIZE..];
            let length = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
            let fragment_length =
                u32::from_be_bytes([0, message[9], message[10], message[11]]) as usize;
            assert_eq!(
                length, fragment_length,
                "the test flights are not fragmented"
            );
            messages.push((message[0], message[12..12 + length].to_vec()));
        }
    }
    messages
}

/// Where the body of the first unfragmented plaintext handshake message of `handshake_type`
/// lies in `datagram`.
pub(crate) fn handshake_body_range(
    datagram: &[u8],
    handshake_type: u8,
) -> Option<std::ops::Range<usize>> {
    let mut at = 0;
    while at + RECORD_LAYER_HEADER_SIZE <= datagram.len() {
        let record_len = u16::from_be_bytes([datagram[at + 11], datagram[at + 12]]) as usize;
        let epoch = u16::from_be_bytes([datagram[at + 3], datagram[at + 4]]);
        let message = at + RECORD_LAYER_HEADER_SIZE;
        if datagram[at] == 22 && epoch == 0 && datagram[message] == handshake_type {
            return Some(message + 12..message + record_len);
        }
        at = message + record_len;
    }
    None
}

pub(crate) fn body_of(messages: &[(u8, Vec<u8>)], handshake_type: u8) -> Option<Vec<u8>> {
    messages
        .iter()
        .find(|(typ, _)| *typ == handshake_type)
        .map(|(_, body)| body.clone())
}

pub(crate) const CLIENT_HELLO: u8 = 1;
pub(crate) const SERVER_HELLO: u8 = 2;
pub(crate) const HELLO_VERIFY_REQUEST: u8 = 3;
const CERTIFICATE: u8 = 11;
const SERVER_KEY_EXCHANGE: u8 = 12;
const SERVER_HELLO_DONE: u8 = 14;

/// One extension: type, length, data.
fn extension(typ: u16, data: &[u8]) -> Vec<u8> {
    let mut out = typ.to_be_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn signature_algorithms(pairs: &[(u8, u8)]) -> Vec<u8> {
    let mut data = ((pairs.len() * 2) as u16).to_be_bytes().to_vec();
    for (hash, signature) in pairs {
        data.extend_from_slice(&[*hash, *signature]);
    }
    extension(EXT_SIGNATURE_ALGORITHMS, &data)
}

/// ecdsa_secp256r1_sha256.
const ECDSA_SHA256: (u8, u8) = (4, 3);

fn supported_groups(groups: &[u16]) -> Vec<u8> {
    let mut data = ((groups.len() * 2) as u16).to_be_bytes().to_vec();
    for group in groups {
        data.extend_from_slice(&group.to_be_bytes());
    }
    extension(EXT_SUPPORTED_GROUPS, &data)
}

fn point_formats() -> Vec<u8> {
    extension(EXT_POINT_FORMATS, &[1, 0])
}

fn renegotiation_info(renegotiated_connection: &[u8]) -> Vec<u8> {
    let mut data = vec![renegotiated_connection.len() as u8];
    data.extend_from_slice(renegotiated_connection);
    extension(EXT_RENEGOTIATION_INFO, &data)
}

fn use_srtp(profiles: &[u16], mki: &[u8]) -> Vec<u8> {
    let mut data = ((profiles.len() * 2) as u16).to_be_bytes().to_vec();
    for profile in profiles {
        data.extend_from_slice(&profile.to_be_bytes());
    }
    data.push(mki.len() as u8);
    data.extend_from_slice(mki);
    extension(EXT_USE_SRTP, &data)
}

/// The extensions an ordinary ECDHE client sends, less the optional ones.
pub(crate) fn usual_client_extensions() -> Vec<u8> {
    [
        signature_algorithms(&[ECDSA_SHA256]),
        supported_groups(&[0x001d, 0x0017]),
        point_formats(),
    ]
    .concat()
}

/// A ClientHello body. `extensions: None` ends the message after the compression methods.
pub(crate) fn client_hello_body(
    session_id: &[u8],
    cookie: &[u8],
    cipher_suites: &[u16],
    extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = vec![0xfe, 0xfd];
    body.extend_from_slice(&[0x5a; 32]);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]);
    if let Some(extensions) = extensions {
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
    }
    body
}

/// A ServerHello body. `extensions: None` ends the message after the compression method.
fn server_hello_body(cipher_suite: u16, compression: u8, extensions: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![0xfe, 0xfd];
    body.extend_from_slice(&[0xa5; 32]);
    body.push(0);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(compression);
    if let Some(extensions) = extensions {
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);
    }
    body
}

/// A handshake message with its 12-byte header, unfragmented.
pub(crate) fn handshake_message(handshake_type: u8, message_sequence: u16, body: &[u8]) -> Vec<u8> {
    let length = (body.len() as u32).to_be_bytes();
    let mut out = vec![handshake_type];
    out.extend_from_slice(&length[1..]);
    out.extend_from_slice(&message_sequence.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&length[1..]);
    out.extend_from_slice(body);
    out
}

/// A plaintext (epoch 0) record around `payload`.
pub(crate) fn plaintext_record(content_type: u8, sequence_number: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type, 0xfe, 0xfd, 0, 0];
    out.extend_from_slice(&sequence_number.to_be_bytes()[2..]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(crate) fn client_hello_datagram(message_sequence: u16, body: &[u8]) -> Vec<u8> {
    plaintext_record(
        22,
        message_sequence as u64,
        &handshake_message(CLIENT_HELLO, message_sequence, body),
    )
}

/// What a server answers a hand-written client: the cookie exchange is done with
/// `client_hello(cookie)`, first without a cookie, then with the server's.
struct ServerAnswer {
    server: DTLSConn,
    /// The outcome of feeding the second ClientHello.
    result: Result<()>,
    /// What the server sent after the second ClientHello.
    datagrams: Vec<Vec<u8>>,
}

impl ServerAnswer {
    fn messages(&self) -> Vec<(u8, Vec<u8>)> {
        plaintext_handshake_messages(&self.datagrams)
    }

    fn server_hello_extension_types(&self) -> Vec<u16> {
        let body = body_of(&self.messages(), SERVER_HELLO).expect("a ServerHello");
        extension_types_after(&body, 2 + 32 + 1 + body[34] as usize + 2 + 1)
    }

    fn server_hello_extension(&self, typ: u16) -> Option<Vec<u8>> {
        let body = body_of(&self.messages(), SERVER_HELLO).expect("a ServerHello");
        extensions_after(&body, 2 + 32 + 1 + body[34] as usize + 2 + 1)
            .into_iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, data)| data)
    }
}

/// The extensions that start at `offset` of a hello body (none when the body ends there).
pub(crate) fn extensions_after(body: &[u8], offset: usize) -> Vec<(u16, Vec<u8>)> {
    let mut extensions = vec![];
    if body.len() == offset {
        return extensions;
    }
    let total = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    let mut rest = &body[offset + 2..];
    assert_eq!(rest.len(), total, "the extensions block fills the message");
    while !rest.is_empty() {
        let typ = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        extensions.push((typ, rest[4..4 + len].to_vec()));
        rest = &rest[4 + len..];
    }
    extensions
}

pub(crate) fn extension_types_after(body: &[u8], offset: usize) -> Vec<u16> {
    extensions_after(body, offset)
        .into_iter()
        .map(|(typ, _)| typ)
        .collect()
}

fn answer_from(
    server_builder: ConfigBuilder,
    client_hello: impl Fn(&[u8]) -> Vec<u8>,
) -> ServerAnswer {
    let now = Instant::now();
    let mut server = server(server_builder);
    server.handshake(now).expect("the server starts");

    feed(
        &mut server,
        now,
        &client_hello_datagram(0, &client_hello(&[])),
    )
    .expect("the first ClientHello is taken");
    let first = drain(&mut server);
    let hello_verify_request = body_of(&plaintext_handshake_messages(&first), HELLO_VERIFY_REQUEST)
        .expect("the server answers a cookieless ClientHello with HelloVerifyRequest");
    let cookie = hello_verify_request[3..3 + hello_verify_request[2] as usize].to_vec();

    let result = feed(
        &mut server,
        now,
        &client_hello_datagram(1, &client_hello(&cookie)),
    );
    let datagrams = drain(&mut server);
    ServerAnswer {
        server,
        result,
        datagrams,
    }
}

/// What `Flight3` makes of a server flight starting with `server_hello` (a ServerHello body),
/// for a client built from `client_builder`.
fn client_parses_server_hello(
    client_builder: ConfigBuilder,
    server_hello: &[u8],
) -> std::result::Result<String, (Option<Alert>, Option<Error>)> {
    let cfg = client_builder
        .with_insecure_skip_verify(true)
        .build(true, None)
        .expect("a client configuration");
    let mut state = State::new(provider(), true);
    let mut cache = HandshakeCache::new();

    assert!(cache.push(
        handshake_message(SERVER_HELLO, 0, server_hello),
        0,
        0,
        HandshakeType::ServerHello,
        false,
    ));
    let mut server_key_exchange = Handshake::new(HandshakeMessage::ServerKeyExchange(
        HandshakeMessageServerKeyExchange {
            identity_hint: vec![],
            elliptic_curve_type: EllipticCurveType::NamedCurve,
            named_curve: NamedCurve::X25519,
            public_key: vec![0x42; 32],
            algorithm: SignatureHashAlgorithm {
                hash: HashAlgorithm::Sha256,
                signature: SignatureAlgorithm::Ecdsa,
            },
            signature: vec![0x30; 70],
        },
    ));
    server_key_exchange.handshake_header.message_sequence = 1;
    let mut raw = vec![];
    server_key_exchange.marshal(&mut raw).unwrap();
    assert!(cache.push(raw, 0, 1, HandshakeType::ServerKeyExchange, false));
    let mut server_hello_done = Handshake::new(HandshakeMessage::ServerHelloDone(
        HandshakeMessageServerHelloDone {},
    ));
    server_hello_done.handshake_header.message_sequence = 2;
    let mut raw = vec![];
    server_hello_done.marshal(&mut raw).unwrap();
    assert!(cache.push(raw, 0, 2, HandshakeType::ServerHelloDone, false));

    Flight3 {}
        .parse(&mut state, &cache, &cfg)
        .map(|next| next.to_string())
}

fn assert_fatal(
    result: std::result::Result<String, (Option<Alert>, Option<Error>)>,
    description: AlertDescription,
    what: &str,
) {
    match result {
        Err((Some(alert), Some(_))) => {
            assert_eq!(alert.alert_level, AlertLevel::Fatal, "{what}");
            assert_eq!(alert.alert_description, description, "{what}");
        }
        Err((alert, err)) => panic!("{what}: unexpected result {alert:?} {err:?}"),
        Ok(next) => panic!("{what}: the flight was accepted, next is {next}"),
    }
}

/// The extensions a server may answer the default test client with.
fn usual_server_extensions() -> Vec<u8> {
    [
        renegotiation_info(&[]),
        extension(EXT_EXTENDED_MASTER_SECRET, &[]),
        point_formats(),
    ]
    .concat()
}

// ---------------------------------------------------------------------------------------------
// Finished (RFC 5246 7.4.9)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.4.9: the server checks the client's verify_data. A client whose Finished does not
/// match the transcript the server saw is refused with decrypt_error, and the server never
/// completes.
#[test]
fn server_refuses_a_client_finished_with_wrong_verify_data() {
    let mut client = client(builder());
    // `Flight5::generate` reuses a cached value, so this is what the client's Finished carries.
    client.state.local_verify_data = vec![0; 12];
    let exchange = Exchange::run(client, server(builder()));

    assert_eq!(exchange.server_err, Some(Error::ErrVerifyDataMismatch));
    assert!(!exchange.server.is_handshake_completed());
    assert!(exchange.server.is_failed());
    assert_eq!(
        plaintext_alerts(&exchange.from_server),
        vec![(ALERT_FATAL, ALERT_DECRYPT_ERROR)]
    );
}

/// RFC 5246 7.4.9: the client checks the server's verify_data, and says so with decrypt_error.
/// The alert leaves in the client's current epoch, protected, so the server can read it.
#[test]
fn client_refuses_a_server_finished_with_wrong_verify_data() {
    let mut server = server(builder());
    server.state.local_verify_data = vec![0; 12];
    let exchange = Exchange::run(client(builder()), server);

    assert_eq!(exchange.client_err, Some(Error::ErrVerifyDataMismatch));
    assert!(!exchange.client.is_handshake_completed());
    assert!(exchange.client.is_failed());
    // The client has sent ChangeCipherSpec, so its alert is an epoch-1 record: the server
    // decrypts it and fails on it.
    assert!(plaintext_alerts(&exchange.from_client).is_empty());
    assert_eq!(exchange.server_err, Some(Error::ErrAlertFatalOrClose));
    assert!(exchange.server.is_failed());
}

/// The check is over the transcript, so a ClientHello altered on the way (here: the offered
/// SRTP profiles reordered, which the record layer does not protect) is caught by the server
/// too, not only by the client. Without the extended master secret, that is: with it the
/// altered transcript already gives the two ends different keys.
#[test]
fn server_refuses_a_finished_over_a_different_transcript() {
    let profiles = vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
    ];
    let legacy = || {
        builder()
            .with_srtp_protection_profiles(profiles.clone())
            .with_extended_master_secret(ExtendedMasterSecretType::Disable)
    };
    let mut client = client(legacy());
    let mut server = server(legacy());
    let now = Instant::now();
    client.handshake(now).unwrap();
    server.handshake(now).unwrap();

    let mut server_err = None;
    let mut client_done = false;
    for _ in 0..16 {
        for mut datagram in drain(&mut client) {
            // The ClientHello lists use_srtp profiles 0x0007 then 0x0001: swap them.
            if let Some(at) = datagram
                .windows(8)
                .position(|w| w == [0x00, 0x0e, 0x00, 0x07, 0x00, 0x04, 0x00, 0x07])
            {
                datagram[at + 7] = 0x01;
                datagram[at + 9] = 0x07;
            }
            if server_err.is_none()
                && let Err(err) = feed(&mut server, now, &datagram)
            {
                server_err = Some(err);
            }
        }
        for datagram in drain(&mut server) {
            // The client sees its own transcript; whatever it concludes is not what is tested.
            client_done |= feed(&mut client, now, &datagram).is_err();
        }
        if server_err.is_some() || client_done {
            break;
        }
    }

    assert_eq!(server_err, Some(Error::ErrVerifyDataMismatch));
    assert!(!server.is_handshake_completed());
}

/// The server's last flight checks a Finished it is handed again like the first one.
#[test]
fn a_repeated_client_finished_is_verified_again() {
    let exchange = Exchange::run(client(builder()), server(builder()));
    assert!(exchange.completed());
    let mut server = exchange.server;
    let cfg = server.handshake_config.clone();

    assert!(
        Flight6 {}
            .parse(&mut server.state, &server.cache, &cfg)
            .is_ok()
    );

    // Under another master secret the cached Finished is not this handshake's.
    server.state.master_secret.as_mut()[0] ^= 1;
    match (Flight6 {}).parse(&mut server.state, &server.cache, &cfg) {
        Err((Some(alert), Some(Error::ErrVerifyDataMismatch))) => {
            assert_eq!(alert.alert_level, AlertLevel::Fatal);
            assert_eq!(alert.alert_description, AlertDescription::DecryptError);
        }
        Err((alert, err)) => panic!("unexpected result {alert:?} {err:?}"),
        Ok(next) => panic!("accepted, next is {next}"),
    }
}

// ---------------------------------------------------------------------------------------------
// ClientHello parsing (RFC 5246 7.4.1.2)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.4.1.2: a ClientHello may carry a session id (up to 32 bytes) the server does not
/// know; the server parses it and performs a full handshake.
#[test]
fn a_client_hello_with_a_session_id_gets_a_full_handshake() {
    let answer = answer_from(builder(), |cookie| {
        client_hello_body(
            &[0x77; 32],
            cookie,
            &[ECDSA_GCM],
            Some(&usual_client_extensions()),
        )
    });

    answer.result.as_ref().expect("the ClientHello is accepted");
    let messages = answer.messages();
    let server_hello = body_of(&messages, SERVER_HELLO).expect("a ServerHello");
    assert_eq!(server_hello[34], 0, "no session is offered for resumption");
    assert!(body_of(&messages, CERTIFICATE).is_some());
    assert!(body_of(&messages, SERVER_KEY_EXCHANGE).is_some());
    assert!(body_of(&messages, SERVER_HELLO_DONE).is_some());
}

/// RFC 5246 7.4.1.2: the server accepts a ClientHello that ends after the compression methods.
/// Without signature_algorithms the client is taken to support only the SHA-1 defaults
/// (7.4.1.4.1), which this server does not sign with, so the PSK suite is the one to prove it.
#[test]
fn a_client_hello_without_an_extensions_block_is_answered() {
    let now = Instant::now();
    let config = ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256])
        .with_psk(Some(Arc::new(|_| Ok(vec![0xab, 0xcd]))))
        .build(false, None)
        .unwrap();
    let mut server = DTLSConn::new(Arc::new(config), false, None);
    server.handshake(now).unwrap();

    let hello = |cookie: &[u8]| client_hello_body(&[], cookie, &[0x00a8], None);
    feed(&mut server, now, &client_hello_datagram(0, &hello(&[]))).unwrap();
    let first = drain(&mut server);
    let hello_verify_request = body_of(&plaintext_handshake_messages(&first), HELLO_VERIFY_REQUEST)
        .expect("a ClientHello without extensions is answered");
    let cookie = hello_verify_request[3..3 + hello_verify_request[2] as usize].to_vec();
    feed(&mut server, now, &client_hello_datagram(1, &hello(&cookie))).unwrap();

    let messages = plaintext_handshake_messages(&drain(&mut server));
    let server_hello = body_of(&messages, SERVER_HELLO).expect("a ServerHello");
    // RFC 5246 7.4.1.4: nothing was offered, so nothing is answered.
    assert!(
        extension_types_after(&server_hello, 2 + 32 + 1 + 2 + 1).is_empty(),
        "a ServerHello to a client without extensions carries none"
    );
}

/// RFC 5246 7.4.1.2: bytes after the extensions block make the message malformed. It is not
/// processed (at epoch 0 it is discarded, RFC 6347 4.1.2.7, rather than answered with an alert).
#[test]
fn a_client_hello_with_trailing_bytes_is_not_processed() {
    let mut body = client_hello_body(&[], &[], &[ECDSA_GCM], Some(&usual_client_extensions()));
    body.extend_from_slice(&[0, 0, 0]);
    let message = handshake_message(CLIENT_HELLO, 0, &body);
    assert!(Handshake::unmarshal(&mut message.as_slice()).is_err());

    let now = Instant::now();
    let mut server = server(builder());
    server.handshake(now).unwrap();
    feed(&mut server, now, &client_hello_datagram(0, &body)).unwrap();
    assert!(drain(&mut server).is_empty());
    assert!(!server.is_failed());
}

/// RFC 5246 7.4.1.2: the ClientHello's compression methods always include null. A server that
/// is offered only others has nothing to select: illegal_parameter.
#[test]
fn a_client_hello_without_the_null_compression_method_is_refused() {
    let answer = answer_from(builder(), |cookie| {
        let mut body =
            client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&usual_client_extensions()));
        // version, random, empty session id, cookie, one suite, then `01 00`: DEFLATE instead.
        let method = 2 + 32 + 1 + 1 + cookie.len() + 2 + 2 + 1;
        assert_eq!(&body[method - 1..=method], &[1, 0]);
        body[method] = 1;
        body
    });
    assert_eq!(answer.result, Err(Error::ErrNoNullCompressionMethod));
    assert_eq!(
        plaintext_alerts(&answer.datagrams),
        vec![(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER)]
    );
}

/// RFC 5246 7.4.1.4: there is at most one extension of a type; a hello with two is malformed.
#[test]
fn a_hello_with_a_repeated_extension_is_malformed() {
    let extensions = [usual_client_extensions(), point_formats()].concat();
    let client_hello = handshake_message(
        CLIENT_HELLO,
        0,
        &client_hello_body(&[], &[], &[ECDSA_GCM], Some(&extensions)),
    );
    assert!(Handshake::unmarshal(&mut client_hello.as_slice()).is_err());

    let extensions = [usual_server_extensions(), renegotiation_info(&[])].concat();
    let server_hello = handshake_message(
        SERVER_HELLO,
        0,
        &server_hello_body(ECDSA_GCM, 0, Some(&extensions)),
    );
    assert!(Handshake::unmarshal(&mut server_hello.as_slice()).is_err());
}

/// RFC 5246 7.4.1.2: the server takes the suites it knows from a list that also holds ones it
/// does not (here GREASE-like and TLS 1.3 values around the one real suite).
#[test]
fn unknown_cipher_suites_in_a_client_hello_are_ignored() {
    let answer = answer_from(builder(), |cookie| {
        client_hello_body(
            &[],
            cookie,
            &[0x0a0a, 0x1301, ECDSA_GCM, 0xc030],
            Some(&usual_client_extensions()),
        )
    });
    answer.result.as_ref().expect("the ClientHello is accepted");
    let server_hello = body_of(&answer.messages(), SERVER_HELLO).expect("a ServerHello");
    assert_eq!(&server_hello[35..37], &ECDSA_GCM.to_be_bytes());
}

/// RFC 5746 section 3.6: "TLS servers implementing this specification MUST ignore any unknown
/// extensions offered by the client". A ClientHello with extension types this server does not
/// know (a GREASE value, empty, and an unassigned one with data) among the usual ones, before
/// and after them, is answered with the same full flight as without them, and the ServerHello
/// answers none of them.
#[test]
fn unknown_extensions_in_a_client_hello_are_ignored() {
    let flight = |answer: &ServerAnswer| {
        answer
            .messages()
            .into_iter()
            .map(|(typ, _)| typ)
            .collect::<Vec<_>>()
    };
    let plain = answer_from(builder(), |cookie| {
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&usual_client_extensions()))
    });
    plain
        .result
        .as_ref()
        .expect("the usual ClientHello is accepted");

    let unknown = [
        extension(0x0a0a, &[]),
        usual_client_extensions(),
        extension(0x7e57, &[0xde, 0xad, 0xbe, 0xef]),
    ]
    .concat();
    let answer = answer_from(builder(), |cookie| {
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&unknown))
    });
    answer
        .result
        .as_ref()
        .expect("a ClientHello with unknown extensions is accepted");
    assert!(plaintext_alerts(&answer.datagrams).is_empty());
    let messages = flight(&answer);
    assert_eq!(messages.first(), Some(&SERVER_HELLO));
    assert!(messages.contains(&CERTIFICATE) && messages.contains(&SERVER_KEY_EXCHANGE));
    assert_eq!(messages.last(), Some(&SERVER_HELLO_DONE), "{messages:?}");
    assert_eq!(messages, flight(&plain));
    let types = answer.server_hello_extension_types();
    assert!(
        !types.contains(&0x0a0a) && !types.contains(&0x7e57),
        "the ServerHello answers no unknown extension: {types:?}"
    );
    assert_eq!(types, plain.server_hello_extension_types());
}

/// RFC 8122 section 7: "TLS_NULL_WITH_NULL_NULL ... is not acceptable" for the DTLS of an
/// SDP-negotiated session, which SHOULD refuse it. A ClientHello offering only that suite
/// (0x0000) has nothing the server selects: a handshake_failure, and no ServerHello; offered
/// before a real suite, it is passed over.
#[test]
fn a_client_hello_offering_only_the_null_suite_is_refused() {
    let answer = answer_from(builder(), |cookie| {
        client_hello_body(&[], cookie, &[0x0000], Some(&usual_client_extensions()))
    });
    assert_eq!(answer.result, Err(Error::ErrCipherSuiteNoIntersection));
    assert_eq!(
        plaintext_alerts(&answer.datagrams),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
    assert!(body_of(&answer.messages(), SERVER_HELLO).is_none());

    let answer = answer_from(builder(), |cookie| {
        client_hello_body(
            &[],
            cookie,
            &[0x0000, ECDSA_GCM],
            Some(&usual_client_extensions()),
        )
    });
    answer.result.as_ref().expect("the ClientHello is accepted");
    let server_hello = body_of(&answer.messages(), SERVER_HELLO).expect("a ServerHello");
    assert_eq!(&server_hello[35..37], &ECDSA_GCM.to_be_bytes());
}

/// RFC 5246 E.1: a ClientHello offering a later version than the server speaks, under whatever
/// record-layer version of the family, is answered with the server's highest version, 1.2.
#[test]
fn a_client_hello_offering_a_later_version_is_answered_with_dtls_1_2() {
    let now = Instant::now();
    let mut server = server(builder());
    server.handshake(now).unwrap();

    // {254, 251}: two versions past 1.2, in the hello and in the record header.
    let later = |cookie: &[u8], message_sequence: u16| {
        let mut body =
            client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&usual_client_extensions()));
        body[1] = 0xfb;
        let mut datagram = client_hello_datagram(message_sequence, &body);
        datagram[2] = 0xfb;
        datagram
    };
    feed(&mut server, now, &later(&[], 0)).unwrap();
    let hello_verify_request = body_of(
        &plaintext_handshake_messages(&drain(&mut server)),
        HELLO_VERIFY_REQUEST,
    )
    .expect("HelloVerifyRequest");
    let cookie = hello_verify_request[3..3 + hello_verify_request[2] as usize].to_vec();
    feed(&mut server, now, &later(&cookie, 1)).unwrap();

    let server_hello = body_of(
        &plaintext_handshake_messages(&drain(&mut server)),
        SERVER_HELLO,
    )
    .expect("a ServerHello");
    assert_eq!(&server_hello[..2], &[0xfe, 0xfd]);
}

// ---------------------------------------------------------------------------------------------
// Extensions in ServerHello (RFC 5246 7.4.1.4, RFC 8422 5.2, RFC 5746 3.6)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.4.1.4: the ServerHello carries only extension types the ClientHello carried.
/// RFC 8422 5.2: supported_groups is never a ServerHello extension.
#[test]
fn server_hello_carries_only_extensions_the_client_offered() {
    // Only signature_algorithms (which a server never answers).
    let answer = answer_from(builder(), |cookie| {
        client_hello_body(
            &[],
            cookie,
            &[ECDSA_GCM],
            Some(&signature_algorithms(&[ECDSA_SHA256])),
        )
    });
    answer.result.as_ref().expect("the ClientHello is accepted");
    assert_eq!(answer.server_hello_extension_types(), Vec::<u16>::new());

    // Everything this server knows how to answer.
    let offered = [
        usual_client_extensions(),
        renegotiation_info(&[]),
        extension(EXT_EXTENDED_MASTER_SECRET, &[]),
        use_srtp(&[0x0001], &[]),
    ]
    .concat();
    let answer = answer_from(
        builder().with_srtp_protection_profiles(vec![
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ]),
        |cookie| client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&offered)),
    );
    answer.result.as_ref().expect("the ClientHello is accepted");
    let mut types = answer.server_hello_extension_types();
    types.sort_unstable();
    assert_eq!(
        types,
        vec![
            EXT_POINT_FORMATS,
            EXT_USE_SRTP,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO
        ]
    );
}

/// RFC 5246 7.4.1.4: a client that receives an extension type it did not offer aborts with
/// unsupported_extension.
#[test]
fn client_refuses_a_server_hello_extension_it_did_not_offer() {
    let accepted = client_parses_server_hello(
        builder(),
        &server_hello_body(ECDSA_GCM, 0, Some(&usual_server_extensions())),
    );
    assert_eq!(accepted.ok().as_deref(), Some("Flight 5"));

    // An extension type this crate does not implement, which it therefore never offers.
    let extensions = [
        usual_server_extensions(),
        extension(EXT_ALPN, &[0, 3, 2, b'h', b'2']),
    ];
    assert_fatal(
        client_parses_server_hello(
            builder(),
            &server_hello_body(ECDSA_GCM, 0, Some(&extensions.concat())),
        ),
        AlertDescription::UnsupportedExtension,
        "an unknown extension type",
    );

    // One it implements but did not offer: this client has no SRTP profiles.
    let extensions = [usual_server_extensions(), use_srtp(&[0x0001], &[])];
    assert_fatal(
        client_parses_server_hello(
            builder(),
            &server_hello_body(ECDSA_GCM, 0, Some(&extensions.concat())),
        ),
        AlertDescription::UnsupportedExtension,
        "use_srtp without an offer",
    );

    // extended_master_secret from a server, to a client that does not offer it.
    assert_fatal(
        client_parses_server_hello(
            builder().with_extended_master_secret(ExtendedMasterSecretType::Disable),
            &server_hello_body(ECDSA_GCM, 0, Some(&usual_server_extensions())),
        ),
        AlertDescription::UnsupportedExtension,
        "extended_master_secret without an offer",
    );
}

/// RFC 5246 7.4.1.3: cipher_suite is "The single cipher suite selected by the server from
/// the list in ClientHello.cipher_suites", and a client that gets one it did not offer
/// aborts with illegal_parameter (RFC 5246 7.4.1.4's rule for what the client did not ask
/// for; RFC 8446 section 4.1.3 for the same field). This client offers ECDHE-ECDSA
/// AES-128-GCM only: a ServerHello with a suite this crate implements but the client did not
/// offer (ECDHE-ECDSA AES-256-CBC-SHA, ECDHE-RSA AES-128-GCM) or with one nobody assigned is
/// refused; with the offered one it is taken.
#[test]
fn client_refuses_a_server_hello_with_a_suite_it_did_not_offer() {
    let accepted = client_parses_server_hello(
        builder(),
        &server_hello_body(ECDSA_GCM, 0, Some(&usual_server_extensions())),
    );
    assert_eq!(accepted.ok().as_deref(), Some("Flight 5"));
    for (suite, what) in [
        (
            0xc00a,
            "ECDHE-ECDSA AES-256-CBC-SHA, implemented, not offered",
        ),
        (0xc02f, "ECDHE-RSA AES-128-GCM, implemented, not offered"),
        (0x4a4a, "an unassigned suite"),
    ] {
        assert!(
            !client(builder())
                .handshake_config
                .local_cipher_suites
                .contains(&CipherSuiteId::from(suite)),
            "{what}"
        );
        assert_fatal(
            client_parses_server_hello(
                builder(),
                &server_hello_body(suite, 0, Some(&usual_server_extensions())),
            ),
            AlertDescription::IllegalParameter,
            what,
        );
    }
}

/// RFC 5246 7.4.1.2 / 7.4.1.3: a ServerHello may end after the compression method, and the
/// compression method must be one the client offered (only null is).
#[test]
fn client_accepts_a_server_hello_without_extensions_and_checks_the_compression_method() {
    let accepted = client_parses_server_hello(
        builder().with_extended_master_secret(ExtendedMasterSecretType::Request),
        &server_hello_body(ECDSA_GCM, 0, None),
    );
    assert_eq!(accepted.ok().as_deref(), Some("Flight 5"));

    assert_fatal(
        client_parses_server_hello(
            builder(),
            &server_hello_body(ECDSA_GCM, 1, Some(&usual_server_extensions())),
        ),
        AlertDescription::IllegalParameter,
        "DEFLATE was not offered",
    );
}

// ---------------------------------------------------------------------------------------------
// Renegotiation indication (RFC 5746)
// ---------------------------------------------------------------------------------------------

/// RFC 5746 3.6: the server answers with an empty renegotiation_info when the client signalled
/// secure renegotiation, by the extension or by TLS_EMPTY_RENEGOTIATION_INFO_SCSV, and only
/// then.
#[test]
fn server_answers_renegotiation_info_only_when_the_client_signalled_it() {
    let hello = |suites: &'static [u16], extra: Vec<u8>| {
        move |cookie: &[u8]| {
            let extensions = [usual_client_extensions(), extra.clone()].concat();
            client_hello_body(&[], cookie, suites, Some(&extensions))
        }
    };

    let by_extension = answer_from(builder(), hello(&[ECDSA_GCM], renegotiation_info(&[])));
    assert_eq!(
        by_extension.server_hello_extension(EXT_RENEGOTIATION_INFO),
        Some(vec![0]),
        "an empty renegotiated_connection"
    );

    let by_scsv = answer_from(builder(), hello(&[ECDSA_GCM, SCSV], vec![]));
    assert_eq!(
        by_scsv.server_hello_extension(EXT_RENEGOTIATION_INFO),
        Some(vec![0])
    );

    let neither = answer_from(builder(), hello(&[ECDSA_GCM], vec![]));
    assert_eq!(neither.server_hello_extension(EXT_RENEGOTIATION_INFO), None);
}

/// RFC 5746 3.6: in an initial handshake the renegotiated_connection field is empty; a server
/// that receives anything else aborts with handshake_failure.
#[test]
fn server_refuses_a_non_empty_renegotiation_info() {
    let extensions = [usual_client_extensions(), renegotiation_info(&[0x11; 12])].concat();
    let answer = answer_from(builder(), |cookie| {
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    assert_eq!(answer.result, Err(Error::ErrRenegotiationInfoNotEmpty));
    assert!(answer.server.is_failed());
    assert_eq!(
        plaintext_alerts(&answer.datagrams),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
}

/// RFC 5746 3.4: the client checks the ServerHello's renegotiation_info and aborts with
/// handshake_failure when renegotiated_connection is not empty.
#[test]
fn client_refuses_a_non_empty_renegotiation_info() {
    let extensions = [
        renegotiation_info(&[0x22; 12]),
        extension(EXT_EXTENDED_MASTER_SECRET, &[]),
    ]
    .concat();
    assert_fatal(
        client_parses_server_hello(
            builder(),
            &server_hello_body(ECDSA_GCM, 0, Some(&extensions)),
        ),
        AlertDescription::HandshakeFailure,
        "a ServerHello claiming a renegotiation",
    );
}

/// RFC 5746 3.4, 3.6: each side notes whether the other signalled secure renegotiation. A
/// client learns it from the ServerHello's renegotiation_info, and that it is missing from a
/// ServerHello without one.
#[test]
fn both_ends_record_whether_secure_renegotiation_was_signalled() {
    let exchange = Exchange::run(client(builder()), server(builder()));
    assert!(exchange.completed());
    assert!(exchange.client.state.secure_renegotiation);
    assert!(exchange.server.state.secure_renegotiation);

    // The same handshake with renegotiation_info taken out of the ClientHello on the way (its
    // type is rewritten to one nobody implements), so the server sees no signal and answers
    // with none. Without the extended master secret the altered transcript only matters to
    // Finished, which comes after both hellos have been read.
    let legacy = || builder().with_extended_master_secret(ExtendedMasterSecretType::Disable);
    let hide = |datagram: &mut Vec<u8>| {
        let extension = [0xff, 0x01, 0x00, 0x01, 0x00];
        if let Some(at) = datagram.windows(5).position(|w| w == extension) {
            datagram[at] = 0x7f;
        }
    };
    let exchange = Exchange::run_altering(client(legacy()), server(legacy()), hide, |_| {});
    assert!(!exchange.server.state.secure_renegotiation);
    assert!(!exchange.client.state.secure_renegotiation);
}

/// RFC 5746 3.4: the client's initial ClientHello carries an empty renegotiation_info, and not
/// the signalling suite as well.
#[test]
fn client_hello_carries_an_empty_renegotiation_info_and_no_scsv() {
    let mut client = client(builder());
    client.handshake(Instant::now()).unwrap();
    let messages = plaintext_handshake_messages(&drain(&mut client));
    let body = body_of(&messages, CLIENT_HELLO).expect("a ClientHello");

    // version, random, session id, cookie, cipher suites, compression methods.
    let mut at = 2 + 32;
    at += 1 + body[at] as usize;
    at += 1 + body[at] as usize;
    let suites_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    let suites = &body[at + 2..at + 2 + suites_len];
    assert!(suites.chunks(2).all(|suite| suite != SCSV.to_be_bytes()));
    at += 2 + suites_len;
    at += 1 + body[at] as usize;

    let renegotiation_info = extensions_after(&body, at)
        .into_iter()
        .find(|(typ, _)| *typ == EXT_RENEGOTIATION_INFO)
        .map(|(_, data)| data);
    assert_eq!(renegotiation_info, Some(vec![0]));
}

// ---------------------------------------------------------------------------------------------
// Signature algorithms (RFC 5246 7.4.1.4.1, 7.4.3, 7.4.4, 7.4.8)
// ---------------------------------------------------------------------------------------------

/// RFC 5246 7.4.3: the ServerKeyExchange is signed with a pair the client listed. A client
/// that lists none this server's key can sign with gets handshake_failure, not a signature it
/// did not ask for.
#[test]
fn server_does_not_sign_with_an_algorithm_the_client_did_not_list() {
    // ecdsa_secp384r1_sha384 only; the server's key is P-256.
    let answer = answer_from(builder(), |cookie| {
        let extensions = [
            signature_algorithms(&[(5, 3)]),
            supported_groups(&[0x001d]),
            point_formats(),
        ]
        .concat();
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    assert_eq!(answer.result, Err(Error::ErrNoAvailableSignatureSchemes));
    assert_eq!(
        plaintext_alerts(&answer.datagrams),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
    assert!(body_of(&answer.messages(), SERVER_KEY_EXCHANGE).is_none());
}

/// The pair is the server's first preference among the ones the client listed, wherever the
/// client put it.
#[test]
fn server_signs_with_an_algorithm_from_the_client_list() {
    // rsa_pkcs1_sha512, ecdsa_secp256r1_sha256, in the client's order.
    let answer = answer_from(builder(), |cookie| {
        let extensions = [
            signature_algorithms(&[(6, 1), ECDSA_SHA256]),
            supported_groups(&[0x001d]),
            point_formats(),
        ]
        .concat();
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    answer.result.as_ref().expect("the ClientHello is accepted");
    let server_key_exchange =
        body_of(&answer.messages(), SERVER_KEY_EXCHANGE).expect("a ServerKeyExchange");
    // curve_type, named_curve, point<1..255>, then the SignatureAndHashAlgorithm.
    let at = 1 + 2 + 1 + server_key_exchange[3] as usize;
    assert_eq!(&server_key_exchange[at..at + 2], &[4, 3]);
}

/// RFC 5246 7.4.2: every certificate the server sends is signed with a pair the client
/// listed. A certificate whose own signature is of another kind is not offered to that client,
/// even though its key could sign the ServerKeyExchange.
#[test]
fn server_certificate_is_signed_with_an_algorithm_the_client_listed() {
    // A P-256 key in a certificate issued (signed) by an Ed25519 authority.
    let authority_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let authority = rcgen::Issuer::new(
        rcgen::CertificateParams::new(vec!["authority.test".to_owned()]).unwrap(),
        authority_key,
    );
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let der = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&key, &authority)
        .unwrap()
        .der()
        .to_owned();
    let certificate = Certificate {
        certificate: vec![der],
        private_key: crate::crypto::CryptoPrivateKey::from_key_pair(&key, provider().crypto())
            .unwrap(),
    };
    let answer_to = |pairs: &'static [(u8, u8)]| {
        let now = Instant::now();
        let config = builder()
            .with_certificates(vec![certificate.clone()])
            .build(false, None)
            .unwrap();
        let mut server = DTLSConn::new(Arc::new(config), false, None);
        server.handshake(now).unwrap();
        let hello = |cookie: &[u8]| {
            let extensions = [
                signature_algorithms(pairs),
                supported_groups(&[0x001d]),
                point_formats(),
            ]
            .concat();
            client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
        };
        feed(&mut server, now, &client_hello_datagram(0, &hello(&[]))).unwrap();
        let hello_verify_request = body_of(
            &plaintext_handshake_messages(&drain(&mut server)),
            HELLO_VERIFY_REQUEST,
        )
        .unwrap();
        let cookie = hello_verify_request[3..3 + hello_verify_request[2] as usize].to_vec();
        let result = feed(&mut server, now, &client_hello_datagram(1, &hello(&cookie)));
        (result, drain(&mut server))
    };

    // ecdsa_secp256r1_sha256 only: the key fits, the certificate's signature does not.
    let (result, datagrams) = answer_to(&[ECDSA_SHA256]);
    assert_eq!(result, Err(Error::ErrNoAvailableSignatureSchemes));
    assert_eq!(
        plaintext_alerts(&datagrams),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );

    // With ed25519 (8, 7) listed as well, the certificate is sent.
    let (result, datagrams) = answer_to(&[ECDSA_SHA256, (8, 7)]);
    result.expect("the ClientHello is accepted");
    assert!(body_of(&plaintext_handshake_messages(&datagrams), CERTIFICATE).is_some());
}

/// RFC 5246 7.4.1.4.1: a client that sends no signature_algorithms is taken to support SHA-1
/// with the suite's signature algorithm only. This server does not sign with SHA-1, so no
/// certificate suite is left: handshake_failure.
#[test]
fn a_client_hello_without_signature_algorithms_means_the_sha1_defaults() {
    let answer = answer_from(builder(), |cookie| {
        let extensions = [supported_groups(&[0x001d]), point_formats()].concat();
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    assert_eq!(answer.result, Err(Error::ErrNoAvailableSignatureSchemes));
    assert_eq!(
        plaintext_alerts(&answer.datagrams),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
}

/// RFC 5246 7.4.3: the client accepts a ServerKeyExchange signature only under an algorithm it
/// offered. The client here offers Ed25519 alone; on the way its list is rewritten to
/// ecdsa_secp256r1_sha256, which the server then signs with.
#[test]
fn client_refuses_a_server_key_exchange_signed_with_an_algorithm_it_did_not_offer() {
    let legacy = || builder().with_extended_master_secret(ExtendedMasterSecretType::Disable);
    let exchange = Exchange::run_altering(
        client(legacy().with_signature_schemes(vec![SignatureScheme::Ed25519])),
        server(legacy()),
        |datagram| {
            // signature_algorithms: type 13, length 4, list length 2, ed25519 (8, 7).
            let offer = [0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x08, 0x07];
            if let Some(at) = datagram.windows(8).position(|w| w == offer) {
                datagram[at + 6] = 0x04;
                datagram[at + 7] = 0x03;
            }
        },
        |_| {},
    );
    assert_eq!(
        exchange.client_err,
        Some(Error::ErrNoAvailableSignatureSchemes)
    );
    assert_eq!(
        plaintext_alerts(&exchange.from_client),
        vec![(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER)]
    );
}

/// RFC 5246 7.4.3, 7.2.2: a ServerKeyExchange whose signature does not verify ends the
/// handshake with decrypt_error.
#[test]
fn client_refuses_a_server_key_exchange_with_a_bad_signature() {
    let exchange = Exchange::run_altering(
        client(builder()),
        server(builder()),
        |_| {},
        |datagram| {
            if let Some(body) = handshake_body_range(datagram, SERVER_KEY_EXCHANGE) {
                // The last byte of the signature.
                datagram[body.end - 1] ^= 0x01;
            }
        },
    );
    assert!(exchange.client_err.is_some());
    assert!(!exchange.client.is_handshake_completed());
    assert_eq!(
        plaintext_alerts(&exchange.from_client),
        vec![(ALERT_FATAL, ALERT_DECRYPT_ERROR)]
    );
}

/// RFC 8422 5.10: an ECDHE public key that is not a point of the curve is refused, by either
/// side, with illegal_parameter. (The server offers secp256r1 first; flipping a bit of the X
/// coordinate takes the point off the curve.)
#[test]
fn an_ecdhe_public_key_that_is_not_on_the_curve_is_refused() {
    const CLIENT_KEY_EXCHANGE: u8 = 16;

    // The server's point, in ServerKeyExchange: curve_type, named_curve, length, 0x04, X, Y.
    let exchange = Exchange::run_altering(
        client(builder()),
        server(builder()),
        |_| {},
        |datagram| {
            if let Some(body) = handshake_body_range(datagram, SERVER_KEY_EXCHANGE) {
                assert_eq!(&datagram[body.start..body.start + 5], &[3, 0, 0x17, 65, 4]);
                datagram[body.start + 10] ^= 0x01;
            }
        },
    );
    assert!(exchange.client_err.is_some());
    assert!(exchange.client.is_failed());
    assert_eq!(
        plaintext_alerts(&exchange.from_client),
        vec![(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER)]
    );

    // The client's point, in ClientKeyExchange: length, 0x04, X, Y.
    let exchange = Exchange::run_altering(
        client(builder()),
        server(builder()),
        |datagram| {
            if let Some(body) = handshake_body_range(datagram, CLIENT_KEY_EXCHANGE) {
                assert_eq!(&datagram[body.start..body.start + 2], &[65, 4]);
                datagram[body.start + 10] ^= 0x01;
            }
        },
        |_| {},
    );
    assert!(exchange.server_err.is_some());
    assert!(exchange.server.is_failed());
    assert_eq!(
        plaintext_alerts(&exchange.from_server),
        vec![(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER)]
    );
}

/// RFC 5246 7.4.2: the server's signing key is of the kind the negotiated key exchange names.
/// A ServerHello rewritten to ECDHE_RSA in front of an ECDSA server is refused when the
/// ServerKeyExchange turns out to be signed with ECDSA.
#[test]
fn client_checks_the_server_key_against_the_negotiated_key_exchange() {
    let exchange = Exchange::run_altering(
        client(builder().with_cipher_suites(vec![
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
            CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
        ])),
        server(builder()),
        |_| {},
        |datagram| {
            if let Some(body) = handshake_body_range(datagram, SERVER_HELLO) {
                // version, random, empty session id, then the suite: 0xc02b becomes 0xc02f.
                assert_eq!(&datagram[body.start + 35..body.start + 37], &[0xc0, 0x2b]);
                datagram[body.start + 36] = 0x2f;
            }
        },
    );
    assert_eq!(
        exchange.client_err,
        Some(Error::ErrInvalidSignatureAlgorithm)
    );
    assert_eq!(
        plaintext_alerts(&exchange.from_client),
        vec![(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER)]
    );
}

/// RFC 5246 7.4.1.4.1: the client sends signature_algorithms, listing what it accepts.
#[test]
fn client_hello_carries_signature_algorithms() {
    let mut client = client(builder().with_signature_schemes(vec![
        SignatureScheme::EcdsaWithP256AndSha256,
        SignatureScheme::Pkcs1WithSha256,
    ]));
    client.handshake(Instant::now()).unwrap();
    let datagrams = drain(&mut client);
    let offer = [0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x04, 0x01];
    assert!(
        datagrams[0].windows(offer.len()).any(|w| w == offer),
        "signature_algorithms with ecdsa_secp256r1_sha256 and rsa_pkcs1_sha256"
    );
}

/// RFC 5246 7.4.4 / 7.4.8: the client's CertificateVerify uses a pair the CertificateRequest
/// listed. With a key that fits none of them the client has no suitable certificate and sends
/// an empty Certificate (7.4.6), which a server that only requests one accepts.
#[test]
fn client_without_a_certificate_for_the_requested_algorithms_sends_none() {
    let ed25519 = Certificate::generate_self_signed_with_alg(
        vec!["localhost".to_owned()],
        &rcgen::PKCS_ED25519,
        provider().crypto(),
    )
    .unwrap();
    // The server's CertificateRequest lists ecdsa_secp256r1_sha256 only.
    let server_builder =
        || builder().with_signature_schemes(vec![SignatureScheme::EcdsaWithP256AndSha256]);
    let client_builder = || builder().with_certificates(vec![ed25519.clone()]);

    let exchange = Exchange::run(
        client(client_builder()),
        server(server_builder().with_client_auth(ClientAuthType::RequestClientCert)),
    );
    assert!(
        exchange.completed(),
        "client: {:?}, server: {:?}",
        exchange.client_err,
        exchange.server_err
    );
    assert!(exchange.server.state.peer_certificates.is_empty());

    // A server that requires one says so with handshake_failure: no_certificate(41) is an
    // SSLv3 alert that TLS 1.2 reserves (RFC 5246 7.2.2).
    let exchange = Exchange::run(
        client(client_builder()),
        server(server_builder().with_client_auth(ClientAuthType::RequireAnyClientCert)),
    );
    assert_eq!(
        exchange.server_err,
        Some(Error::ErrClientCertificateRequired)
    );
    assert_eq!(
        plaintext_alerts(&exchange.from_server),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );

    // RFC 8122 section 6.2, the SDP offer/answer model: "if the client does not provide one
    // ... the server endpoint MUST terminate the media connection with a bad_certificate
    // error", where the option is set (as the peer connection sets it).
    let exchange = Exchange::run(
        client(client_builder()),
        server(
            server_builder()
                .with_client_auth(ClientAuthType::RequireAnyClientCert)
                .with_bad_certificate_for_a_missing_client_certificate(true),
        ),
    );
    assert_eq!(
        exchange.server_err,
        Some(Error::ErrClientCertificateRequired)
    );
    assert_eq!(
        plaintext_alerts(&exchange.from_server),
        vec![(ALERT_FATAL, ALERT_BAD_CERTIFICATE)]
    );
}

/// An X.509 version 1 certificate (made with `openssl req -x509 -x509v1`) and its P-256 key.
const X509_V1_CERTIFICATE: &str = "-----BEGIN PRIVATE_KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6+14bt8ExWwuTVQF
mFQWQaNIUDUNHItv/0PT/eSZxDuhRANCAASxCffFOAud1+ExGQKC9+AwqlN50ezm
quPd33OhZBdFMvvqbSuUuTKpD+pKNmNJEGKTaiD2gytFTiRnjzfsl+dL
-----END PRIVATE_KEY-----
-----BEGIN CERTIFICATE-----
MIIBJDCBywIUL8+MlzZYcSIdauPKnvmFImVtNS0wCgYIKoZIzj0EAwIwFDESMBAG
A1UEAwwJdjEtY2xpZW50MCAXDTI2MTEyMzAwNTcyOFoYDzIxMjYxMDMwMDA1NzI4
WjAUMRIwEAYDVQQDDAl2MS1jbGllbnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASxCffFOAud1+ExGQKC9+AwqlN50ezmquPd33OhZBdFMvvqbSuUuTKpD+pKNmNJ
EGKTaiD2gytFTiRnjzfsl+dLMAoGCCqGSM49BAMCA0gAMEUCIH9qVw5paD7jRMp7
LlA/uH5K9cPAqfZ5zgzZ1wJQO4hjAiEAoNgskDSHp0uLkamBtJaTZm+Kag7TXVh7
2jTqPtYaBEI=
-----END CERTIFICATE-----
";

/// RFC 5246 7.4.6: "The certificate type MUST be X.509v3". A client configured with an
/// X.509v1 certificate, whose key and signature otherwise fit the request, has no suitable
/// certificate and sends an empty Certificate; the server that only requests one completes
/// without a client certificate.
#[test]
fn a_client_with_an_x509v1_certificate_sends_none() {
    let v1 = Certificate::from_pem(X509_V1_CERTIFICATE, provider().crypto()).unwrap();
    let exchange = Exchange::run(
        client(builder().with_certificates(vec![v1])),
        server(builder().with_client_auth(ClientAuthType::RequestClientCert)),
    );
    assert!(
        exchange.completed(),
        "client: {:?}, server: {:?}",
        exchange.client_err,
        exchange.server_err
    );
    assert!(exchange.server.state.peer_certificates.is_empty());
}

/// The positive case: a client whose key fits the request signs with a listed pair.
#[test]
fn client_signs_certificate_verify_with_an_algorithm_the_request_listed() {
    let exchange = Exchange::run(
        client(builder().with_certificates(vec![self_signed()])),
        server(
            builder()
                .with_signature_schemes(vec![
                    SignatureScheme::EcdsaWithP256AndSha256,
                    SignatureScheme::Ed25519,
                ])
                .with_client_auth(ClientAuthType::RequireAnyClientCert),
        ),
    );
    assert!(
        exchange.completed(),
        "client: {:?}, server: {:?}",
        exchange.client_err,
        exchange.server_err
    );
    assert_eq!(exchange.server.state.peer_certificates.len(), 1);
}

/// RFC 5246 7.2.2: no_certificate(41) is never sent. A required client certificate that is
/// missing is a handshake_failure.
#[test]
fn a_missing_client_certificate_is_a_handshake_failure() {
    let exchange = Exchange::run(
        client(builder()),
        server(builder().with_client_auth(ClientAuthType::RequireAnyClientCert)),
    );
    assert_eq!(
        exchange.server_err,
        Some(Error::ErrClientCertificateRequired)
    );
    assert_eq!(
        plaintext_alerts(&exchange.from_server),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
}

// ---------------------------------------------------------------------------------------------
// Curves (RFC 8422 5.1)
// ---------------------------------------------------------------------------------------------

/// RFC 8422 5.1: when the client's supported_groups holds no curve the server supports, an
/// ECDHE suite cannot be negotiated; with no other suite the handshake fails with
/// handshake_failure instead of going on with a curve the client did not list.
#[test]
fn no_common_curve_is_a_handshake_failure() {
    // secp521r1 only.
    let answer = answer_from(builder(), |cookie| {
        let extensions = [
            signature_algorithms(&[ECDSA_SHA256]),
            supported_groups(&[0x0019]),
            point_formats(),
        ]
        .concat();
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    assert_eq!(answer.result, Err(Error::ErrNoSupportedEllipticCurves));
    assert_eq!(
        plaintext_alerts(&answer.datagrams),
        vec![(ALERT_FATAL, ALERT_HANDSHAKE_FAILURE)]
    );
    assert!(body_of(&answer.messages(), SERVER_KEY_EXCHANGE).is_none());
}

/// The server takes the first of the client's curves that it supports.
#[test]
fn server_uses_a_curve_from_the_client_list() {
    // secp521r1 (unknown here), then secp384r1.
    let answer = answer_from(builder(), |cookie| {
        let extensions = [
            signature_algorithms(&[ECDSA_SHA256]),
            supported_groups(&[0x0019, 0x0018]),
            point_formats(),
        ]
        .concat();
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    answer.result.as_ref().expect("the ClientHello is accepted");
    let server_key_exchange =
        body_of(&answer.messages(), SERVER_KEY_EXCHANGE).expect("a ServerKeyExchange");
    assert_eq!(&server_key_exchange[..3], &[3, 0x00, 0x18]);
}

// ---------------------------------------------------------------------------------------------
// use_srtp (RFC 5764 4.1)
// ---------------------------------------------------------------------------------------------

/// RFC 5764 4.1.1: the server's use_srtp holds exactly one profile; RFC 5764 4.1.3: an MKI the
/// client did not offer is refused. Both with illegal_parameter.
#[test]
fn client_refuses_a_use_srtp_answer_with_an_mki_or_several_profiles() {
    let srtp_client = || {
        builder().with_srtp_protection_profiles(vec![
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        ])
    };
    let server_hello = |use_srtp: Vec<u8>| {
        let extensions = [usual_server_extensions(), use_srtp].concat();
        server_hello_body(ECDSA_GCM, 0, Some(&extensions))
    };

    let accepted =
        client_parses_server_hello(srtp_client(), &server_hello(use_srtp(&[0x0001], &[])));
    assert_eq!(accepted.ok().as_deref(), Some("Flight 5"));

    assert_fatal(
        client_parses_server_hello(
            srtp_client(),
            &server_hello(use_srtp(&[0x0001], &[0xde, 0xad, 0xbe, 0xef])),
        ),
        AlertDescription::IllegalParameter,
        "an MKI the client did not offer",
    );
    assert_fatal(
        client_parses_server_hello(
            srtp_client(),
            &server_hello(use_srtp(&[0x0001, 0x0007], &[])),
        ),
        AlertDescription::IllegalParameter,
        "two profiles",
    );
    assert_fatal(
        client_parses_server_hello(srtp_client(), &server_hello(use_srtp(&[], &[]))),
        AlertDescription::IllegalParameter,
        "no profile",
    );
    assert_fatal(
        client_parses_server_hello(srtp_client(), &server_hello(use_srtp(&[0x0008], &[]))),
        AlertDescription::IllegalParameter,
        "a profile the client did not offer",
    );
}

/// RFC 5764 4.1.3: a server that does not use the client's MKI answers with an empty one.
#[test]
fn server_answers_a_client_mki_with_an_empty_mki() {
    let answer = answer_from(
        builder().with_srtp_protection_profiles(vec![
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ]),
        |cookie| {
            let extensions = [
                usual_client_extensions(),
                use_srtp(&[0x0001], &[1, 2, 3, 4]),
            ]
            .concat();
            client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
        },
    );
    answer.result.as_ref().expect("the ClientHello is accepted");
    assert_eq!(
        answer.server_hello_extension(EXT_USE_SRTP),
        Some(vec![0x00, 0x02, 0x00, 0x01, 0x00]),
        "one profile and an empty MKI"
    );
}

/// RFC 5764 4.1.1: a server that does not do DTLS-SRTP ignores use_srtp and goes on without it.
#[test]
fn a_server_without_srtp_profiles_ignores_use_srtp() {
    let answer = answer_from(builder(), |cookie| {
        let extensions = [usual_client_extensions(), use_srtp(&[0x0001], &[])].concat();
        client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&extensions))
    });
    answer.result.as_ref().expect("the ClientHello is accepted");
    assert_eq!(answer.server_hello_extension(EXT_USE_SRTP), None);
}

// ---------------------------------------------------------------------------------------------
// Extended master secret and exporters (RFC 7627 5.4)
// ---------------------------------------------------------------------------------------------

/// RFC 7627 5.4: without the extended master secret no key material is exported, so
/// DTLS-SRTP keys never come from a master secret that is not bound to the handshake.
#[test]
fn key_material_is_exported_only_with_the_extended_master_secret() {
    let label = "EXTRACTOR-dtls_srtp";

    let legacy = Exchange::run(
        client(builder().with_extended_master_secret(ExtendedMasterSecretType::Disable)),
        server(builder().with_extended_master_secret(ExtendedMasterSecretType::Disable)),
    );
    assert!(legacy.completed());
    assert_eq!(
        legacy
            .client
            .state
            .export_keying_material(label, &[], 60)
            .err(),
        Some(Error::ErrExportWithoutExtendedMasterSecret)
    );
    assert_eq!(
        legacy
            .server
            .state
            .export_keying_material(label, &[], 60)
            .err(),
        Some(Error::ErrExportWithoutExtendedMasterSecret)
    );

    let bound = Exchange::run(client(builder()), server(builder()));
    assert!(bound.completed());
    let client_keys = bound.client.state.export_keying_material(label, &[], 60);
    let server_keys = bound.server.state.export_keying_material(label, &[], 60);
    assert_eq!(
        client_keys.unwrap().as_ref(),
        server_keys.unwrap().as_ref(),
        "both ends export the same keys"
    );
}

/// RFC 5246 F.1.1.3 (stated for DHE, applied to ECDHE): a fresh ephemeral key for each
/// handshake. Two handshakes between the same configurations carry different ephemeral
/// public keys in the ServerKeyExchange and in the ClientKeyExchange.
#[test]
fn every_handshake_has_fresh_ephemeral_keys() {
    let keys = |_: usize| {
        let certificate = self_signed();
        let exchange = Exchange::run(
            client(builder()),
            server(builder().with_certificates(vec![certificate])),
        );
        assert!(
            exchange.completed(),
            "{:?} / {:?}",
            exchange.client_err,
            exchange.server_err
        );
        let server = body_of(&plaintext_handshake_messages(&exchange.from_server), 12)
            .expect("a ServerKeyExchange");
        let client = body_of(&plaintext_handshake_messages(&exchange.from_client), 16)
            .expect("a ClientKeyExchange");
        // ServerKeyExchange: curve type, named curve, public key length, public key.
        let point_len = usize::from(server[3]);
        (server[4..4 + point_len].to_vec(), client)
    };
    let (first_server, first_client) = keys(0);
    let (second_server, second_client) = keys(1);
    assert_ne!(first_server, second_server, "the server's ephemeral key");
    assert_ne!(first_client, second_client, "the client's ephemeral key");
}

/// RFC 5246 7.4.1.2: client_version is the latest (highest) version the client supports. A
/// DTLS 1.2 client writes DTLS 1.2 (254, 253) in its ClientHello.
#[test]
fn the_client_hello_names_the_latest_version_supported() {
    let exchange = Exchange::run(client(builder()), server(builder()));
    let hello =
        body_of(&plaintext_handshake_messages(&exchange.from_client), 1).expect("a ClientHello");
    assert_eq!(hello[..2], [254, 253]);
}
