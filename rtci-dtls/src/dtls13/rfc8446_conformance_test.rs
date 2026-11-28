//! RFC 8446 and RFC 9147 clauses about what a DTLS 1.3 endpoint refuses in the hellos and
//! the server's flight, the certificates it sends and takes, and the last epoch: each test
//! changes one thing in a real message from a real peer and checks the alert, or drives the
//! association to the state the clause is about.

use super::codec::*;
use super::conn::*;
use super::handshake_test::*;
use super::messages::{self, ClientHello, ServerHello, alert};
use super::record::*;
use crate::cipher_suite::CipherSuiteId;
use crate::config::ConfigBuilder;
use crate::crypto::{Certificate, CryptoPrivateKey};
use crate::endpoint::Endpoint;
use bytes::BytesMut;
use shared::TransportProtocol;
use shared::error::Result;

// ----------------------------------------------------------------------------------------
// Messages taken apart and put together again.
// ----------------------------------------------------------------------------------------

/// The first record of `datagram`, a plaintext handshake record that holds one whole
/// message: (handshake type, message_seq, body, record sequence number).
fn first_message(datagram: &[u8]) -> (u8, u16, Vec<u8>, u64) {
    assert_eq!(
        datagram[0], CONTENT_TYPE_HANDSHAKE,
        "a plaintext handshake record"
    );
    let mut sequence = [0u8; 8];
    sequence[2..].copy_from_slice(&datagram[5..11]);
    let record_len = usize::from(u16::from_be_bytes([datagram[11], datagram[12]]));
    let fragment = &datagram[13..13 + record_len];
    let length =
        usize::from(fragment[1]) << 16 | usize::from(fragment[2]) << 8 | usize::from(fragment[3]);
    let fragment_len =
        usize::from(fragment[9]) << 16 | usize::from(fragment[10]) << 8 | usize::from(fragment[11]);
    assert_eq!(length, fragment_len, "a whole message");
    (
        fragment[0],
        u16::from_be_bytes([fragment[4], fragment[5]]),
        fragment[12..12 + length].to_vec(),
        u64::from_be_bytes(sequence),
    )
}

/// A datagram of one plaintext record holding the whole message `body`.
fn handshake_datagram(
    handshake_type: u8,
    message_seq: u16,
    body: &[u8],
    sequence: u64,
) -> BytesMut {
    BytesMut::from(
        &plaintext_record(
            CONTENT_TYPE_HANDSHAKE,
            sequence,
            &messages::handshake_fragment(handshake_type, body.len(), message_seq, 0, body),
        )[..],
    )
}

fn put_extensions(out: &mut Vec<u8>, extensions: &[(u16, Vec<u8>)]) {
    put_vec16(out, |block| {
        for (extension_type, data) in extensions {
            put_extension(block, *extension_type, |out| out.extend_from_slice(data));
        }
    });
}

/// A ClientHello whose every field can be changed.
#[derive(Clone)]
struct Hello {
    legacy_version: u16,
    random: Vec<u8>,
    session_id: Vec<u8>,
    cookie: Vec<u8>,
    suites: Vec<u16>,
    compression: Vec<u8>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    fn parse(body: &[u8]) -> Self {
        let hello = ClientHello::parse(body).expect("a ClientHello");
        Self {
            legacy_version: hello.legacy_version,
            random: hello.random.to_vec(),
            session_id: hello.legacy_session_id.to_vec(),
            cookie: hello.legacy_cookie.to_vec(),
            suites: hello.cipher_suites.clone(),
            compression: hello.legacy_compression_methods.to_vec(),
            extensions: hello
                .extensions
                .iter()
                .map(|(t, data)| (*t, data.to_vec()))
                .collect(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut body = vec![];
        put_u16(&mut body, self.legacy_version);
        body.extend_from_slice(&self.random);
        put_vec8(&mut body, |out| out.extend_from_slice(&self.session_id));
        put_vec8(&mut body, |out| out.extend_from_slice(&self.cookie));
        put_vec16(&mut body, |out| {
            for suite in &self.suites {
                put_u16(out, *suite);
            }
        });
        put_vec8(&mut body, |out| out.extend_from_slice(&self.compression));
        put_extensions(&mut body, &self.extensions);
        body
    }

    fn remove(&mut self, extension_type: u16) {
        self.extensions.retain(|(t, _)| *t != extension_type);
    }

    fn set(&mut self, extension_type: u16, data: Vec<u8>) {
        match self
            .extensions
            .iter_mut()
            .find(|(t, _)| *t == extension_type)
        {
            Some((_, existing)) => *existing = data,
            None => self.extensions.push((extension_type, data)),
        }
    }

    fn get(&self, extension_type: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == extension_type)
            .map(|(_, data)| data.as_slice())
    }
}

/// A ServerHello (or HelloRetryRequest) whose every field can be changed.
#[derive(Clone)]
struct Answer {
    legacy_version: u16,
    random: Vec<u8>,
    session_id_echo: Vec<u8>,
    suite: u16,
    compression: u8,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl Answer {
    fn parse(body: &[u8]) -> Self {
        let hello = ServerHello::parse(body).expect("a ServerHello");
        Self {
            legacy_version: hello.legacy_version,
            random: hello.random.to_vec(),
            session_id_echo: hello.legacy_session_id_echo.to_vec(),
            suite: hello.cipher_suite,
            compression: hello.legacy_compression_method,
            extensions: hello
                .extensions
                .iter()
                .map(|(t, data)| (*t, data.to_vec()))
                .collect(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut body = vec![];
        put_u16(&mut body, self.legacy_version);
        body.extend_from_slice(&self.random);
        put_vec8(&mut body, |out| {
            out.extend_from_slice(&self.session_id_echo)
        });
        put_u16(&mut body, self.suite);
        body.push(self.compression);
        put_extensions(&mut body, &self.extensions);
        body
    }

    fn set(&mut self, extension_type: u16, data: Vec<u8>) {
        match self
            .extensions
            .iter_mut()
            .find(|(t, _)| *t == extension_type)
        {
            Some((_, existing)) => *existing = data,
            None => self.extensions.push((extension_type, data)),
        }
    }

    fn get(&self, extension_type: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == extension_type)
            .map(|(_, data)| data.as_slice())
    }
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut data = vec![];
    put_vec16(&mut data, |list| {
        for value in values {
            put_u16(list, *value);
        }
    });
    data
}

fn client_key_shares(shares: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut data = vec![];
    put_vec16(&mut data, |list| {
        for (group, key) in shares {
            put_u16(list, *group);
            put_vec16(list, |out| out.extend_from_slice(key));
        }
    });
    data
}

const X25519: u16 = 0x001d;
const SECP256R1: u16 = 0x0017;
const SECP384R1: u16 = 0x0018;
const SECP521R1: u16 = 0x0019;

fn no_cookies() -> ConfigBuilder {
    server_builder().with_cookie_exchange(false)
}

/// What a server answers the client's first ClientHello with once `change` has been made
/// to it.
fn server_answers(server: ConfigBuilder, change: impl FnOnce(&mut Hello)) -> Result<Vec<BytesMut>> {
    let mut pair = Pair::new(client_builder(), server)?;
    let up = take(&mut pair.client);
    assert_eq!(up.len(), 1, "one datagram");
    let (handshake_type, message_seq, body, sequence) = first_message(&up[0]);
    assert_eq!(handshake_type, messages::CLIENT_HELLO);
    let mut hello = Hello::parse(&body);
    change(&mut hello);
    pair.deliver_to_server(vec![handshake_datagram(
        messages::CLIENT_HELLO,
        message_seq,
        &hello.encode(),
        sequence,
    )]);
    Ok(take(&mut pair.server))
}

/// The client of `pair` sends its ClientHello; the server's first answer (its ServerHello,
/// or its HelloRetryRequest) reaches the client with `change` made to it, and nothing else of
/// the server's flight. Returns the client's plaintext alerts.
fn client_refuses(pair: &mut Pair, change: impl FnOnce(&mut Answer)) -> Vec<(u8, u8)> {
    plaintext_alerts(&client_answers(pair, change))
}

/// As [`client_refuses`], returning what the client sends.
fn client_answers(pair: &mut Pair, change: impl FnOnce(&mut Answer)) -> Vec<BytesMut> {
    let up = take(&mut pair.client);
    pair.deliver_to_server(up);
    let down = take(&mut pair.server);
    let (handshake_type, message_seq, body, sequence) = first_message(&down[0]);
    assert_eq!(handshake_type, messages::SERVER_HELLO);
    let mut answer = Answer::parse(&body);
    change(&mut answer);
    pair.deliver_to_client(vec![handshake_datagram(
        messages::SERVER_HELLO,
        message_seq,
        &answer.encode(),
        sequence,
    )]);
    take(&mut pair.client)
}

fn fatal(description: u8) -> Vec<(u8, u8)> {
    vec![(2, description)]
}

/// A pair whose client has taken the server's ServerHello, and nothing after it: the client
/// waits for EncryptedExtensions, with the handshake keys.
fn client_after_server_hello(client: ConfigBuilder) -> Result<Pair> {
    let mut pair = Pair::new(client, no_cookies())?;
    let up = take(&mut pair.client);
    pair.deliver_to_server(up);
    let down = take(&mut pair.server);
    let (handshake_type, message_seq, body, sequence) = first_message(&down[0]);
    assert_eq!(handshake_type, messages::SERVER_HELLO);
    pair.deliver_to_client(vec![handshake_datagram(
        handshake_type,
        message_seq,
        &body,
        sequence,
    )]);
    assert_eq!(
        pair.client_conn().state,
        HandshakeState::ClientWaitEncryptedExtensions
    );
    Ok(pair)
}

fn encrypted_extensions(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = vec![];
    put_extensions(&mut body, extensions);
    body
}

/// A message the association took, or the error of the refusal.
fn taken(outcome: std::result::Result<(), messages::Refusal>) -> Result<()> {
    outcome.map_err(|refusal| refusal.error)
}

fn refusal_alert(outcome: std::result::Result<(), messages::Refusal>) -> Option<u8> {
    outcome.err().map(|refusal| refusal.alert)
}

// ----------------------------------------------------------------------------------------
// What a server refuses in a ClientHello.
// ----------------------------------------------------------------------------------------

/// RFC 8446 section 4.1.1: with no group in common, the server aborts with
/// handshake_failure.
#[test]
fn a_client_hello_without_a_common_group_is_a_handshake_failure() -> Result<()> {
    let answer = server_answers(no_cookies(), |hello| {
        hello.set(messages::EXT_SUPPORTED_GROUPS, u16_list(&[SECP521R1]));
        hello.set(
            messages::EXT_KEY_SHARE,
            client_key_shares(&[(SECP521R1, vec![4; 133])]),
        );
    })?;
    assert_eq!(plaintext_alerts(&answer), fatal(alert::HANDSHAKE_FAILURE));
    Ok(())
}

/// RFC 8446 section 4.2.8: the client_shares vector "MAY be empty if the client is
/// requesting a HelloRetryRequest". A ClientHello with an empty key_share is answered with a
/// HelloRetryRequest naming a group the client listed, not refused.
#[test]
fn an_empty_key_share_is_answered_with_a_hello_retry_request() -> Result<()> {
    let answer = server_answers(no_cookies(), |hello| {
        hello.set(
            messages::EXT_SUPPORTED_GROUPS,
            u16_list(&[X25519, SECP256R1]),
        );
        hello.set(messages::EXT_KEY_SHARE, client_key_shares(&[]));
    })?;
    assert!(plaintext_alerts(&answer).is_empty(), "no alert");
    let (handshake_type, _, body, _) = first_message(&answer[0]);
    assert_eq!(handshake_type, messages::SERVER_HELLO);
    let retry = Answer::parse(&body);
    assert_eq!(retry.random, messages::HELLO_RETRY_REQUEST_RANDOM.to_vec());
    let group = retry
        .extensions
        .iter()
        .find(|(t, _)| *t == messages::EXT_KEY_SHARE)
        .map(|(_, data)| u16::from_be_bytes([data[0], data[1]]))
        .expect("the group asked for");
    assert!([X25519, SECP256R1].contains(&group), "{group:#06x}");
    Ok(())
}

/// RFC 8446 section 4.1.2: the compression methods of a TLS 1.3 ClientHello are exactly
/// one zero byte; anything else is an illegal_parameter.
#[test]
fn a_client_hello_with_other_compression_methods_is_an_illegal_parameter() -> Result<()> {
    for methods in [vec![1], vec![0, 1], vec![1, 0]] {
        let answer = server_answers(no_cookies(), |hello| hello.compression = methods.clone())?;
        assert_eq!(
            plaintext_alerts(&answer),
            fatal(alert::ILLEGAL_PARAMETER),
            "{methods:?}"
        );
    }
    Ok(())
}

/// RFC 9147 section 5.3: a DTLS 1.3 ClientHello has an empty legacy_cookie; one with a
/// cookie there is an illegal_parameter.
#[test]
fn a_dtls_1_3_client_hello_with_a_legacy_cookie_is_an_illegal_parameter() -> Result<()> {
    let answer = server_answers(no_cookies(), |hello| hello.cookie = vec![7; 20])?;
    assert_eq!(plaintext_alerts(&answer), fatal(alert::ILLEGAL_PARAMETER));
    Ok(())
}

/// RFC 8446 sections 9.2 and 4.2.3: a ClientHello without pre_shared_key has
/// signature_algorithms and supported_groups, and key_share comes with supported_groups and
/// the other way round; a server answers one that does not with missing_extension.
#[test]
fn a_client_hello_without_the_mandatory_extensions_is_a_missing_extension() -> Result<()> {
    let removals: [&[u16]; 4] = [
        &[messages::EXT_SIGNATURE_ALGORITHMS],
        &[messages::EXT_SUPPORTED_GROUPS],
        &[messages::EXT_KEY_SHARE],
        &[messages::EXT_SUPPORTED_GROUPS, messages::EXT_KEY_SHARE],
    ];
    for removed in removals {
        let answer = server_answers(no_cookies(), |hello| {
            assert!(hello.get(messages::EXT_PRE_SHARED_KEY).is_none());
            for extension_type in removed {
                hello.remove(*extension_type);
            }
        })?;
        assert_eq!(
            plaintext_alerts(&answer),
            fatal(alert::MISSING_EXTENSION),
            "without {removed:?}"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.2: at most one extension of a type in a block. Those this crate sends
/// have none twice, and a ClientHello with one twice is malformed: it is not answered, and
/// no association is made for it (an unauthenticated datagram, discarded as RFC 9147 section
/// 4.5.2 and RFC 6347 section 4.1.2.7 have it for what does not parse).
#[test]
fn an_extension_appears_once_in_a_block() -> Result<()> {
    // What this crate sends: the ClientHello and the ServerHello.
    let mut pair = Pair::new(client_builder(), no_cookies())?;
    let up = take(&mut pair.client);
    let (_, _, client_hello, _) = first_message(&up[0]);
    pair.deliver_to_server(up);
    let down = take(&mut pair.server);
    let (_, _, server_hello, _) = first_message(&down[0]);
    for extensions in [
        Hello::parse(&client_hello).extensions,
        Answer::parse(&server_hello).extensions,
    ] {
        let mut types: Vec<u16> = extensions.iter().map(|(t, _)| *t).collect();
        let count = types.len();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), count);
    }

    // What it takes.
    let answer = server_answers(no_cookies(), |hello| {
        let groups = hello.get(messages::EXT_SUPPORTED_GROUPS).unwrap().to_vec();
        hello
            .extensions
            .insert(0, (messages::EXT_SUPPORTED_GROUPS, groups));
    })?;
    assert!(answer.is_empty(), "not answered");
    // The same ClientHello without the repetition is.
    let answer = server_answers(no_cookies(), |_| {})?;
    assert_eq!(first_message(&answer[0]).0, messages::SERVER_HELLO);
    Ok(())
}

/// RFC 8446 section 4.2.1: a ClientHello with supported_versions that does not list
/// (D)TLS 1.3 is served as a ClientHello of the versions it lists: here DTLS 1.2.
#[test]
fn a_client_hello_whose_supported_versions_lacks_dtls_1_3_gets_dtls_1_2() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?;
    let up = take(&mut pair.client);
    let (_, message_seq, body, sequence) = first_message(&up[0]);
    let mut hello = Hello::parse(&body);
    let mut versions = vec![];
    put_vec8(&mut versions, |list| {
        put_u16(list, super::DTLS1_2_WIRE_VERSION)
    });
    hello.set(messages::EXT_SUPPORTED_VERSIONS, versions);
    pair.deliver_to_server(vec![handshake_datagram(
        messages::CLIENT_HELLO,
        message_seq,
        &hello.encode(),
        sequence,
    )]);
    let down = take(&mut pair.server);
    assert!(plaintext_alerts(&down).is_empty());
    let (handshake_type, _, server_hello, _) = first_message(&down[0]);
    assert_eq!(handshake_type, messages::SERVER_HELLO);
    let server_hello = ServerHello::parse(&server_hello).unwrap();
    assert_eq!(server_hello.legacy_version, super::DTLS1_2_WIRE_VERSION);
    assert_eq!(
        server_hello.selected_version(),
        None,
        "no supported_versions"
    );
    let conn = pair
        .server
        .connection_mut(&client_addr())
        .expect("an association");
    assert!(conn.v13.is_none(), "a DTLS 1.2 association");
    Ok(())
}

/// RFC 8446 section 4.2.8.2 and 7.4.2: a share that is not a point on its curve, or an
/// X25519 share that makes an all-zero secret, ends the handshake.
#[test]
fn a_client_share_that_is_no_valid_point_ends_the_handshake() -> Result<()> {
    // A P-256 point off the curve: x and y of all ones.
    let mut off_curve = vec![4u8];
    off_curve.extend_from_slice(&[0xff; 64]);
    for (group, key) in [(SECP256R1, off_curve), (X25519, vec![0u8; 32])] {
        let answer = server_answers(no_cookies(), |hello| {
            hello.set(messages::EXT_SUPPORTED_GROUPS, u16_list(&[group]));
            hello.set(messages::EXT_KEY_SHARE, client_key_shares(&[(group, key)]));
        })?;
        assert_eq!(
            plaintext_alerts(&answer),
            fatal(alert::ILLEGAL_PARAMETER),
            "group {group:#06x}"
        );
        assert!(
            answer
                .iter()
                .all(|datagram| datagram[0] == CONTENT_TYPE_ALERT),
            "no ServerHello"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.2.8: "Clients MUST NOT offer multiple KeyShareEntry values for the same
/// group. Clients MUST NOT offer any KeyShareEntry values for groups not listed in the
/// client's "supported_groups" extension. Servers MAY check for violations of these rules and
/// abort the handshake with an "illegal_parameter" alert if one is violated." (and the shares
/// come "in the same order" as supported_groups). Each violation, made with the client's own
/// valid shares, is refused; the hello unchanged gets a ServerHello.
#[test]
fn key_shares_that_break_the_client_rules_are_an_illegal_parameter() -> Result<()> {
    type Shares = Vec<(u16, Vec<u8>)>;
    type Violation = fn(&mut Vec<u16>, &mut Shares);
    fn groups_and_shares(hello: &Hello) -> (Vec<u16>, Shares) {
        let groups = hello.get(messages::EXT_SUPPORTED_GROUPS).unwrap()[2..]
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        let shares = messages::parse_client_key_shares(hello.get(messages::EXT_KEY_SHARE).unwrap())
            .unwrap()
            .into_iter()
            .map(|(group, key)| (group, key.to_vec()))
            .collect();
        (groups, shares)
    }

    // The client's own hello: two shares, for groups it lists, in its order.
    let answer = server_answers(no_cookies(), |hello| {
        let (groups, shares) = groups_and_shares(hello);
        assert_eq!(shares.len(), 2, "the client offers two shares");
        assert!(
            groups.iter().position(|g| *g == shares[0].0)
                < groups.iter().position(|g| *g == shares[1].0)
        );
    })?;
    assert!(plaintext_alerts(&answer).is_empty(), "no alert");
    let (handshake_type, _, body, _) = first_message(&answer[0]);
    assert_eq!(handshake_type, messages::SERVER_HELLO);
    assert_ne!(
        Answer::parse(&body).random,
        messages::HELLO_RETRY_REQUEST_RANDOM.to_vec(),
        "a ServerHello, not a HelloRetryRequest"
    );

    let violations: [(&str, Violation); 3] = [
        ("a share for a group not listed", |groups, shares| {
            let unlisted = shares[1].0;
            groups.retain(|g| *g != unlisted);
        }),
        ("two shares for one group", |_, shares| {
            shares[1] = shares[0].clone();
        }),
        (
            "shares out of the order of supported_groups",
            |_, shares| {
                shares.swap(0, 1);
            },
        ),
    ];
    for (violation, change) in violations {
        let answer = server_answers(no_cookies(), |hello| {
            let (mut groups, mut shares) = groups_and_shares(hello);
            change(&mut groups, &mut shares);
            hello.set(messages::EXT_SUPPORTED_GROUPS, u16_list(&groups));
            hello.set(messages::EXT_KEY_SHARE, client_key_shares(&shares));
        })?;
        assert_eq!(
            plaintext_alerts(&answer),
            fatal(alert::ILLEGAL_PARAMETER),
            "{violation}"
        );
        assert!(
            answer
                .iter()
                .all(|datagram| datagram[0] == CONTENT_TYPE_ALERT),
            "{violation}: no ServerHello"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.1.4: after a HelloRetryRequest the server negotiates the same suite;
/// a second ClientHello that would make it choose another is an illegal_parameter.
#[test]
fn a_second_client_hello_that_changes_the_suite_is_an_illegal_parameter() -> Result<()> {
    let suites = vec![
        CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
    ];
    let mut pair = Pair::new(
        client_builder().with_cipher_suites(suites.clone()),
        server_builder().with_cipher_suites(suites),
    )?;
    // ClientHello, HelloRetryRequest with the cookie and the first suite.
    let (_, retry) = pair.round();
    let (_, _, retry, _) = first_message(&retry[0]);
    assert_eq!(
        Answer::parse(&retry).suite,
        CipherSuiteId::Tls_Aes_128_Gcm_Sha256 as u16
    );
    let up = take(&mut pair.client);
    let (_, message_seq, body, sequence) = first_message(&up[0]);
    let mut second = Hello::parse(&body);
    assert!(second.get(messages::EXT_COOKIE).is_some());
    second
        .suites
        .retain(|suite| *suite != CipherSuiteId::Tls_Aes_128_Gcm_Sha256 as u16);
    pair.deliver_to_server(vec![handshake_datagram(
        messages::CLIENT_HELLO,
        message_seq,
        &second.encode(),
        sequence,
    )]);
    assert_eq!(
        plaintext_alerts(&take(&mut pair.server)),
        fatal(alert::ILLEGAL_PARAMETER)
    );
    Ok(())
}

// ----------------------------------------------------------------------------------------
// What a client refuses in a ServerHello or a HelloRetryRequest.
// ----------------------------------------------------------------------------------------

/// RFC 8446 section 4.1.3: the session id echo is what the client sent (nothing), the suite
/// one it offered, the compression method zero; anything else is an illegal_parameter. The
/// same for a HelloRetryRequest (section 4.1.4). Its legacy_version is ignored (section 4.2.1,
/// the next test).
#[test]
fn a_server_hello_or_retry_request_with_wrong_fixed_fields_is_an_illegal_parameter() -> Result<()> {
    let changes: Vec<(&str, Box<dyn Fn(&mut Answer)>)> = vec![
        (
            "session id echo",
            Box::new(|answer: &mut Answer| answer.session_id_echo = vec![1; 32]),
        ),
        (
            "a suite not offered",
            Box::new(|answer: &mut Answer| {
                answer.suite = CipherSuiteId::Tls_Aes_256_Gcm_Sha384 as u16
            }),
        ),
        (
            "compression",
            Box::new(|answer: &mut Answer| answer.compression = 1),
        ),
    ];
    let client =
        || client_builder().with_cipher_suites(vec![CipherSuiteId::Tls_Aes_128_Gcm_Sha256]);
    for (what, change) in &changes {
        // A ServerHello (no cookie exchange) and a HelloRetryRequest (with it).
        for server in [no_cookies(), server_builder()] {
            let mut pair = Pair::new(client(), server)?;
            assert_eq!(
                client_refuses(&mut pair, |answer| change(answer)),
                fatal(alert::ILLEGAL_PARAMETER),
                "{what}"
            );
            assert!(pair.client.is_connection_failed(&server_addr()), "{what}");
        }
    }
    Ok(())
}

/// RFC 8446 section 4.2.1: when the ServerHello carries "supported_versions", "clients MUST
/// ignore the ServerHello.legacy_version value and MUST use only the "supported_versions"
/// extension to determine the selected version". A ServerHello, or a HelloRetryRequest,
/// whose legacy_version is not {254, 253} (RFC 9147 section 5.4 binds the sender) is taken by
/// its supported_versions: no alert, and the handshake goes on.
#[test]
fn a_server_hello_or_retry_request_with_another_legacy_version_is_taken() -> Result<()> {
    let client =
        || client_builder().with_cipher_suites(vec![CipherSuiteId::Tls_Aes_128_Gcm_Sha256]);
    for legacy_version in [0xfeff, 0x0303, 0x0000] {
        // A ServerHello: the client waits for EncryptedExtensions.
        let mut pair = Pair::new(client(), no_cookies())?;
        let sent = client_answers(&mut pair, |answer| answer.legacy_version = legacy_version);
        assert!(plaintext_alerts(&sent).is_empty(), "{legacy_version:#06x}");
        assert!(!pair.client.is_connection_failed(&server_addr()));
        assert_eq!(
            pair.client_conn().state,
            HandshakeState::ClientWaitEncryptedExtensions,
            "{legacy_version:#06x}"
        );
        // A HelloRetryRequest: the client answers with its second ClientHello.
        let mut pair = Pair::new(client(), server_builder())?;
        let sent = client_answers(&mut pair, |answer| answer.legacy_version = legacy_version);
        assert!(plaintext_alerts(&sent).is_empty(), "{legacy_version:#06x}");
        assert!(!pair.client.is_connection_failed(&server_addr()));
        assert_eq!(
            first_message(&sent[0]).0,
            messages::CLIENT_HELLO,
            "{legacy_version:#06x}"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.1.4: a HelloRetryRequest that would change nothing in the ClientHello
/// (no cookie, no group) is an illegal_parameter.
#[test]
fn a_hello_retry_request_that_changes_nothing_is_an_illegal_parameter() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?;
    let alerts = client_refuses(&mut pair, |answer| {
        assert!(
            answer.get(messages::EXT_COOKIE).is_some(),
            "a HelloRetryRequest"
        );
        answer
            .extensions
            .retain(|(t, _)| *t == messages::EXT_SUPPORTED_VERSIONS);
    });
    assert_eq!(alerts, fatal(alert::ILLEGAL_PARAMETER));
    Ok(())
}

/// RFC 8446 section 4.2.8: the group a HelloRetryRequest asks for is one the client listed
/// and sent no share for; anything else is an illegal_parameter.
#[test]
fn a_hello_retry_request_for_a_group_already_shared_or_not_listed_is_refused() -> Result<()> {
    // The client sends shares for P-256 and X25519 and lists P-384 too.
    for group in [SECP256R1, X25519, SECP521R1] {
        let mut pair = Pair::new(client_builder(), server_builder())?;
        let alerts = client_refuses(&mut pair, |answer| {
            answer.set(messages::EXT_KEY_SHARE, group.to_be_bytes().to_vec());
        });
        assert_eq!(alerts, fatal(alert::ILLEGAL_PARAMETER), "{group:#06x}");
    }
    // P-384, listed without a share, is taken: the second ClientHello carries its share.
    let mut pair = Pair::new(client_builder(), server_builder())?;
    let up = client_answers(&mut pair, |answer| {
        answer.set(messages::EXT_KEY_SHARE, SECP384R1.to_be_bytes().to_vec());
    });
    assert!(plaintext_alerts(&up).is_empty());
    let (_, _, second, _) = first_message(&up[0]);
    let shares = Hello::parse(&second)
        .get(messages::EXT_KEY_SHARE)
        .unwrap()
        .to_vec();
    assert_eq!(
        messages::parse_client_key_shares(&shares)?
            .iter()
            .map(|(group, _)| *group)
            .collect::<Vec<_>>(),
        vec![SECP384R1]
    );
    Ok(())
}

/// RFC 8446 section 4.1.4: the ServerHello after a HelloRetryRequest has the suite of the
/// HelloRetryRequest; another, even one the client offered, is an illegal_parameter.
#[test]
fn a_server_hello_with_another_suite_than_its_retry_request_is_refused() -> Result<()> {
    let suites = vec![
        CipherSuiteId::Tls_Aes_128_Gcm_Sha256,
        CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256,
    ];
    let mut pair = Pair::new(
        client_builder().with_cipher_suites(suites.clone()),
        server_builder().with_cipher_suites(suites),
    )?;
    pair.round();
    let alerts = client_refuses(&mut pair, |answer| {
        assert_eq!(answer.suite, CipherSuiteId::Tls_Aes_128_Gcm_Sha256 as u16);
        answer.suite = CipherSuiteId::Tls_ChaCha20_Poly1305_Sha256 as u16;
    });
    assert_eq!(alerts, fatal(alert::ILLEGAL_PARAMETER));
    Ok(())
}

/// RFC 8446 section 4.2.8: the server's share is for a group the client sent a share for;
/// for any other (P-384 here: listed, no share), an illegal_parameter. Its key is checked
/// (sections 4.2.8.2 and 7.4.2): a P-256 point off the curve, an all-zero X25519 secret.
#[test]
fn a_server_share_for_another_group_or_of_a_bad_key_is_refused() -> Result<()> {
    let changes: Vec<(&str, Box<dyn Fn(&mut Answer)>)> = vec![
        (
            "a group without a client share",
            Box::new(|answer: &mut Answer| {
                let mut share = answer.get(messages::EXT_KEY_SHARE).unwrap().to_vec();
                share[..2].copy_from_slice(&SECP384R1.to_be_bytes());
                answer.set(messages::EXT_KEY_SHARE, share);
            }),
        ),
        (
            "a point off the curve",
            Box::new(|answer: &mut Answer| {
                let mut share = answer.get(messages::EXT_KEY_SHARE).unwrap().to_vec();
                assert_eq!(share[..2], SECP256R1.to_be_bytes(), "the server took P-256");
                share[20] ^= 0x01;
                answer.set(messages::EXT_KEY_SHARE, share);
            }),
        ),
        (
            "an all-zero X25519 secret",
            Box::new(|answer: &mut Answer| {
                let mut share = vec![];
                put_u16(&mut share, X25519);
                put_vec16(&mut share, |out| out.extend_from_slice(&[0; 32]));
                answer.set(messages::EXT_KEY_SHARE, share);
            }),
        ),
    ];
    for (what, change) in &changes {
        let mut pair = Pair::new(client_builder(), no_cookies())?;
        assert_eq!(
            client_refuses(&mut pair, |answer| change(answer)),
            fatal(alert::ILLEGAL_PARAMETER),
            "{what}"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.2: an extension the client did not offer, in a ServerHello, is an
/// unsupported_extension; one it offered that does not belong in a ServerHello
/// (supported_groups) an illegal_parameter.
#[test]
fn a_server_hello_with_an_extension_out_of_place_is_refused() -> Result<()> {
    for (extension_type, expected) in [
        (0x7777, alert::UNSUPPORTED_EXTENSION),
        (messages::EXT_SUPPORTED_GROUPS, alert::ILLEGAL_PARAMETER),
    ] {
        let mut pair = Pair::new(client_builder(), no_cookies())?;
        let alerts = client_refuses(&mut pair, |answer| {
            answer.set(extension_type, u16_list(&[X25519]));
        });
        assert_eq!(alerts, fatal(expected), "{extension_type:#06x}");
    }
    Ok(())
}

// ----------------------------------------------------------------------------------------
// The rest of the server's flight, as the client takes it.
// ----------------------------------------------------------------------------------------

/// RFC 8446 sections 4.2 and 4.3.1: EncryptedExtensions carries answers to what the client
/// offered, and nothing that belongs in another message: an extension not offered is an
/// unsupported_extension, a forbidden one (key_share, supported_versions) an
/// illegal_parameter.
#[test]
fn encrypted_extensions_with_forbidden_or_unoffered_extensions_are_refused() -> Result<()> {
    for (extension_type, expected) in [
        (0x7777, alert::UNSUPPORTED_EXTENSION),
        (messages::EXT_KEY_SHARE, alert::ILLEGAL_PARAMETER),
        (messages::EXT_SUPPORTED_VERSIONS, alert::ILLEGAL_PARAMETER),
        (messages::EXT_SIGNATURE_ALGORITHMS, alert::ILLEGAL_PARAMETER),
    ] {
        let mut pair = client_after_server_hello(client_builder())?;
        let body = encrypted_extensions(&[(extension_type, vec![0, 0])]);
        let outcome = pair.client_conn().on_handshake_message(
            messages::ENCRYPTED_EXTENSIONS,
            &body,
            EPOCH_HANDSHAKE,
        );
        assert_eq!(
            refusal_alert(outcome),
            Some(expected),
            "{extension_type:#06x}"
        );
    }
    // An empty one is taken.
    let mut pair = client_after_server_hello(client_builder())?;
    taken(pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[]),
        EPOCH_HANDSHAKE,
    ))?;
    Ok(())
}

/// RFC 8446 section 4.6.3: a KeyUpdate before the Finished is an unexpected_message.
#[test]
fn a_key_update_before_the_finished_is_an_unexpected_message() -> Result<()> {
    let mut pair = client_after_server_hello(client_builder())?;
    taken(pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[]),
        EPOCH_HANDSHAKE,
    ))?;
    let outcome =
        pair.client_conn()
            .on_handshake_message(messages::KEY_UPDATE, &[0], EPOCH_HANDSHAKE);
    assert_eq!(refusal_alert(outcome), Some(alert::UNEXPECTED_MESSAGE));
    Ok(())
}

/// RFC 8446 section 4.4.2.4: a server's Certificate with no certificate is a decode_error.
#[test]
fn an_empty_server_certificate_is_a_decode_error() -> Result<()> {
    let mut pair = client_after_server_hello(client_builder())?;
    taken(pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[]),
        EPOCH_HANDSHAKE,
    ))?;
    let outcome = pair.client_conn().on_handshake_message(
        messages::CERTIFICATE,
        &messages::certificate(&[], &[]),
        EPOCH_HANDSHAKE,
    );
    assert_eq!(refusal_alert(outcome), Some(alert::DECODE_ERROR));
    Ok(())
}

/// RFC 8446 section 4.3.2: a client ignores the extensions of a CertificateRequest it does
/// not know.
#[test]
fn a_certificate_request_with_unknown_extensions_is_taken() -> Result<()> {
    let mut body = vec![0u8]; // an empty context
    put_extensions(
        &mut body,
        &[
            (0x7777, vec![1, 2, 3]),
            (messages::EXT_SIGNATURE_ALGORITHMS, u16_list(&[0x0403])),
            (0x7778, vec![]),
        ],
    );
    let mut pair = client_after_server_hello(client_builder())?;
    taken(pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[]),
        EPOCH_HANDSHAKE,
    ))?;
    taken(pair.client_conn().on_handshake_message(
        messages::CERTIFICATE_REQUEST,
        &body,
        EPOCH_HANDSHAKE,
    ))?;
    let (schemes, filters) = pair
        .client_conn()
        .certificate_requested
        .clone()
        .expect("the request is kept");
    assert_eq!(schemes, vec![0x0403]);
    assert!(filters.is_empty());
    Ok(())
}

/// RFC 8446 section 4.4.2: the extensions of a certificate entry answer extensions of the
/// request (the CertificateRequest, or the ClientHello); this side asks for none, so an
/// entry with one is an unsupported_extension, from a server or a client.
#[test]
fn a_certificate_entry_with_an_extension_is_refused() {
    let mut body = vec![0u8];
    put_vec24(&mut body, |list| {
        put_vec24(list, |der| der.extend_from_slice(&[0x30, 0x00]));
        put_extensions(list, &[(5, vec![1, 0, 0, 0, 0])]);
    });
    assert_eq!(
        messages::parse_certificate(&body).err().map(|r| r.alert),
        Some(alert::UNSUPPORTED_EXTENSION)
    );
}

// ----------------------------------------------------------------------------------------
// Signature schemes, key exchange outputs, records.
// ----------------------------------------------------------------------------------------

/// RFC 8446 section 4.2.3: a client that offers SHA-1 schemes lists them last. The default
/// client lists none.
#[test]
fn sha1_schemes_are_listed_last_if_at_all() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?;
    let up = take(&mut pair.client);
    let (_, _, body, _) = first_message(&up[0]);
    let schemes = messages::parse_u16_list(
        Hello::parse(&body)
            .get(messages::EXT_SIGNATURE_ALGORITHMS)
            .unwrap(),
    )?;
    let is_sha1 = |scheme: &u16| scheme.to_be_bytes()[0] == 0x02;
    let first_sha1 = schemes.iter().position(is_sha1).unwrap_or(schemes.len());
    assert!(
        schemes[first_sha1..].iter().all(is_sha1),
        "SHA-1 schemes after others: {schemes:04x?}"
    );
    assert!(!schemes.is_empty());
    Ok(())
}

/// RFC 8446 section 7.4.2: the ECDHE secret is the x-coordinate in full, leading zero bytes
/// included: always 32 bytes for P-256 and 48 for P-384, and both sides compute the same
/// bytes. Exchanges are drawn until one secret starts with a zero byte (one in 256 does);
/// that secret has its full length on both sides and is byte for byte the same.
///
/// Not by fixed key pairs: the provider boundary (`RTCCrypto::start_key_exchange`) starts
/// ephemeral exchanges only, and ring cannot import an ECDH private key at all. The bound on
/// the draws makes a miss a 2^-1000 event, not a 0.3 % one, and the expected cost is about
/// 256 exchanges per curve.
#[test]
fn ecdhe_secrets_keep_their_leading_zeros() -> Result<()> {
    use crate::curve::named_curve::NamedCurve;
    const MAX_DRAWS: usize = 200_000;
    let provider = provider();
    for (curve, length) in [(NamedCurve::P256, 32), (NamedCurve::P384, 48)] {
        let mut found = None;
        for _ in 0..MAX_DRAWS {
            let mut ours = curve.generate_keypair_with_crypto(provider.crypto())?;
            let mut theirs = curve.generate_keypair_with_crypto(provider.crypto())?;
            let our_secret = ours.complete(&theirs.public_key)?;
            let their_secret = theirs.complete(&ours.public_key)?;
            assert_eq!(our_secret.len(), length, "{curve:?}");
            assert_eq!(
                our_secret.as_ref(),
                their_secret.as_ref(),
                "{curve:?}: both sides agree"
            );
            if our_secret.as_ref()[0] == 0 {
                found = Some(our_secret);
                break;
            }
        }
        let secret = found.unwrap_or_else(|| panic!("{curve:?}: no secret with a leading zero"));
        assert_eq!(secret.len(), length, "{curve:?}: the leading zero is kept");
    }
    Ok(())
}

/// RFC 8446 section 5.1: an authenticated record whose content is longer than 2^14 bytes
/// is a record_overflow.
#[test]
fn an_overlong_protected_record_is_a_record_overflow() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    let record = pair.server_conn().seal_oversized_for_test(
        CONTENT_TYPE_APPLICATION_DATA,
        &vec![0x42; MAX_PLAINTEXT + 1],
    );
    pair.deliver_to_client(vec![BytesMut::from(&record[..])]);
    assert!(pair.client.is_connection_failed(&server_addr()));
    assert_eq!(
        pair.client.connection_fatal_alerts(&server_addr()),
        Some((Some(alert::RECORD_OVERFLOW), None))
    );
    // A record of exactly 2^14 bytes is fine.
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    let record = pair
        .server_conn()
        .seal_oversized_for_test(CONTENT_TYPE_APPLICATION_DATA, &vec![0x42; MAX_PLAINTEXT]);
    pair.deliver_to_client(vec![BytesMut::from(&record[..])]);
    assert!(!pair.client.is_connection_failed(&server_addr()));
    assert_eq!(
        application_data(&pair.to_client),
        vec![vec![0x42; MAX_PLAINTEXT]]
    );
    Ok(())
}

/// RFC 8446 section 6: a connection that fails forgets its secrets.
#[test]
fn a_failed_handshake_forgets_its_secrets() -> Result<()> {
    let mut pair = client_after_server_hello(client_builder())?;
    assert!(pair.client_conn().schedule.is_some());
    let outcome = pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[(0x7777, vec![])]),
        EPOCH_HANDSHAKE,
    );
    let refusal = outcome.expect_err("refused");
    pair.client_conn().refuse(refusal);
    let conn = pair.client_conn();
    assert!(conn.failed);
    assert!(
        conn.schedule
            .as_ref()
            .is_none_or(|schedule| schedule.is_forgotten()),
        "the key schedule's secrets are gone"
    );
    assert!(conn.exporter_secret.is_none() && conn.offer.is_none());
    Ok(())
}

/// RFC 8446 section 7.1: "Once all the values which are to be derived from a given secret
/// have been computed, that secret SHOULD be erased." After a handshake, on both sides: the
/// handshake traffic secrets are gone (both Finished are done, the epoch's record keys
/// derived), the Main Secret too (the resumption master secret is derived), and the key
/// schedule keeps no copy of the application traffic secrets the association took for its
/// key updates. Data still flows both ways, and a key update still works.
#[test]
fn a_completed_handshake_keeps_only_the_secrets_still_needed() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    for client in [true, false] {
        let conn = if client {
            pair.client_conn()
        } else {
            pair.server_conn()
        };
        let schedule = conn.schedule.as_ref().expect("a key schedule");
        assert!(
            schedule.handshake_secrets_forgotten(),
            "handshake traffic secrets"
        );
        assert!(
            schedule.application_secrets_handed_over(),
            "application secret copies"
        );
        assert!(conn.local_application_secret().is_some());
    }
    assert_eq!(pair.client_sends(b"after"), vec![b"after".to_vec()]);
    assert_eq!(pair.server_sends(b"back"), vec![b"back".to_vec()]);
    pair.client.update_keys(pair.now, server_addr(), true)?;
    pair.run();
    assert_eq!(pair.client_sends(b"updated"), vec![b"updated".to_vec()]);
    Ok(())
}

// ----------------------------------------------------------------------------------------
// Certificates.
// ----------------------------------------------------------------------------------------

fn certificate(params: rcgen::CertificateParams, key: &rcgen::KeyPair) -> Certificate {
    let der = params
        .self_signed(key)
        .expect("a certificate")
        .der()
        .to_owned();
    Certificate {
        certificate: vec![der],
        private_key: CryptoPrivateKey::from_key_pair(key, provider().crypto())
            .expect("the key imports"),
    }
}

fn params_with(
    key_usages: Vec<rcgen::KeyUsagePurpose>,
    extended: Vec<rcgen::ExtendedKeyUsagePurpose>,
) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params.key_usages = key_usages;
    params.extended_key_usages = extended;
    params
}

/// RFC 8446 section 4.4.2.2: the server's certificate allows its key to sign. One whose
/// KeyUsage lacks digitalSignature is passed over for another, and never sent.
#[test]
fn a_server_certificate_whose_key_may_not_sign_is_not_sent() -> Result<()> {
    use rcgen::KeyUsagePurpose::*;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cannot_sign = certificate(params_with(vec![KeyEncipherment], vec![]), &key);
    let can_sign = certificate(params_with(vec![DigitalSignature], vec![]), &key);
    let server = |certificates: Vec<Certificate>| no_cookies().with_certificates(certificates);
    let pair = Pair::new(
        client_builder(),
        server(vec![cannot_sign.clone(), can_sign.clone()]),
    )?
    .complete();
    assert_eq!(
        pair.client
            .get_connection_state(server_addr())
            .unwrap()
            .peer_certificates,
        vec![can_sign.certificate[0].as_ref().to_vec()]
    );

    let mut pair = Pair::new(client_builder(), server(vec![cannot_sign]))?;
    let up = take(&mut pair.client);
    pair.deliver_to_server(up);
    assert_eq!(
        plaintext_alerts(&take(&mut pair.server)),
        fatal(alert::HANDSHAKE_FAILURE)
    );
    Ok(())
}

fn oid_filters(filters: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut data = vec![];
    put_vec16(&mut data, |list| {
        for (oid, values) in filters {
            put_vec8(list, |out| out.extend_from_slice(oid));
            put_vec16(list, |out| out.extend_from_slice(values));
        }
    });
    data
}

/// ExtendedKeyUsage, 2.5.29.37, and the DER of a list of id-kp-clientAuth.
const EKU_OID: [u8; 3] = [0x55, 0x1d, 0x25];
const CLIENT_AUTH: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
];
/// KeyUsage, 2.5.29.15 (with its tag this time), and a BIT STRING of digitalSignature.
const KEY_USAGE_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x0f];
const DIGITAL_SIGNATURE: [u8; 4] = [0x03, 0x02, 0x07, 0x80];

/// RFC 8446 sections 4.2.5 and 4.4.2.3: a client answers a CertificateRequest's
/// oid_filters with a certificate that has every recognized extension asked for, with the
/// values asked for, and with no certificate when it has none such. Filters for extensions
/// it does not know are skipped.
#[test]
fn a_client_certificate_meets_the_requests_oid_filters() -> Result<()> {
    use super::certificate_checks::{OidFilter, matches_oid_filters};
    use rcgen::ExtendedKeyUsagePurpose::*;
    use rcgen::KeyUsagePurpose::*;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let der = |params| certificate(params, &key).certificate[0].as_ref().to_vec();
    let client_auth = der(params_with(vec![DigitalSignature], vec![ClientAuth]));
    let server_auth = der(params_with(vec![KeyEncipherment], vec![ServerAuth]));
    let plain = der(params_with(vec![], vec![]));
    let filter = |oid: &[u8], values: &[u8]| OidFilter {
        oid: oid.to_vec(),
        values: values.to_vec(),
    };
    let eku = [filter(&EKU_OID, &CLIENT_AUTH)];
    let key_usage = [filter(&KEY_USAGE_OID, &DIGITAL_SIGNATURE)];
    let unknown = [filter(&[0x2a, 0x03], &[0x05, 0x00])];
    assert!(matches_oid_filters(&client_auth, &eku));
    assert!(matches_oid_filters(&client_auth, &key_usage));
    assert!(!matches_oid_filters(&server_auth, &eku));
    assert!(!matches_oid_filters(&server_auth, &key_usage));
    assert!(
        !matches_oid_filters(&plain, &eku),
        "the extension is missing"
    );
    assert!(matches_oid_filters(&plain, &unknown));
    assert!(matches_oid_filters(&plain, &[]));

    // In a handshake: the client with a server-auth certificate answers a request for
    // client-auth ones with no certificate; with a client-auth one, it sends it.
    for (client_certificate, sent) in [(server_auth, false), (client_auth, true)] {
        let client_certificate = Certificate {
            certificate: vec![rustls::pki_types::CertificateDer::from(client_certificate)],
            private_key: CryptoPrivateKey::from_key_pair(&key, provider().crypto())?,
        };
        let mut pair = client_after_server_hello(
            client_builder().with_certificates(vec![client_certificate]),
        )?;
        taken(pair.client_conn().on_handshake_message(
            messages::ENCRYPTED_EXTENSIONS,
            &encrypted_extensions(&[]),
            EPOCH_HANDSHAKE,
        ))?;
        let mut request = vec![0u8];
        put_extensions(
            &mut request,
            &[
                (messages::EXT_SIGNATURE_ALGORITHMS, u16_list(&[0x0403])),
                (
                    messages::EXT_OID_FILTERS,
                    oid_filters(&[(&EKU_OID, &CLIENT_AUTH)]),
                ),
            ],
        );
        taken(pair.client_conn().on_handshake_message(
            messages::CERTIFICATE_REQUEST,
            &request,
            EPOCH_HANDSHAKE,
        ))?;
        let (schemes, filters) = pair.client_conn().certificate_requested.clone().unwrap();
        assert_eq!(
            pair.client_conn()
                .client_credentials_for_test(&schemes, &filters),
            sent
        );
    }
    Ok(())
}

/// RFC 8446 section 4.4.2.3: the client's chain is signed with algorithms the request
/// lists; a certificate issued under another is not sent. A self-signed one begins its path
/// and is exempt (section 4.2.3).
#[test]
fn a_client_chain_signed_with_an_algorithm_the_request_lacks_is_not_sent() -> Result<()> {
    let provider = provider();
    // An Ed25519 leaf issued by a P-256 (ECDSA-SHA256) authority.
    let authority_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let named = |name: &str| {
        let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, name);
        params.distinguished_name = dn;
        params
    };
    let authority = rcgen::Issuer::new(named("authority"), authority_key);
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let leaf = named("client").signed_by(&leaf_key, &authority).unwrap();
    let issued = Certificate {
        certificate: vec![leaf.der().to_owned()],
        private_key: CryptoPrivateKey::from_key_pair(&leaf_key, provider.crypto())?,
    };
    let self_signed = Certificate::generate_self_signed_with_alg(
        vec!["client".to_owned()],
        &rcgen::PKCS_ED25519,
        provider.crypto(),
    )?;
    // The request lists Ed25519 only (0x0807), so the CertificateVerify can be made, and
    // the authority's ECDSA-SHA256 signature is not acceptable.
    for (certificate, sent) in [(issued, false), (self_signed, true)] {
        let mut pair =
            client_after_server_hello(client_builder().with_certificates(vec![certificate]))?;
        taken(pair.client_conn().on_handshake_message(
            messages::ENCRYPTED_EXTENSIONS,
            &encrypted_extensions(&[]),
            EPOCH_HANDSHAKE,
        ))?;
        taken(pair.client_conn().on_handshake_message(
            messages::CERTIFICATE_REQUEST,
            &messages::certificate_request(&[], &[0x0807]),
            EPOCH_HANDSHAKE,
        ))?;
        let (schemes, filters) = pair.client_conn().certificate_requested.clone().unwrap();
        assert_eq!(
            pair.client_conn()
                .client_credentials_for_test(&schemes, &filters),
            sent
        );
    }
    Ok(())
}

/// RFC 8446 section 4.4.2.4: a certificate signed with MD5 ends the handshake with
/// bad_certificate, also where the chain itself is not verified (fingerprint
/// authentication, here `insecure_skip_verify`).
#[test]
fn a_certificate_signed_with_md5_is_a_bad_certificate() -> Result<()> {
    let key_pair = rcgen::KeyPair::from_pem(include_str!("testdata/rsa-2048.pkcs8.pem"))
        .expect("an RSA key pair");
    let sha256 = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    // sha256WithRSAEncryption, 1.2.840.113549.1.1.11, becomes md5WithRSAEncryption,
    // 1.2.840.113549.1.1.4, in the TBSCertificate and the outer signature algorithm: same
    // length, and the signature, which nobody looks at here, stays as it is.
    let sha256_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ];
    let mut der = sha256.der().to_vec();
    let mut replaced = 0;
    let mut at = 0;
    while let Some(found) = der[at..]
        .windows(sha256_oid.len())
        .position(|window| window == sha256_oid)
    {
        let position = at + found;
        der[position + sha256_oid.len() - 1] = 0x04;
        replaced += 1;
        at = position + sha256_oid.len();
    }
    assert_eq!(replaced, 2);
    assert!(super::certificate_checks::signed_with_md5(&der));
    let md5 = Certificate {
        certificate: vec![rustls::pki_types::CertificateDer::from(der)],
        private_key: CryptoPrivateKey::from_key_pair(&key_pair, provider().crypto())?,
    };
    let mut pair = Pair::new(
        client_builder(),
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_cookie_exchange(false)
            .with_certificates(vec![md5]),
    )?;
    pair.run();
    assert!(!pair.client_complete);
    assert_eq!(
        pair.client.connection_fatal_alerts(&server_addr()),
        Some((Some(alert::BAD_CERTIFICATE), None))
    );
    Ok(())
}

/// RFC 8446 section 4.4.2.4: "it is RECOMMENDED that any endpoint receiving any certificate
/// which it would need to validate using any signature algorithm using a SHA-1 hash abort the
/// handshake with a bad_certificate alert". A server certificate whose signature algorithm is
/// sha1WithRSAEncryption is refused by a client that validates the chain (with that error,
/// before the chain verifier sees it), and taken by one that authenticates by fingerprint and
/// so validates no certificate signature (WebRTC's self-signed certificates).
#[test]
fn a_certificate_signed_with_sha1_is_refused_where_the_chain_is_validated() -> Result<()> {
    let key_pair = rcgen::KeyPair::from_pem(include_str!("testdata/rsa-2048.pkcs8.pem"))
        .expect("an RSA key pair");
    let sha256 = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    // sha256WithRSAEncryption, 1.2.840.113549.1.1.11, becomes sha1WithRSAEncryption,
    // 1.2.840.113549.1.1.5, in the TBSCertificate and the outer signature algorithm.
    let sha256_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ];
    let mut der = sha256.der().to_vec();
    let mut replaced = 0;
    let mut at = 0;
    while let Some(found) = der[at..]
        .windows(sha256_oid.len())
        .position(|window| window == sha256_oid)
    {
        let position = at + found;
        der[position + sha256_oid.len() - 1] = 0x05;
        replaced += 1;
        at = position + sha256_oid.len();
    }
    assert_eq!(replaced, 2);
    assert!(super::certificate_checks::signed_with_sha1(&der));
    let sha1 = rustls::pki_types::CertificateDer::from(der);
    let server = || -> Result<ConfigBuilder> {
        Ok(ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_cookie_exchange(false)
            .with_certificates(vec![Certificate {
                certificate: vec![sha1.clone()],
                private_key: CryptoPrivateKey::from_key_pair(&key_pair, provider().crypto())?,
            }]))
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.add(sha1.clone()).expect("a root");
    let validating = ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_post_quantum_key_share(false)
        .with_server_name("localhost".to_owned())
        .with_roots_cas(roots);
    let mut pair = Pair::new(validating, server()?)?;
    pair.run();
    assert!(!pair.client_complete);
    assert_eq!(
        pair.client.connection_fatal_alerts(&server_addr()),
        Some((Some(alert::BAD_CERTIFICATE), None))
    );
    assert!(
        format!("{:?}", pair.client_error).contains("SHA-1"),
        "{:?}",
        pair.client_error
    );

    // Fingerprint authentication validates no certificate signature.
    let mut pair = Pair::new(client_builder(), server()?)?;
    pair.run();
    assert!(
        pair.client_complete && pair.server_complete,
        "{:?}",
        pair.client_error
    );
    Ok(())
}

/// An RSA public key of `bits` bits (an odd modulus with its top bit set, e = 65537), for a
/// certificate an issuer signs: nobody holds its private key.
struct BareRsaKey(Vec<u8>);

impl BareRsaKey {
    fn new(bits: usize) -> Self {
        let mut modulus = vec![0xa5u8; bits / 8];
        modulus[0] = 0xc3;
        *modulus.last_mut().unwrap() |= 1;
        let integer = |bytes: &[u8]| {
            let mut value = vec![0u8];
            value.extend_from_slice(bytes);
            der(0x02, &value)
        };
        let mut body = integer(&modulus);
        body.extend(der(0x02, &[0x01, 0x00, 0x01]));
        Self(der(0x30, &body))
    }
}

/// A DER element: tag, definite length, value.
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match value.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
    out
}

impl rcgen::PublicKeyData for BareRsaKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

/// RFC 8446 appendix C.2: "Applications SHOULD also enforce minimum and maximum key sizes."
/// A signature from a certificate whose RSA key has 9216 bits is refused for its size, before
/// any RSA operation; one of 8192 bits is not refused for its size (it fails as the forged
/// signature it is).
#[test]
fn rsa_keys_above_8192_bits_are_refused() -> Result<()> {
    let issuer_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let issuer = rcgen::Issuer::new(
        rcgen::CertificateParams::new(vec!["issuer".to_owned()]).unwrap(),
        issuer_key,
    );
    let verify = |bits: usize| {
        let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .signed_by(&BareRsaKey::new(bits), &issuer)
            .unwrap();
        crate::crypto::verify_key_signature(
            provider().crypto(),
            b"signed",
            &crate::signature_hash_algorithm::SignatureHashAlgorithm {
                hash: crate::signature_hash_algorithm::HashAlgorithm::Sha256,
                signature: crate::signature_hash_algorithm::SignatureAlgorithm::Rsa,
            },
            &vec![0x42; bits / 8],
            &[certificate.der().to_vec()],
            false,
        )
    };
    let large = verify(9216);
    assert!(
        format!("{large:?}").contains("RFC 8446 appendix C.2"),
        "{large:?}"
    );
    let largest = verify(8192);
    assert!(largest.is_err(), "a forged signature");
    assert!(
        !format!("{largest:?}").contains("appendix C.2"),
        "{largest:?}"
    );
    Ok(())
}

// ----------------------------------------------------------------------------------------
// RFC 9147: the last epoch, closure, a new association, ACKs, CCM_8.
// ----------------------------------------------------------------------------------------

/// RFC 9147 sections 4.2.1, 6.1 and 8: the epoch never passes 2^48-1. At it no KeyUpdate
/// is sent, none in answer to the peer's either, and when the keys run out the association
/// is closed rather than the epoch wrapped.
#[test]
fn the_epoch_never_passes_its_last_value() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    pair.client_conn().set_send_epoch_for_test(MAX_SEND_EPOCH);
    assert!(pair.client_conn().send_key_update(false).is_err());
    // Records in the last epoch still carry data.
    assert_eq!(pair.client_sends(b"last"), vec![b"last".to_vec()]);

    // The server asks for an update: the client takes the server's new keys, and sends no
    // KeyUpdate of its own.
    pair.server_conn().send_key_update(true)?;
    let now = pair.now;
    let _ = pair.server.handle_timeout(client_addr(), now);
    pair.run();
    assert!(!pair.client_conn().key_update_outstanding());
    assert_eq!(pair.server_sends(b"newer"), vec![b"newer".to_vec()]);
    assert!(
        !pair.server_conn().has_read_epoch(EPOCH_APPLICATION + 1),
        "the client never updated its keys"
    );

    // The keys of the last epoch reach their limit: the association closes.
    pair.client_conn().confidentiality_limit = Some(16);
    let mut closed = false;
    for index in 0..16u8 {
        if pair
            .client
            .write(pair.now, server_addr(), &[index])
            .is_err()
        {
            closed = true;
            break;
        }
        if pair.client_conn().closed {
            closed = true;
            break;
        }
    }
    assert!(closed, "the association is closed at the limit");
    pair.to_server.clear();
    pair.run();
    assert!(
        pair.to_server
            .iter()
            .any(|event| matches!(event, crate::endpoint::EndpointEvent::PeerClosed)),
        "the server got close_notify"
    );
    Ok(())
}

/// RFC 9147 section 5.10: nothing that follows the peer's closure alert is read, in the
/// same datagram or a later one.
#[test]
fn data_after_a_close_notify_is_ignored() -> Result<()> {
    for together in [false, true] {
        let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
        pair.server_conn().close();
        let now = pair.now;
        let _ = pair.server.handle_timeout(client_addr(), now);
        let close = take(&mut pair.server);
        assert_eq!(close.len(), 1);
        let after = pair
            .server_conn()
            .seal_for_fuzzing(CONTENT_TYPE_APPLICATION_DATA, b"after the close")
            .expect("a record");
        pair.to_client.clear();
        if together {
            let mut datagram = close[0].clone();
            datagram.extend_from_slice(&after);
            pair.deliver_to_client(vec![datagram]);
        } else {
            pair.deliver_to_client(close);
            pair.deliver_to_client(vec![BytesMut::from(&after[..])]);
        }
        assert!(
            pair.to_client
                .iter()
                .any(|event| matches!(event, crate::endpoint::EndpointEvent::PeerClosed)),
            "together: {together}"
        );
        assert!(
            application_data(&pair.to_client).is_empty(),
            "together: {together}"
        );
    }
    Ok(())
}

/// RFC 9147 section 5.11: a client that restarts from the same address makes a new
/// association, which takes the old one's place once its handshake is complete; the old
/// one's records are not read any more.
#[test]
fn a_completed_new_association_replaces_the_old_one() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?.complete();
    assert_eq!(pair.client_sends(b"old"), vec![b"old".to_vec()]);
    pair.client
        .write(pair.now, server_addr(), b"from the old association")?;
    let stale = take(&mut pair.client);

    // The new client, same address.
    let config = std::sync::Arc::new(client_builder().build(true, None)?);
    let mut new_client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    new_client.connect(pair.now, server_addr(), config, None)?;
    let _old_client = std::mem::replace(&mut pair.client, new_client);
    pair.client_complete = false;
    pair.server_complete = false;
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"new"), vec![b"new".to_vec()]);

    pair.to_server.clear();
    pair.deliver_to_server(stale);
    assert!(
        application_data(&pair.to_server).is_empty(),
        "the old association is gone"
    );
    Ok(())
}

/// RFC 9147 section 7: a handshake message that is discarded, here one beyond the window
/// of messages taken out of order, is not acknowledged; one inside it is.
#[test]
fn a_discarded_handshake_message_is_not_acknowledged() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?;
    let up = take(&mut pair.client);
    pair.deliver_to_server(up);
    take(&mut pair.server);
    let next = pair.server_conn().next_receive_seq_for_test();
    let beyond = handshake_datagram(messages::CERTIFICATE, next + 9, &[0, 0, 0, 0], 40);
    let inside = handshake_datagram(messages::CERTIFICATE, next + 1, &[0, 0, 0, 0], 41);
    pair.deliver_to_server(vec![beyond, inside]);
    let noted = pair.server_conn().acknowledgeable_records().to_vec();
    assert!(!noted.contains(&RecordNumber {
        epoch: 0,
        sequence: 40
    }));
    assert!(noted.contains(&RecordNumber {
        epoch: 0,
        sequence: 41
    }));
    Ok(())
}

/// RFC 9147 section 4.5.3: TLS_AES_128_CCM_8_SHA256 has its own limit on forged records,
/// 2^7: at the 128th that fails authentication the association is closed.
#[test]
fn ccm_8_closes_after_two_to_the_seventh_forgeries() -> Result<()> {
    let suite = CipherSuiteId::Tls_Aes_128_Ccm_8_Sha256;
    let mut pair = Pair::new(
        client_builder().with_cipher_suites(vec![suite]),
        no_cookies().with_cipher_suites(vec![suite]),
    )?
    .complete();
    pair.client.write(pair.now, server_addr(), b"genuine")?;
    let genuine = take(&mut pair.client);
    for forgery in 1..=128u32 {
        let mut forged = genuine[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= (forgery % 255 + 1) as u8;
        forged[last - 1] ^= (forgery / 255) as u8;
        let _ = pair
            .server
            .read(pair.now, client_addr(), None, BytesMut::from(&forged[..]));
        take(&mut pair.server);
        assert_eq!(
            pair.server.is_connection_failed(&client_addr()),
            forgery == 128,
            "after {forgery} forgeries"
        );
    }
    Ok(())
}

/// RFC 5764 section 4.1.3, RFC 8827 section 6.5: this client offers no SRTP MKI, so an
/// answer in EncryptedExtensions that carries one is an illegal_parameter; one without is
/// taken.
#[test]
fn a_use_srtp_answer_with_an_mki_is_refused() -> Result<()> {
    use crate::extension::extension_use_srtp::SrtpProtectionProfile;
    let profile = SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm;
    let answer = |mki: &[u8]| {
        let mut data = vec![];
        put_vec16(&mut data, |list| put_u16(list, profile as u16));
        put_vec8(&mut data, |out| out.extend_from_slice(mki));
        encrypted_extensions(&[(messages::EXT_USE_SRTP, data)])
    };
    let client = || client_builder().with_srtp_protection_profiles(vec![profile]);
    let mut pair = client_after_server_hello(client())?;
    let outcome = pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &answer(&[1, 2]),
        EPOCH_HANDSHAKE,
    );
    assert_eq!(refusal_alert(outcome), Some(alert::ILLEGAL_PARAMETER));
    let mut pair = client_after_server_hello(client())?;
    taken(pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &answer(&[]),
        EPOCH_HANDSHAKE,
    ))?;
    Ok(())
}

/// RFC 8827 section 6.5: forward-secret suites are preferred to the others. A default client
/// offers no other: every suite of its ClientHello is a TLS 1.3 one or an ECDHE one.
#[test]
fn a_default_client_offers_only_forward_secret_suites() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?;
    let up = take(&mut pair.client);
    let (_, _, body, _) = first_message(&up[0]);
    let suites = Hello::parse(&body).suites;
    assert!(!suites.is_empty());
    for suite in suites {
        let name = format!("{}", CipherSuiteId::from(suite));
        assert!(
            (0x1301..=0x1305).contains(&suite) || name.starts_with("TLS_ECDHE_"),
            "{suite:#06x} {name}"
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------------------------
// Unknown parameters, versions, alerts and closure (audit sweep 4 rows).
// ----------------------------------------------------------------------------------------

/// Code points this crate does not know: GREASE values (RFC 8701), which no implementation
/// assigns a meaning to, and a private-use extension.
const UNKNOWN_EXTENSIONS: [u16; 3] = [0x0a0a, 0x7777, 0xfafa];
const UNKNOWN_GROUP: u16 = 0x2a2a;
const UNKNOWN_SCHEME: u16 = 0x3a3a;
const UNKNOWN_SUITE: u16 = 0x4a4a;
const UNKNOWN_VERSION: u16 = 0x5a5a;

fn u16s(data: &[u8]) -> Vec<u16> {
    data.chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

/// RFC 8446 sections 4.1.2 ("Servers MUST ignore unrecognized extensions") and 9.3 ("A
/// server receiving a ClientHello MUST correctly ignore all unrecognized cipher suites,
/// extensions, and other parameters"), which RFC 9147 section 13 names for DTLS: the
/// client's own ClientHello with unknown extensions first, in the middle and last, an
/// unknown suite first, an unknown group first in supported_groups with a key share of its
/// own first, an unknown signature scheme first. The server answers with a ServerHello (no
/// alert, no HelloRetryRequest) of a suite, group and version it knows, and none of the
/// unknown extensions; the same hello without them gets the same choices and extensions.
#[test]
fn a_client_hello_with_unknown_extensions_suites_groups_and_schemes_is_served() -> Result<()> {
    let choices = |answer: &[BytesMut]| {
        assert!(plaintext_alerts(answer).is_empty(), "no alert");
        let (handshake_type, _, body, _) = first_message(&answer[0]);
        assert_eq!(handshake_type, messages::SERVER_HELLO);
        let server_hello = Answer::parse(&body);
        assert_ne!(
            server_hello.random,
            messages::HELLO_RETRY_REQUEST_RANDOM.to_vec(),
            "a ServerHello, not a HelloRetryRequest"
        );
        let types: Vec<u16> = server_hello.extensions.iter().map(|(t, _)| *t).collect();
        // The answers to what this client offered (supported_versions, key_share and
        // connection_id), none of the unknown ones.
        assert!(
            types.iter().all(|t| !UNKNOWN_EXTENSIONS.contains(t)),
            "no unknown extension answered: {types:04x?}"
        );
        let group = u16::from_be_bytes(
            server_hello.get(messages::EXT_KEY_SHARE).unwrap()[..2]
                .try_into()
                .unwrap(),
        );
        (
            types,
            server_hello.suite,
            group,
            server_hello
                .get(messages::EXT_SUPPORTED_VERSIONS)
                .unwrap()
                .to_vec(),
        )
    };
    let plain = choices(&server_answers(no_cookies(), |_| {})?);

    let answer = server_answers(no_cookies(), |hello| {
        assert!(hello.get(messages::EXT_PRE_SHARED_KEY).is_none());
        hello.suites.insert(0, UNKNOWN_SUITE);
        let mut groups = u16s(&hello.get(messages::EXT_SUPPORTED_GROUPS).unwrap()[2..]);
        groups.insert(0, UNKNOWN_GROUP);
        hello.set(messages::EXT_SUPPORTED_GROUPS, u16_list(&groups));
        let mut shares: Vec<(u16, Vec<u8>)> =
            messages::parse_client_key_shares(hello.get(messages::EXT_KEY_SHARE).unwrap())
                .unwrap()
                .into_iter()
                .map(|(group, key)| (group, key.to_vec()))
                .collect();
        shares.insert(0, (UNKNOWN_GROUP, vec![0x42; 40]));
        hello.set(messages::EXT_KEY_SHARE, client_key_shares(&shares));
        let mut schemes = u16s(&hello.get(messages::EXT_SIGNATURE_ALGORITHMS).unwrap()[2..]);
        schemes.insert(0, UNKNOWN_SCHEME);
        hello.set(messages::EXT_SIGNATURE_ALGORITHMS, u16_list(&schemes));
        hello.extensions.insert(0, (UNKNOWN_EXTENSIONS[0], vec![]));
        let middle = hello.extensions.len() / 2;
        hello
            .extensions
            .insert(middle, (UNKNOWN_EXTENSIONS[1], vec![1, 2, 3, 4, 5]));
        hello.extensions.push((UNKNOWN_EXTENSIONS[2], vec![0]));
    })?;
    assert_eq!(choices(&answer), plain);
    Ok(())
}

fn supported_versions(versions: &[u16]) -> Vec<u8> {
    let mut data = vec![];
    put_vec8(&mut data, |list| {
        for version in versions {
            put_u16(list, *version);
        }
    });
    data
}

/// RFC 8446 section 4.2.1: "Servers MUST only select a version of TLS present in that
/// extension and MUST ignore any unknown versions that are present in that extension." An
/// unknown version before and after DTLS 1.3 is ignored (DTLS 1.3 selected); one before
/// DTLS 1.2 alone is too (a DTLS 1.2 ServerHello); a list of unknown versions only has no
/// version this server may select, and is refused with protocol_version, not served with
/// DTLS 1.2 by the legacy_version.
#[test]
fn unknown_versions_are_ignored_and_only_a_listed_version_is_selected() -> Result<()> {
    let with_versions = |versions: Vec<u16>| {
        server_answers(no_cookies(), move |hello| {
            assert_eq!(hello.legacy_version, super::DTLS1_2_WIRE_VERSION);
            hello.set(
                messages::EXT_SUPPORTED_VERSIONS,
                supported_versions(&versions),
            );
        })
    };
    let answer = with_versions(vec![
        UNKNOWN_VERSION,
        super::DTLS1_3_WIRE_VERSION,
        0x0304, // TLS 1.3: no DTLS version
        super::DTLS1_2_WIRE_VERSION,
    ])?;
    assert!(plaintext_alerts(&answer).is_empty());
    let (_, _, body, _) = first_message(&answer[0]);
    assert_eq!(
        ServerHello::parse(&body).unwrap().selected_version(),
        Some(super::DTLS1_3_WIRE_VERSION)
    );

    let answer = with_versions(vec![UNKNOWN_VERSION, super::DTLS1_2_WIRE_VERSION])?;
    assert!(plaintext_alerts(&answer).is_empty());
    let (handshake_type, _, body, _) = first_message(&answer[0]);
    assert_eq!(handshake_type, messages::SERVER_HELLO);
    let server_hello = ServerHello::parse(&body).unwrap();
    assert_eq!(server_hello.legacy_version, super::DTLS1_2_WIRE_VERSION);
    assert_eq!(
        server_hello.selected_version(),
        None,
        "a DTLS 1.2 ServerHello"
    );

    for versions in [vec![UNKNOWN_VERSION], vec![0x0304, UNKNOWN_VERSION]] {
        let answer = with_versions(versions.clone())?;
        assert_eq!(
            plaintext_alerts(&answer),
            fatal(alert::PROTOCOL_VERSION),
            "{versions:04x?}"
        );
        assert!(
            answer
                .iter()
                .all(|datagram| datagram[0] == CONTENT_TYPE_ALERT),
            "{versions:04x?}: no ServerHello"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.1.4: "The value of selected_version in the HelloRetryRequest
/// "supported_versions" extension MUST be retained in the ServerHello, and a client MUST
/// abort the handshake with an "illegal_parameter" alert if the value changes." After a
/// HelloRetryRequest for DTLS 1.3, a ServerHello that selects DTLS 1.2, an unknown version,
/// or (without the extension) none, is refused with illegal_parameter; the unchanged one is
/// taken.
#[test]
fn a_server_hello_whose_version_differs_from_the_retry_requests_is_refused() -> Result<()> {
    let changes: [(&str, Option<u16>); 3] = [
        ("DTLS 1.2", Some(super::DTLS1_2_WIRE_VERSION)),
        ("an unknown version", Some(UNKNOWN_VERSION)),
        ("no supported_versions", None),
    ];
    for (what, version) in changes {
        let mut pair = Pair::new(client_builder(), server_builder())?;
        let (_, retry) = pair.round();
        let (_, _, retry, _) = first_message(&retry[0]);
        let retry = Answer::parse(&retry);
        assert_eq!(retry.random, messages::HELLO_RETRY_REQUEST_RANDOM.to_vec());
        assert_eq!(
            retry.get(messages::EXT_SUPPORTED_VERSIONS),
            Some(&super::DTLS1_3_WIRE_VERSION.to_be_bytes()[..])
        );
        let alerts = client_refuses(&mut pair, |answer| {
            assert_eq!(
                answer.get(messages::EXT_SUPPORTED_VERSIONS),
                Some(&super::DTLS1_3_WIRE_VERSION.to_be_bytes()[..]),
                "the server retains it"
            );
            match version {
                Some(version) => answer.set(
                    messages::EXT_SUPPORTED_VERSIONS,
                    version.to_be_bytes().to_vec(),
                ),
                None => answer
                    .extensions
                    .retain(|(t, _)| *t != messages::EXT_SUPPORTED_VERSIONS),
            }
        });
        assert_eq!(alerts, fatal(alert::ILLEGAL_PARAMETER), "{what}");
        assert!(pair.client.is_connection_failed(&server_addr()), "{what}");
    }
    let mut pair = Pair::new(client_builder(), server_builder())?;
    pair.round();
    let up = client_answers(&mut pair, |_| {});
    assert!(
        plaintext_alerts(&up).is_empty(),
        "the version retained is taken"
    );
    assert_eq!(
        pair.client_conn().state,
        HandshakeState::ClientWaitEncryptedExtensions
    );
    Ok(())
}

/// RFC 8446 section 6: "Unknown Alert types MUST be treated as error alerts." A protected
/// alert of a description this crate does not know, at level warning and at level fatal,
/// ends the association like a fatal alert: it is reported as the alert received, and data
/// that follows it is not read. A known warning-level closure alert is not an error.
#[test]
fn an_alert_of_an_unknown_type_is_an_error_alert() -> Result<()> {
    for (level, description) in [(1u8, 0xfeu8), (2, 0xfe), (1, 200)] {
        let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
        let unknown = pair
            .server_conn()
            .seal_for_fuzzing(CONTENT_TYPE_ALERT, &[level, description])
            .expect("a record");
        let after = pair
            .server_conn()
            .seal_for_fuzzing(CONTENT_TYPE_APPLICATION_DATA, b"after the alert")
            .expect("a record");
        let mut datagram = BytesMut::from(&unknown[..]);
        datagram.extend_from_slice(&after);
        pair.to_client.clear();
        pair.deliver_to_client(vec![datagram]);
        assert!(
            pair.client.is_connection_failed(&server_addr()),
            "level {level}, description {description}"
        );
        assert_eq!(
            pair.client.connection_fatal_alerts(&server_addr()),
            Some((None, Some(description))),
            "level {level}, description {description}"
        );
        assert!(application_data(&pair.to_client).is_empty());
    }
    Ok(())
}

/// RFC 8446 section 6.1: closure alerts are close_notify and user_canceled; "Any data
/// received after a closure alert has been received MUST be ignored" (RFC 9147 section 5.10:
/// after it by epoch and sequence number). A protected user_canceled followed by data, in
/// the same datagram and in a later one: the data is not read.
#[test]
fn data_after_a_user_canceled_is_ignored() -> Result<()> {
    for together in [false, true] {
        let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
        let canceled = pair
            .server_conn()
            .seal_for_fuzzing(CONTENT_TYPE_ALERT, &[1, alert::USER_CANCELED])
            .expect("a record");
        let after = pair
            .server_conn()
            .seal_for_fuzzing(CONTENT_TYPE_APPLICATION_DATA, b"after the user_canceled")
            .expect("a record");
        pair.to_client.clear();
        if together {
            let mut datagram = BytesMut::from(&canceled[..]);
            datagram.extend_from_slice(&after);
            pair.deliver_to_client(vec![datagram]);
        } else {
            pair.deliver_to_client(vec![BytesMut::from(&canceled[..])]);
            pair.deliver_to_client(vec![BytesMut::from(&after[..])]);
        }
        assert!(
            application_data(&pair.to_client).is_empty(),
            "together: {together}"
        );
        assert!(
            !pair.client.is_connection_failed(&server_addr()),
            "together: {together}: a closure alert, not an error alert"
        );
    }
    Ok(())
}

// ----------------------------------------------------------------------------------------
// Rows audit sweep 6 found without a test of their own (dtlsrows2).
// ----------------------------------------------------------------------------------------

/// RFC 8446 sections 4.1.3 and 4.2.1 (RFC 9147 section 5.4: {254, 253} in DTLS): a server
/// that negotiates DTLS 1.3 writes legacy_version {254, 253} in its ServerHello and its
/// HelloRetryRequest, bytes 25 and 26 of the datagram, and says the version in
/// supported_versions. Section 4.1.3: its random "MUST be generated independently of the
/// ClientHello.random": the same ClientHello to two servers gets two different randoms,
/// neither the client's.
#[test]
fn the_server_hello_has_its_own_random_and_legacy_version_fefd() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?;
    let client_hello = take(&mut pair.client);
    assert_eq!(client_hello.len(), 1, "one datagram");
    let (handshake_type, _, client_body, _) = first_message(&client_hello[0]);
    assert_eq!(handshake_type, messages::CLIENT_HELLO);
    let client_random = client_body[2..34].to_vec();
    let mut randoms = vec![];
    for cookie_exchange in [false, false, true] {
        let mut server = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(std::sync::Arc::new(
                server_builder()
                    .with_cookie_exchange(cookie_exchange)
                    .build(false, None)?,
            )),
        );
        server.read(pair.now, client_addr(), None, client_hello[0].clone())?;
        let answer = take(&mut server);
        let (handshake_type, _, body, _) = first_message(&answer[0]);
        assert_eq!(handshake_type, messages::SERVER_HELLO);
        assert_eq!(
            answer[0][25..27],
            [0xfe, 0xfd],
            "cookies: {cookie_exchange}"
        );
        assert_eq!(body[..2], [0xfe, 0xfd], "cookies: {cookie_exchange}");
        assert_eq!(
            Answer::parse(&body).get(messages::EXT_SUPPORTED_VERSIONS),
            Some(&[0xfe, 0xfc][..]),
            "cookies: {cookie_exchange}"
        );
        if !cookie_exchange {
            randoms.push(body[2..34].to_vec());
        }
    }
    assert_ne!(randoms[0], randoms[1]);
    assert!(randoms.iter().all(|random| *random != client_random));
    Ok(())
}

/// RFC 9147 section 5: "DTLS servers MUST NOT echo the "legacy_session_id" value from the
/// client" (no TLS 1.3 compatibility mode). A client that cached a session id of a DTLS 1.2
/// server sends it (section 5.3); this one's ClientHello is given a full 32-byte id. The
/// ServerHello (no cookie exchange) and the HelloRetryRequest (cookie exchange) both carry an
/// empty legacy_session_id_echo, byte 34 of the body.
#[test]
fn the_server_echoes_no_legacy_session_id() -> Result<()> {
    for cookie_exchange in [false, true] {
        let answer = server_answers(
            server_builder().with_cookie_exchange(cookie_exchange),
            |hello| hello.session_id = vec![0x5e; 32],
        )?;
        assert!(!answer.is_empty(), "cookies: {cookie_exchange}: answered");
        let (handshake_type, _, body, _) = first_message(&answer[0]);
        assert_eq!(handshake_type, messages::SERVER_HELLO);
        let hello = ServerHello::parse(&body).expect("a ServerHello");
        assert_eq!(
            hello.legacy_session_id_echo,
            &[] as &[u8],
            "cookies: {cookie_exchange}: the session id is not echoed"
        );
        assert_eq!(body[34], 0, "cookies: {cookie_exchange}");
        assert_eq!(
            hello.random == messages::HELLO_RETRY_REQUEST_RANDOM,
            cookie_exchange,
            "a HelloRetryRequest exactly when the server asks for a cookie"
        );
    }
    Ok(())
}

/// The cookie a ClientHello carries, in the legacy_cookie field (DTLS 1.2) or the cookie
/// extension (DTLS 1.3), if any.
fn cookie_of(datagram: &[u8]) -> Option<Vec<u8>> {
    let (handshake_type, _, body, _) = first_message(datagram);
    assert_eq!(handshake_type, messages::CLIENT_HELLO);
    let at = 35 + usize::from(body[34]);
    let legacy = &body[at + 1..at + 1 + usize::from(body[at])];
    if !legacy.is_empty() {
        return Some(legacy.to_vec());
    }
    Hello::parse(&body)
        .get(messages::EXT_COOKIE)
        .map(<[u8]>::to_vec)
}

/// RFC 8446 section 4.2.2: "Clients MUST NOT use cookies in their initial ClientHello in
/// subsequent connections." A client that went through the cookie exchange (a
/// HelloRetryRequest in DTLS 1.3, a HelloVerifyRequest in DTLS 1.2) connects again from the
/// same endpoint and configuration: its first ClientHello carries no cookie, and the new
/// connection runs the exchange again.
#[test]
fn a_later_connection_starts_without_the_cookie_of_an_earlier_one() -> Result<()> {
    for version in [
        crate::config::DtlsVersion::Dtls1_3,
        crate::config::DtlsVersion::Dtls1_2,
    ] {
        let client = std::sync::Arc::new(
            client_builder()
                .with_protocol_versions(version, version)
                .build(true, None)?,
        );
        let server = std::sync::Arc::new(
            server_builder()
                .with_protocol_versions(version, version)
                .build(false, None)?,
        );
        let mut pair = Pair::with(client.clone(), server)?;
        let (first, _) = pair.round();
        let (second, _) = pair.round();
        assert_eq!(cookie_of(&first[0]), None, "{version:?}");
        assert!(
            cookie_of(&second[0]).is_some(),
            "{version:?}: the cookie exchange ran"
        );
        pair.run();
        assert!(pair.client_complete && pair.server_complete, "{version:?}");

        let now = pair.now;
        let _ = pair.client.stop(now, server_addr());
        let _ = pair.server.stop(now, client_addr());
        let _ = take(&mut pair.client);
        let _ = take(&mut pair.server);
        pair.client
            .connect(now, server_addr(), client.clone(), None)?;
        let (again, _) = pair.round();
        assert_eq!(
            cookie_of(&again[0]),
            None,
            "{version:?}: no cookie in the next connection's first ClientHello"
        );
        let (answer, _) = pair.round();
        assert!(
            cookie_of(&answer[0]).is_some(),
            "{version:?}: the new connection has a cookie of its own"
        );
    }
    Ok(())
}

/// RFC 8446 section 4.2.7: "Clients MUST NOT act upon any information found in
/// "supported_groups" prior to successful completion of the handshake". EncryptedExtensions
/// with a supported_groups the client did not ask for (groups it did not offer, one it does
/// not know) is taken as one without it: the handshake goes on in the same state.
#[test]
fn supported_groups_in_encrypted_extensions_change_nothing() -> Result<()> {
    let mut plain = client_after_server_hello(client_builder())?;
    taken(plain.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[]),
        EPOCH_HANDSHAKE,
    ))?;
    let mut pair = client_after_server_hello(client_builder())?;
    taken(pair.client_conn().on_handshake_message(
        messages::ENCRYPTED_EXTENSIONS,
        &encrypted_extensions(&[(
            messages::EXT_SUPPORTED_GROUPS,
            u16_list(&[0x7777, SECP521R1]),
        )]),
        EPOCH_HANDSHAKE,
    ))?;
    assert_eq!(pair.client_conn().state, plain.client_conn().state);
    Ok(())
}

/// RFC 8446 sections 5 and 5.4: an authenticated record of a content type that is not known
/// ("an unexpected record type") and one that is nothing but padding ("does not find a
/// non-zero octet in the cleartext") end the connection with unexpected_message: sent by the
/// receiver, and read by its peer.
#[test]
fn an_unknown_or_all_padding_protected_record_is_an_unexpected_message() -> Result<()> {
    for (content_type, content) in [(99u8, b"x".to_vec()), (0, vec![])] {
        let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
        let record = pair
            .server_conn()
            .seal_for_fuzzing(content_type, &content)
            .expect("a record");
        pair.deliver_to_client(vec![BytesMut::from(&record[..])]);
        assert!(
            pair.client.is_connection_failed(&server_addr()),
            "type {content_type}"
        );
        assert_eq!(
            pair.client.connection_fatal_alerts(&server_addr()),
            Some((Some(alert::UNEXPECTED_MESSAGE), None)),
            "type {content_type}"
        );
        let alert = take(&mut pair.client);
        pair.deliver_to_server(alert);
        assert_eq!(
            pair.server.connection_fatal_alerts(&client_addr()),
            Some((None, Some(alert::UNEXPECTED_MESSAGE))),
            "type {content_type}"
        );
    }
    Ok(())
}

/// A pair whose client and server both offer connection ids, the client asking for an empty
/// one and the server for five bytes (RFC 9147 section 9).
fn pair_with_connection_ids() -> Result<Pair> {
    Ok(Pair::new(
        client_builder().with_connection_id(Some(0)),
        no_cookies().with_connection_id(Some(5)),
    )?
    .complete())
}

/// The post-handshake messages a DTLS 1.3 association refuses, each with the alert its RFC
/// names, as `on_post_handshake_message` gives it and as it goes through the record layer:
/// the receiver sends it, its peer reads it. RFC 8446 section 4.1.2 (a ClientHello after a
/// DTLS 1.3 handshake: unexpected_message), 4.6.2 (a CertificateRequest to a client that did
/// not send post_handshake_auth: unexpected_message), 4.6.3 (a KeyUpdate other than 0 or 1:
/// illegal_parameter), RFC 9147 section 9 (NewConnectionId and RequestConnectionId without
/// connection ids, or towards an empty one: unexpected_message).
#[test]
fn post_handshake_messages_out_of_place_draw_the_alert_their_rfc_names() -> Result<()> {
    let alert_of =
        |result: std::result::Result<(), messages::Refusal>| result.err().map(|r| r.alert);
    let new_connection_id = || messages::new_connection_id(&[vec![1, 2]], messages::CID_SPARE);
    // (a pair with connection ids, the message goes to the client, type, body, alert)
    let mut cases: Vec<(bool, bool, u8, Vec<u8>, u8)> = vec![
        (
            false,
            false,
            messages::CERTIFICATE_REQUEST,
            messages::certificate_request(&[1], &[0x0403]),
            alert::UNEXPECTED_MESSAGE,
        ),
        (
            false,
            false,
            messages::NEW_CONNECTION_ID,
            new_connection_id(),
            alert::UNEXPECTED_MESSAGE,
        ),
        (
            false,
            true,
            messages::REQUEST_CONNECTION_ID,
            messages::request_connection_id(1),
            alert::UNEXPECTED_MESSAGE,
        ),
        (
            false,
            false,
            messages::REQUEST_CONNECTION_ID,
            messages::request_connection_id(1),
            alert::UNEXPECTED_MESSAGE,
        ),
        // The client has an empty connection id: it is sent no RequestConnectionId, and it
        // has none to hand the server in a NewConnectionId.
        (
            true,
            true,
            messages::REQUEST_CONNECTION_ID,
            messages::request_connection_id(1),
            alert::UNEXPECTED_MESSAGE,
        ),
        (
            true,
            false,
            messages::NEW_CONNECTION_ID,
            new_connection_id(),
            alert::UNEXPECTED_MESSAGE,
        ),
    ];
    for value in [2u8, 0x80, 0xff] {
        cases.push((
            false,
            true,
            messages::KEY_UPDATE,
            vec![value],
            alert::ILLEGAL_PARAMETER,
        ));
        cases.push((
            false,
            false,
            messages::KEY_UPDATE,
            vec![value],
            alert::ILLEGAL_PARAMETER,
        ));
    }
    // Every case is run, and every mismatch reported.
    let mut mismatches = vec![];
    for (connection_ids, to_client, handshake_type, mut body, expected) in cases {
        let case = format!(
            "type {handshake_type} {body:?} to the client: {to_client}, connection ids: {connection_ids}"
        );
        let new_pair = || -> Result<Pair> {
            if connection_ids {
                pair_with_connection_ids()
            } else {
                Ok(Pair::new(client_builder(), no_cookies())?.complete())
            }
        };
        let mut pair = new_pair()?;
        let receiver = if to_client {
            pair.client_conn()
        } else {
            pair.server_conn()
        };
        let refused = alert_of(receiver.on_post_handshake_message(handshake_type, &body));
        if refused != Some(expected) {
            mismatches.push(format!("{case}: refused with {refused:?}"));
        }

        let mut pair = new_pair()?;
        let sender = if to_client {
            pair.server_conn()
        } else {
            pair.client_conn()
        };
        sender.send_post_handshake(
            FlightKind::NewConnectionId,
            handshake_type,
            std::mem::take(&mut body),
        )?;
        let now = pair.now;
        let _ = pair.client.handle_timeout(server_addr(), now);
        let _ = pair.server.handle_timeout(client_addr(), now);
        pair.run();
        let (receiver, sender) = if to_client {
            (
                pair.client.connection_fatal_alerts(&server_addr()),
                pair.server.connection_fatal_alerts(&client_addr()),
            )
        } else {
            (
                pair.server.connection_fatal_alerts(&client_addr()),
                pair.client.connection_fatal_alerts(&server_addr()),
            )
        };
        if (receiver, sender) != (Some((Some(expected), None)), Some((None, Some(expected)))) {
            mismatches.push(format!(
                "{case}: on the wire, receiver {receiver:?}, sender {sender:?}"
            ));
        }
    }

    // RFC 8446 section 4.1.2: a ClientHello after the handshake, protected, to the server
    // that negotiated DTLS 1.3. (A plaintext one is a new client's, RFC 9147 section 5.11.)
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    let hello = pair.client_conn().client_hello.clone();
    assert!(!hello.is_empty());
    let refused = alert_of(
        pair.server_conn()
            .on_post_handshake_message(messages::CLIENT_HELLO, &hello),
    );
    if refused != Some(alert::UNEXPECTED_MESSAGE) {
        mismatches.push(format!("ClientHello: refused with {refused:?}"));
    }
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    let hello = pair.client_conn().client_hello.clone();
    pair.client_conn().send_post_handshake(
        FlightKind::NewConnectionId,
        messages::CLIENT_HELLO,
        hello,
    )?;
    let now = pair.now;
    let _ = pair.client.handle_timeout(server_addr(), now);
    pair.run();
    let alerts = (
        pair.server.connection_fatal_alerts(&client_addr()),
        pair.client.connection_fatal_alerts(&server_addr()),
    );
    if alerts
        != (
            Some((Some(alert::UNEXPECTED_MESSAGE), None)),
            Some((None, Some(alert::UNEXPECTED_MESSAGE))),
        )
    {
        mismatches.push(format!("ClientHello: on the wire, {alerts:?}"));
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    Ok(())
}

/// RFC 9147 section 4: "Plaintext records MUST NOT be sent with sequence numbers that would
/// exceed 2^48-1". The client's second ClientHello (the answer to a HelloRetryRequest, the
/// first plaintext record its DTLS 1.3 association writes) is retransmitted with the counter
/// at 2^48-1, so with that sequence number; after it no plaintext record is sent again.
#[test]
fn a_plaintext_record_never_takes_a_sequence_number_past_2_48_minus_1() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?;
    pair.round();
    let second = take(&mut pair.client);
    assert_eq!(
        second.len(),
        1,
        "the ClientHello that answers the HelloRetryRequest"
    );
    assert!(first_message(&second[0]).3 < 16);
    pair.client_conn()
        .set_plaintext_send_sequence(MAX_SEQUENCE_NUMBER);
    let at = pair
        .client
        .poll_timeout(&server_addr())
        .expect("the retransmission timer");
    let _ = pair.client.handle_timeout(server_addr(), at);
    let again = take(&mut pair.client);
    assert_eq!(again.len(), 1);
    assert_eq!(first_message(&again[0]).0, messages::CLIENT_HELLO);
    assert_eq!(first_message(&again[0]).3, MAX_SEQUENCE_NUMBER);
    assert_eq!(
        pair.client_conn().plaintext_send_sequence(),
        MAX_SEQUENCE_NUMBER + 1
    );
    // The next retransmission would take 2^48: nothing goes out.
    if let Some(at) = pair.client.poll_timeout(&server_addr()) {
        let _ = pair.client.handle_timeout(server_addr(), at);
    }
    assert!(take(&mut pair.client).is_empty());
    assert_eq!(
        pair.client_conn().plaintext_send_sequence(),
        MAX_SEQUENCE_NUMBER + 1
    );
    Ok(())
}

/// RFC 9147 section 4.5.1: "The window MUST NOT be updated due to a received record until
/// that record has been deprotected successfully." A forgery far ahead of the records in
/// flight (the sequence number of a genuine record a thousand ahead, its tag altered) is
/// discarded, and the genuine records below it, then the genuine one it copied, are all
/// delivered.
#[test]
fn a_forged_record_far_ahead_does_not_move_the_window() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    let held: Vec<Vec<u8>> = (0..5u8)
        .map(|index| {
            pair.client_conn()
                .seal_for_fuzzing(CONTENT_TYPE_APPLICATION_DATA, &[index])
                .expect("a record")
        })
        .collect();
    for _ in 0..995 {
        pair.client_conn()
            .seal_for_fuzzing(CONTENT_TYPE_APPLICATION_DATA, b"burnt")
            .expect("a record");
    }
    let far = pair
        .client_conn()
        .seal_for_fuzzing(CONTENT_TYPE_APPLICATION_DATA, b"far ahead")
        .expect("a record");
    let mut forged = far.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    pair.to_server.clear();
    pair.deliver_to_server(vec![BytesMut::from(&forged[..])]);
    assert!(application_data(&pair.to_server).is_empty());
    assert!(!pair.server.is_connection_failed(&client_addr()));
    pair.deliver_to_server(
        held.iter()
            .map(|record| BytesMut::from(&record[..]))
            .collect(),
    );
    assert_eq!(
        application_data(&pair.to_server),
        (0..5u8).map(|index| vec![index]).collect::<Vec<_>>(),
        "the records below the forgery are still in the window"
    );
    pair.to_server.clear();
    pair.deliver_to_server(vec![BytesMut::from(&far[..])]);
    assert_eq!(
        application_data(&pair.to_server),
        vec![b"far ahead".to_vec()]
    );
    Ok(())
}

/// RFC 9147 section 8: a sender never moves past epoch 2^48-1, and "In order to allow this
/// value to be changed later, receiving implementations MUST NOT enforce this rule." A peer
/// at epoch 2^48-1 that sends a KeyUpdate all the same (breaking the sender's rule, which the
/// receiver must not check) has it taken: the receiver acknowledges it, keeps the
/// association, and reads the records of epoch 2^48 that follow.
#[test]
fn a_receiver_takes_a_key_update_past_the_last_epoch() -> Result<()> {
    let mut pair = Pair::new(client_builder(), no_cookies())?.complete();
    pair.client_conn().set_send_epoch_for_test(MAX_SEND_EPOCH);
    pair.server_conn().set_read_epoch_for_test(MAX_SEND_EPOCH);
    assert_eq!(pair.client_sends(b"last"), vec![b"last".to_vec()]);
    pair.client_conn()
        .send_post_handshake(FlightKind::KeyUpdate, messages::KEY_UPDATE, vec![0])?;
    let now = pair.now;
    let _ = pair.client.handle_timeout(server_addr(), now);
    pair.run();
    assert!(!pair.server.is_connection_failed(&client_addr()));
    assert_eq!(
        pair.server.connection_fatal_alerts(&client_addr()),
        Some((None, None))
    );
    assert!(pair.server_conn().has_read_epoch(MAX_SEND_EPOCH + 1));
    assert!(!pair.client_conn().key_update_outstanding(), "acknowledged");
    assert_eq!(pair.client_sends(b"past"), vec![b"past".to_vec()]);
    Ok(())
}
