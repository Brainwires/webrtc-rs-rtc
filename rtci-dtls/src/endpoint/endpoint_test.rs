//! Endpoint-level tests for how an association ends, and for what an unauthenticated peer can
//! make a handshake do. The helpers repeat the ones in `endpoint.rs`'s own test module, which
//! are private to it.

use super::*;
use crate::cipher_suite::CipherSuiteId;
use crate::config::ConfigBuilder;
use crate::crypto::Certificate;
use crypto::RTCCryptoProvider;
use std::time::Duration;

fn client_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 5444))
}

fn server_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 5445))
}

fn provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider is enabled for tests")
}

const SUITE: CipherSuiteId = CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256;

fn client_builder() -> ConfigBuilder {
    ConfigBuilder::default()
        .with_crypto_provider(provider())
        .with_cipher_suites(vec![SUITE])
        .with_insecure_skip_verify(true)
}

fn client_config() -> Result<Arc<HandshakeConfig>> {
    Ok(Arc::new(client_builder().build(true, None)?))
}

fn server_config() -> Result<Arc<HandshakeConfig>> {
    let provider = provider();
    Ok(Arc::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![SUITE])
            .with_insecure_skip_verify(true)
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .build(false, None)?,
    ))
}

/// Takes every datagram `endpoint` has queued.
fn take_transmits(endpoint: &mut Endpoint) -> Vec<BytesMut> {
    let mut datagrams = vec![];
    while let Some(transmit) = endpoint.poll_transmit() {
        datagrams.push(transmit.message);
    }
    datagrams
}

/// Hands `datagrams` to `destination` as coming from `source_addr`, collecting the events and
/// whether any read failed.
fn deliver(
    destination: &mut Endpoint,
    source_addr: SocketAddr,
    datagrams: Vec<BytesMut>,
    now: Instant,
) -> (Vec<EndpointEvent>, bool) {
    let mut events = vec![];
    let mut errored = false;
    for datagram in datagrams {
        match destination.read(now, source_addr, None, datagram) {
            Ok(more) => events.extend(more),
            Err(_) => errored = true,
        }
    }
    (events, errored)
}

/// Runs a handshake between `client` (already connected) and `server` to completion, failing the
/// test if it does not complete.
fn complete_handshake(client: &mut Endpoint, server: &mut Endpoint, now: Instant) {
    let mut client_complete = false;
    let mut server_complete = false;
    for _ in 0..32 {
        let to_server = take_transmits(client);
        let (events, _) = deliver(server, client_addr(), to_server, now);
        server_complete |= events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        let to_client = take_transmits(server);
        let (events, _) = deliver(client, server_addr(), to_client, now);
        client_complete |= events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        if client_complete && server_complete {
            return;
        }
    }
    panic!("the handshake did not complete (client: {client_complete}, server: {server_complete})");
}

/// The content type of every record in `datagram`.
fn record_content_types(datagram: &[u8]) -> Vec<u8> {
    crate::record_layer::unpack_datagram(datagram)
        .expect("a datagram splits into records")
        .into_iter()
        .map(|record| record[0])
        .collect()
}

const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;

// ---------------------------------------------------------------------------------------------
// The association fails on a fatal alert or a handshake that gives up, and only then
// (W3C webrtc 5.5.1 RTCDtlsTransport "failed", RFC 5246 7.2.2).
// ---------------------------------------------------------------------------------------------

/// A client that rejects the server's certificate (as a WebRTC fingerprint mismatch does) sends a
/// fatal alert and fails; the server, receiving it, fails too.
#[test]
fn a_rejected_certificate_fails_both_associations() -> Result<()> {
    let now = Instant::now();
    let reject: crate::config::VerifyPeerCertificateFn = Arc::new(
        |_certs: &[Vec<u8>], _chains: &[rustls::pki_types::CertificateDer<'static>]| {
            Err(Error::ErrNoMatchingCertificateFingerprint)
        },
    );
    let client_config = Arc::new(
        client_builder()
            .with_verify_peer_certificate(Some(reject))
            .build(true, None)?,
    );
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config, None)?;

    let mut client_failed = false;
    let mut server_failed = false;
    let mut client_sent_alert = false;
    for _ in 0..16 {
        let to_server = take_transmits(&mut client);
        client_sent_alert |= client_failed
            && to_server
                .iter()
                .any(|datagram| record_content_types(datagram).contains(&ALERT));
        for datagram in to_server {
            let _ = server.read(now, client_addr(), None, datagram);
            server_failed |= server.is_connection_failed(&client_addr());
        }
        let to_client = take_transmits(&mut server);
        for datagram in to_client {
            let _ = client.read(now, server_addr(), None, datagram);
            client_failed |= client.is_connection_failed(&server_addr());
        }
        if client_failed && server_failed {
            break;
        }
    }
    assert!(
        client_failed,
        "the client that rejected the certificate failed"
    );
    assert!(
        client_sent_alert,
        "the client told the server with a fatal alert"
    );
    assert!(
        server_failed,
        "the server that received the fatal alert failed"
    );
    assert_eq!(
        client.poll_timeout(&server_addr()),
        None,
        "a failed association retransmits nothing"
    );
    assert!(
        client
            .write(now, server_addr(), b"after the failure")
            .is_err(),
        "a failed association carries no data"
    );
    Ok(())
}

/// A lost flight is retransmitted, and the handshake completes without failing.
#[test]
fn an_ordinary_retransmission_does_not_fail_the_association() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    // Lose the first ClientHello; the client's timer fires and it sends it again.
    assert!(!take_transmits(&mut client).is_empty());
    let deadline = client
        .poll_timeout(&server_addr())
        .expect("a client waiting for an answer arms its retransmit timer");
    client.handle_timeout(server_addr(), deadline)?;
    assert!(
        !client.is_connection_failed(&server_addr()),
        "a retransmission is not a failure"
    );

    complete_handshake(&mut client, &mut server, deadline);
    assert!(!client.is_connection_failed(&server_addr()));
    assert!(!server.is_connection_failed(&client_addr()));
    Ok(())
}

/// A handshake nobody answers is retransmitted on a doubling timer and, where a handshake
/// deadline is configured, given up there: the association fails then, and only then.
#[test]
fn a_handshake_nobody_answers_fails_at_its_configured_deadline() -> Result<()> {
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let config = Arc::new(
        client_builder()
            .with_handshake_timeout(Some(Duration::from_secs(30)))
            .build(true, None)?,
    );
    client.connect(start, server_addr(), config, None)?;
    take_transmits(&mut client);

    // Retransmissions 1, 3, 7 and 15 seconds in; the next would be at 31.
    for expected in [1, 3, 7, 15] {
        let now = client
            .poll_timeout(&server_addr())
            .expect("the retransmit timer stays armed until the deadline");
        assert_eq!(now.duration_since(start), Duration::from_secs(expected));
        client.handle_timeout(server_addr(), now)?;
        assert!(
            !take_transmits(&mut client).is_empty(),
            "the flight is retransmitted {expected} s in"
        );
        assert!(
            !client.is_connection_failed(&server_addr()),
            "an ordinary retransmission is not a failure"
        );
    }

    let now = client
        .poll_timeout(&server_addr())
        .expect("the deadline is the next timeout");
    assert_eq!(now.duration_since(start), Duration::from_secs(30));
    assert_eq!(
        client.handle_timeout(server_addr(), now),
        Err(Error::ErrHandshakeTimeout)
    );
    assert!(client.is_connection_failed(&server_addr()));
    assert_eq!(client.poll_timeout(&server_addr()), None);
    // RFC 6347 4.2.7: nothing is retransmitted after the association has failed.
    client.handle_timeout(server_addr(), now + Duration::from_secs(120))?;
    assert!(take_transmits(&mut client).is_empty());
    Ok(())
}

/// RFC 6347 4.2.4 sets no total limit on a handshake, and by default neither does this crate:
/// what ends a handshake nobody answers is the transport under it (ICE consent, in a peer
/// connection), a fatal alert or the application. The flight goes out at most once a
/// minute, the same flight each time, for as long as the association exists.
#[test]
fn by_default_a_handshake_nobody_answers_is_never_given_up() -> Result<()> {
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client.connect(start, server_addr(), client_config()?, None)?;
    let first = take_transmits(&mut client);
    let mut at = start;
    for _ in 0..120 {
        at = client
            .poll_timeout(&server_addr())
            .expect("the retransmission timer stays armed");
        client.handle_timeout(server_addr(), at)?;
        let again = take_transmits(&mut client);
        assert_eq!(again.len(), first.len(), "the same flight, no more");
        assert!(!client.is_connection_failed(&server_addr()));
    }
    // 1 + 2 + ... + 32 seconds, then 114 minutes at 60 seconds.
    assert_eq!(at.duration_since(start), Duration::from_secs(63 + 114 * 60));
    Ok(())
}

/// RFC 6347 4.2.4.1: the timer doubles up to 60 seconds and stays there. Without a handshake
/// deadline the flight is retransmitted for as long as the association exists.
#[test]
fn the_retransmission_timer_stops_doubling_at_sixty_seconds() -> Result<()> {
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let config = Arc::new(
        client_builder()
            .with_handshake_timeout(None)
            .build(true, None)?,
    );
    client.connect(start, server_addr(), config, None)?;
    take_transmits(&mut client);

    let mut intervals = vec![];
    let mut previous = start;
    for _ in 0..10 {
        let at = client.poll_timeout(&server_addr()).expect("armed");
        client.handle_timeout(server_addr(), at)?;
        assert!(!take_transmits(&mut client).is_empty());
        intervals.push(at.duration_since(previous).as_secs());
        previous = at;
    }
    assert_eq!(intervals, vec![1, 2, 4, 8, 16, 32, 60, 60, 60, 60]);
    assert!(!client.is_connection_failed(&server_addr()));
    Ok(())
}

/// The initial value, the maximum and the deadline are configuration.
#[test]
fn the_retransmission_timer_follows_its_configuration() -> Result<()> {
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let config = Arc::new(
        client_builder()
            .with_flight_interval(Duration::from_millis(50))
            .with_maximum_flight_interval(Duration::from_millis(300))
            .with_handshake_timeout(Some(Duration::from_secs(1)))
            .build(true, None)?,
    );
    client.connect(start, server_addr(), config, None)?;
    take_transmits(&mut client);

    let mut fired = vec![];
    let result = loop {
        let at = client.poll_timeout(&server_addr()).expect("armed");
        fired.push(at.duration_since(start).as_millis());
        if let Err(err) = client.handle_timeout(server_addr(), at) {
            break err;
        }
    };
    // 50, 100, 200, then 300 at a time, until the deadline one second in.
    assert_eq!(fired, vec![50, 150, 350, 650, 950, 1000]);
    assert_eq!(result, Error::ErrHandshakeTimeout);
    Ok(())
}

/// RFC 6347 4.2.4.1: the backed-off value is kept until a flight is answered without loss. A
/// flight that needed two retransmissions leaves the timer at four seconds for the next one;
/// after a flight that needed none, it is one second again.
#[test]
fn the_backed_off_timer_is_kept_until_a_flight_gets_through_without_loss() -> Result<()> {
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(start, server_addr(), client_config()?, None)?;

    // The first ClientHello and its first retransmission are lost.
    take_transmits(&mut client);
    let mut now = client.poll_timeout(&server_addr()).expect("armed");
    client.handle_timeout(server_addr(), now)?;
    take_transmits(&mut client);
    now = client.poll_timeout(&server_addr()).expect("armed");
    assert_eq!(now.duration_since(start), Duration::from_secs(3));
    client.handle_timeout(server_addr(), now)?;

    // The second retransmission is answered: the next flight starts with the 4 s value.
    let to_server = take_transmits(&mut client);
    deliver(&mut server, client_addr(), to_server, now);
    let to_client = take_transmits(&mut server);
    deliver(&mut client, server_addr(), to_client, now);
    let second_client_hello = take_transmits(&mut client);
    assert_eq!(
        client.poll_timeout(&server_addr()),
        Some(now + Duration::from_secs(4))
    );

    // That flight is answered at once: the one after it starts at 1 s.
    deliver(&mut server, client_addr(), second_client_hello, now);
    let to_client = take_transmits(&mut server);
    deliver(&mut client, server_addr(), to_client, now);
    assert!(
        !take_transmits(&mut client).is_empty(),
        "the client's flight 5"
    );
    assert_eq!(
        client.poll_timeout(&server_addr()),
        Some(now + Duration::from_secs(1))
    );
    Ok(())
}

/// A record that is silently discarded (here an undecodable one) fails nothing.
#[test]
fn a_discarded_record_does_not_fail_the_association() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    // Thirteen bytes that do not form a record header the server can use.
    let _ = server.read(now, client_addr(), None, BytesMut::from(&[0xffu8; 13][..]));
    assert!(!server.is_connection_failed(&client_addr()));

    complete_handshake(&mut client, &mut server, now);
    assert!(!server.is_connection_failed(&client_addr()));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// RFC 6347 4.2.4: a peer that repeats a flight we already processed gets our answer again at
// once, not when our timer fires.
// ---------------------------------------------------------------------------------------------

/// Runs flights 1 to 3, then loses the server's Flight 4. Returns the client's repeat of
/// Flight 3, sent when its own timer fired.
fn lose_flight_four(client: &mut Endpoint, server: &mut Endpoint, now: Instant) -> Vec<BytesMut> {
    let flight1 = take_transmits(client);
    deliver(server, client_addr(), flight1, now);
    let flight2 = take_transmits(server);
    deliver(client, server_addr(), flight2, now);
    let flight3 = take_transmits(client);
    assert!(!flight3.is_empty(), "the client sends Flight 3");
    deliver(server, client_addr(), flight3, now);
    let flight4 = take_transmits(server);
    assert!(
        !flight4.is_empty(),
        "the server answers with Flight 4, which is lost"
    );
    assert!(
        server.poll_timeout(&client_addr()).is_some(),
        "the server waits for Flight 5 with its timer armed"
    );

    let client_timer = client
        .poll_timeout(&server_addr())
        .expect("the client waits for Flight 4 with its timer armed");
    client
        .handle_timeout(server_addr(), client_timer)
        .expect("the client retransmits Flight 3");
    let repeat = take_transmits(client);
    assert!(!repeat.is_empty(), "the client repeats Flight 3");
    repeat
}

/// The server, which already processed Flight 3, answers its repeat with Flight 4 at once,
/// before its own timer fires.
#[test]
fn a_repeated_flight_is_answered_at_once() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let repeat = lose_flight_four(&mut client, &mut server, now);

    // Delivered before the server's own timer fires.
    let (_, errored) = deliver(&mut server, client_addr(), repeat, now);
    assert!(!errored);
    let answer = take_transmits(&mut server);
    assert!(
        !answer.is_empty(),
        "the server retransmits Flight 4 as soon as the client repeats Flight 3"
    );
    assert!(
        answer.iter().all(|datagram| record_content_types(datagram)
            .iter()
            .all(|content_type| *content_type == HANDSHAKE)),
        "the answer is the handshake flight"
    );
    assert_eq!(
        server.connections[&client_addr()].current_retransmit_count,
        1,
        "the immediate retransmission comes out of the retransmission budget"
    );
    assert!(!server.is_connection_failed(&client_addr()));

    // The client completes from the retransmitted flight.
    deliver(&mut client, server_addr(), answer, now);
    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// A different message under a sequence number already processed is not a repeat: it provokes
/// no retransmission.
#[test]
fn a_changed_message_under_an_old_sequence_number_is_not_a_repeat() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let mut repeat = lose_flight_four(&mut client, &mut server, now);

    // Change one byte of the ClientHello's random: record header (13), handshake header (12),
    // client version (2), then the random.
    let datagram = repeat.first_mut().expect("the repeat has a datagram");
    datagram[13 + 12 + 2 + 5] ^= 0xff;
    deliver(&mut server, client_addr(), repeat, now);
    assert!(
        take_transmits(&mut server).is_empty(),
        "a changed message is not answered"
    );
    assert_eq!(
        server.connections[&client_addr()].current_retransmit_count,
        0
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Received alerts are never echoed; a received fatal alert ends the association
// (RFC 5246 7.2, 7.2.2).
// ---------------------------------------------------------------------------------------------

/// A plaintext (epoch 0) alert record, as anyone who can spoof the peer's address can send.
fn plaintext_alert(level: u8, description: u8, sequence_number: u64) -> BytesMut {
    use crate::content::ContentType;
    use crate::record_layer::record_layer_header::{PROTOCOL_VERSION1_2, RecordLayerHeader};

    let header = RecordLayerHeader {
        content_type: ContentType::Alert,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 0,
        sequence_number,
        content_len: 2,
    };
    let mut raw = vec![];
    header.marshal(&mut raw).expect("a record header marshals");
    raw.extend_from_slice(&[level, description]);
    BytesMut::from(&raw[..])
}

const WARNING: u8 = 1;
const FATAL: u8 = 2;
const NO_RENEGOTIATION: u8 = 100;
const HANDSHAKE_FAILURE: u8 = 40;

/// A warning alert is not answered and changes nothing: two instances of this stack used to
/// bounce one such alert between them, each echoing the other's.
#[test]
fn a_received_warning_alert_is_neither_echoed_nor_fatal() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let flight1 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight1, now);
    let flight2 = take_transmits(&mut server);
    deliver(&mut client, server_addr(), flight2, now);

    // Both ends get one, as a spoofer on either side would send.
    let events = server.read(
        now,
        client_addr(),
        None,
        plaintext_alert(WARNING, NO_RENEGOTIATION, 5),
    )?;
    assert!(events.is_empty());
    assert!(
        take_transmits(&mut server).is_empty(),
        "the server answered a warning alert"
    );
    let flight3 = take_transmits(&mut client);
    client.read(
        now,
        server_addr(),
        None,
        plaintext_alert(WARNING, NO_RENEGOTIATION, 5),
    )?;
    assert!(
        take_transmits(&mut client).is_empty(),
        "the client answered a warning alert"
    );
    assert!(!server.is_connection_failed(&client_addr()));
    assert!(!client.is_connection_failed(&server_addr()));

    // The handshake goes on, and no alert crosses in either direction while it does.
    deliver(&mut server, client_addr(), flight3, now);
    for _ in 0..8 {
        let to_client = take_transmits(&mut server);
        assert!(
            to_client
                .iter()
                .all(|datagram| !record_content_types(datagram).contains(&ALERT))
        );
        deliver(&mut client, server_addr(), to_client, now);
        let to_server = take_transmits(&mut client);
        assert!(
            to_server
                .iter()
                .all(|datagram| !record_content_types(datagram).contains(&ALERT))
        );
        deliver(&mut server, client_addr(), to_server, now);
    }
    assert!(client.connections[&server_addr()].is_handshake_completed());
    assert!(server.connections[&client_addr()].is_handshake_completed());
    Ok(())
}

/// A fatal alert ends the association at once and is not answered.
#[test]
fn a_received_fatal_alert_closes_the_association_unanswered() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    // Through the cookie exchange: only then does the server have an association to fail.
    let flight1 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight1, now);
    let hello_verify_request = take_transmits(&mut server);
    deliver(&mut client, server_addr(), hello_verify_request, now);
    let flight3 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight3, now);
    take_transmits(&mut server);

    let result = server.read(
        now,
        client_addr(),
        None,
        plaintext_alert(FATAL, HANDSHAKE_FAILURE, 5),
    );
    assert_eq!(result.err(), Some(Error::ErrAlertFatalOrClose));
    assert!(
        take_transmits(&mut server).is_empty(),
        "a fatal alert is not answered"
    );
    assert!(server.is_connection_failed(&client_addr()));
    assert_eq!(
        server.poll_timeout(&client_addr()),
        None,
        "nothing is retransmitted after a fatal alert"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// One forged epoch-0 record before the handshake must not stall it (RFC 6347 4.1.2.6, 4.1.2.7).
// ---------------------------------------------------------------------------------------------

/// An epoch-0 handshake record whose body is a well-formed fragment header (type 0xff, an
/// unknown message, so it never parses) over a four-byte payload, at message sequence 0.
fn junk_handshake_datagram(record_sequence: u64) -> BytesMut {
    use crate::content::ContentType;
    use crate::record_layer::record_layer_header::{PROTOCOL_VERSION1_2, RecordLayerHeader};

    let header = RecordLayerHeader {
        content_type: ContentType::Handshake,
        protocol_version: PROTOCOL_VERSION1_2,
        epoch: 0,
        sequence_number: record_sequence,
        content_len: 16,
    };
    let mut raw = vec![];
    header.marshal(&mut raw).expect("a record header marshals");
    raw.extend_from_slice(&[
        0xff, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x00,
    ]);
    BytesMut::from(&raw[..])
}

/// A forged record far ahead in the record sequence used to move the replay window past every
/// genuine record, and its unparseable message used to take message sequence 0 for good.
#[test]
fn a_forged_record_before_the_handshake_does_not_stall_it() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    let _ = server.read(now, client_addr(), None, junk_handshake_datagram(1 << 40));
    assert!(
        take_transmits(&mut server).is_empty(),
        "a forged record is not answered"
    );
    assert!(!server.is_connection_failed(&client_addr()));

    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// A forged first fragment of the client's first message, disagreeing with its real length, used
/// to win offset 0 and keep the real ClientHello from ever reassembling.
#[test]
fn a_forged_conflicting_fragment_before_the_handshake_does_not_stall_it() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    // ClientHello (1), length 1000, message sequence 0, offset 0, ten bytes of it.
    let mut forged = vec![
        HANDSHAKE, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 22,
    ];
    forged.extend_from_slice(&[
        0x01, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
    ]);
    forged.extend_from_slice(&[0xee; 10]);
    let _ = server.read(now, client_addr(), None, BytesMut::from(&forged[..]));
    assert!(take_transmits(&mut server).is_empty());

    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// An undecodable plaintext record (a one-byte alert) is silently discarded, not answered with a
/// fatal alert that would end the handshake.
#[test]
fn an_undecodable_plaintext_record_is_discarded_not_fatal() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let flight1 = take_transmits(&mut client);
    deliver(&mut server, client_addr(), flight1, now);
    let flight2 = take_transmits(&mut server);
    deliver(&mut client, server_addr(), flight2, now);

    let truncated_alert = BytesMut::from(
        &[
            ALERT, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x01, FATAL,
        ][..],
    );
    let _ = server.read(now, client_addr(), None, truncated_alert);
    assert!(
        take_transmits(&mut server).is_empty(),
        "an undecodable plaintext record is not answered"
    );
    assert!(!server.is_connection_failed(&client_addr()));

    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The stateless cookie exchange (RFC 6347 4.2.1): no state, no work and no amplification for a
// source address before it has echoed a cookie.
// ---------------------------------------------------------------------------------------------

use crate::conn::conn_conformance_test::{
    CLIENT_HELLO, ECDSA_GCM, HELLO_VERIFY_REQUEST, SERVER_HELLO, body_of, client_hello_body,
    handshake_message, plaintext_handshake_messages, plaintext_record, usual_client_extensions,
};

fn spoofed_addr(index: usize) -> SocketAddr {
    SocketAddr::from(([10, 0, (index >> 8) as u8, index as u8], 7000))
}

/// A ClientHello datagram written by hand: `message_sequence`, `record_sequence`, `cookie`,
/// the random filled with `random`.
fn raw_client_hello(
    message_sequence: u16,
    record_sequence: u64,
    cookie: &[u8],
    random: u8,
) -> BytesMut {
    let mut body = client_hello_body(&[], cookie, &[ECDSA_GCM], Some(&usual_client_extensions()));
    body[2..34].fill(random);
    let record = plaintext_record(
        HANDSHAKE,
        record_sequence,
        &handshake_message(CLIENT_HELLO, message_sequence, &body),
    );
    BytesMut::from(record.as_slice())
}

/// The cookie of the HelloVerifyRequest in `datagram`.
fn cookie_of(datagram: &[u8]) -> Vec<u8> {
    let body = body_of(
        &plaintext_handshake_messages(&[datagram.to_vec()]),
        HELLO_VERIFY_REQUEST,
    )
    .expect("a HelloVerifyRequest");
    body[3..3 + body[2] as usize].to_vec()
}

fn datagrams_as_vecs(datagrams: &[BytesMut]) -> Vec<Vec<u8>> {
    datagrams.iter().map(|datagram| datagram.to_vec()).collect()
}

/// A cookieless ClientHello from any number of source addresses: each is answered with one
/// HelloVerifyRequest, smaller than the ClientHello, and the server keeps nothing. A genuine
/// client still completes, before and after.
#[test]
fn a_client_hello_without_a_valid_cookie_costs_the_server_no_state() -> Result<()> {
    let now = Instant::now();
    let mut genuine = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );

    let mut prober = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    prober.connect(now, server_addr(), client_config()?, None)?;
    let client_hello = take_transmits(&mut prober);
    assert_eq!(client_hello.len(), 1);

    for index in 0..300 {
        let (events, errored) =
            deliver(&mut server, spoofed_addr(index), client_hello.clone(), now);
        assert!(!errored && events.is_empty());
        let answer = take_transmits(&mut server);
        assert_eq!(answer.len(), 1, "one HelloVerifyRequest");
        assert!(
            answer[0].len() < client_hello[0].len(),
            "the answer is smaller than what it answers"
        );
    }
    assert!(server.connections.is_empty(), "no association is kept");
    assert!(server.pending.is_empty());

    genuine.connect(now, server_addr(), client_config()?, None)?;
    complete_handshake(&mut genuine, &mut server, now);
    assert_eq!(server.connections.len(), 1);

    // Something that is not a ClientHello, from an address without an association: dropped.
    let events = server.read(now, spoofed_addr(999), None, plaintext_application_data(1))?;
    assert!(events.is_empty());
    assert!(take_transmits(&mut server).is_empty());
    assert_eq!(server.connections.len(), 1);
    Ok(())
}

/// RFC 6347 4.2.1: the cookie is made from the client's address and the ClientHello
/// parameters, and checked against both when it comes back. A cookie issued to one address,
/// or for another random, is not valid: the ClientHello is answered with a HelloVerifyRequest
/// again, as one without a cookie.
#[test]
fn a_cookie_is_bound_to_the_address_and_the_client_hello_parameters() -> Result<()> {
    let now = Instant::now();
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    server.read(now, client_addr(), None, raw_client_hello(0, 0, &[], 0x11))?;
    let cookie = cookie_of(&take_transmits(&mut server)[0]);
    assert_eq!(cookie.len(), 20);

    // The same ClientHello gets the same cookie: nothing was remembered to make it.
    server.read(now, client_addr(), None, raw_client_hello(0, 0, &[], 0x11))?;
    assert_eq!(cookie_of(&take_transmits(&mut server)[0]), cookie);

    for (what, source, random) in [
        ("another address", spoofed_addr(1), 0x11),
        ("another random", client_addr(), 0x22),
    ] {
        server.read(now, source, None, raw_client_hello(1, 1, &cookie, random))?;
        let answer = take_transmits(&mut server);
        assert_eq!(answer.len(), 1, "{what}");
        assert_ne!(
            cookie_of(&answer[0]),
            cookie,
            "{what}: answered as cookieless"
        );
        assert!(server.connections.is_empty(), "{what}");
    }

    // From the address and with the parameters it was issued for, it is accepted.
    server.read(
        now,
        client_addr(),
        None,
        raw_client_hello(1, 1, &cookie, 0x11),
    )?;
    assert_eq!(server.connections.len(), 1);
    let flight = datagrams_as_vecs(&take_transmits(&mut server));
    assert!(body_of(&plaintext_handshake_messages(&flight), SERVER_HELLO).is_some());
    Ok(())
}

/// RFC 6347 4.2.1: the HelloVerifyRequest record carries the record sequence number of the
/// ClientHello it answers, and the server's first ServerHello record that of the ClientHello
/// with the cookie; the records after it count up from there. RFC 6347 4.2.2: the answer's
/// message_seq is the ClientHello's.
#[test]
fn the_servers_answers_take_their_sequence_numbers_from_the_client_hello() -> Result<()> {
    let now = Instant::now();
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    let sequence_of = |record: &[u8]| {
        let mut bytes = [0u8; 8];
        bytes[2..].copy_from_slice(&record[5..11]);
        u64::from_be_bytes(bytes)
    };
    let message_sequence_of = |record: &[u8]| u16::from_be_bytes([record[17], record[18]]);

    server.read(
        now,
        client_addr(),
        None,
        raw_client_hello(0, 0x1234, &[], 0x11),
    )?;
    let hello_verify_request = take_transmits(&mut server);
    assert_eq!(sequence_of(&hello_verify_request[0]), 0x1234);
    assert_eq!(message_sequence_of(&hello_verify_request[0]), 0);
    // DTLS 1.0, whatever the ServerHello will carry (RFC 6347 4.2.1).
    assert_eq!(&hello_verify_request[0][25..27], &[0xfe, 0xff]);
    let cookie = cookie_of(&hello_verify_request[0]);

    // A second exchange (message_seq 1) is answered with message_seq 1.
    server.read(
        now,
        client_addr(),
        None,
        raw_client_hello(1, 0x1235, &[0xee; 20], 0x11),
    )?;
    let again = take_transmits(&mut server);
    assert_eq!(sequence_of(&again[0]), 0x1235);
    assert_eq!(message_sequence_of(&again[0]), 1);

    server.read(
        now,
        client_addr(),
        None,
        raw_client_hello(1, 0x4321, &cookie, 0x11),
    )?;
    let records: Vec<Vec<u8>> = take_transmits(&mut server)
        .iter()
        .flat_map(|datagram| crate::record_layer::unpack_datagram(datagram).unwrap())
        .collect();
    assert!(
        records.len() >= 4,
        "ServerHello, Certificate, ServerKeyExchange, ServerHelloDone"
    );
    assert_eq!(records[0][13], SERVER_HELLO);
    for (index, record) in records.iter().enumerate() {
        assert_eq!(sequence_of(record), 0x4321 + index as u64);
        assert_eq!(message_sequence_of(record), 1 + index as u16);
    }
    Ok(())
}

/// The cookie secret changes with time: a cookie is good for at least one lifetime of the
/// secret and at most two. A client whose cookie has expired gets a new HelloVerifyRequest,
/// under the message sequence number it expects, and completes with the new cookie (RFC 6347
/// 4.2.1: a client answers each HelloVerifyRequest with a new ClientHello).
#[test]
fn an_expired_cookie_is_answered_with_a_new_hello_verify_request() -> Result<()> {
    use crate::cookie::COOKIE_SECRET_LIFETIME;

    let start = Instant::now();
    for (wait, exchanges) in [
        (COOKIE_SECRET_LIFETIME + Duration::from_secs(1), 1),
        (2 * COOKIE_SECRET_LIFETIME + Duration::from_secs(1), 2),
    ] {
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let mut server = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(server_config()?),
        );
        let config = Arc::new(
            client_builder()
                .with_handshake_timeout(None)
                .build(true, None)?,
        );
        client.connect(start, server_addr(), config, None)?;
        let to_server = take_transmits(&mut client);
        deliver(&mut server, client_addr(), to_server, start);
        let to_client = take_transmits(&mut server);
        deliver(&mut client, server_addr(), to_client, start);

        // The ClientHello with the cookie arrives late.
        let late = start + wait;
        let second_client_hello = take_transmits(&mut client);
        deliver(&mut server, client_addr(), second_client_hello, late);
        let answer = datagrams_as_vecs(&take_transmits(&mut server));
        let messages = plaintext_handshake_messages(&answer);
        if exchanges == 1 {
            assert!(
                body_of(&messages, SERVER_HELLO).is_some(),
                "a cookie of the previous secret is still good"
            );
        } else {
            assert!(
                body_of(&messages, HELLO_VERIFY_REQUEST).is_some(),
                "a cookie two secrets old is not"
            );
            assert!(server.connections.is_empty());
        }

        let to_client: Vec<BytesMut> = answer
            .iter()
            .map(|datagram| BytesMut::from(datagram.as_slice()))
            .collect();
        deliver(&mut client, server_addr(), to_client, late);
        complete_handshake(&mut client, &mut server, late);
    }
    Ok(())
}

/// A ClientHello too large for one datagram is cut into fragments (RFC 6347 4.2.3). What the
/// cookie covers is in its first fragment, so the exchange stays stateless and the handshake
/// completes.
#[test]
fn a_fragmented_client_hello_completes_the_cookie_exchange() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    // A long server name makes the ClientHello larger than the smallest MTU (128): without a
    // name this client's ClientHello carries no server_name extension and fits in one.
    let config = Arc::new(
        client_builder()
            .with_server_name("a-client-hello-fragmented-by-its-server-name.example".to_owned())
            .with_mtu(128)
            .build(true, None)?,
    );
    client.connect(now, server_addr(), config, None)?;
    let first = take_transmits(&mut client);
    assert!(first.len() > 1, "the ClientHello is fragmented");
    let (_, errored) = deliver(&mut server, client_addr(), first, now);
    assert!(!errored);
    assert!(server.connections.is_empty());
    let to_client = take_transmits(&mut server);
    assert_eq!(
        to_client.len(),
        1,
        "one HelloVerifyRequest, for the first fragment"
    );
    deliver(&mut client, server_addr(), to_client, now);
    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// RFC 6347 4.2.1: a server can be configured not to perform the cookie exchange. The first
/// ClientHello then gets the server's flight at once.
#[test]
fn a_server_configured_without_the_cookie_exchange_answers_the_first_client_hello() -> Result<()> {
    let now = Instant::now();
    let provider = provider();
    let server_config = Arc::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![SUITE])
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .with_cookie_exchange(false)
            .build(false, None)?,
    );
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
    client.connect(now, server_addr(), client_config()?, None)?;
    let to_server = take_transmits(&mut client);
    deliver(&mut server, client_addr(), to_server, now);
    let flight = take_transmits(&mut server);
    let messages = plaintext_handshake_messages(&datagrams_as_vecs(&flight));
    assert!(body_of(&messages, HELLO_VERIFY_REQUEST).is_none());
    assert!(body_of(&messages, SERVER_HELLO).is_some());
    deliver(&mut client, server_addr(), flight, now);
    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// A new association on an address that has one (RFC 6347 4.2.8).
// ---------------------------------------------------------------------------------------------

/// Whether `data`, written by `from`, arrives at `to` as application data.
fn arrives(
    from: &mut Endpoint,
    to: &mut Endpoint,
    to_addr: SocketAddr,
    from_addr: SocketAddr,
    data: &[u8],
    now: Instant,
) -> bool {
    if from.write(now, to_addr, data).is_err() {
        return false;
    }
    let datagrams = take_transmits(from);
    let (events, _) = deliver(to, from_addr, datagrams, now);
    events
        .iter()
        .any(|event| matches!(event, EndpointEvent::ApplicationData(got) if got[..] == data[..]))
}

/// RFC 6347 4.2.8: a client that lost its state starts over from the same address. The server
/// keeps the existing association, and keeps using it, until the new client has completed a
/// handshake; then the new association replaces the old one.
#[test]
fn a_new_handshake_from_the_same_address_replaces_the_association_once_it_completes() -> Result<()>
{
    let now = Instant::now();
    let (mut old_client, mut server) = connected_pair()?;
    assert!(arrives(
        &mut old_client,
        &mut server,
        server_addr(),
        client_addr(),
        b"before",
        now
    ));

    // The restarted client: same address, no memory of the association.
    let mut new_client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    new_client.connect(now, server_addr(), client_config()?, None)?;

    // Its first ClientHello is answered with a HelloVerifyRequest and changes nothing.
    let to_server = take_transmits(&mut new_client);
    let (events, errored) = deliver(&mut server, client_addr(), to_server, now);
    assert!(events.is_empty() && !errored);
    assert!(server.pending.is_empty());
    let hello_verify_request = take_transmits(&mut server);
    assert_eq!(hello_verify_request.len(), 1);
    assert!(arrives(
        &mut old_client,
        &mut server,
        server_addr(),
        client_addr(),
        b"during 1",
        now
    ));

    // The ClientHello with the cookie starts the new handshake beside the old association,
    // which still carries data both ways.
    deliver(&mut new_client, server_addr(), hello_verify_request, now);
    let to_server = take_transmits(&mut new_client);
    let (events, _) = deliver(&mut server, client_addr(), to_server, now);
    assert!(events.is_empty());
    assert_eq!(server.pending.len(), 1);
    let server_flight = take_transmits(&mut server);
    assert!(arrives(
        &mut old_client,
        &mut server,
        server_addr(),
        client_addr(),
        b"during 2",
        now
    ));
    assert!(arrives(
        &mut server,
        &mut old_client,
        client_addr(),
        server_addr(),
        b"during 3",
        now
    ));

    // The new client completes: the server reports a completed handshake and the new
    // association is the one for the address.
    deliver(&mut new_client, server_addr(), server_flight, now);
    let to_server = take_transmits(&mut new_client);
    let (events, _) = deliver(&mut server, client_addr(), to_server, now);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete)),
        "the new handshake completes on the server"
    );
    assert!(server.pending.is_empty());
    let to_client = take_transmits(&mut server);
    let (events, _) = deliver(&mut new_client, server_addr(), to_client, now);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete))
    );

    assert!(arrives(
        &mut new_client,
        &mut server,
        server_addr(),
        client_addr(),
        b"after",
        now
    ));
    assert!(arrives(
        &mut server,
        &mut new_client,
        client_addr(),
        server_addr(),
        b"after",
        now
    ));
    // The previous association is abandoned: its records open nothing any more.
    assert!(!arrives(
        &mut old_client,
        &mut server,
        server_addr(),
        client_addr(),
        b"stale",
        now
    ));
    Ok(())
}

/// RFC 6347 4.2.8: the existing association survives a new handshake that does not complete.
/// The association in the making goes at its deadline (configured here: by default there is
/// none) and the established one is as it was.
#[test]
fn a_new_handshake_that_does_not_complete_leaves_the_association_in_place() -> Result<()> {
    let start = Instant::now();
    let (mut old_client, mut server) = connected_pair()?;
    server.set_server_config(Some(server_config_from(
        ConfigBuilder::default().with_handshake_timeout(Some(Duration::from_secs(30))),
    )?));

    let mut new_client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    new_client.connect(start, server_addr(), client_config()?, None)?;
    let to_server = take_transmits(&mut new_client);
    deliver(&mut server, client_addr(), to_server, start);
    let to_client = take_transmits(&mut server);
    deliver(&mut new_client, server_addr(), to_client, start);
    let to_server = take_transmits(&mut new_client);
    deliver(&mut server, client_addr(), to_server, start);
    assert_eq!(server.pending.len(), 1);
    take_transmits(&mut server);

    // The new client is never heard from again. The server retransmits its flight for the
    // association in the making until that one's deadline.
    let mut now = start;
    while let Some(at) = server.poll_timeout(&client_addr()) {
        now = at;
        server.handle_timeout(client_addr(), now)?;
        take_transmits(&mut server);
    }
    assert_eq!(now.duration_since(start), Duration::from_secs(30));
    assert!(server.pending.is_empty());
    assert!(!server.is_connection_failed(&client_addr()));
    assert!(arrives(
        &mut old_client,
        &mut server,
        server_addr(),
        client_addr(),
        b"still here",
        now
    ));
    Ok(())
}

/// A late copy of the ClientHello an association was made from is that association's own
/// ClientHello, not a client starting over: it starts nothing.
#[test]
fn a_repeat_of_the_associations_own_client_hello_starts_no_new_handshake() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let to_server = take_transmits(&mut client);
    deliver(&mut server, client_addr(), to_server, now);
    let to_client = take_transmits(&mut server);
    deliver(&mut client, server_addr(), to_client, now);
    let client_hello_with_cookie = take_transmits(&mut client);
    deliver(
        &mut server,
        client_addr(),
        client_hello_with_cookie.clone(),
        now,
    );
    complete_handshake(&mut client, &mut server, now);

    let (events, errored) = deliver(&mut server, client_addr(), client_hello_with_cookie, now);
    assert!(events.is_empty() && !errored);
    assert!(server.pending.is_empty());
    assert!(take_transmits(&mut server).is_empty());
    assert!(arrives(
        &mut client,
        &mut server,
        server_addr(),
        client_addr(),
        b"fine",
        now
    ));
    Ok(())
}

/// A failed server association is replaced when the client starts over with a ClientHello and
/// echoes the cookie; until then the peer's repeated flight draws the fatal alert again (RFC
/// 6347 4.2.7) and nothing else.
#[test]
fn a_failed_association_is_replaced_by_a_new_handshake() -> Result<()> {
    let now = Instant::now();
    let provider = provider();
    let server_config = Arc::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![SUITE])
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert)
            .build(false, None)?,
    );
    let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));

    // A client without a certificate: the server fails the association.
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client.connect(now, server_addr(), client_config()?, None)?;
    let mut last_flight = vec![];
    for _ in 0..4 {
        let to_server = take_transmits(&mut client);
        if !to_server.is_empty() {
            last_flight = to_server.clone();
        }
        deliver(&mut server, client_addr(), to_server, now);
        if server.is_connection_failed(&client_addr()) {
            break;
        }
        let to_client = take_transmits(&mut server);
        deliver(&mut client, server_addr(), to_client, now);
    }
    assert!(server.is_connection_failed(&client_addr()));
    let alert = take_transmits(&mut server);
    assert_eq!(record_content_types(&alert[0]), vec![ALERT]);

    // The same flight again: the alert again, and no error for the caller.
    let events = server.read(now, client_addr(), None, last_flight[0].clone())?;
    assert!(events.is_empty());
    let again = take_transmits(&mut server);
    assert_eq!(again.len(), 1);
    assert_eq!(record_content_types(&again[0]), vec![ALERT]);
    assert_eq!(
        again[0][13..],
        alert[0][13..],
        "the same alert, in a new record"
    );
    assert_ne!(again[0][5..11], alert[0][5..11]);

    // A client with a certificate starts over from the same address.
    let mut retry = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let config = Arc::new(
        client_builder()
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .build(true, None)?,
    );
    retry.connect(now, server_addr(), config, None)?;
    complete_handshake(&mut retry, &mut server, now);
    assert!(!server.is_connection_failed(&client_addr()));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Unauthenticated input does not end a handshake (RFC 6347 4.1.2.7, 4.2.1).
// ---------------------------------------------------------------------------------------------

/// A plaintext application-data record, which needs no keys: `17 fe fd`, epoch 0, the given
/// sequence number, one byte of data.
fn plaintext_application_data(sequence_number: u64) -> BytesMut {
    let mut datagram = vec![0x17, 0xfe, 0xfd, 0, 0];
    datagram.extend_from_slice(&sequence_number.to_be_bytes()[2..]);
    datagram.extend_from_slice(&[0, 1, 0]);
    BytesMut::from(datagram.as_slice())
}

/// RFC 6347 4.1.2.7: an application-data record in epoch 0 is invalid, and anyone who knows the
/// peer's address can send one. It is discarded without an alert, on either side, and the
/// handshake completes.
#[test]
fn plaintext_application_data_during_the_handshake_is_discarded() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let to_server = take_transmits(&mut client);
    deliver(&mut server, client_addr(), to_server, now);
    let to_client = take_transmits(&mut server);

    let events = server.read(now, client_addr(), None, plaintext_application_data(1000))?;
    assert!(events.is_empty());
    assert!(!server.is_connection_failed(&client_addr()));
    assert!(
        take_transmits(&mut server).is_empty(),
        "no alert answers it"
    );

    let events = client.read(now, server_addr(), None, plaintext_application_data(1000))?;
    assert!(events.is_empty());
    assert!(!client.is_connection_failed(&server_addr()));
    assert!(
        take_transmits(&mut client).is_empty(),
        "no alert answers it"
    );

    deliver(&mut client, server_addr(), to_client, now);
    complete_handshake(&mut client, &mut server, now);
    Ok(())
}

/// A ClientHello with message sequence 1, as the one answering HelloVerifyRequest has, carrying
/// `cookie`. Written out byte by byte: it is what an attacker sends, not what this crate builds.
fn forged_second_client_hello(cookie: &[u8]) -> BytesMut {
    let mut body = vec![0xfe, 0xfd];
    body.extend_from_slice(&[0x66; 32]);
    body.push(0);
    body.push(cookie.len() as u8);
    body.extend_from_slice(cookie);
    body.extend_from_slice(&[0, 2, 0xc0, 0x2b, 1, 0, 0, 0]);

    let length = (body.len() as u32).to_be_bytes();
    let mut message = vec![1];
    message.extend_from_slice(&length[1..]);
    message.extend_from_slice(&[0, 1, 0, 0, 0]);
    message.extend_from_slice(&length[1..]);
    message.extend_from_slice(&body);

    let mut datagram = vec![HANDSHAKE, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 1];
    datagram.extend_from_slice(&(message.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&message);
    BytesMut::from(datagram.as_slice())
}

/// RFC 6347 4.2.1: a ClientHello with an invalid cookie is not an error. One spoofed datagram
/// (a wrong cookie, or none, under the message sequence number of the genuine second
/// ClientHello) must not end the handshake, be answered with an alert, or take the place of the
/// genuine ClientHello, which is still accepted afterwards.
#[test]
fn a_client_hello_with_a_wrong_cookie_does_not_block_the_genuine_one() -> Result<()> {
    for forged_cookie in [vec![0x99; 20], vec![]] {
        let now = Instant::now();
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let mut server = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(server_config()?),
        );
        client.connect(now, server_addr(), client_config()?, None)?;
        let to_server = take_transmits(&mut client);
        deliver(&mut server, client_addr(), to_server, now);
        let hello_verify_request = take_transmits(&mut server);
        assert_eq!(hello_verify_request.len(), 1);

        let events = server.read(
            now,
            client_addr(),
            None,
            forged_second_client_hello(&forged_cookie),
        )?;
        assert!(events.is_empty());
        assert!(!server.is_connection_failed(&client_addr()));
        for datagram in take_transmits(&mut server) {
            assert!(
                !record_content_types(&datagram).contains(&ALERT),
                "a wrong cookie is not answered with an alert"
            );
        }

        deliver(&mut client, server_addr(), hello_verify_request, now);
        complete_handshake(&mut client, &mut server, now);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Records, datagrams and the retransmission timer (RFC 6347 4.1.1, 4.2.3, 4.2.4; RFC 5246 6.2).
// ---------------------------------------------------------------------------------------------

/// Every (message sequence, total length, fragment offset, fragment length) of the plaintext
/// handshake records in `datagram`.
fn handshake_fragments(datagram: &[u8]) -> Vec<(u16, usize, usize, usize)> {
    let mut fragments = vec![];
    for record in crate::record_layer::unpack_datagram(datagram).expect("records") {
        if record[0] != HANDSHAKE || record[3..5] != [0, 0] {
            continue;
        }
        let m = &record[13..];
        let u24 = |b: &[u8]| u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
        fragments.push((
            u16::from_be_bytes([m[4], m[5]]),
            u24(&m[1..4]),
            u24(&m[6..9]),
            u24(&m[9..12]),
        ));
    }
    fragments
}

/// RFC 6347 4.1.1, 4.2.3: no handshake datagram is larger than the configured MTU, and the
/// fragments of each message cover it exactly, without overlap, each in one datagram.
#[test]
fn handshake_datagrams_fit_the_configured_mtu() -> Result<()> {
    for mtu in [200usize, 257, 600] {
        let now = Instant::now();
        let provider = provider();
        let certificate =
            Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
        let builder = || {
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_cipher_suites(vec![SUITE])
                .with_insecure_skip_verify(true)
                .with_certificates(vec![certificate.clone()])
                .with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert)
                .with_mtu(mtu)
        };
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let mut server = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(Arc::new(builder().build(false, None)?)),
        );
        client.connect(
            now,
            server_addr(),
            Arc::new(builder().build(true, None)?),
            None,
        )?;

        let mut largest = 0;
        let mut fragmented_messages = 0;
        // Checks one side's datagrams: each within the MTU, each message's fragments abutting
        // and covering it.
        let mut check = |datagrams: &[BytesMut]| {
            let mut coverage: std::collections::BTreeMap<u16, (usize, Vec<(usize, usize)>)> =
                Default::default();
            for datagram in datagrams {
                assert!(
                    datagram.len() <= mtu,
                    "a {}-byte datagram with an MTU of {mtu}",
                    datagram.len()
                );
                largest = largest.max(datagram.len());
                for (sequence, length, offset, fragment_length) in handshake_fragments(datagram) {
                    let entry = coverage.entry(sequence).or_insert((length, vec![]));
                    assert_eq!(entry.0, length);
                    entry.1.push((offset, fragment_length));
                }
            }
            for (sequence, (length, mut ranges)) in coverage {
                ranges.sort_unstable();
                let mut next = 0;
                for (offset, fragment_length) in &ranges {
                    assert_eq!(*offset, next, "message {sequence}: fragments abut");
                    next = offset + fragment_length;
                }
                assert_eq!(next, length, "message {sequence}: fragments cover it");
                if ranges.len() > 1 {
                    fragmented_messages += 1;
                }
            }
        };
        let mut complete = (false, false);
        for _ in 0..32 {
            let datagrams = take_transmits(&mut client);
            check(&datagrams);
            let (events, _) = deliver(&mut server, client_addr(), datagrams, now);
            complete.1 |= events
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
            let datagrams = take_transmits(&mut server);
            check(&datagrams);
            let (events, _) = deliver(&mut client, server_addr(), datagrams, now);
            complete.0 |= events
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
            if complete.0 && complete.1 {
                break;
            }
        }
        assert!(
            complete.0 && complete.1,
            "mtu {mtu}: the handshake completes"
        );
        assert!(
            fragmented_messages > 0 || mtu > 400,
            "mtu {mtu}: a certificate is fragmented"
        );
        assert!(
            largest > mtu / 2,
            "mtu {mtu}: fragments use the room ({largest})"
        );
    }
    Ok(())
}

/// A completed client and server.
fn connected_pair() -> Result<(Endpoint, Endpoint)> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    complete_handshake(&mut client, &mut server, now);
    Ok((client, server))
}

/// RFC 5246 6.2.1, RFC 6347 4.1.1.1: a record carries at most 2^14 bytes. A larger write is
/// refused (splitting it would break the datagram boundary the application relies on), never
/// sent with a wrapped length; a write of exactly 2^14 bytes, and an empty one, arrive whole.
#[test]
fn application_writes_are_limited_to_two_to_the_fourteen_bytes() -> Result<()> {
    let now = Instant::now();
    let (mut client, mut server) = connected_pair()?;

    for too_long in [(1 << 14) + 1, 70_000] {
        assert!(
            client
                .write(now, server_addr(), &vec![0x5a; too_long])
                .is_err(),
            "a {too_long}-byte write"
        );
        assert!(take_transmits(&mut client).is_empty(), "nothing is sent");
    }

    for len in [1 << 14, 0] {
        let payload = vec![0xa5; len];
        client.write(now, server_addr(), &payload)?;
        let datagrams = take_transmits(&mut client);
        assert_eq!(datagrams.len(), 1);
        let (events, errored) = deliver(&mut server, client_addr(), datagrams, now);
        assert!(!errored);
        assert!(
            matches!(&events[..], [EndpointEvent::ApplicationData(data)] if data[..] == payload[..]),
            "a {len}-byte write arrives as one message"
        );
    }
    Ok(())
}

/// RFC 6347 4.1.2.7: an invalid record is discarded, and only that record. Junk after the valid
/// records of a datagram (here the server's whole first flight) does not cost them.
#[test]
fn junk_after_the_valid_records_of_a_datagram_is_ignored() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;

    let mut junk_appended = 0;
    let mut complete = (false, false);
    for _ in 0..32 {
        let to_server = take_transmits(&mut client);
        let (events, _) = deliver(&mut server, client_addr(), to_server, now);
        complete.1 |= events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        for mut datagram in take_transmits(&mut server) {
            // Five bytes: too short to be a record. Then a header announcing more than follows.
            datagram.extend_from_slice(if junk_appended % 2 == 0 {
                &[0x16, 0xfe, 0xfd, 0x00, 0x00][..]
            } else {
                &[0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 9, 0x01, 0x00, 0xaa][..]
            });
            junk_appended += 1;
            let events = client.read(now, server_addr(), None, datagram)?;
            complete.0 |= events
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        }
        if complete.0 && complete.1 {
            break;
        }
    }
    assert!(junk_appended >= 3);
    assert!(complete.0 && complete.1, "the handshake completes");
    Ok(())
}

/// RFC 6347 4.2.4.1: the retransmission timer starts at one second and doubles with each
/// retransmission.
#[test]
fn the_retransmission_timer_doubles_from_one_second() -> Result<()> {
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client.connect(start, server_addr(), client_config()?, None)?;
    take_transmits(&mut client);

    let mut fired = vec![];
    let mut previous = start;
    for _ in 0..4 {
        let at = client
            .poll_timeout(&server_addr())
            .expect("the retransmission timer is armed");
        client.handle_timeout(server_addr(), at)?;
        assert_eq!(
            take_transmits(&mut client).len(),
            1,
            "the flight is sent again"
        );
        fired.push(at.duration_since(previous).as_secs_f64());
        previous = at;
    }
    assert_eq!(fired, vec![1.0, 2.0, 4.0, 8.0]);
    Ok(())
}

/// RFC 6347 4.1.1.1: when a flight's retransmissions go unanswered its records may be too
/// large for the path, so they are cut smaller. The peer reassembles the message from
/// fragments of both cuts (RFC 6347 4.2.3).
#[test]
fn unanswered_retransmissions_are_sent_in_smaller_records() -> Result<()> {
    let mtu = 600;
    let start = Instant::now();
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
    let builder = || {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![SUITE])
            .with_insecure_skip_verify(true)
            .with_certificates(vec![certificate.clone()])
            .with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert)
            .with_mtu(mtu)
    };
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(Arc::new(builder().build(false, None)?)),
    );
    client.connect(
        start,
        server_addr(),
        Arc::new(builder().build(true, None)?),
        None,
    )?;

    // Up to the client's flight with its certificate, which is lost.
    for _ in 0..2 {
        let to_server = take_transmits(&mut client);
        deliver(&mut server, client_addr(), to_server, start);
        let to_client = take_transmits(&mut server);
        deliver(&mut client, server_addr(), to_client, start);
    }
    let largest = |datagrams: &[BytesMut]| datagrams.iter().map(|d| d.len()).max().unwrap_or(0);
    let first = take_transmits(&mut client);
    assert!(largest(&first) > mtu / 2 && largest(&first) <= mtu);

    // Two retransmissions at the configured size; the first datagram of the second reaches
    // the server, the rest is lost.
    let mut partial = vec![];
    for _ in 0..2 {
        let now = client.poll_timeout(&server_addr()).expect("armed");
        client.handle_timeout(server_addr(), now)?;
        let again = take_transmits(&mut client);
        assert!(largest(&again) > mtu / 2 && largest(&again) <= mtu);
        partial = again[..1].to_vec();
    }
    deliver(&mut server, client_addr(), partial, start);
    assert!(take_transmits(&mut server).is_empty());

    // From the third on the records are cut for half the size, then for the 228-byte floor.
    let now = client.poll_timeout(&server_addr()).expect("armed");
    client.handle_timeout(server_addr(), now)?;
    let halved = take_transmits(&mut client);
    assert!(largest(&halved) <= mtu / 2, "{}", largest(&halved));
    let now = client.poll_timeout(&server_addr()).expect("armed");
    client.handle_timeout(server_addr(), now)?;
    let smallest = take_transmits(&mut client);
    assert!(largest(&smallest) <= 228, "{}", largest(&smallest));

    // The server completes from the partial flight and the smallest cut.
    let (events, errored) = deliver(&mut server, client_addr(), smallest, now);
    assert!(!errored);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete))
    );
    let to_client = take_transmits(&mut server);
    let (events, _) = deliver(&mut client, server_addr(), to_client, now);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete))
    );
    Ok(())
}

/// RFC 6347 4.2.1: the ClientHello that answers HelloVerifyRequest repeats the first one's
/// version, random, session id, cipher suites, compression methods (and extensions), with the
/// cookie added.
#[test]
fn the_second_client_hello_repeats_the_first_but_for_the_cookie() -> Result<()> {
    let now = Instant::now();
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(server_config()?),
    );
    client.connect(now, server_addr(), client_config()?, None)?;
    let first = take_transmits(&mut client);
    deliver(&mut server, client_addr(), first.clone(), now);
    let hello_verify_request = take_transmits(&mut server);
    deliver(&mut client, server_addr(), hello_verify_request, now);
    let second = take_transmits(&mut client);

    // Record header (13), handshake header (12), then the body: version (2), random (32),
    // session id, cookie, and the rest.
    let split = |datagram: &BytesMut| {
        let body = datagram[25..].to_vec();
        let session_id_end = 34 + 1 + body[34] as usize;
        let cookie_end = session_id_end + 1 + body[session_id_end] as usize;
        (
            body[..session_id_end].to_vec(),
            body[session_id_end + 1..cookie_end].to_vec(),
            body[cookie_end..].to_vec(),
        )
    };
    let (first_head, first_cookie, first_rest) = split(&first[0]);
    let (second_head, second_cookie, second_rest) = split(&second[0]);
    assert!(first_cookie.is_empty());
    assert!(!second_cookie.is_empty());
    assert_eq!(first_head, second_head, "version, random and session id");
    assert_eq!(
        first_rest, second_rest,
        "cipher suites, compression methods and extensions"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// DTLS 1.2 rules that follow the RFC by default and keep the other behaviour as a setting:
// HelloVerifyRequest.server_version (RFC 6347 4.2.1), server_name without IP addresses
// (RFC 6066 3), EdDSA certificates under ECDHE_ECDSA (RFC 8422 5.1.1), and the final flight
// sent again on early application data (RFC 6347 4.2.4).
// ---------------------------------------------------------------------------------------------

fn server_config_from(builder: ConfigBuilder) -> Result<Arc<HandshakeConfig>> {
    let provider = provider();
    Ok(Arc::new(
        builder
            .with_crypto_provider(provider.clone())
            .with_cipher_suites(vec![SUITE])
            .with_insecure_skip_verify(true)
            .with_certificates(vec![Certificate::generate_self_signed(
                vec!["localhost".to_owned()],
                provider.crypto(),
            )?])
            .build(false, None)?,
    ))
}

/// The server_version field of the HelloVerifyRequest in `datagram`: the two bytes after the
/// record header and the handshake header.
fn hello_verify_request_version(datagram: &[u8]) -> [u8; 2] {
    assert_eq!(datagram[0], HANDSHAKE);
    assert_eq!(datagram[13], 3, "the message is a HelloVerifyRequest");
    [datagram[25], datagram[26]]
}

#[test]
fn hello_verify_request_says_dtls_1_0_unless_configured_to_say_1_2() -> Result<()> {
    use crate::record_layer::record_layer_header::{PROTOCOL_VERSION1_0, PROTOCOL_VERSION1_2};

    let now = Instant::now();
    for (builder, expected) in [
        (ConfigBuilder::default(), [254, 255]),
        (
            ConfigBuilder::default().with_hello_verify_request_version(PROTOCOL_VERSION1_0),
            [254, 255],
        ),
        (
            ConfigBuilder::default().with_hello_verify_request_version(PROTOCOL_VERSION1_2),
            [254, 253],
        ),
    ] {
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let mut server = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(server_config_from(builder)?),
        );
        client.connect(now, server_addr(), client_config()?, None)?;
        let (_, errored) = deliver(&mut server, client_addr(), take_transmits(&mut client), now);
        assert!(!errored);
        let answer = take_transmits(&mut server);
        assert_eq!(
            answer.len(),
            1,
            "one HelloVerifyRequest answers the ClientHello"
        );
        assert_eq!(hello_verify_request_version(&answer[0]), expected);
        // The record that carries it says DTLS 1.2 either way.
        assert_eq!(&answer[0][1..3], &[254, 253]);

        // A client takes either and completes.
        let (_, errored) = deliver(&mut client, server_addr(), answer, now);
        assert!(!errored);
        complete_handshake(&mut client, &mut server, now);
    }
    Ok(())
}

#[test]
fn a_hello_verify_request_version_other_than_dtls_1_0_or_1_2_is_refused_by_the_builder() {
    use crate::record_layer::record_layer_header::ProtocolVersion;

    let result = server_config_from(
        ConfigBuilder::default()
            .with_hello_verify_request_version(ProtocolVersion { major: 3, minor: 3 }),
    );
    assert!(matches!(result, Err(Error::ErrUnsupportedProtocolVersion)));
}

/// The host_name of the server_name extension of the ClientHello in `datagram`, if it has one.
fn client_hello_server_name(datagram: &[u8]) -> Option<String> {
    use crate::extension::Extension;
    use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;

    assert_eq!(datagram[13], 1, "the message is a ClientHello");
    let mut body = &datagram[25..];
    let hello = HandshakeMessageClientHello::unmarshal(&mut body).expect("a ClientHello parses");
    hello
        .extensions
        .iter()
        .find_map(|extension| match extension {
            Extension::ServerName(name) => Some(name.server_name.clone()),
            other if other.extension_type() == 0 => panic!("server_name did not parse: {other:?}"),
            _ => None,
        })
}

/// A client that verifies nothing by name, with no server name and no remote address, has no
/// name to send: its ClientHello has no server_name extension (RFC 6066 section 3: the
/// extension is a MAY, its HostName the server's DNS name "as understood by the client");
/// none is made up (0.2.0 sent "localhost"). Given a name, it sends it.
#[test]
fn a_client_with_no_name_and_no_address_sends_no_server_name() -> Result<()> {
    let now = Instant::now();
    let config = Arc::new(client_builder().build(true, None)?);
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client.connect(now, server_addr(), config, None)?;
    let hello = take_transmits(&mut client).remove(0);
    assert_eq!(client_hello_server_name(&hello), None);

    let named = client_builder().with_server_name("example.org".to_owned());
    let config = Arc::new(named.build(true, None)?);
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    client.connect(now, server_addr(), config, None)?;
    let hello = take_transmits(&mut client).remove(0);
    assert_eq!(
        client_hello_server_name(&hello).as_deref(),
        Some("example.org")
    );
    Ok(())
}

/// A client that would verify the server's certificate by name, with no server name and no
/// remote address, has nothing to verify against: the builder refuses it (0.2.0 verified
/// against a made-up "localhost"). With a name, or with an address, it builds.
#[test]
fn a_nameless_client_that_verifies_by_name_is_refused() -> Result<()> {
    let verifying = || {
        ConfigBuilder::default()
            .with_crypto_provider(provider())
            .with_cipher_suites(vec![SUITE])
    };
    assert!(
        matches!(
            verifying().build(true, None),
            Err(Error::Other(message)) if message.contains("server name")
        ),
        "no name to verify the certificate against"
    );
    verifying()
        .with_server_name("example.org".to_owned())
        .build(true, None)?;
    verifying().build(true, Some(server_addr()))?;
    Ok(())
}

#[test]
fn the_server_name_extension_never_carries_an_ip_address() -> Result<()> {
    let now = Instant::now();
    let first_client_hello = |builder: ConfigBuilder, remote: Option<SocketAddr>| -> Result<_> {
        let config = Arc::new(builder.build(true, remote)?);
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        client.connect(now, server_addr(), config, None)?;
        Ok(take_transmits(&mut client).remove(0))
    };

    // The name defaults to the remote address, which RFC 6066 section 3 keeps out of the
    // extension; so is an address given as the name, in either family.
    let hello = first_client_hello(client_builder(), Some(server_addr()))?;
    assert_eq!(client_hello_server_name(&hello), None);
    for literal in ["192.0.2.7", "2001:db8::7", "[2001:db8::7]"] {
        let hello =
            first_client_hello(client_builder().with_server_name(literal.to_owned()), None)?;
        assert_eq!(client_hello_server_name(&hello), None, "{literal}");
    }

    // A DNS name is sent, without a trailing dot.
    let hello = first_client_hello(
        client_builder().with_server_name("example.org".to_owned()),
        None,
    )?;
    assert_eq!(
        client_hello_server_name(&hello).as_deref(),
        Some("example.org")
    );
    let hello = first_client_hello(
        client_builder().with_server_name("example.org.".to_owned()),
        None,
    )?;
    assert_eq!(
        client_hello_server_name(&hello).as_deref(),
        Some("example.org")
    );
    Ok(())
}

#[test]
fn an_ed25519_certificate_serves_an_ecdhe_ecdsa_suite() -> Result<()> {
    let now = Instant::now();
    let provider = provider();
    let certificate = Certificate::generate_self_signed_with_alg(
        vec!["localhost".to_owned()],
        &rcgen::PKCS_ED25519,
        provider.crypto(),
    )?;
    let expected = certificate.certificate[0].as_ref().to_vec();
    let server_config = Arc::new(
        ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_cipher_suites(vec![SUITE])
            .with_certificates(vec![certificate])
            .build(false, None)?,
    );
    let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
    let mut server = Endpoint::new(server_addr(), TransportProtocol::UDP, Some(server_config));
    client.connect(now, server_addr(), client_config()?, None)?;
    complete_handshake(&mut client, &mut server, now);

    let state = client
        .get_connection_state(server_addr())
        .expect("the client holds the association");
    assert_eq!(state.peer_certificates, vec![expected]);
    assert_eq!(state.cipher_suite().map(|suite| suite.id()), Some(SUITE));
    Ok(())
}

/// Drives a handshake until the server has completed and returns its unsent final flight
/// (ChangeCipherSpec and Finished), which the caller loses.
fn handshake_until_the_server_completes(
    client: &mut Endpoint,
    server: &mut Endpoint,
    now: Instant,
) -> Vec<BytesMut> {
    for _ in 0..32 {
        let (events, _) = deliver(server, client_addr(), take_transmits(client), now);
        if events
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete))
        {
            return take_transmits(server);
        }
        deliver(client, server_addr(), take_transmits(server), now);
    }
    panic!("the server did not complete");
}

#[test]
fn application_data_ahead_of_the_servers_finished_makes_the_client_repeat_its_final_flight()
-> Result<()> {
    let now = Instant::now();
    for enabled in [true, false] {
        let mut client = Endpoint::new(client_addr(), TransportProtocol::UDP, None);
        let mut server = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(server_config()?),
        );
        let config = Arc::new(
            client_builder()
                .with_early_data_retransmit(enabled)
                .build(true, None)?,
        );
        client.connect(now, server_addr(), config, None)?;
        let lost = handshake_until_the_server_completes(&mut client, &mut server, now);
        assert!(!lost.is_empty());
        assert!(take_transmits(&mut client).is_empty());

        // A record that only claims the next epoch is anyone's: nothing is sent for it.
        let mut forged = vec![23, 254, 253, 0, 1, 0, 0, 0, 0, 0, 9, 0, 32];
        forged.extend_from_slice(&[0x5a; 32]);
        let (_, errored) = deliver(&mut client, server_addr(), vec![forged[..].into()], now);
        assert!(!errored);
        assert!(
            take_transmits(&mut client).is_empty(),
            "a forged record was answered"
        );

        // The server's application data authenticates: its Finished was lost.
        server.write(now, client_addr(), b"early")?;
        let data = take_transmits(&mut server);
        let (events, errored) = deliver(&mut client, server_addr(), data, now);
        assert!(
            !errored && events.is_empty(),
            "nothing is delivered before the Finished"
        );
        let repeated = take_transmits(&mut client);
        if !enabled {
            assert!(repeated.is_empty(), "the setting is off");
            continue;
        }
        let types: Vec<u8> = repeated
            .iter()
            .flat_map(|datagram| record_content_types(datagram))
            .collect();
        assert!(
            types.contains(&20) && types.iter().filter(|t| **t == HANDSHAKE).count() >= 2,
            "the client's final flight goes out again at once: {types:?}"
        );

        // Once per flight: more early data does not send it a third time.
        server.write(now, client_addr(), b"more")?;
        deliver(&mut client, server_addr(), take_transmits(&mut server), now);
        assert!(take_transmits(&mut client).is_empty());

        // The server answers the repeated flight with its own, and the client completes and
        // delivers what it held.
        let (_, errored) = deliver(&mut server, client_addr(), repeated, now);
        assert!(!errored);
        let (events, _) = deliver(&mut client, server_addr(), take_transmits(&mut server), now);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete))
        );
        assert!(events.iter().any(
            |event| matches!(event, EndpointEvent::ApplicationData(data) if data.as_ref() == b"early")
        ));
    }
    Ok(())
}
