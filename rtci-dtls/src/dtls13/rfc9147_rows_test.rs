//! RFC 9147 SHOULD clauses about the record layer and the handshake's retransmission: what
//! the layer above learns of the record expansion (4.4), smaller records after unanswered
//! retransmissions (4.4), the timer value kept across a retransmitted flight (5.8.2), at most
//! ten records per transmission (5.8.3), an alert repeated for a repeated offending record
//! (5.10), and a HelloRetryRequest cookie that does not carry the ClientHello (11).

use super::handshake_test::*;
use super::messages;
use crate::config::ConfigBuilder;
use crate::crypto::Certificate;
use bytes::BytesMut;

use shared::error::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn record_count(datagrams: &[BytesMut]) -> usize {
    datagrams
        .iter()
        .map(|datagram| record_first_bytes(datagram).len())
        .sum()
}

/// Fires the next timer of the client (`client`) or the server.
fn fire(pair: &mut Pair, client: bool) -> Instant {
    let (endpoint, remote) = if client {
        (&mut pair.client, server_addr())
    } else {
        (&mut pair.server, client_addr())
    };
    let at = endpoint.poll_timeout(&remote).expect("a timer is armed");
    pair.now = pair.now.max(at);
    if let Err(err) = endpoint.handle_timeout(remote, at) {
        panic!("the timer at {:?} failed: {err}", at - pair.now);
    }
    at
}

/// A server whose Certificate message is large: its certificate followed by `extra` copies of
/// itself (extraneous certificates, which RFC 8446 section 4.4.2 has a peer accept).
fn server_with_a_long_chain(extra: usize) -> ConfigBuilder {
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())
            .expect("a self-signed certificate");
    let mut chain = certificate.certificate.clone();
    for _ in 0..extra {
        chain.push(certificate.certificate[0].clone());
    }
    let certificate = Certificate {
        certificate: chain,
        private_key: certificate.private_key,
    };
    ConfigBuilder::default()
        .with_crypto_provider(provider)
        .with_insecure_skip_verify(true)
        .with_cookie_exchange(false)
        .with_certificates(vec![certificate])
}

/// RFC 9147 section 4.4: "The DTLS record layer SHOULD also allow the upper layer protocol to
/// discover the amount of record expansion expected by the DTLS processing". What the
/// endpoint reports is exactly what a protected record adds to its content, for every length.
#[test]
fn the_record_expansion_the_endpoint_reports_is_what_a_record_adds() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?.complete();
    let overhead = pair
        .client
        .record_overhead(server_addr())
        .expect("the association has keys");
    for len in [0usize, 1, 100, 1000] {
        pair.client
            .write(pair.now, server_addr(), &vec![0x5a; len])
            .expect("the client writes");
        let datagrams = take(&mut pair.client);
        assert_eq!(datagrams.len(), 1, "{len} bytes in one record");
        assert_eq!(datagrams[0].len() - len, overhead, "{len} bytes");
    }
    Ok(())
}

/// RFC 9147 section 4.4: "If repeated retransmissions do not result in a response, and the
/// PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size". The
/// server's flight, never answered, goes out in datagrams of up to the configured MTU at
/// first and its first two retransmissions, and in datagrams of half of it from the third on.
#[test]
fn unanswered_retransmissions_make_the_records_smaller() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_with_a_long_chain(3))?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    // The largest record (datagrams may hold several records).
    let largest = |datagrams: &[BytesMut]| {
        let mut largest = 0;
        for datagram in datagrams {
            let mut rest = &datagram[..];
            while !rest.is_empty() {
                let (_, taken) = super::record::next_record(rest, 0).expect("whole records");
                largest = largest.max(taken);
                rest = &rest[taken..];
            }
        }
        largest
    };
    let first = take(&mut pair.server);
    assert!(
        largest(&first) > 600,
        "the Certificate fills records of the 1200-byte MTU: {}",
        largest(&first)
    );
    for retransmission in 1..=2 {
        fire(&mut pair, false);
        let again = take(&mut pair.server);
        assert!(
            largest(&again) > 600,
            "retransmission {retransmission} is cut as the first was"
        );
    }
    fire(&mut pair, false);
    let smaller = take(&mut pair.server);
    assert!(!smaller.is_empty());
    assert!(
        largest(&smaller) <= 600,
        "the third retransmission is cut to half the MTU: {}",
        largest(&smaller)
    );
    // The smaller records complete the handshake.
    pair.deliver_to_client(smaller);
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"through"), vec![b"through".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.8.2: "Implementations SHOULD retain the current timer value until a
/// message is transmitted and acknowledged without having to be retransmitted". The client's
/// ClientHello is lost once, so its timer doubles to two seconds; the retransmission is
/// answered at once, but the timer of the client's next flight keeps the two seconds (it was
/// the initial second: the backed-off value was lost when the association went on as DTLS
/// 1.3). Without the loss the next flight has the initial value.
#[test]
fn the_backed_off_timer_is_kept_until_a_flight_goes_through_the_first_time() -> Result<()> {
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let _lost = take(&mut pair.client);
    let first = fire(&mut pair, true);
    let again = take(&mut pair.client);
    assert_eq!(again.len(), 1, "the ClientHello again");
    pair.deliver_to_server(again);
    let flight = take(&mut pair.server);
    pair.deliver_to_client(flight);
    assert!(pair.client_complete);
    let finished_timer = pair
        .client
        .poll_timeout(&server_addr())
        .expect("the client's last flight waits for its ACK");
    assert_eq!(
        finished_timer - first,
        Duration::from_secs(2),
        "the doubled value, not one reset by the answer to a retransmitted flight"
    );

    // Without the loss the timer of the client's next flight is the initial value.
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )?;
    let start = pair.now;
    pair.round();
    assert!(pair.client_complete);
    let finished_timer = pair
        .client
        .poll_timeout(&server_addr())
        .expect("the client's last flight waits for its ACK");
    assert_eq!(finished_timer - start, Duration::from_secs(1));
    Ok(())
}

/// RFC 9147 section 5.8.3: "DTLS stacks SHOULD NOT send more than 10 records in a single
/// transmission." A flight of more pieces than that, at a small MTU, goes out ten records at
/// a time; the next transmission goes on with the pieces not sent yet, and the handshake
/// completes.
#[test]
fn a_transmission_carries_at_most_ten_records() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_with_a_long_chain(3).with_mtu(200))?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let first = take(&mut pair.server);
    assert_eq!(record_count(&first), 10, "ten records, of a flight of more");
    // The client acknowledges what it has after a quarter of its timer; what the server
    // sends then is again at most ten records, and none of the first ten.
    pair.deliver_to_client(first);
    assert!(!pair.client_complete);
    let mut transmissions = 1;
    for _ in 0..16 {
        if pair.client_complete {
            break;
        }
        fire(&mut pair, true);
        let ack = take(&mut pair.client);
        pair.deliver_to_server(ack);
        let next = take(&mut pair.server);
        if next.is_empty() {
            continue;
        }
        transmissions += 1;
        assert!(record_count(&next) <= 10, "{} records", record_count(&next));
        pair.deliver_to_client(next);
    }
    assert!(
        transmissions > 1,
        "the flight took more than one transmission"
    );
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"done"), vec![b"done".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.10: "a DTLS implementation which would ordinarily issue an alert SHOULD
/// generate a new alert message if the offending record is received again". A server flight
/// with a CertificateVerify that does not verify ends the client's association with an alert;
/// the same flight again (the server did not get the alert and retransmits) draws another.
#[test]
fn a_repeated_offending_flight_draws_the_alert_again() -> Result<()> {
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
    let mut pair = Pair::new(
        client_builder(),
        ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_cookie_exchange(false)
            .with_certificates(vec![Certificate::from_signing_key(
                certificate.certificate.clone(),
                Arc::new(super::reliability_test::WrongSigner(
                    certificate.private_key.signing_key.clone(),
                )),
            )]),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let flight = take(&mut pair.server);
    pair.deliver_to_client(flight.clone());
    assert!(pair.client.is_connection_failed(&server_addr()));
    let alert = take(&mut pair.client);
    assert_eq!(alert.len(), 1, "the alert");
    pair.deliver_to_client(flight.clone());
    let again = take(&mut pair.client);
    assert_eq!(again.len(), 1, "a new alert for the repeated flight");
    assert_ne!(
        again[0], alert[0],
        "a new record, not the old one sent again"
    );

    // RFC 8446 section 6.2: "The implementation SHOULD provide a way to facilitate logging
    // the sending and receiving of alerts": the application reads them from each side.
    assert_eq!(
        pair.client.connection_fatal_alerts(&server_addr()),
        Some((Some(messages::alert::DECRYPT_ERROR), None)),
        "the alert the client sent"
    );
    pair.deliver_to_server(alert);
    assert_eq!(
        pair.server.connection_fatal_alerts(&client_addr()),
        Some((None, Some(messages::alert::DECRYPT_ERROR))),
        "the alert the server received"
    );
    Ok(())
}

/// RFC 9147 section 11: the HelloRetryRequest cookie "SHOULD be constructed so that knowledge
/// of the cookie is insufficient to reproduce the ClientHello contents". The cookie holds the
/// hash of the first ClientHello and what the HelloRetryRequest said: it has the same length
/// for a ClientHello with a long server name as for one without, and contains neither the
/// client's random nor the name.
#[test]
fn the_cookie_does_not_carry_the_client_hello() -> Result<()> {
    let cookie_for = |client: ConfigBuilder| -> Result<(Vec<u8>, Vec<u8>)> {
        let mut pair = Pair::new(client, server_builder())?;
        let first = take(&mut pair.client);
        let random = client_hello(&first[0]).random.to_vec();
        pair.deliver_to_server(first);
        let hello_retry_request = take(&mut pair.server);
        pair.deliver_to_client(hello_retry_request);
        let second = take(&mut pair.client);
        let cookie = client_hello(&second[0])
            .extension(messages::EXT_COOKIE)
            .expect("the second ClientHello carries the cookie")
            .to_vec();
        Ok((random, cookie))
    };
    let name = "a-rather-long-server-name-that-a-cookie-holding-the-hello-would-hold.example";
    let (random, plain) = cookie_for(client_builder())?;
    let (named_random, named) = cookie_for(client_builder().with_server_name(name.to_owned()))?;
    assert_eq!(
        plain.len(),
        named.len(),
        "the cookie does not grow with the ClientHello"
    );
    for (random, cookie) in [(&random, &plain), (&named_random, &named)] {
        assert!(
            !cookie.windows(random.len()).any(|w| w == random.as_slice()),
            "the cookie holds the client's random"
        );
    }
    assert!(!named.windows(name.len()).any(|w| w == name.as_bytes()));
    Ok(())
}

/// The ClientHello in `datagram` (one plaintext record holding the whole message).
fn client_hello(datagram: &[u8]) -> messages::ClientHello<'_> {
    assert_eq!(datagram[13], 1, "a ClientHello");
    let length = usize::from(datagram[14]) << 16
        | usize::from(datagram[15]) << 8
        | usize::from(datagram[16]);
    messages::ClientHello::parse(&datagram[25..25 + length]).expect("the ClientHello parses")
}

/// RFC 6347 section 4.2.7 for DTLS 1.2, as RFC 9147 section 5.10 for 1.3: a peer that keeps
/// sending records that fail authentication is given up on where the configuration sets a
/// limit (off by default: such records are unauthenticated, see
/// `ConfigBuilder::with_invalid_record_limit`), without an alert.
#[test]
fn a_dtls_1_2_peer_that_keeps_sending_bad_records_is_given_up_on_where_configured() -> Result<()> {
    use crate::config::DtlsVersion;
    let dtls12 = |builder: ConfigBuilder| {
        builder.with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
    };
    let mut pair = Pair::new(
        dtls12(client_builder()),
        dtls12(server_builder())
            .with_cookie_exchange(false)
            .with_invalid_record_limit(Some(3)),
    )?
    .complete();
    assert_eq!(pair.versions().0, Some(DtlsVersion::Dtls1_2));
    pair.client
        .write(pair.now, server_addr(), b"genuine")
        .expect("the client writes");
    let genuine = take(&mut pair.client);
    for attempt in 1..=4u8 {
        let mut forged = genuine[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= attempt;
        let _ = pair
            .server
            .read(pair.now, client_addr(), None, BytesMut::from(&forged[..]));
        assert_eq!(
            pair.server.is_connection_failed(&client_addr()),
            attempt == 4,
            "after {attempt} invalid records"
        );
        assert!(take(&mut pair.server).is_empty(), "no alert for them");
    }
    // The client, which has no limit, takes any number.
    for attempt in 0..100u8 {
        let mut forged = genuine[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= attempt | 1;
        let _ = pair
            .client
            .read(pair.now, server_addr(), None, BytesMut::from(&forged[..]));
    }
    assert!(!pair.client.is_connection_failed(&server_addr()));
    Ok(())
}

/// RFC 8446 section 4.4.2: "all implementations SHOULD be prepared to handle potentially
/// extraneous certificates and arbitrary orderings". A DTLS 1.3 server whose Certificate
/// message has, after its end-entity certificate, a certificate that has nothing to do with
/// the chain and a copy of its own, is verified against the client's root all the same; the
/// same chain against another root is refused.
#[test]
fn extraneous_certificates_in_the_chain_are_tolerated() -> Result<()> {
    let provider = provider();
    let generate = |name: &str| {
        Certificate::generate_self_signed(vec![name.to_owned()], provider.crypto())
            .expect("a self-signed certificate")
    };
    let server = generate("localhost");
    let unrelated = generate("unrelated.example");
    let chain = vec![
        server.certificate[0].clone(),
        unrelated.certificate[0].clone(),
        server.certificate[0].clone(),
    ];
    let root_of = |certificate: &Certificate| {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate.certificate[0].clone())
            .expect("a root");
        roots
    };
    let server_config = || {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_cookie_exchange(false)
            .with_certificates(vec![Certificate {
                certificate: chain.clone(),
                private_key: server.private_key.clone(),
            }])
    };
    let client = |roots| {
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_post_quantum_key_share(false)
            .with_server_name("localhost".to_owned())
            .with_roots_cas(roots)
    };
    let mut pair = Pair::new(client(root_of(&server)), server_config())?;
    pair.run();
    assert!(
        pair.client_complete && pair.server_complete,
        "{:?}",
        pair.client_error
    );

    let mut pair = Pair::new(client(root_of(&unrelated)), server_config())?;
    pair.run();
    assert!(
        !pair.client_complete,
        "verified against a root it does not chain to"
    );
    Ok(())
}

// ----------------------------------------------------------------------------------------
// MUST rows of audit batch 8 (must8a): datagrams of one association, fragments that tile.
// ----------------------------------------------------------------------------------------

/// Every handshake fragment in the plaintext records of `datagrams`, in the order sent:
/// (message_seq, the message's length, fragment_offset, fragment_length).
fn plaintext_fragments(datagrams: &[BytesMut]) -> Vec<(u16, usize, usize, usize)> {
    use super::record::{CONTENT_TYPE_HANDSHAKE, DatagramRecord, next_record};
    let u24 = |b: &[u8]| usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]);
    let mut fragments = vec![];
    for datagram in datagrams {
        let mut rest = &datagram[..];
        while !rest.is_empty() {
            let (record, taken) = next_record(rest, 0).expect("a datagram of whole records");
            if let DatagramRecord::Plaintext {
                content_type: CONTENT_TYPE_HANDSHAKE,
                fragment,
                ..
            } = record
            {
                let fragment_length = u24(&fragment[9..12]);
                assert_eq!(
                    fragment.len(),
                    12 + fragment_length,
                    "one fragment a record"
                );
                fragments.push((
                    u16::from_be_bytes([fragment[4], fragment[5]]),
                    u24(&fragment[1..4]),
                    u24(&fragment[6..9]),
                    fragment_length,
                ));
            }
            rest = &rest[taken..];
        }
    }
    fragments
}

/// RFC 9147 section 5.5: "the sender divides the message into a series of N contiguous data
/// ranges. The ranges MUST NOT overlap." A client at the smallest MTU (128 bytes) cuts each
/// of its ClientHellos (the first, and the second with the server's cookie) into several
/// fragments; in each transmission the fragments of a message, in the order sent, start at
/// 0, each where the one before it ended, and end at the message's length. The handshake
/// completes.
#[test]
fn the_fragments_of_a_handshake_message_tile_it_without_overlap() -> Result<()> {
    let mut pair = Pair::new(client_builder().with_mtu(128), server_builder())?;
    let mut fragmented = 0;
    for _ in 0..32 {
        let (up, down) = pair.round();
        for transmission in [&up, &down] {
            let fragments = plaintext_fragments(transmission);
            let mut messages: Vec<u16> = fragments.iter().map(|f| f.0).collect();
            messages.dedup();
            for seq in messages {
                let pieces: Vec<_> = fragments.iter().filter(|f| f.0 == seq).collect();
                let length = pieces[0].1;
                let mut end = 0;
                for &&(_, message_length, offset, fragment_length) in &pieces {
                    assert_eq!(message_length, length, "message {seq}: {pieces:?}");
                    assert_eq!(
                        offset, end,
                        "message {seq}: a fragment at {offset} after one that ended at {end}: \
                         {pieces:?}"
                    );
                    end = offset + fragment_length;
                }
                assert_eq!(
                    end, length,
                    "message {seq}: the fragments cover it: {pieces:?}"
                );
                if pieces.len() > 1 {
                    fragmented += 1;
                }
            }
        }
        if up.is_empty() && down.is_empty() {
            break;
        }
    }
    assert!(
        pair.client_complete && pair.server_complete,
        "the handshake completes (client: {:?}, server: {:?})",
        pair.client_error,
        pair.server_error
    );
    assert!(
        fragmented >= 2,
        "both ClientHellos are cut into several fragments at an MTU of 128: {fragmented}"
    );
    Ok(())
}

/// The address of a second client of the server in [`Pair`]'s addresses.
fn second_client_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 6446))
}

/// The server's datagrams in [`records_of_two_associations_never_share_a_datagram`]: which
/// client each went to, and its bytes.
type Sent = Vec<(usize, BytesMut)>;

/// Hands every queued datagram to its peer until nobody sends: the clients' to the server,
/// the server's to the client its address names. Returns what the server sent, and adds the
/// application data each client was handed to `received`.
fn exchange(
    server: &mut crate::endpoint::Endpoint,
    clients: &mut [crate::endpoint::Endpoint],
    addresses: &[std::net::SocketAddr],
    now: Instant,
    received: &mut [Vec<Vec<u8>>],
    completed: &mut [bool],
) -> Sent {
    let mut sent = vec![];
    for _ in 0..32 {
        let mut quiet = true;
        for (index, client) in clients.iter_mut().enumerate() {
            while let Some(transmit) = client.poll_transmit() {
                quiet = false;
                let _ = server.read(now, addresses[index], None, transmit.message);
            }
        }
        while let Some(transmit) = server.poll_transmit() {
            quiet = false;
            let index = addresses
                .iter()
                .position(|address| *address == transmit.transport.peer_addr)
                .expect("a datagram to one of the clients");
            sent.push((index, transmit.message.clone()));
            if let Ok(events) = clients[index].read(now, server_addr(), None, transmit.message) {
                received[index].extend(application_data(&events));
                completed[index] |= events.iter().any(|event| {
                    matches!(event, crate::endpoint::EndpointEvent::HandshakeComplete)
                });
            }
        }
        if quiet {
            break;
        }
    }
    sent
}

/// The connection id of every protected record of `datagram` (each client asked for 4-byte
/// ids), and how many plaintext records it holds.
fn record_connection_ids(datagram: &[u8]) -> (Vec<Vec<u8>>, usize) {
    use super::record::{DatagramRecord, next_record};
    let mut ids = vec![];
    let mut plaintext = 0;
    let mut rest = datagram;
    while !rest.is_empty() {
        let (record, taken) = next_record(rest, 4).expect("a datagram of whole records");
        match record {
            DatagramRecord::Ciphertext { header, record } => {
                ids.push(record[header.connection_id].to_vec());
            }
            DatagramRecord::Plaintext { .. } => plaintext += 1,
        }
        rest = &rest[taken..];
    }
    (ids, plaintext)
}

/// RFC 9147 section 4: "Sending implementations MUST NOT mix records from multiple DTLS
/// associations in the same datagram." One server endpoint with two DTLS 1.3 associations
/// (two clients, each asking for its own 4-byte connection id, so that every protected record
/// says whose it is): their handshakes run together, then the server writes to both in turn
/// and closes both at once. Every protected record of every datagram the server sent carries
/// the connection id of the client the datagram went to, and each client is handed exactly
/// what was written to it.
#[test]
fn records_of_two_associations_never_share_a_datagram() -> Result<()> {
    use crate::config::DtlsVersion;
    use crate::endpoint::Endpoint;
    use shared::TransportProtocol;
    let dtls13 = |builder: ConfigBuilder| {
        builder
            .with_protocol_versions(DtlsVersion::Dtls1_3, DtlsVersion::Dtls1_3)
            .with_connection_id(Some(4))
    };
    let now = Instant::now();
    let addresses = [client_addr(), second_client_addr()];
    let mut server = Endpoint::new(
        server_addr(),
        TransportProtocol::UDP,
        Some(Arc::new(
            dtls13(server_builder())
                .with_cookie_exchange(false)
                .build(false, None)?,
        )),
    );
    let mut clients = vec![];
    for address in addresses {
        let mut client = Endpoint::new(address, TransportProtocol::UDP, None);
        client.connect(
            now,
            server_addr(),
            Arc::new(dtls13(client_builder()).build(true, None)?),
            None,
        )?;
        clients.push(client);
    }
    let mut received = vec![vec![], vec![]];
    let mut completed = vec![false, false];
    let handshakes = exchange(
        &mut server,
        &mut clients,
        &addresses,
        now,
        &mut received,
        &mut completed,
    );
    // The id each client asked for, as the server took it from the client's ClientHello (a
    // client sets its own only once it has the ServerHello). Read before the close, which
    // ends the associations.
    let ids: Vec<Vec<u8>> = addresses
        .iter()
        .map(|address| {
            server
                .connection_mut(address)
                .expect("the server's association")
                .connection_ids()
                .expect("a DTLS 1.3 association")
                .1
                .to_vec()
        })
        .collect();
    assert_eq!(ids[0].len(), 4);
    assert_ne!(ids[0], ids[1], "the clients asked for different ids");
    let mut protected = [0usize; 2];
    let mut check = |sent: &Sent| {
        for (index, datagram) in sent {
            let (record_ids, plaintext) = record_connection_ids(datagram);
            assert!(
                record_ids.iter().all(|id| *id == ids[*index]),
                "a datagram to client {index} holds records of {record_ids:?} (its id: {:?}, \
                 the other's: {:?}) and {plaintext} plaintext records",
                ids[*index],
                ids[1 - *index]
            );
            protected[*index] += record_ids.len();
        }
    };
    check(&handshakes);
    assert_eq!(completed, vec![true, true], "both handshakes complete");
    for (index, client) in clients.iter_mut().enumerate() {
        let conn = client
            .connection_mut(&server_addr())
            .expect("the client's association");
        assert_eq!(
            conn.connection_ids().expect("a DTLS 1.3 association").0,
            &ids[index][..],
            "client {index} asked for the id the server sends"
        );
    }

    let mut written = vec![vec![], vec![]];
    for n in 0..8 {
        for (index, address) in addresses.iter().enumerate() {
            let data = format!("to client {index}, message {n}").into_bytes();
            server.write(now, *address, &data)?;
            written[index].push(data);
        }
    }
    server.close(now)?;
    let data = exchange(
        &mut server,
        &mut clients,
        &addresses,
        now,
        &mut received,
        &mut completed,
    );
    check(&data);
    assert!(
        protected.iter().all(|count| *count > 8),
        "each association's records were looked at: {protected:?}"
    );
    assert_eq!(
        received, written,
        "each client is handed what was written to it"
    );
    Ok(())
}
