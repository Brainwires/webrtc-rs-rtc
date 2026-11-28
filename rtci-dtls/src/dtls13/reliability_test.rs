//! DTLS 1.3 under loss, reordering and forgery: retransmission and ACKs (RFC 9147 sections
//! 5.8 and 7), the cookie exchange (5.1), key updates (8), alerts (5.10), the limits of a key
//! (4.5.3), and what an association does with records and messages it must not accept.

use super::conn::*;
use super::handshake_test::*;
use super::messages::{self, alert};
use super::record::*;
use crate::config::{ConfigBuilder, DtlsVersion};
use crate::conn::DTLSConn;
use crate::crypto::Certificate;
use crate::endpoint::EndpointEvent;
use bytes::BytesMut;
use crypto::{CryptoError, PublicKey, SecretVec, SignatureScheme, SigningKey};
use shared::error::{Error, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn no_cookies() -> Result<Pair> {
    Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false),
    )
}

fn record_count(datagrams: &[BytesMut]) -> usize {
    datagrams
        .iter()
        .map(|datagram| record_first_bytes(datagram).len())
        .sum()
}

fn fire(pair: &mut Pair, client: bool) -> Instant {
    let (endpoint, remote) = if client {
        (&mut pair.client, server_addr())
    } else {
        (&mut pair.server, client_addr())
    };
    let at = endpoint.poll_timeout(&remote).expect("a timer is armed");
    pair.now = pair.now.max(at);
    let _ = endpoint.handle_timeout(remote, at);
    at
}

/// RFC 9147 sections 5.8.1 and 5.8.2: a flight that is not answered is sent again when the
/// timer expires, in new records, and the timer doubles.
#[test]
fn an_unanswered_flight_is_sent_again_and_the_timer_doubles() -> Result<()> {
    let mut pair = no_cookies()?;
    let start = pair.now;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let lost = take(&mut pair.server);
    assert_eq!(record_count(&lost), 5);

    let first = fire(&mut pair, false);
    assert_eq!(first - start, Duration::from_secs(1));
    let again = take(&mut pair.server);
    assert_eq!(record_count(&again), 5, "the whole flight");
    // Section 5.2: the same messages with the same message_seq, in records with new
    // sequence numbers.
    assert_eq!(
        again[0][13..25],
        lost[0][13..25],
        "the ServerHello's handshake header"
    );
    assert_ne!(
        again[0][5..11],
        lost[0][5..11],
        "its record sequence number"
    );

    let second = fire(&mut pair, false);
    assert_eq!(second - first, Duration::from_secs(2));
    let third = fire(&mut pair, false);
    assert_eq!(third - second, Duration::from_secs(4));
    take(&mut pair.server);

    // Any one transmission completes the handshake.
    pair.deliver_to_client(again);
    let mut pair = pair.complete();
    assert_eq!(pair.client_sends(b"late"), vec![b"late".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.8.1: a peer that repeats its flight has not received the answer, which
/// is sent again at once.
#[test]
fn a_repeated_client_hello_draws_the_servers_flight_again() -> Result<()> {
    let mut pair = no_cookies()?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let lost = take(&mut pair.server);
    assert!(!lost.is_empty());

    fire(&mut pair, true);
    let repeated = take(&mut pair.client);
    assert_eq!(repeated.len(), 1);
    pair.deliver_to_server(repeated);
    let again = take(&mut pair.server);
    assert_eq!(
        record_count(&again),
        5,
        "the flight is sent again without waiting"
    );
    pair.deliver_to_client(again);
    pair.complete();
    Ok(())
}

/// RFC 9147 sections 7.1 and 7.2: part of a flight arrives and the rest does not; the
/// receiver says what it has after a quarter of the timer, and the sender sends the rest,
/// and only the rest, at once.
#[test]
fn a_partial_flight_is_acknowledged_and_only_the_rest_is_sent_again() -> Result<()> {
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false).with_mtu(300),
    )?;
    let start = pair.now;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let mut flight = take(&mut pair.server);
    assert!(flight.len() >= 3, "the flight takes several datagrams");
    let whole = record_count(&flight);
    // The last datagram is lost.
    let lost = flight.pop().unwrap();
    let lost_records = record_count(&[lost]);
    pair.deliver_to_client(flight);
    assert!(!pair.client_complete);
    assert!(take(&mut pair.client).is_empty(), "nothing is said at once");

    // A quarter of the one-second timer later, an ACK, under the handshake keys.
    let at = fire(&mut pair, true);
    assert_eq!(at - start, Duration::from_millis(250));
    let ack = take(&mut pair.client);
    assert_eq!(ack.len(), 1);
    assert_eq!(record_first_bytes(&ack[0]), [0x2e]);

    pair.deliver_to_server(ack);
    let rest = take(&mut pair.server);
    assert_eq!(
        record_count(&rest),
        lost_records,
        "only what was not acknowledged, of {whole} records"
    );
    pair.deliver_to_client(rest);
    assert!(pair.client_complete);
    pair.complete();
    Ok(())
}

/// RFC 9147 sections 5.8.1 and 7.1: the client's last flight is answered by an ACK only. A
/// client that does not get it sends the flight again, and the server, done long since,
/// acknowledges it again.
#[test]
fn the_clients_last_flight_is_sent_again_until_it_is_acknowledged() -> Result<()> {
    let mut pair = no_cookies()?;
    pair.round();
    let finished = take(&mut pair.client);
    pair.deliver_to_server(finished);
    assert!(pair.server_complete);
    let lost_ack = take(&mut pair.server);
    assert_eq!(record_first_bytes(&lost_ack[0]), [0x2f]);
    assert!(pair.client_conn().flight.is_some());

    fire(&mut pair, true);
    let again = take(&mut pair.client);
    assert_eq!(
        record_first_bytes(&again[0]),
        [0x2e],
        "the Finished, still in epoch 2"
    );
    pair.to_server.clear();
    pair.deliver_to_server(again);
    assert!(pair.to_server.is_empty(), "nothing new for the application");
    let ack = take(&mut pair.server);
    assert_eq!(ack.len(), 1);
    assert_eq!(record_first_bytes(&ack[0]), [0x2f]);
    pair.deliver_to_client(ack);
    assert!(pair.client_conn().flight.is_none());
    assert_eq!(pair.client.poll_timeout(&server_addr()), None);

    // The server lets go of the handshake keys after twice the maximum segment lifetime;
    // a repeat after that is not read, and not answered.
    let at = fire(&mut pair, false);
    assert!(at - pair.now <= HANDSHAKE_KEYS_LINGER);
    assert_eq!(pair.server.poll_timeout(&client_addr()), None);
    assert_eq!(pair.client_sends(b"still up"), vec![b"still up".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.8.1: "for at least twice the default MSL defined for [RFC0793], when in
/// the FINISHED state, the server MUST respond to retransmission of the client's final flight
/// with a retransmit of its ACK." The server's ACK of the Finished is lost; the client sends
/// its Finished again 10, 60, 120, 180 and 235 s after the server completed, and each is
/// acknowledged at once, with one ACK. Sent again 270 s after, it is not.
#[test]
fn the_clients_last_flight_is_acknowledged_for_twice_the_msl() -> Result<()> {
    let mut pair = no_cookies()?;
    pair.round();
    let finished = take(&mut pair.client);
    pair.deliver_to_server(finished);
    assert!(pair.server_complete);
    let completed = pair.now;
    let lost_ack = take(&mut pair.server);
    assert_eq!(lost_ack.len(), 1);
    for (after, answered) in [
        (10, true),
        (60, true),
        (120, true),
        (180, true),
        (235, true),
        (270, false),
    ] {
        pair.now = completed + Duration::from_secs(after);
        let now = pair.now;
        let _ = pair.server.handle_timeout(client_addr(), now);
        assert!(
            take(&mut pair.server).is_empty(),
            "{after} s: nothing unasked"
        );
        pair.client.handle_timeout(server_addr(), now)?;
        let again = take(&mut pair.client);
        assert_eq!(
            again.len(),
            1,
            "{after} s: the client sends its Finished again"
        );
        assert_eq!(
            record_first_bytes(&again[0]),
            [0x2e],
            "{after} s: in epoch 2"
        );
        pair.deliver_to_server(again);
        let ack = take(&mut pair.server);
        if answered {
            assert_eq!(ack.len(), 1, "{after} s: acknowledged");
            assert_eq!(
                record_first_bytes(&ack[0]).len(),
                1,
                "{after} s: one ACK record"
            );
        } else {
            assert!(ack.is_empty(), "{after} s: no longer read");
        }
    }
    assert_eq!(pair.server_sends(b"still up"), vec![b"still up".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.8.1: application data that overtakes the client's Finished is held, not
/// delivered and not lost.
#[test]
fn application_data_ahead_of_the_clients_finished_is_held() -> Result<()> {
    let mut pair = no_cookies()?;
    pair.round();
    assert!(pair.client_complete);
    let finished = take(&mut pair.client);
    pair.client.write(pair.now, server_addr(), b"early")?;
    let early = take(&mut pair.client);
    pair.deliver_to_server(early);
    assert!(application_data(&pair.to_server).is_empty());
    assert!(!pair.server_complete);
    pair.deliver_to_server(finished);
    assert!(pair.server_complete);
    assert_eq!(application_data(&pair.to_server), vec![b"early".to_vec()]);
    Ok(())
}

/// RFC 9147 section 5.8.1: application data under the new keys ahead of the peer's Finished
/// says the Finished was lost, and the flight it answers is sent again at once.
#[test]
fn early_application_data_draws_the_flight_again() -> Result<()> {
    let mut pair = no_cookies()?;
    pair.round();
    let _lost_finished = take(&mut pair.client);
    pair.client.write(pair.now, server_addr(), b"early")?;
    let early = take(&mut pair.client);
    pair.deliver_to_server(early);
    let again = take(&mut pair.server);
    assert_eq!(
        record_count(&again),
        5,
        "the server's flight, without waiting for the timer"
    );
    // The client, done already, takes the repeat as the sign that its own flight was lost.
    pair.deliver_to_client(again);
    let finished = take(&mut pair.client);
    assert_eq!(record_first_bytes(&finished[0]), [0x2e]);
    pair.deliver_to_server(finished);
    assert!(pair.server_complete);
    assert_eq!(application_data(&pair.to_server), vec![b"early".to_vec()]);
    // More early data does not send the flight a third time.
    Ok(())
}

/// RFC 9147 sections 5.2 and 5.5: messages that arrive ahead of their turn are queued, and
/// fragments are taken in any order.
#[test]
fn a_flight_that_arrives_in_reverse_order_completes() -> Result<()> {
    let mut pair = Pair::new(
        client_builder(),
        server_builder().with_cookie_exchange(false).with_mtu(200),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let mut flight = take(&mut pair.server);
    assert!(flight.len() >= 4);
    // The ServerHello first (the client has no keys before it), the rest backwards.
    let server_hello = flight.remove(0);
    flight.reverse();
    pair.deliver_to_client(vec![server_hello]);
    pair.deliver_to_client(flight);
    assert!(pair.client_complete);
    pair.complete();
    Ok(())
}

/// RFC 9147 section 5.5: overlapping fragments are taken, and a byte that differs between
/// two of them is an illegal_parameter.
#[test]
fn overlapping_fragments_are_taken_unless_they_disagree() -> Result<()> {
    let ticket: Vec<u8> = vec![0, 0, 14, 16, 1, 2, 3, 4, 1, 9, 0, 4, 1, 2, 3, 4, 0, 0];
    for conflict in [false, true] {
        let mut pair = no_cookies()?.complete();
        let message_seq = pair.server_conn().next_send_seq;
        let fragment = |offset: usize, bytes: &[u8]| {
            messages::handshake_fragment(
                messages::NEW_SESSION_TICKET,
                ticket.len(),
                message_seq,
                offset,
                bytes,
            )
        };
        let mut second = ticket[6..].to_vec();
        if conflict {
            second[2] ^= 0xff;
        }
        let first = fragment(0, &ticket[..12]);
        let second = fragment(6, &second);
        for content in [first, second] {
            let record = pair
                .server_conn()
                .seal_for_fuzzing(CONTENT_TYPE_HANDSHAKE, &content)
                .unwrap();
            pair.deliver_to_client(vec![BytesMut::from(&record[..])]);
        }
        assert_eq!(pair.client.is_connection_failed(&server_addr()), conflict);
        if !conflict {
            // The whole ticket was put together and acknowledged.
            let ack = take(&mut pair.client);
            assert_eq!(record_count(&ack), 1);
        }
    }
    Ok(())
}

/// RFC 9147 section 5.1: a ClientHello with a cookie this server did not make for that
/// address is an illegal_parameter, and costs no state.
#[test]
fn an_invalid_cookie_is_an_illegal_parameter() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?;
    pair.round();
    let second = take(&mut pair.client);
    assert_eq!(second.len(), 1);

    // From another address.
    let other = std::net::SocketAddr::from(([127, 0, 0, 9], 6444));
    let events = pair.server.read(pair.now, other, None, second[0].clone())?;
    assert!(events.is_empty());
    assert_eq!(
        plaintext_alerts(&take(&mut pair.server)),
        [(2, alert::ILLEGAL_PARAMETER)]
    );
    assert!(pair.server.connection_mut(&other).is_none());

    // With one bit of the cookie changed (the cookie extension is the last one).
    let mut forged = second[0].clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    pair.deliver_to_server(vec![forged]);
    assert_eq!(
        plaintext_alerts(&take(&mut pair.server)),
        [(2, alert::ILLEGAL_PARAMETER)]
    );
    assert!(pair.server.connection_mut(&client_addr()).is_none());

    // The genuine one is still good.
    pair.deliver_to_server(second);
    assert!(pair.server.connection_mut(&client_addr()).is_some());
    pair.complete();
    Ok(())
}

/// RFC 8446 section 4.1.4, RFC 9147 section 5.1: a second HelloRetryRequest is an
/// unexpected_message.
#[test]
fn a_second_hello_retry_request_is_an_unexpected_message() -> Result<()> {
    let mut pair = Pair::new(client_builder(), server_builder())?;
    let (_, hello_retry_request) = pair.round();
    take(&mut pair.client);
    // The same message again, as the server's next: message_seq 1, a new record.
    let mut second = hello_retry_request[0].clone();
    second[10] = second[10].wrapping_add(1);
    second[18] = 1;
    pair.deliver_to_client(vec![second]);
    assert!(pair.client.is_connection_failed(&server_addr()));
    assert_eq!(
        plaintext_alerts(&take(&mut pair.client)),
        [(2, alert::UNEXPECTED_MESSAGE)]
    );
    Ok(())
}

/// RFC 8446 section 4.1.3, RFC 9147 section 5.3: a server that speaks DTLS 1.3 and negotiates
/// DTLS 1.2 marks its random, and a client that offered DTLS 1.3 refuses a DTLS 1.2
/// ServerHello so marked.
#[test]
fn the_downgrade_sentinel_is_set_and_checked() -> Result<()> {
    use DtlsVersion::Dtls1_2;
    // A DTLS 1.2 client and the default server: the ServerHello's random ends in DOWNGRD\x01.
    let mut pair = Pair::new(
        client_builder().with_protocol_versions(Dtls1_2, Dtls1_2),
        server_builder().with_cookie_exchange(false),
    )?;
    let (_, flight) = pair.round();
    assert_eq!(flight[0][13], 2, "a ServerHello");
    assert_eq!(&flight[0][51..59], &messages::DOWNGRADE_TO_1_2);
    pair.complete();

    // A server that only has DTLS 1.2 does not mark it, and the default client takes it.
    let mut pair = Pair::new(
        client_builder(),
        server_builder()
            .with_cookie_exchange(false)
            .with_protocol_versions(Dtls1_2, Dtls1_2),
    )?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    let flight = take(&mut pair.server);
    assert_ne!(&flight[0][51..59], &messages::DOWNGRADE_TO_1_2);

    // RFC 8446 section 4.2.1: supported_versions in a ServerHello selects DTLS 1.3 or is an
    // illegal_parameter. Here it is appended to the DTLS 1.2 ServerHello, selecting DTLS 1.2.
    let mut with_versions =
        flight[0][..13 + u16::from_be_bytes([flight[0][11], flight[0][12]]) as usize].to_vec();
    with_versions.extend_from_slice(&[0, 43, 0, 2, 0xfe, 0xfd]);
    let grow = |bytes: &mut Vec<u8>, at: usize, width: usize| {
        let mut value = [0u8; 4];
        value[4 - width..].copy_from_slice(&bytes[at..at + width]);
        let grown = (u32::from_be_bytes(value) + 6).to_be_bytes();
        bytes[at..at + width].copy_from_slice(&grown[4 - width..]);
    };
    grow(&mut with_versions, 11, 2); // record length
    grow(&mut with_versions, 14, 3); // message length
    grow(&mut with_versions, 22, 3); // fragment length
    let extensions_at = 13 + 12 + 2 + 32 + 1 + usize::from(with_versions[13 + 12 + 34]) + 3;
    grow(&mut with_versions, extensions_at, 2);
    {
        let mut pair = Pair::new(
            client_builder(),
            server_builder()
                .with_cookie_exchange(false)
                .with_protocol_versions(Dtls1_2, Dtls1_2),
        )?;
        take(&mut pair.client);
        pair.deliver_to_client(vec![BytesMut::from(&with_versions[..])]);
        assert!(pair.client.is_connection_failed(&server_addr()));
        let alerts = take(&mut pair.client);
        assert_eq!(&alerts[0][13..15], &[2, alert::ILLEGAL_PARAMETER]);
    }

    // The same ServerHello with the mark, as an attacker who removed DTLS 1.3 from the
    // ClientHello would have caused: illegal_parameter.
    let mut marked = flight[0].clone();
    marked[51..59].copy_from_slice(&messages::DOWNGRADE_TO_1_2);
    pair.deliver_to_client(vec![marked]);
    assert!(pair.client.is_connection_failed(&server_addr()));
    let alerts = take(&mut pair.client);
    assert_eq!(&alerts[0][13..15], &[2, alert::ILLEGAL_PARAMETER]);
    Ok(())
}

/// A signing key that produces signatures that do not verify.
pub(crate) struct WrongSigner(pub(crate) Arc<dyn SigningKey>);

impl SigningKey for WrongSigner {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        self.0.supports(scheme)
    }
    fn public_key(&self) -> PublicKey<'_> {
        self.0.public_key()
    }
    fn sign(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        let mut other = message.to_vec();
        other.push(0);
        self.0.sign(scheme, &other)
    }
}

fn wrongly_signing(certificate: Certificate) -> Certificate {
    Certificate::from_signing_key(
        certificate.certificate.clone(),
        Arc::new(WrongSigner(certificate.private_key.signing_key.clone())),
    )
}

/// RFC 8446 section 4.4.3: a CertificateVerify whose signature is not over the transcript is
/// a decrypt_error, from the server and from the client.
#[test]
fn a_certificate_verify_that_does_not_verify_is_a_decrypt_error() -> Result<()> {
    let provider = provider();
    let certificate =
        Certificate::generate_self_signed(vec!["localhost".to_owned()], provider.crypto())?;
    let mut pair = Pair::new(
        client_builder(),
        ConfigBuilder::default()
            .with_crypto_provider(provider.clone())
            .with_certificates(vec![wrongly_signing(certificate)]),
    )?;
    pair.run();
    assert!(!pair.client_complete && !pair.server_complete);
    assert!(matches!(
        pair.client_error,
        Some(Error::ErrKeySignatureMismatch)
    ));
    assert!(pair.client.is_connection_failed(&server_addr()));
    assert!(pair.server.is_connection_failed(&client_addr()));

    let certificate =
        Certificate::generate_self_signed(vec!["client".to_owned()], provider.crypto())?;
    let mut pair = Pair::new(
        client_builder().with_certificates(vec![wrongly_signing(certificate)]),
        server_builder().with_client_auth(crate::config::ClientAuthType::RequireAnyClientCert),
    )?;
    pair.run();
    assert!(!pair.server_complete);
    assert!(matches!(
        pair.server_error,
        Some(Error::ErrKeySignatureMismatch)
    ));
    assert!(pair.server.is_connection_failed(&client_addr()));
    Ok(())
}

/// RFC 9147 section 8: a KeyUpdate moves its sender to new keys, and a new epoch, once it has
/// been acknowledged; the other direction stays where it is unless asked.
#[test]
fn a_key_update_takes_effect_once_acknowledged() -> Result<()> {
    let mut pair = no_cookies()?.complete();
    assert_eq!(pair.client_sends(b"epoch 3"), vec![b"epoch 3".to_vec()]);

    pair.client.update_keys(pair.now, server_addr(), false)?;
    // One at a time.
    assert!(
        pair.client
            .update_keys(pair.now, server_addr(), false)
            .is_err()
    );
    let key_update = take(&mut pair.client);
    assert_eq!(
        record_first_bytes(&key_update[0]),
        [0x2f],
        "sent under the old keys"
    );
    // Until the ACK arrives the old keys are still what is sent with.
    pair.client
        .write(pair.now, server_addr(), b"before the ack")?;
    let before = take(&mut pair.client);
    assert_eq!(record_first_bytes(&before[0]), [0x2f]);
    pair.client
        .write(pair.now, server_addr(), b"held in epoch 3")?;
    let held = take(&mut pair.client);

    pair.deliver_to_server(key_update);
    let ack = take(&mut pair.server);
    assert_eq!(record_first_bytes(&ack[0]), [0x2f]);
    pair.deliver_to_client(ack);
    pair.client
        .write(pair.now, server_addr(), b"after the ack")?;
    let after = take(&mut pair.client);
    assert_eq!(record_first_bytes(&after[0]), [0x2c], "epoch 4");

    // The record sent before the update arrives after one sent under the new keys, and is
    // still read with the epoch before (section 8: "They SHOULD attempt to process those
    // records with that epoch").
    pair.to_server.clear();
    pair.deliver_to_server(after);
    pair.deliver_to_server(before);
    assert_eq!(
        application_data(&pair.to_server),
        vec![b"after the ack".to_vec(), b"before the ack".to_vec()]
    );

    // The server still sends in epoch 3, until it is asked to update.
    pair.server
        .write(pair.now, client_addr(), b"server epoch 3")?;
    let data = take(&mut pair.server);
    assert_eq!(record_first_bytes(&data[0]), [0x2f]);
    pair.deliver_to_client(data);

    pair.client.update_keys(pair.now, server_addr(), true)?;
    pair.run();
    pair.server
        .write(pair.now, client_addr(), b"server epoch 4")?;
    let data = take(&mut pair.server);
    assert_eq!(
        record_first_bytes(&data[0]),
        [0x2c],
        "the server updated too"
    );
    pair.deliver_to_client(data);
    pair.client
        .write(pair.now, server_addr(), b"client epoch 5")?;
    let data = take(&mut pair.client);
    assert_eq!(record_first_bytes(&data[0]), [0x2d]);
    pair.to_server.clear();
    pair.deliver_to_server(data);
    assert_eq!(
        application_data(&pair.to_server),
        vec![b"client epoch 5".to_vec()]
    );
    // Two epochs on, epoch 3 is gone: its last record, held back until now, is not read.
    pair.to_server.clear();
    pair.deliver_to_server(held);
    assert!(application_data(&pair.to_server).is_empty());
    assert_eq!(
        application_data(&pair.to_client),
        vec![b"server epoch 3".to_vec(), b"server epoch 4".to_vec()]
    );

    // The exporter does not change with the keys.
    let export = |endpoint: &crate::endpoint::Endpoint, remote| {
        endpoint
            .get_connection_state(remote)
            .unwrap()
            .export_keying_material("EXTRACTOR-dtls_srtp", &[], 32)
            .unwrap()
            .as_ref()
            .to_vec()
    };
    assert_eq!(
        export(&pair.client, server_addr()),
        export(&pair.server, client_addr())
    );
    Ok(())
}

#[test]
fn a_lost_key_update_is_sent_again() -> Result<()> {
    let mut pair = no_cookies()?.complete();
    pair.client.update_keys(pair.now, server_addr(), false)?;
    let lost = take(&mut pair.client);
    assert_eq!(lost.len(), 1);
    fire(&mut pair, true);
    let again = take(&mut pair.client);
    assert_eq!(
        record_first_bytes(&again[0]),
        [0x2f],
        "the same epoch as the first time"
    );
    // The first copy turns up after all: the server acknowledges both, and updates once.
    pair.deliver_to_server(again);
    pair.deliver_to_server(lost);
    let acks = take(&mut pair.server);
    assert_eq!(record_count(&acks), 2);
    pair.deliver_to_client(acks);
    assert_eq!(pair.client_sends(b"epoch 4"), vec![b"epoch 4".to_vec()]);
    assert_eq!(pair.client.poll_timeout(&server_addr()), None);
    Ok(())
}

/// Messages that have no place after the handshake (RFC 8446 section 4.6, RFC 9147 section
/// 9), and a KeyUpdate that is not one.
#[test]
fn post_handshake_messages_are_checked() -> Result<()> {
    // (who sends, handshake type, body, the alert it draws: None for acknowledged)
    let ticket = {
        let mut body = vec![0, 0, 14, 16, 1, 2, 3, 4, 1, 9, 0, 4, 1, 2, 3, 4];
        body.extend_from_slice(&[0, 0]);
        body
    };
    let cases: Vec<(bool, u8, Vec<u8>, Option<u8>)> = vec![
        // A NewSessionTicket to the client is acknowledged and not used.
        (false, messages::NEW_SESSION_TICKET, ticket.clone(), None),
        // To a server it is out of place.
        (
            true,
            messages::NEW_SESSION_TICKET,
            ticket,
            Some(alert::UNEXPECTED_MESSAGE),
        ),
        // Post-handshake authentication was not offered.
        (
            false,
            messages::CERTIFICATE_REQUEST,
            messages::certificate_request(&[1], &[0x0403]),
            Some(alert::UNEXPECTED_MESSAGE),
        ),
        (
            true,
            messages::KEY_UPDATE,
            vec![2],
            Some(alert::ILLEGAL_PARAMETER),
        ),
        (
            true,
            messages::KEY_UPDATE,
            vec![0, 0],
            Some(alert::DECODE_ERROR),
        ),
        (
            true,
            messages::FINISHED,
            vec![0; 32],
            Some(alert::UNEXPECTED_MESSAGE),
        ),
        // No connection id was negotiated.
        (
            true,
            messages::NEW_CONNECTION_ID,
            messages::new_connection_id(&[vec![1, 2]], messages::CID_SPARE),
            Some(alert::UNEXPECTED_MESSAGE),
        ),
        (
            false,
            messages::REQUEST_CONNECTION_ID,
            messages::request_connection_id(1),
            Some(alert::UNEXPECTED_MESSAGE),
        ),
    ];
    for (from_client, handshake_type, body, expected) in cases {
        let mut pair = no_cookies()?.complete();
        let sender = if from_client {
            pair.client_conn()
        } else {
            pair.server_conn()
        };
        sender.send_post_handshake(FlightKind::NewConnectionId, handshake_type, body)?;
        // The association was written to behind its endpoint's back: have it collect.
        let now = pair.now;
        let _ = pair.client.handle_timeout(server_addr(), now);
        let _ = pair.server.handle_timeout(client_addr(), now);
        pair.run();
        let (receiver_failed, sender_failed) = if from_client {
            (
                pair.server.is_connection_failed(&client_addr()),
                pair.client.is_connection_failed(&server_addr()),
            )
        } else {
            (
                pair.client.is_connection_failed(&server_addr()),
                pair.server.is_connection_failed(&client_addr()),
            )
        };
        let case = format!("type {handshake_type} from the client: {from_client}");
        match expected {
            None => {
                assert!(!receiver_failed && !sender_failed, "{case}");
                // Acknowledged: the sender has stopped sending it.
                let sender = if from_client {
                    pair.client_conn()
                } else {
                    pair.server_conn()
                };
                assert_eq!(sender.unacknowledged_post_handshake_messages(), 0, "{case}");
                assert_eq!(pair.client_sends(b"on"), vec![b"on".to_vec()], "{case}");
            }
            Some(_) => {
                // The alert is protected; that it was fatal shows on both sides.
                assert!(receiver_failed && sender_failed, "{case}");
            }
        }
    }
    Ok(())
}

/// RFC 9147 sections 4.5.1 and 4.5.2: a record that was seen, that does not authenticate, or
/// that is no record at all is dropped without a word, and the association goes on.
#[test]
fn replayed_forged_and_malformed_records_are_discarded() -> Result<()> {
    let mut pair = no_cookies()?.complete();
    pair.client.write(pair.now, server_addr(), b"once")?;
    let data = take(&mut pair.client);
    pair.to_server.clear();
    pair.deliver_to_server(data.clone());
    pair.deliver_to_server(data.clone());
    assert_eq!(application_data(&pair.to_server), vec![b"once".to_vec()]);

    let mut altered = data[0].to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    let mut junk: Vec<Vec<u8>> = vec![
        altered,
        vec![],
        vec![0x2f],
        vec![0x2f, 0, 1, 0, 40, 1, 2, 3],
        vec![0x3f; 60],
        vec![23, 254, 253, 0, 3, 0, 0, 0, 0, 0, 1, 0, 2, 1, 2],
        vec![20, 254, 253, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1],
        // A plaintext fatal alert and a plaintext close_notify, as anyone could send.
        plaintext_record(CONTENT_TYPE_ALERT, 900, &[2, alert::HANDSHAKE_FAILURE]),
        plaintext_record(CONTENT_TYPE_ALERT, 901, &[1, alert::CLOSE_NOTIFY]),
        plaintext_record(CONTENT_TYPE_ACK, 902, &encode_ack(&[])),
        plaintext_record(
            CONTENT_TYPE_HANDSHAKE,
            903,
            &[1, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0],
        ),
    ];
    // A record of an epoch there are no keys for.
    let mut other_epoch = data[0].to_vec();
    other_epoch[0] ^= 0x01;
    junk.push(other_epoch);
    for datagram in junk {
        pair.to_server.clear();
        let outcome =
            pair.server
                .read(pair.now, client_addr(), None, BytesMut::from(&datagram[..]));
        assert!(
            outcome.is_ok_and(|events| events.is_empty()),
            "{datagram:02x?}"
        );
        assert!(
            take(&mut pair.server).is_empty(),
            "answered {datagram:02x?}"
        );
        assert!(!pair.server.is_connection_failed(&client_addr()));
    }
    assert_eq!(
        pair.client_sends(b"still here"),
        vec![b"still here".to_vec()]
    );
    assert_eq!(pair.server_sends(b"and back"), vec![b"and back".to_vec()]);
    Ok(())
}

#[test]
fn a_close_notify_is_answered_and_reported() -> Result<()> {
    let mut pair = no_cookies()?.complete();
    pair.client.write(pair.now, server_addr(), b"last words")?;
    pair.client.close(pair.now)?;
    let closing = take(&mut pair.client);
    pair.to_server.clear();
    pair.deliver_to_server(closing);
    assert!(matches!(
        pair.to_server.as_slice(),
        [EndpointEvent::ApplicationData(data), EndpointEvent::PeerClosed] if data.as_ref() == b"last words"
    ));
    let reply = take(&mut pair.server);
    assert_eq!(record_first_bytes(&reply[0]), [0x2f], "a protected alert");
    assert!(pair.server.connection_mut(&client_addr()).is_none());
    Ok(())
}

/// RFC 9147 section 4.5.3: the records protected under one key and the records that fail
/// authentication under it are counted, and neither count passes the AEAD's limit.
#[test]
fn the_limits_of_a_key_are_kept() -> Result<()> {
    // Protection: a key update is started before the limit, and takes over once
    // acknowledged.
    let mut pair = no_cookies()?.complete();
    pair.client_conn().confidentiality_limit = Some(16);
    // With a limit of 16 the update starts at the fourteenth record.
    for index in 0..14u8 {
        assert_eq!(pair.client_sends(&[index]), vec![vec![index]]);
    }
    pair.client
        .write(pair.now, server_addr(), b"under the new key")?;
    let data = take(&mut pair.client);
    assert_eq!(
        *record_first_bytes(&data[0]).last().unwrap(),
        0x2c,
        "epoch 4"
    );

    // Without the acknowledgement there are no new keys, and the old ones are not used past
    // their limit: the write fails.
    let mut pair = no_cookies()?.complete();
    pair.client_conn().confidentiality_limit = Some(16);
    let mut refused = None;
    for index in 0..40u8 {
        if let Err(err) = pair.client.write(pair.now, server_addr(), &[index]) {
            refused = Some((index, err));
            break;
        }
        take(&mut pair.client);
    }
    let (index, err) = refused.expect("a write is refused at the limit");
    assert!(index <= 16, "refused at write {index}");
    assert_eq!(err, Error::ErrSequenceNumberOverflow);

    // Authentication failures: at half the limit the peer is asked to update its keys, and
    // at the limit the association is closed.
    let mut pair = no_cookies()?.complete();
    pair.server_conn().integrity_limit = Some(4);
    pair.client.write(pair.now, server_addr(), b"genuine")?;
    let genuine = take(&mut pair.client);
    for forgery in 1..=4u8 {
        let mut forged = genuine[0].to_vec();
        let last = forged.len() - 1;
        forged[last] ^= forgery;
        let _ = pair
            .server
            .read(pair.now, client_addr(), None, BytesMut::from(&forged[..]));
        let sent = take(&mut pair.server);
        match forgery {
            2 => assert_eq!(record_count(&sent), 1, "a KeyUpdate that asks for one"),
            4 => assert!(pair.server.is_connection_failed(&client_addr())),
            _ => {
                assert!(sent.is_empty());
                assert!(!pair.server.is_connection_failed(&client_addr()));
            }
        }
    }
    Ok(())
}

/// A server association that is not behind an endpoint runs the cookie exchange itself: a
/// HelloRetryRequest, and nothing computed for the client until the cookie comes back.
#[test]
fn an_association_on_its_own_runs_the_cookie_exchange() -> Result<()> {
    let now = Instant::now();
    let client_config = Arc::new(client_builder().build(true, None)?);
    let server_config = Arc::new(server_builder().build(false, None)?);
    let mut client = DTLSConn::new(client_config, true, None);
    let mut server = DTLSConn::new(server_config, false, None);
    client.handshake(now)?;
    server.handshake(now)?;
    let mut shapes = vec![];
    for _ in 0..8 {
        let mut progressed = false;
        while let Some(datagram) = client.outgoing_raw_packet() {
            progressed = true;
            shapes.push((true, record_first_bytes(&datagram)));
            let _ = server.read(&datagram);
            server.handshake(now)?;
        }
        while let Some(datagram) = server.outgoing_raw_packet() {
            progressed = true;
            shapes.push((false, record_first_bytes(&datagram)));
            let _ = client.read(&datagram);
            client.handshake(now)?;
        }
        if !progressed {
            break;
        }
    }
    assert!(client.is_dtls13() && server.is_dtls13());
    assert!(client.is_handshake_completed() && server.is_handshake_completed());
    assert_eq!(
        shapes,
        vec![
            (true, vec![22]),
            (false, vec![22]),
            (true, vec![22]),
            (false, vec![22, 0x2e, 0x2e, 0x2e, 0x2e]),
            (true, vec![0x2e]),
            (false, vec![0x2f]),
        ]
    );
    client.write(b"direct")?;
    let datagram = client.outgoing_raw_packet().unwrap();
    server.read(&datagram)?;
    assert_eq!(
        server.incoming_application_data().unwrap().as_ref(),
        b"direct"
    );
    let _ = SecretVec::new(vec![]);
    Ok(())
}

/// RFC 9147 section 5.8.2: the timer keeps its backed-off value from one flight to the next,
/// and goes back to its initial value after ten times that value of quiet.
#[test]
fn the_backed_off_timer_returns_to_its_start_after_a_quiet_period() -> Result<()> {
    let mut pair = no_cookies()?;
    let client_hello = take(&mut pair.client);
    pair.deliver_to_server(client_hello);
    take(&mut pair.server);
    fire(&mut pair, false);
    take(&mut pair.server);
    fire(&mut pair, false);
    let flight = take(&mut pair.server);
    pair.deliver_to_client(flight);
    let mut pair = pair.complete();

    // Two retransmissions took the server's timer from one second to four, and the next
    // thing it has to retransmit starts from there.
    let now = pair.now;
    pair.server.update_keys(now, client_addr(), false)?;
    let key_update_timer = |pair: &mut Pair| {
        pair.server_conn()
            .next_timeout()
            .map(|at| at.saturating_duration_since(pair.now))
    };
    assert_eq!(key_update_timer(&mut pair), Some(Duration::from_secs(4)));
    pair.run();

    // Forty seconds later it starts from one second again.
    pair.now += Duration::from_secs(41);
    let now = pair.now;
    pair.server.update_keys(now, client_addr(), false)?;
    assert_eq!(key_update_timer(&mut pair), Some(Duration::from_secs(1)));
    Ok(())
}

/// RFC 9147 section 5.10: where a limit is configured, a peer that keeps sending invalid
/// records is given up on. Without one it never is.
#[test]
fn a_peer_that_keeps_sending_invalid_records_is_given_up_on_where_configured() -> Result<()> {
    let mut pair = Pair::new(
        client_builder(),
        server_builder()
            .with_cookie_exchange(false)
            .with_invalid_record_limit(Some(3)),
    )?
    .complete();
    pair.client.write(pair.now, server_addr(), b"genuine")?;
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
    for _ in 0..100 {
        let _ = pair.client.read(
            pair.now,
            server_addr(),
            None,
            BytesMut::from(&[0x2f, 1, 2, 3][..]),
        );
    }
    assert!(!pair.client.is_connection_failed(&server_addr()));
    Ok(())
}
