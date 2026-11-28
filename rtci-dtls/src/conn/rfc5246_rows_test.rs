//! RFC 5246 and RFC 6347 clauses about what a DTLS 1.2 endpoint puts on the wire: the
//! record types and their order, the server's random, the certificate chain, and the
//! suites that are never negotiated. Each test runs real DTLS 1.2 handshakes between two
//! endpoints of this crate and reads the datagrams.

use crate::cipher_suite::CipherSuiteId;
use crate::config::{ConfigBuilder, DtlsVersion};
use crate::crypto::{Certificate, CryptoPrivateKey};
use crate::dtls13::handshake_test::{
    Pair, client_addr, client_builder, plaintext_alerts, provider, server_addr, server_builder,
    take,
};
use crate::endpoint::Endpoint;
use bytes::BytesMut;
use shared::TransportProtocol;
use shared::error::Result;
use std::sync::Arc;

fn dtls12(builder: ConfigBuilder) -> ConfigBuilder {
    builder.with_protocol_versions(DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_2)
}

/// A record header as read from a datagram: (content type, epoch, sequence, length).
fn records(datagram: &[u8]) -> Vec<(u8, u16, u64, usize)> {
    let mut out = vec![];
    let mut rest = datagram;
    while rest.len() >= 13 {
        let mut sequence = [0u8; 8];
        sequence[2..].copy_from_slice(&rest[5..11]);
        let length = usize::from(u16::from_be_bytes([rest[11], rest[12]]));
        out.push((
            rest[0],
            u16::from_be_bytes([rest[3], rest[4]]),
            u64::from_be_bytes(sequence),
            length,
        ));
        rest = &rest[(13 + length).min(rest.len())..];
    }
    assert!(rest.is_empty(), "a datagram of whole records");
    out
}

/// Every datagram of a whole DTLS 1.2 association, in the order each side sent them:
/// handshake (with the cookie exchange), data both ways, close.
fn a_whole_association(suite: CipherSuiteId) -> Result<(Vec<BytesMut>, Vec<BytesMut>)> {
    let mut pair = Pair::new(
        dtls12(client_builder()).with_cipher_suites(vec![suite]),
        dtls12(server_builder()).with_cipher_suites(vec![suite]),
    )?;
    let (mut from_client, mut from_server) = (vec![], vec![]);
    for _ in 0..16 {
        let (up, down) = pair.round();
        if up.is_empty() && down.is_empty() {
            break;
        }
        from_client.extend(up);
        from_server.extend(down);
    }
    assert!(pair.client_complete && pair.server_complete);
    pair.client
        .write(pair.now, server_addr(), b"to the server")?;
    pair.server
        .write(pair.now, client_addr(), b"to the client")?;
    pair.client.close(pair.now)?;
    for _ in 0..4 {
        let (up, down) = pair.round();
        from_client.extend(up);
        from_server.extend(down);
    }
    Ok((from_client, from_server))
}

/// RFC 5246 sections 6 and 6.2.1: only change_cipher_spec, alert, handshake and
/// application_data records are sent, and no Handshake, Alert or ChangeCipherSpec record is
/// empty (a protected one is longer than the AEAD's nonce and tag, 24 bytes for GCM).
#[test]
fn only_the_four_record_types_are_sent_and_none_is_empty() -> Result<()> {
    let (from_client, from_server) =
        a_whole_association(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256)?;
    let mut types = vec![];
    for datagram in from_client.iter().chain(from_server.iter()) {
        for (content_type, epoch, _, length) in records(datagram) {
            assert!(
                (20..=23).contains(&content_type),
                "record type {content_type}"
            );
            if content_type != 23 {
                let empty_at = if epoch == 0 { 0 } else { 8 + 16 };
                assert!(length > empty_at, "an empty record of type {content_type}");
            }
            types.push(content_type);
        }
    }
    for content_type in 20..=23 {
        assert!(
            types.contains(&content_type),
            "type {content_type} was seen"
        );
    }
    Ok(())
}

/// RFC 5246 section 6.2.1: records reach the network in the order they were protected:
/// within an epoch, each side's sequence numbers only grow, datagram after datagram.
#[test]
fn records_leave_in_the_order_they_were_protected() -> Result<()> {
    let (from_client, from_server) =
        a_whole_association(CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256)?;
    for side in [from_client, from_server] {
        let mut last: std::collections::HashMap<u16, u64> = Default::default();
        let mut seen = 0;
        for datagram in &side {
            for (_, epoch, sequence, _) in records(datagram) {
                if let Some(before) = last.insert(epoch, sequence) {
                    assert!(
                        sequence > before,
                        "epoch {epoch}: {sequence} after {before}"
                    );
                }
                seen += 1;
            }
        }
        assert!(seen > 3);
    }
    Ok(())
}

/// RFC 5246 section 7.4.1.3: the server's random is its own: the same ClientHello to two
/// servers gets two different ServerHello randoms, neither of them the client's.
#[test]
fn the_server_random_is_made_independently_of_the_clients() -> Result<()> {
    let server = || dtls12(server_builder()).with_cookie_exchange(false);
    let mut pair = Pair::new(dtls12(client_builder()), server())?;
    let client_hello = take(&mut pair.client);
    let client_random = client_hello[0][27..59].to_vec();
    let mut randoms = vec![];
    for _ in 0..2 {
        let mut endpoint = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            Some(Arc::new(server().build(false, None)?)),
        );
        for datagram in &client_hello {
            endpoint.read(pair.now, client_addr(), None, datagram.clone())?;
        }
        let answer = take(&mut endpoint);
        assert_eq!(answer[0][13], 2, "a ServerHello");
        randoms.push(answer[0][27..59].to_vec());
    }
    assert_ne!(randoms[0], randoms[1]);
    assert!(randoms.iter().all(|random| *random != client_random));
    Ok(())
}

/// RFC 5246 section 7.4.2: the sender's certificate comes first in the chain, and each one
/// after it certifies the one before.
#[test]
fn the_certificate_chain_is_sent_leaf_first() -> Result<()> {
    let authority_params = {
        let mut params = rcgen::CertificateParams::new(vec!["authority".to_owned()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
    };
    let authority_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let authority_der = authority_params
        .self_signed(&authority_key)
        .unwrap()
        .der()
        .to_owned();
    let authority = rcgen::Issuer::new(authority_params, authority_key);
    let leaf_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_der = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &authority)
        .unwrap()
        .der()
        .to_owned();
    let chain = Certificate {
        certificate: vec![leaf_der.clone(), authority_der.clone()],
        private_key: CryptoPrivateKey::from_key_pair(&leaf_key, provider().crypto())?,
    };
    for version in [DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_3] {
        let pair = Pair::new(
            client_builder().with_protocol_versions(version, version),
            ConfigBuilder::default()
                .with_crypto_provider(provider())
                .with_protocol_versions(version, version)
                .with_certificates(vec![chain.clone()]),
        )?
        .complete();
        let sent = &pair
            .client
            .get_connection_state(server_addr())
            .unwrap()
            .peer_certificates;
        assert_eq!(
            *sent,
            vec![leaf_der.as_ref().to_vec(), authority_der.as_ref().to_vec()],
            "{version:?}"
        );
        // The leaf names its issuer, the authority.
        let (_, leaf) = x509_parser::parse_x509_certificate(&sent[0]).unwrap();
        let (_, issuer) = x509_parser::parse_x509_certificate(&sent[1]).unwrap();
        assert_eq!(leaf.issuer().as_raw(), issuer.subject().as_raw());
    }
    Ok(())
}

/// RFC 5246 appendix A.5 and RFC 6347 section 4.1.2.2: TLS_NULL_WITH_NULL_NULL, the
/// anonymous suites and RC4 are never negotiated: a ClientHello that offers only those is
/// a handshake_failure.
#[test]
fn null_anonymous_and_rc4_suites_are_never_negotiated() -> Result<()> {
    const NULL_WITH_NULL_NULL: u16 = 0x0000;
    const DH_ANON_WITH_AES_128_CBC_SHA: u16 = 0x0034;
    const ECDH_ANON_WITH_AES_128_CBC_SHA: u16 = 0xc018;
    const RSA_WITH_RC4_128_SHA: u16 = 0x0005;
    const ECDHE_ECDSA_WITH_RC4_128_SHA: u16 = 0xc007;
    const ECDHE_PSK_WITH_RC4_128_SHA: u16 = 0xc033;
    let mut pair = Pair::new(
        dtls12(client_builder()),
        dtls12(server_builder()).with_cookie_exchange(false),
    )?;
    let client_hello = take(&mut pair.client);
    let mut datagram = client_hello[0].to_vec();
    // The suites follow the version, the random, the session id and the cookie.
    let at = 13 + 12 + 2 + 32;
    let session_id_len = usize::from(datagram[at]);
    let cookie_at = at + 1 + session_id_len;
    let suites_at = cookie_at + 1 + usize::from(datagram[cookie_at]);
    let suites_len = usize::from(u16::from_be_bytes([
        datagram[suites_at],
        datagram[suites_at + 1],
    ]));
    let offered: Vec<u16> = [
        NULL_WITH_NULL_NULL,
        DH_ANON_WITH_AES_128_CBC_SHA,
        ECDH_ANON_WITH_AES_128_CBC_SHA,
        RSA_WITH_RC4_128_SHA,
        ECDHE_ECDSA_WITH_RC4_128_SHA,
        ECDHE_PSK_WITH_RC4_128_SHA,
    ]
    .to_vec();
    let mut replacement = ((offered.len() * 2) as u16).to_be_bytes().to_vec();
    for suite in &offered {
        replacement.extend_from_slice(&suite.to_be_bytes());
    }
    let removed = 2 + suites_len;
    datagram.splice(suites_at..suites_at + removed, replacement.iter().copied());
    let grow = |bytes: &mut Vec<u8>, at: usize, width: usize, by: isize| {
        let mut value = [0u8; 4];
        value[4 - width..].copy_from_slice(&bytes[at..at + width]);
        let grown = (u32::from_be_bytes(value) as isize + by) as u32;
        bytes[at..at + width].copy_from_slice(&grown.to_be_bytes()[4 - width..]);
    };
    let by = replacement.len() as isize - removed as isize;
    grow(&mut datagram, 11, 2, by); // record length
    grow(&mut datagram, 14, 3, by); // message length
    grow(&mut datagram, 22, 3, by); // fragment length
    pair.deliver_to_server(vec![BytesMut::from(&datagram[..])]);
    assert_eq!(plaintext_alerts(&take(&mut pair.server)), vec![(2, 40)]);
    for suite in offered {
        assert!(
            matches!(CipherSuiteId::from(suite), CipherSuiteId::Unsupported),
            "{suite:#06x} is a suite this crate has"
        );
    }
    Ok(())
}

/// RFC 5246 section 7.2.2: decryption_failed is never sent, in particular not for a CBC
/// record whose padding is wrong; a DTLS record that does not authenticate is dropped
/// without an alert at all (RFC 6347 section 4.1.2.7), and the association goes on.
#[test]
fn a_record_that_does_not_decrypt_draws_no_alert() -> Result<()> {
    for suite in [
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
        CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
    ] {
        let mut pair = Pair::new(
            dtls12(client_builder()).with_cipher_suites(vec![suite]),
            dtls12(server_builder()).with_cipher_suites(vec![suite]),
        )?
        .complete();
        pair.client.write(pair.now, server_addr(), b"genuine")?;
        let genuine = take(&mut pair.client);
        for position in [genuine[0].len() - 1, genuine[0].len() - 17, 30] {
            let mut forged = genuine[0].to_vec();
            forged[position] ^= 0x5a;
            let _ = pair
                .server
                .read(pair.now, client_addr(), None, BytesMut::from(&forged[..]));
            assert!(take(&mut pair.server).is_empty(), "{suite}: no answer");
            assert!(!pair.server.is_connection_failed(&client_addr()));
        }
        pair.to_server.clear();
        pair.deliver_to_server(genuine);
        assert_eq!(
            crate::dtls13::handshake_test::application_data(&pair.to_server),
            vec![b"genuine".to_vec()]
        );
    }
    Ok(())
}

/// RFC 8827 section 6.5: no cipher suite with NULL encryption is negotiated, DTLS
/// (TLS_NULL_WITH_NULL_NULL, above) or SRTP: a ClientHello whose use_srtp lists only
/// SRTP_NULL_HMAC_SHA1_80 and SRTP_NULL_HMAC_SHA1_32 gets a ServerHello without use_srtp.
#[test]
fn null_srtp_profiles_are_never_selected() -> Result<()> {
    use crate::extension::extension_use_srtp::SrtpProtectionProfile;
    let profiles = vec![
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
    ];
    let answer = |null_profiles: bool| -> Result<Vec<u8>> {
        let mut pair = Pair::new(
            dtls12(client_builder()).with_srtp_protection_profiles(profiles.clone()),
            dtls12(server_builder())
                .with_cookie_exchange(false)
                .with_srtp_protection_profiles(profiles.clone()),
        )?;
        let mut client_hello = take(&mut pair.client)[0].to_vec();
        // use_srtp (14): two profiles, in the client's order, and an empty MKI.
        let offered = [0x00, 0x0e, 0x00, 0x07, 0x00, 0x04];
        let at = client_hello
            .windows(offered.len())
            .position(|window| window == offered)
            .unwrap_or_else(|| panic!("no use_srtp of two profiles in {client_hello:02x?}"));
        let listed: Vec<u16> = client_hello[at + 6..at + 10]
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        assert!(
            listed.contains(&0x0001) && listed.contains(&0x0007),
            "{listed:04x?}"
        );
        assert_eq!(client_hello[at + 10], 0, "no MKI");
        if null_profiles {
            client_hello[at + 6..at + 10].copy_from_slice(&[0x00, 0x05, 0x00, 0x06]);
        }
        pair.deliver_to_server(vec![BytesMut::from(&client_hello[..])]);
        let server_flight = take(&mut pair.server);
        Ok(server_flight[0].to_vec())
    };
    // The ServerHello's extensions end its message, the first of the flight.
    let use_srtp_answered = |datagram: &[u8]| {
        let length = usize::from(u16::from_be_bytes([datagram[11], datagram[12]]));
        let server_hello = &datagram[13 + 12..13 + length];
        let session_id_len = usize::from(server_hello[34]);
        let mut extensions = &server_hello[35 + session_id_len + 3 + 2..];
        let mut found = false;
        while extensions.len() >= 4 {
            let extension_type = u16::from_be_bytes([extensions[0], extensions[1]]);
            let length = usize::from(u16::from_be_bytes([extensions[2], extensions[3]]));
            found |= extension_type == 14;
            extensions = &extensions[4 + length..];
        }
        found
    };
    assert!(
        use_srtp_answered(&answer(false)?),
        "a real profile is selected"
    );
    assert!(!use_srtp_answered(&answer(true)?), "a NULL one never is");
    Ok(())
}

/// RFC 3711 section 9.1, RFC 5764 section 4.2: no two RTP sessions share a master key. Each
/// DTLS association exports its own SRTP keying material (two associations between the same
/// endpoints never the same), and within one the two directions' master keys differ.
#[test]
fn each_association_exports_its_own_srtp_master_keys() -> Result<()> {
    use crate::extension::extension_use_srtp::SrtpProtectionProfile;
    const LABEL: &str = "EXTRACTOR-dtls_srtp";
    let profile = SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm;
    for version in [DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_3] {
        let mut exports = std::collections::HashSet::new();
        for _ in 0..4 {
            let pair = Pair::new(
                client_builder()
                    .with_protocol_versions(version, version)
                    .with_srtp_protection_profiles(vec![profile]),
                server_builder()
                    .with_protocol_versions(version, version)
                    .with_srtp_protection_profiles(vec![profile]),
            )?
            .complete();
            let material = pair
                .client
                .get_connection_state(server_addr())
                .unwrap()
                .export_keying_material(LABEL, &[], 56)?;
            // client_write_SRTP_master_key, server_write_SRTP_master_key, then the salts.
            let material = material.as_ref().to_vec();
            assert_ne!(material[..16], material[16..32], "{version:?}");
            assert!(exports.insert(material), "{version:?}");
        }
    }
    Ok(())
}

/// RFC 8261 section 5: DTLS takes a message larger than the path MTU: an application record
/// is not cut to the MTU (SCTP over it sizes its packets itself), and arrives whole, in DTLS
/// 1.2 and 1.3.
#[test]
fn a_message_larger_than_the_mtu_is_sent_whole() -> Result<()> {
    for version in [DtlsVersion::Dtls1_2, DtlsVersion::Dtls1_3] {
        let mut pair = Pair::new(
            client_builder()
                .with_protocol_versions(version, version)
                .with_mtu(1200),
            server_builder()
                .with_protocol_versions(version, version)
                .with_mtu(1200),
        )?
        .complete();
        let message = vec![0x3c; 3000];
        pair.client.write(pair.now, server_addr(), &message)?;
        let sent = take(&mut pair.client);
        assert!(
            sent.iter().any(|datagram| datagram.len() > 1200),
            "{version:?}"
        );
        pair.to_server.clear();
        pair.deliver_to_server(sent);
        assert_eq!(
            crate::dtls13::handshake_test::application_data(&pair.to_server),
            vec![message],
            "{version:?}"
        );
    }
    Ok(())
}

/// A ClientHello's cipher suites and its extensions (type, data).
type SuitesAndExtensions = (Vec<u16>, Vec<(u16, Vec<u8>)>);

/// The cipher suites and the extensions of the first ClientHello `client` writes.
fn client_hello_suites_and_extensions(client: ConfigBuilder) -> Result<SuitesAndExtensions> {
    let mut pair = Pair::new(client, server_builder())?;
    let hello = take(&mut pair.client);
    let datagram = &hello[0];
    assert_eq!((datagram[0], datagram[13]), (22, 1), "a ClientHello");
    let length = usize::from(datagram[14]) << 16
        | usize::from(datagram[15]) << 8
        | usize::from(datagram[16]);
    let body = &datagram[25..25 + length];
    let session_end = 35 + usize::from(body[34]);
    let cookie_end = session_end + 1 + usize::from(body[session_end]);
    let suites_len = usize::from(u16::from_be_bytes([body[cookie_end], body[cookie_end + 1]]));
    let suites: Vec<u16> = body[cookie_end + 2..cookie_end + 2 + suites_len]
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    let compression_at = cookie_end + 2 + suites_len;
    let extensions = crate::conn::conn_conformance_test::extensions_after(
        body,
        compression_at + 1 + usize::from(body[compression_at]),
    );
    Ok((suites, extensions))
}

/// RFC 8422 section 5.1 (RFC5246-8422-5.1-1, a SHOULD): "A TLS client that proposes ECC
/// cipher suites in its ClientHello message SHOULD include these extensions." The ClientHello
/// the engine writes, DTLS 1.2 only and offering both versions, read from the wire:
/// supported_groups with at least one group, ec_point_formats with uncompressed (0).
#[test]
fn a_client_offering_ecc_suites_sends_supported_groups_and_point_formats() -> Result<()> {
    for client in [dtls12(client_builder()), client_builder()] {
        // The default suites, ECDHE ones among them.
        let (suites, extensions) = client_hello_suites_and_extensions(client)?;
        assert!(
            suites.contains(&0xc02b),
            "an ECDHE_ECDSA suite is offered: {suites:x?}"
        );
        let find = |typ: u16| {
            extensions
                .iter()
                .find(|(t, _)| *t == typ)
                .map(|(_, data)| data.clone())
        };
        let groups = find(10).expect("supported_groups");
        let listed = usize::from(u16::from_be_bytes([groups[0], groups[1]]));
        assert!(listed >= 2 && listed == groups.len() - 2, "{groups:?}");
        let formats = find(11).expect("ec_point_formats");
        assert_eq!(usize::from(formats[0]), formats.len() - 1, "{formats:?}");
        assert!(formats[1..].contains(&0), "uncompressed: {formats:?}");
    }
    Ok(())
}

/// RFC 8422 section 5.1 (RFC5246-8422-5.1-3): "The client MUST NOT include these extensions
/// in the ClientHello message if it does not propose any ECC cipher suites." A DTLS 1.2
/// client configured for a pre-shared key, offering TLS_PSK_WITH_AES_128_GCM_SHA256 alone:
/// its ClientHello has neither supported_groups nor ec_point_formats.
#[test]
fn a_client_offering_no_ecc_suite_sends_neither_ecc_extension() -> Result<()> {
    let client = dtls12(client_builder())
        .with_cipher_suites(vec![CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256])
        .with_psk(Some(Arc::new(|_| Ok(vec![0xab, 0xcd]))))
        .with_psk_identity_hint(Some(b"rtci".to_vec()));
    let (suites, extensions) = client_hello_suites_and_extensions(client)?;
    assert_eq!(suites, vec![0x00a8], "the PSK suite alone");
    let types: Vec<u16> = extensions.iter().map(|(t, _)| *t).collect();
    assert!(!types.contains(&10), "no supported_groups: {types:x?}");
    assert!(!types.contains(&11), "no ec_point_formats: {types:x?}");
    Ok(())
}
