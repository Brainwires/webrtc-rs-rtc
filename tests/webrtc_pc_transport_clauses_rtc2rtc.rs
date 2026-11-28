//! W3C webrtc-pc clauses that need two connected peers: the certificate a connection with
//! several presents (4.2.1), the ICE role after a role conflict (5.6), the ICE transport state
//! an ICE restart starts from (5.6.4), and the alert of a DTLS failure this side ended
//! (11.1 `sentAlert`). Two engines in memory on a virtual clock.

mod dc_common;

use anyhow::Result;
use dc_common::{Pair, Peer};
use dtls::cipher_suite::CipherSuiteId;
use rtci::crypto::SignatureScheme;
use rtci::peer_connection::certificate::RTCCertificate;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::rtc_error::RTCErrorDetailType;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    RTCDtlsRole, RTCIceCandidateInit, RTCIceRole, RTCIceTransportState,
};
use std::time::{Instant, SystemTime};

fn engine(role: RTCDtlsRole) -> SettingEngineBuilder {
    SettingEngineBuilder::new().with_answering_dtls_role(role)
}

fn ice_state(peer: &Peer) -> Option<RTCIceTransportState> {
    peer.pc
        .sctp()
        .map(|sctp| sctp.transport().ice_transport().state())
}

fn ice_role(peer: &Peer) -> Option<RTCIceRole> {
    peer.pc
        .sctp()
        .map(|sctp| sctp.transport().ice_transport().role())
}

/// W3C 4.2.1 `certificates`: with several, the implementation selects the one a connection
/// uses; every one has its fingerprint in the description. The engine presents the first:
/// the peer's DTLS transport reports it as the remote certificate.
#[test]
fn of_several_certificates_the_first_is_presented() -> Result<()> {
    let provider = rtci::crypto::default_provider()?;
    let now = SystemTime::now();
    let first = RTCCertificate::generate_certificate(
        provider.crypto(),
        SignatureScheme::EcdsaP256Sha256,
        None,
        now,
    )?;
    let second = RTCCertificate::generate_certificate(
        provider.crypto(),
        SignatureScheme::EcdsaP256Sha256,
        None,
        now,
    )?;
    let start = Instant::now();
    let offerer = Peer::with_configuration(
        "127.0.0.1:52110".parse()?,
        engine(RTCDtlsRole::Server),
        RTCConfigurationBuilder::new()
            .with_certificates(vec![first.clone(), second.clone()])
            .build(),
        start,
    )?;
    let answerer = Peer::new("127.0.0.1:52111".parse()?, RTCDtlsRole::Client, start)?;
    let mut pair = Pair::of(offerer, answerer, start);
    pair.offerer.pc.create_data_channel("data", None)?;
    let (offer, _) = pair.negotiate()?;
    let fingerprints = offer
        .sdp
        .lines()
        .filter(|l| l.starts_with("a=fingerprint:sha-256 "))
        .count();
    assert!(
        fingerprints >= 2,
        "both certificates are described:\n{}",
        offer.sdp
    );
    assert!(pair.run_until(|p| p.offerer.connected() && p.answerer.connected())?);

    let presented = pair
        .answerer
        .pc
        .sctp()
        .expect("sctp")
        .transport()
        .get_remote_certificates()
        .first()
        .cloned()
        .expect("a remote certificate");
    assert_eq!(
        presented,
        first.dtls_certificate.certificate[0].as_ref().to_vec(),
        "the first certificate"
    );
    assert_ne!(
        presented,
        second.dtls_certificate.certificate[0].as_ref().to_vec()
    );
    Ok(())
}

/// W3C 5.6 `[[IceRole]]`: after a role conflict (RFC 8445 section 7.3.1.1) the transport's
/// role is the one the conflict left. The answerer is told the offerer is a lite agent, so
/// both start controlling; the offerer's smaller tie-breaker makes it switch to controlled.
#[test]
fn a_role_conflict_leaves_the_ice_role_the_conflict_decided() -> Result<()> {
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52120",
        engine(RTCDtlsRole::Client).with_ice_tie_breaker(1),
        "127.0.0.1:52121",
        engine(RTCDtlsRole::Server).with_ice_tie_breaker(u64::MAX),
    )?;
    pair.offerer.pc.create_data_channel("data", None)?;
    pair.exchange_with(
        false,
        |offer| offer.replacen("t=0 0\r\n", "t=0 0\r\na=ice-lite\r\n", 1),
        |answer| answer.to_owned(),
    )?;
    assert_eq!(ice_role(&pair.answerer), Some(RTCIceRole::Controlling));
    assert_eq!(ice_role(&pair.offerer), Some(RTCIceRole::Controlling));
    assert!(pair.run_until(|p| p.offerer.connected() && p.answerer.connected())?);
    assert_eq!(
        ice_role(&pair.offerer),
        Some(RTCIceRole::Controlled),
        "the offerer lost the tie-break"
    );
    assert_eq!(ice_role(&pair.answerer), Some(RTCIceRole::Controlling));
    Ok(())
}

/// W3C 5.6.4: an ICE restart takes a "failed" (or "disconnected") transport back to
/// "checking", and then connects again. The offerer ends its gathering and is told the
/// answerer's end-of-candidates, so that losing consent fails its transport ("failed" needs
/// them; without them it would stay "disconnected").
#[test]
fn an_ice_restart_takes_a_failed_transport_back_to_checking() -> Result<()> {
    let (mut pair, _) = Pair::connected(RTCDtlsRole::Client, "data")?;
    pair.offerer
        .pc
        .add_local_candidate(RTCIceCandidateInit::default())?;
    pair.offerer.pc.add_remote_candidate(RTCIceCandidateInit {
        sdp_mline_index: Some(0),
        ..Default::default()
    })?;
    pair.offerer.drop_outgoing = true;
    pair.answerer.drop_outgoing = true;
    assert!(
        pair.run_until(|p| ice_state(&p.offerer) == Some(RTCIceTransportState::Failed))?,
        "consent lapses: {:?}",
        ice_state(&pair.offerer)
    );
    pair.offerer.drop_outgoing = false;
    pair.answerer.drop_outgoing = false;

    pair.offerer.pc.restart_ice();
    pair.negotiate()?;
    pair.trickle()?;
    assert_eq!(
        ice_state(&pair.offerer),
        Some(RTCIceTransportState::Checking),
        "a restarted failed transport is checking"
    );
    assert!(pair.run_until(
        |p| ice_state(&p.offerer) == Some(RTCIceTransportState::Connected)
            || ice_state(&p.offerer) == Some(RTCIceTransportState::Completed)
    )?);
    Ok(())
}

/// W3C 11.1 `RTCError.sentAlert`: a DTLS handshake this side ends with a fatal alert fails
/// its transport with `dtls-failure` and the alert it sent; the peer's error names it as
/// received. The two sides share no cipher suite, so the server refuses the ClientHello.
#[test]
fn a_dtls_failure_this_side_ended_names_the_alert_it_sent() -> Result<()> {
    let mut pair = Pair::with_setting_engines(
        "127.0.0.1:52130",
        engine(RTCDtlsRole::Server)
            .with_dtls_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]),
        "127.0.0.1:52131",
        engine(RTCDtlsRole::Client).with_dtls_cipher_suites(vec![
            CipherSuiteId::Tls_Ecdhe_Ecdsa_With_ChaCha20_Poly1305_Sha256,
        ]),
    )?;
    pair.offerer.tolerate_read_errors = true;
    pair.answerer.tolerate_read_errors = true;
    pair.offerer.pc.create_data_channel("data", None)?;
    pair.negotiate()?;
    let failed = |p: &Peer| p.connection_states.last() == Some(&RTCPeerConnectionState::Failed);
    assert!(pair.run_until(|p| failed(&p.offerer) && failed(&p.answerer))?);

    let error_of = |peer: &Peer| {
        peer.other_events
            .iter()
            .find_map(|e| match e {
                RTCPeerConnectionEvent::OnDtlsTransportError(error) => Some(error.clone()),
                _ => None,
            })
            .expect("an error event")
    };
    // The offerer is the DTLS server: it sent the alert.
    let server = error_of(&pair.offerer);
    assert_eq!(server.error_detail, RTCErrorDetailType::DtlsFailure);
    assert!(server.sent_alert.is_some(), "{server:?}");
    let client = error_of(&pair.answerer);
    assert_eq!(client.error_detail, RTCErrorDetailType::DtlsFailure);
    assert_eq!(client.received_alert, server.sent_alert, "{client:?}");
    Ok(())
}

/// The non-standard PEM export and import (a server that keeps its DTLS fingerprint across
/// restarts): a certificate exported and imported again has the same fingerprints, the
/// description carries them, and DTLS completes with it, the peer seeing that certificate.
#[test]
fn a_reimported_pem_certificate_keeps_its_fingerprint_and_completes_dtls() -> Result<()> {
    let provider = rtci::crypto::default_provider()?;
    let now = SystemTime::now();
    let original = RTCCertificate::generate_certificate(
        provider.crypto(),
        SignatureScheme::EcdsaP256Sha256,
        None,
        now,
    )?;
    let pem = original.export_pem()?;
    let fingerprints = original.get_fingerprints(provider.crypto())?;
    let restarted = RTCCertificate::import_pem(&pem, provider.crypto(), now, &fingerprints)?;
    assert_eq!(restarted.get_fingerprints(provider.crypto())?, fingerprints);

    let start = Instant::now();
    let offerer = Peer::with_configuration(
        "127.0.0.1:52140".parse()?,
        engine(RTCDtlsRole::Server),
        RTCConfigurationBuilder::new()
            .with_certificates(vec![restarted])
            .build(),
        start,
    )?;
    let answerer = Peer::new("127.0.0.1:52141".parse()?, RTCDtlsRole::Client, start)?;
    let mut pair = Pair::of(offerer, answerer, start);
    pair.offerer.pc.create_data_channel("data", None)?;
    let (offer, _) = pair.negotiate()?;
    let sha256 = fingerprints
        .iter()
        .find(|f| f.algorithm == "sha-256")
        .expect("a SHA-256 fingerprint");
    assert!(
        offer.sdp.to_ascii_lowercase().contains(&format!(
            "a=fingerprint:sha-256 {}",
            sha256.value.to_ascii_lowercase()
        )),
        "{}",
        offer.sdp
    );
    assert!(pair.run_until(|p| p.offerer.connected() && p.answerer.connected())?);
    let presented = pair
        .answerer
        .pc
        .sctp()
        .expect("sctp")
        .transport()
        .get_remote_certificates()
        .first()
        .cloned()
        .expect("a remote certificate");
    assert_eq!(
        presented,
        original.dtls_certificate.certificate[0].as_ref().to_vec()
    );
    Ok(())
}

/// W3C 4.8.1 `address`: an exposed remote candidate's address stays null until the
/// application supplied it. The answerer signals no candidate of its own (it is stripped from
/// the answer and never trickled), so the offerer learns it only as a peer-reflexive candidate
/// from its checks: that pair's remote address is null in `getCandidatePairs`, the
/// selected pair and the pair events. Once the application adds the candidate, the address
/// shows.
#[test]
fn a_remote_address_the_application_never_gave_stays_null() -> Result<()> {
    let mut pair = Pair::new(RTCDtlsRole::Client)?;
    pair.offerer.pc.create_data_channel("data", None)?;
    pair.exchange_with(
        false,
        |offer| offer.to_owned(),
        |answer| {
            answer
                .split("\r\n")
                .filter(|l| !l.starts_with("a=candidate:"))
                .collect::<Vec<_>>()
                .join("\r\n")
        },
    )?;
    assert!(pair.run_until(|p| p.offerer.connected() && p.answerer.connected())?);
    let answerer_addr = pair.answerer.addr.ip().to_string();

    let selected = pair
        .offerer
        .pc
        .sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_selected_candidate_pair()
        .expect("a selected pair");
    assert_eq!(selected.remote().address, "", "{selected:?}");
    let pairs = pair
        .offerer
        .pc
        .sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_candidate_pairs();
    assert!(!pairs.is_empty());
    assert!(
        pairs.iter().all(|p| p.remote().address != answerer_addr),
        "{pairs:?}"
    );
    let announced: Vec<String> = pair
        .offerer
        .other_events
        .iter()
        .filter_map(|e| match e {
            RTCPeerConnectionEvent::OnIceCandidatePairAdd(p) => Some(p.remote().address.clone()),
            _ => None,
        })
        .collect();
    assert!(
        announced.iter().all(|a| *a != answerer_addr),
        "{announced:?}"
    );

    // The application supplies the address: it is exposed from then on.
    let candidate = pair.answerer.candidate()?;
    pair.offerer.pc.add_remote_candidate(candidate)?;
    let pairs = pair
        .offerer
        .pc
        .sctp()
        .expect("sctp")
        .transport()
        .ice_transport()
        .get_candidate_pairs();
    assert!(
        pairs.iter().any(|p| p.remote().address == answerer_addr),
        "{pairs:?}"
    );
    Ok(())
}
