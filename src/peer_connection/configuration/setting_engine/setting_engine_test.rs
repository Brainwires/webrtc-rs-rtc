//! Tests for [`SettingEngine`] and [`SettingEngineBuilder`], after Pion's
//! `settingengine_test.go`: each builder method lands where the engine reads it, the defaults
//! are the documented ones, and the settings a peer connection acts on during negotiation show
//! up in the descriptions it writes. Pion's tests of options this crate does not have (ephemeral
//! UDP port ranges, detached data channels, ICE-TCP muxes, proxy dialers, DTLS retransmission
//! intervals) have no counterpart here.

use std::time::Instant;

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;

fn pc_with(setting_engine: SettingEngine) -> crate::peer_connection::RTCPeerConnection {
    let mut media_engine = MediaEngine::default();
    media_engine
        .register_default_codecs()
        .expect("default codecs");
    RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(setting_engine)
        .build(Instant::now())
        .expect("peer connection")
}

/// An offer with an audio and a video section, from a peer with `setting_engine`.
fn offer_with(setting_engine: SettingEngine) -> String {
    let mut pc = pc_with(setting_engine);
    pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )
    .expect("audio");
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )
    .expect("video");
    pc.create_offer(None).expect("offer").sdp
}

#[test]
fn test_setting_engine_defaults() {
    let s = SettingEngine::default();
    assert!(!s.candidates.ice_lite);
    assert!(s.candidates.nat_1to1_ips.is_empty());
    assert!(
        !s.sdp_session_level_fingerprints,
        "media-level fingerprints by default"
    );
    assert!(!s.disable_certificate_fingerprint_verification);
    assert!(!s.allow_insecure_verification_algorithm);
    assert_eq!(s.answering_dtls_role, RTCDtlsRole::Unspecified);
    // RFC 8832 has no DCEP handshake timeout.
    assert_eq!(s.data_channel.dcep_handshake_timeout, None);
    assert_eq!(s.multicast_dns.timeout, Some(Duration::from_secs(10)));
    assert_eq!(s.multicast_dns.mode, MulticastDnsMode::QueryOnly);
    assert_eq!(s.replay_protection.dtls, 0);
    assert_eq!(s.replay_protection.srtp, 0);
    assert_eq!(s.replay_protection.srtcp, 0);
    assert_eq!(
        s.sctp_max_message_size.as_usize(),
        SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize
    );
    assert_eq!(s.sctp_max_receive_buffer_size, None);
    assert!(s.crypto_provider().is_none());
}

#[test]
fn test_set_connection_timeout() {
    let s = SettingEngineBuilder::new()
        .with_ice_timeouts(
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(3)),
        )
        .with_ice_connection_attempts(Some(Duration::from_millis(40)), Some(9))
        .build();
    assert_eq!(
        s.timeout.ice_disconnected_timeout,
        Some(Duration::from_secs(1))
    );
    assert_eq!(s.timeout.ice_failed_timeout, Some(Duration::from_secs(2)));
    assert_eq!(
        s.timeout.ice_keepalive_interval,
        Some(Duration::from_secs(3))
    );
    assert_eq!(
        s.timeout.ice_check_interval,
        Some(Duration::from_millis(40))
    );
    assert_eq!(s.timeout.ice_max_binding_requests, Some(9));
}

#[test]
fn test_set_candidate_acceptance_min_waits() {
    let s = SettingEngineBuilder::new()
        .with_host_acceptance_min_wait(Some(Duration::from_millis(1)))
        .with_srflx_acceptance_min_wait(Some(Duration::from_millis(2)))
        .with_prflx_acceptance_min_wait(Some(Duration::from_millis(3)))
        .with_relay_acceptance_min_wait(Some(Duration::from_millis(4)))
        .build();
    assert_eq!(
        s.timeout.ice_host_acceptance_min_wait,
        Some(Duration::from_millis(1))
    );
    assert_eq!(
        s.timeout.ice_srflx_acceptance_min_wait,
        Some(Duration::from_millis(2))
    );
    assert_eq!(
        s.timeout.ice_prflx_acceptance_min_wait,
        Some(Duration::from_millis(3))
    );
    assert_eq!(
        s.timeout.ice_relay_acceptance_min_wait,
        Some(Duration::from_millis(4))
    );
}

#[test]
fn test_set_nat_1to1_ips() {
    let s = SettingEngineBuilder::new()
        .with_nat_1to1_ips(vec!["1.2.3.4".to_owned()], RTCIceCandidateType::Srflx)
        .build();
    assert_eq!(s.candidates.nat_1to1_ips, vec!["1.2.3.4".to_owned()]);
    assert_eq!(
        s.candidates.nat_1to1_ip_candidate_type,
        RTCIceCandidateType::Srflx
    );
}

#[test]
fn test_set_answering_dtls_role() {
    // The builder does not validate the role (see `with_answering_dtls_role`): every value is
    // stored as given.
    for role in [
        RTCDtlsRole::Auto,
        RTCDtlsRole::Client,
        RTCDtlsRole::Server,
        RTCDtlsRole::Unspecified,
    ] {
        let s = SettingEngineBuilder::new()
            .with_answering_dtls_role(role)
            .build();
        assert_eq!(s.answering_dtls_role, role);
    }
}

/// The answering role decides the `a=setup` of an answer (RFC 8842 §5.2).
#[test]
fn test_answering_dtls_role_in_answer() {
    for (role, setup) in [
        (RTCDtlsRole::Client, "a=setup:active"),
        (RTCDtlsRole::Server, "a=setup:passive"),
    ] {
        let mut offerer = pc_with(SettingEngine::default());
        offerer
            .add_transceiver_from_kind(
                RtpCodecKind::Video,
                Some(crate::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
            )
            .expect("video");
        let offer = offerer.create_offer(None).expect("offer");

        let mut answerer = pc_with(
            SettingEngineBuilder::new()
                .with_answering_dtls_role(role)
                .build(),
        );
        answerer
            .set_remote_description(Instant::now(), offer)
            .expect("remote offer");
        let answer = answerer.create_answer(None).expect("answer");
        assert!(answer.sdp.contains(setup), "{role:?}: {}", answer.sdp);
    }
}

#[test]
fn test_set_replay_protection() {
    let s = SettingEngineBuilder::new()
        .with_dtls_replay_protection_window(128)
        .with_srtp_replay_protection_window(64)
        .with_srtcp_replay_protection_window(32)
        .build();
    assert_eq!(s.replay_protection.dtls, 128);
    assert_eq!(s.replay_protection.srtp, 64);
    assert_eq!(s.replay_protection.srtcp, 32);
}

#[test]
fn test_set_multicast_dns() {
    let ip: IpAddr = "192.168.1.2".parse().unwrap();
    let s = SettingEngineBuilder::new()
        .with_multicast_dns_timeout(Some(Duration::from_secs(3)))
        .with_multicast_dns_mode(MulticastDnsMode::QueryAndGather)
        .with_multicast_dns_local_name("local.local".to_owned())
        .with_multicast_dns_local_ip(Some(ip))
        .build();
    let mdns = s.multicast_dns();
    assert_eq!(mdns.timeout, Some(Duration::from_secs(3)));
    assert_eq!(mdns.mode, MulticastDnsMode::QueryAndGather);
    assert_eq!(mdns.local_name, "local.local");
    assert_eq!(mdns.local_ip, Some(ip));
}

#[test]
// Calls a builder method deprecated as a no-op (stored, never read); this checks it still stores.
#[allow(deprecated)]
fn test_set_network_types_and_candidates() {
    let s = SettingEngineBuilder::new()
        .with_network_types(vec![NetworkType::Udp4, NetworkType::Tcp4])
        .with_include_loopback_candidate(true)
        .with_discard_local_candidates_during_ice_restart(true)
        .build();
    assert_eq!(
        s.candidates.ice_network_types,
        vec![NetworkType::Udp4, NetworkType::Tcp4]
    );
    assert!(s.candidates.include_loopback_candidate);
    assert!(s.discard_local_candidates_during_ice_restart());
}

#[test]
// Calls a builder method deprecated as a no-op (stored, never read); this checks it still stores.
#[allow(deprecated)]
fn test_set_verification_flags() {
    let s = SettingEngineBuilder::new()
        .with_disable_certificate_fingerprint_verification(true)
        .with_allow_insecure_verification_algorithm(true)
        .with_disable_media_engine_copy(true)
        .with_disable_media_engine_multiple_codecs(true)
        .build();
    assert!(s.disable_certificate_fingerprint_verification);
    assert!(s.allow_insecure_verification_algorithm);
    assert!(s.disable_media_engine_copy);
    assert!(s.disable_media_engine_multiple_codecs);
}

#[test]
// Calls a builder method deprecated as a no-op (stored, never read); this checks it still stores.
#[allow(deprecated)]
fn test_set_dtls_srtp_parameters() {
    let s = SettingEngineBuilder::new()
        .with_srtp_protection_profiles(vec![SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm])
        .with_dtls_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
        .with_receive_mtu(1200)
        .build();
    assert_eq!(
        s.srtp_protection_profiles,
        vec![SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm]
    );
    assert_eq!(
        s.dtls_cipher_suites,
        vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256]
    );
    assert_eq!(s.receive_mtu, 1200);
}

#[test]
fn test_set_sctp_parameters() {
    let s = SettingEngineBuilder::new()
        .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(1024))
        .with_sctp_max_receive_buffer_size(4096)
        .with_sctp_mtu(1100)
        .with_sctp_weighted_fair_queueing(true)
        .with_dcep_handshake_timeout(None)
        .build();
    assert_eq!(s.sctp_max_message_size.as_usize(), 1024);
    assert_eq!(s.sctp_max_receive_buffer_size, Some(4096));
    assert_eq!(s.sctp_mtu, Some(1100));
    assert_eq!(s.sctp_weighted_fair_queueing, Some(true));
    assert_eq!(s.data_channel.dcep_handshake_timeout, None);

    // A bound past the implementation ceiling, and no bound at all, both resolve to the ceiling.
    assert_eq!(
        SctpMaxMessageSize::Bounded(u32::MAX).as_usize(),
        SctpMaxMessageSize::MAX_MESSAGE_SIZE as usize
    );
    assert_eq!(
        SctpMaxMessageSize::Unbounded.as_usize(),
        SctpMaxMessageSize::MAX_MESSAGE_SIZE as usize
    );
}

#[test]
fn test_set_simulcast_flags() {
    let s = SettingEngineBuilder::new()
        .with_ignore_rid_pause_for_recv(true)
        .with_write_ssrc_attributes_for_simulcast(true)
        .build();
    assert!(s.ignore_rid_pause_for_recv);
    assert!(s.write_ssrc_attributes_for_simulcast);
}

#[test]
fn test_set_mid_generator() {
    let s = SettingEngineBuilder::new()
        .with_mid_generator(|max_mid| format!("custom_{}", max_mid + 1))
        .build();
    let generator = s.mid_generator.as_ref().expect("a generator is stored");
    assert_eq!(generator(4), "custom_5");
}

/// RFC 9429 section 5.2.1: attributes allowed at both levels "SHOULD generally be at the
/// media level": by default every media section has the DTLS fingerprint;
/// `with_sdp_media_level_fingerprints(false)` puts one at session level.
#[test]
fn test_sdp_media_level_fingerprints() {
    let media_level = offer_with(SettingEngine::default());
    assert_eq!(
        media_level.matches("a=fingerprint:").count(),
        2,
        "{media_level}"
    );

    let session_level = offer_with(
        SettingEngineBuilder::new()
            .with_sdp_media_level_fingerprints(false)
            .build(),
    );
    assert_eq!(
        session_level.matches("a=fingerprint:").count(),
        1,
        "{session_level}"
    );
}

/// `with_lite` makes the peer an ICE lite agent, which says so in its offer (RFC 8839 §5.3).
#[test]
fn test_set_lite() {
    let full = offer_with(SettingEngine::default());
    assert!(!full.contains("a=ice-lite"), "{full}");
    assert!(full.contains("a=ice-options:trickle"), "{full}");
    // RFC 8839 section 4.3.1: a full implementation SHOULD state its Ta, a lite one MUST NOT.
    assert!(full.contains("a=ice-pacing:50\r\n"), "{full}");

    let lite = offer_with(SettingEngineBuilder::new().with_lite(true).build());
    assert!(lite.contains("a=ice-lite"), "{lite}");
    // RFC 8840 section 4 / RFC 8838 Appendix B: a lite agent that trickles says so.
    assert!(lite.contains("a=ice-options:trickle ice2"), "{lite}");
    assert!(!lite.contains("a=ice-pacing"), "{lite}");
}

/// Fixed ICE credentials are the ones the offer carries.
#[test]
fn test_set_ice_credentials() {
    let ufrag = "FixedUfrag";
    let pwd = "FixedPasswordFixedPassword";
    let offer = offer_with(
        SettingEngineBuilder::new()
            .with_ice_credentials(ufrag.to_owned(), pwd.to_owned())
            .build(),
    );
    assert!(offer.contains(&format!("a=ice-ufrag:{ufrag}")), "{offer}");
    assert!(offer.contains(&format!("a=ice-pwd:{pwd}")), "{offer}");
}
