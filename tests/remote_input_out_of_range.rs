//! A remote description or trickled candidate carries numbers the peer chooses. Values at the
//! ends of their types used to panic later: a candidate component above 256 underflowed its
//! priority, and a numeric mid of `isize::MAX` overflowed the next mid a local offer assigned.
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_OPUS, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
};
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodec;
use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use std::time::Instant;

fn make_media_engine() -> MediaEngine {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_OPUS.to_owned(),
                clock_rate: 48000,
                channels: 2,
                sdp_fmtp_line: "".to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 111,
        },
        RtpCodecKind::Audio,
    )
    .unwrap();
    me
}

fn build_pc(dtls_role: RTCDtlsRole) -> rtc::peer_connection::RTCPeerConnection {
    let se = SettingEngineBuilder::new()
        .with_answering_dtls_role(dtls_role)
        .build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_media_engine(make_media_engine())
        .with_setting_engine(se)
        .build(Instant::now())
        .unwrap();
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 9,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .unwrap();
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json().unwrap())
        .unwrap();
    pc
}

/// The answerer holds the offerer's description, with `mid` rewritten to `remote_mid`.
fn negotiated_with_remote_mid(remote_mid: &str) -> rtc::peer_connection::RTCPeerConnection {
    let mut offer_pc = build_pc(RTCDtlsRole::Server);
    let mut answer_pc = build_pc(RTCDtlsRole::Client);
    offer_pc
        .add_transceiver_from_kind(RtpCodecKind::Audio, None)
        .unwrap();
    let offer = offer_pc.create_offer(None).unwrap();
    assert!(offer.sdp.contains("a=mid:0\r\n") && offer.sdp.contains("a=group:BUNDLE 0\r\n"));
    let sdp = offer
        .sdp
        .replace("a=mid:0\r\n", &format!("a=mid:{remote_mid}\r\n"))
        .replace(
            "a=group:BUNDLE 0\r\n",
            &format!("a=group:BUNDLE {remote_mid}\r\n"),
        );
    answer_pc
        .set_remote_description(Instant::now(), RTCSessionDescription::offer(sdp).unwrap())
        .unwrap();
    let answer = answer_pc.create_answer(None).unwrap();
    answer_pc
        .set_local_description(Instant::now(), answer)
        .unwrap();
    answer_pc
}

#[test]
fn test_remote_mid_at_isize_max_does_not_panic_a_later_offer() {
    let mut pc = negotiated_with_remote_mid(&isize::MAX.to_string());
    // A new transceiver has no mid yet, so the offer must pick one above every mid in use.
    pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)
        .unwrap();
    let err = pc
        .create_offer(None)
        .expect_err("no numeric mid is left above isize::MAX");
    assert!(err.to_string().contains("mid"), "unexpected error: {err}");
}

#[test]
fn test_trickled_candidate_component_out_of_range_is_rejected() {
    let mut pc = negotiated_with_remote_mid("0");
    for component in ["300", "257", "65535", "0"] {
        let result = pc.add_remote_candidate(RTCIceCandidateInit {
            candidate: format!("candidate:1 {component} udp 0 127.0.0.1 9 typ host"),
            sdp_mid: Some("0".to_owned()),
            sdp_mline_index: Some(0),
            ..Default::default()
        });
        assert!(result.is_err(), "component {component} was accepted");
    }
    // An in-range component is still accepted.
    pc.add_remote_candidate(RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 0 127.0.0.1 9 typ host".to_owned(),
        sdp_mid: Some("0".to_owned()),
        sdp_mline_index: Some(0),
        ..Default::default()
    })
    .unwrap();
}
