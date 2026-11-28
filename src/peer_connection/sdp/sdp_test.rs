//! Ported from the async `webrtc` crate's `sdp_test.rs` to the sans-IO internals.
//!
//! The old tests built transceivers through `APIBuilder`, `DtlsTransport` and
//! `TrackLocalStaticSample` and awaited `populate_sdp`; here a transceiver is a plain
//! [`RTCRtpTransceiverInternal`] and `populate_sdp` is a synchronous associated function of
//! [`RTCPeerConnection`] that takes the transceivers it describes. Each test keeps the behaviour
//! its predecessor asserted; where the current API changed shape the test says how.

use sdp::description::common::Attribute;

use super::*;
use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8,
};
use crate::rtp_transceiver::RTCRtpTransceiverInit;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRtxParameters,
};

fn attr(key: &str, value: Option<&str>) -> Attribute {
    Attribute {
        key: key.to_owned(),
        value: value.map(str::to_owned),
    }
}

fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "".to_owned(),
        rtcp_feedback: vec![],
    }
}

fn default_media_engine() -> MediaEngine {
    let mut me = MediaEngine::default();
    me.register_default_codecs().expect("default codecs");
    me
}

fn recvonly_transceiver(kind: RtpCodecKind) -> RTCRtpTransceiverInternal {
    RTCRtpTransceiverInternal::new(
        kind,
        None,
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Recvonly,
            streams: vec![],
            send_encodings: vec![],
        },
    )
}

fn sendonly_transceiver(
    kind: RtpCodecKind,
    encodings: Vec<RTCRtpEncodingParameters>,
) -> RTCRtpTransceiverInternal {
    let track = MediaStreamTrack::new(
        "webrtc-rs".to_owned(),
        "video".to_owned(),
        "video".to_owned(),
        kind,
        encodings.clone(),
    );
    RTCRtpTransceiverInternal::new(
        kind,
        Some(track),
        RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendonly,
            streams: vec![],
            send_encodings: encodings,
        },
    )
}

fn params(
    media_description_fingerprint: bool,
    match_bundle_group: Option<String>,
) -> PopulateSdpParams {
    PopulateSdpParams {
        media_description_fingerprint,
        is_ice_lite: false,
        is_extmap_allow_mixed: true,
        // DEFAULT_DTLS_ROLE_OFFER in the old crate: an offer is `actpass`.
        connection_role: ConnectionRole::Actpass,
        ice_gathering_state: RTCIceGatheringState::Complete,
        bundle: match match_bundle_group {
            None => BundleMode::initial_offer(),
            Some(group) => {
                BundleMode::Answer(vec![group.split_whitespace().map(str::to_owned).collect()])
            }
        },
        offered_tag_rtcp_mux_only: false,
        rtcp_mux_only: true,
        rtcp_mux_only_renegotiated: false,
        bundle_policy: RTCBundlePolicy::MaxCompat,
        initial_offer: false,
        bundle_attributes_in_tagged_section_only: false,
        bundle_only_browser_form: false,
        answer_offered_formats_only: false,
        sctp_max_message_size: 0,
        sctp_port: 5000,
        sctp_over_tcp: false,
        ignore_rid_pause_for_recv: false,
        write_ssrc_attributes_for_simulcast: false,
        ice_pacing: None,
        ice_options_in_media_sections: false,
        ice_options: vec!["trickle", "ice2"],
        ls_groups: vec![],
        selected_destination: None,
        remote_candidates: vec![],
        ecn: None,
        rid_pause_marks: false,
        video_receive_limits: None,
        codec_video_receive_limits: vec![],
        w3c_simulcast_answer: false,
        msid_appdata: false,
    }
}

fn media_section(mid: &str, transceiver_index: usize) -> MediaSection {
    MediaSection {
        mid: mid.to_owned(),
        transceiver_index,
        ..Default::default()
    }
}

fn populate(
    me: &MediaEngine,
    transceivers: &mut [RTCRtpTransceiverInternal],
    media_sections: &[MediaSection],
    params: PopulateSdpParams,
    fingerprints: &[RTCDtlsFingerprint],
) -> Result<SessionDescription> {
    RTCPeerConnection::populate_sdp(
        SessionDescription::default(),
        fingerprints,
        me,
        transceivers,
        &[],
        &RTCIceParameters::default(),
        media_sections,
        params,
    )
}

#[test]
fn test_extract_fingerprint() -> Result<()> {
    const SHA256_A: &str = "sha-256 AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA:AA";
    const SHA256_B: &str = "sha-256 BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB:BB";

    //"Good Session Fingerprint"
    {
        let s = SessionDescription {
            attributes: vec![attr("fingerprint", Some(SHA256_A))],
            ..Default::default()
        };

        let fingerprints = extract_fingerprints(&s)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].value, &SHA256_A[8..]);
        assert_eq!(fingerprints[0].algorithm, "sha-256");
    }

    //"Good Media Fingerprint"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                attributes: vec![attr("fingerprint", Some(SHA256_A))],
                ..Default::default()
            }],
            ..Default::default()
        };

        let fingerprints = extract_fingerprints(&s)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].value, &SHA256_A[8..]);
        assert_eq!(fingerprints[0].algorithm, "sha-256");
    }

    //"No Fingerprint"
    {
        let s = SessionDescription::default();

        assert_eq!(
            extract_fingerprints(&s).expect_err("fingerprint absence must be detected"),
            Error::ErrSessionDescriptionNoFingerprint
        );
    }

    //"Invalid Fingerprint": no value, a value that is not hex bytes (RFC 8122 section 5), a
    // value of the wrong length for its hash function, an attribute without a value.
    for invalid in [Some("foo"), Some("foo bar"), Some("sha-256 AA:BB"), None] {
        let s = SessionDescription {
            attributes: vec![attr("fingerprint", invalid)],
            ..Default::default()
        };

        assert_eq!(
            extract_fingerprints(&s).expect_err("invalid fingerprint text must be detected"),
            Error::ErrSessionDescriptionInvalidFingerprint,
            "{invalid:?}"
        );
    }

    //"Conflicting Fingerprint"
    //
    // Two m-sections of the one transport with different fingerprints are a conflict. (A
    // session-level fingerprint next to a different media-level one is not: the media level
    // overrides it, RFC 8122 section 5.)
    {
        let live = |fingerprint| MediaDescription {
            media_name: MediaName {
                media: "audio".to_owned(),
                port: RangedPort {
                    value: 9,
                    range: None,
                },
                protos: vec![],
                formats: vec![],
            },
            attributes: vec![attr("fingerprint", Some(fingerprint))],
            ..Default::default()
        };
        let s = SessionDescription {
            media_descriptions: vec![live(SHA256_B), live(SHA256_A)],
            ..Default::default()
        };

        assert_eq!(
            extract_fingerprints(&s).expect_err("mismatching fingerprint texts must be detected"),
            Error::ErrSessionDescriptionConflictingFingerprints
        );

        let s = SessionDescription {
            attributes: vec![attr("fingerprint", Some(SHA256_B))],
            media_descriptions: vec![live(SHA256_A)],
            ..Default::default()
        };
        let fingerprints = extract_fingerprints(&s)?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].value, &SHA256_A[8..]);
    }

    Ok(())
}

#[test]
fn test_extract_ice_details() -> Result<()> {
    // The old constants ("DEFAULT_PWD" / "DEFAULT_UFRAG", swapped) are not valid ICE
    // credentials: `_` is not an ice-char and the password is shorter than 22 characters
    // (RFC 8839 §5.4), which `extract_ice_details` now checks.
    const DEFAULT_UFRAG: &str = "DEFAULTufrag";
    const DEFAULT_PWD: &str = "DEFAULTpasswordDEFAULTpassword";
    // A section with port 0 is rejected (RFC 8843 §6) and sets up no transport, so every
    // section here has a real port; the old tests left it at the default 0.
    let in_use = || MediaName {
        media: "audio".to_owned(),
        port: RangedPort {
            value: 9,
            range: None,
        },
        ..Default::default()
    };

    //"Missing ice-pwd"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![attr("ice-ufrag", Some(DEFAULT_UFRAG))],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("ICE requires password for authentication"),
            Error::ErrSessionDescriptionMissingIcePwd
        );
    }

    //"Missing ice-ufrag"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![attr("ice-pwd", Some(DEFAULT_PWD))],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("ICE requires 'user fragment' for authentication"),
            Error::ErrSessionDescriptionMissingIceUfrag
        );
    }

    //"ice details at session level"
    {
        let s = SessionDescription {
            attributes: vec![
                attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                attr("ice-pwd", Some(DEFAULT_PWD)),
            ],
            media_descriptions: vec![],
            ..Default::default()
        };

        let details = extract_ice_details(&s)?.expect("session credentials set up a transport");
        assert_eq!(details.ufrag, DEFAULT_UFRAG);
        assert_eq!(details.pwd, DEFAULT_PWD);
    }

    //"ice details at media level"
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![
                    attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                    attr("ice-pwd", Some(DEFAULT_PWD)),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        let details = extract_ice_details(&s)?.expect("media credentials set up a transport");
        assert_eq!(details.ufrag, DEFAULT_UFRAG);
        assert_eq!(details.pwd, DEFAULT_PWD);
    }

    //"Conflict ufrag"
    {
        let s = SessionDescription {
            attributes: vec![attr("ice-ufrag", Some("invalidUfrag"))],
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![
                    attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                    attr("ice-pwd", Some(DEFAULT_PWD)),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("mismatching ICE ufrags must be detected"),
            Error::ErrSessionDescriptionConflictingIceUfrag
        );
    }

    //"Conflict pwd"
    {
        let s = SessionDescription {
            attributes: vec![attr("ice-pwd", Some("invalidPasswordInvalidPassword"))],
            media_descriptions: vec![MediaDescription {
                media_name: in_use(),
                attributes: vec![
                    attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                    attr("ice-pwd", Some(DEFAULT_PWD)),
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        assert_eq!(
            extract_ice_details(&s).expect_err("mismatching ICE passwords must be detected"),
            Error::ErrSessionDescriptionConflictingIcePwd
        );
    }

    //"Allow Conflict ufrag from inactive MediaDescription"
    {
        let s = SessionDescription {
            media_descriptions: vec![
                MediaDescription {
                    media_name: in_use(),
                    attributes: vec![
                        attr("ice-ufrag", Some(DEFAULT_UFRAG)),
                        attr("ice-pwd", Some(DEFAULT_PWD)),
                    ],
                    ..Default::default()
                },
                MediaDescription {
                    media_name: in_use(),
                    attributes: vec![
                        attr("ice-ufrag", Some("invalidUfrag")),
                        attr("ice-pwd", Some(DEFAULT_PWD)),
                        attr(ATTR_KEY_INACTIVE, None),
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let details = extract_ice_details(&s)
            .expect("should allow conflicting ICE ufrag when MediaDescription is inactive")
            .expect("a transport");
        assert_eq!(details.ufrag, DEFAULT_UFRAG);
        assert_eq!(details.pwd, DEFAULT_PWD);
    }

    Ok(())
}

fn media(kind: &str, attributes: Vec<Attribute>) -> MediaDescription {
    MediaDescription {
        media_name: MediaName {
            media: kind.to_owned(),
            ..Default::default()
        },
        attributes,
        ..Default::default()
    }
}

#[test]
fn test_track_details_from_sdp() -> Result<()> {
    //"Tracks unknown, audio and video with RTX"
    {
        let s = SessionDescription {
            media_descriptions: vec![
                media(
                    "foobar",
                    vec![
                        attr("mid", Some("0")),
                        attr("sendrecv", None),
                        attr("ssrc", Some("1000 msid:unknown_trk_label unknown_trk_guid")),
                    ],
                ),
                media(
                    "audio",
                    vec![
                        attr("mid", Some("1")),
                        attr("sendrecv", None),
                        attr("ssrc", Some("2000 msid:audio_trk_label audio_trk_guid")),
                    ],
                ),
                media(
                    "video",
                    vec![
                        attr("mid", Some("2")),
                        attr("sendrecv", None),
                        attr("ssrc", Some("3000 msid:video_trk_label video_trk_guid")),
                        attr("ssrc", Some("4000 msid:rtx_trk_label rtx_trck_guid")),
                        attr("ssrc-group", Some("FID 3000 4000")),
                    ],
                ),
                media(
                    "video",
                    vec![
                        attr("mid", Some("3")),
                        attr("sendonly", None),
                        attr("msid", Some("video_stream_id video_trk_id")),
                        attr("ssrc", Some("5000")),
                    ],
                ),
                // No mid: not a section a track can be bound to, so it is skipped.
                media(
                    "video",
                    vec![
                        attr("sendonly", None),
                        attr(
                            SDP_ATTRIBUTE_RID,
                            Some("f send pt=97;max-width=1280;max-height=720"),
                        ),
                    ],
                ),
            ],
            ..Default::default()
        };

        let tracks = track_details_from_sdp(&s, RidIdGrammar::Corrected);
        assert_eq!(tracks.len(), 3);
        if track_details_for_ssrc(&tracks, 1000).is_some() {
            panic!("got the unknown track ssrc:1000 which should have been skipped");
        }
        if let Some(track) = track_details_for_ssrc(&tracks, 2000) {
            assert_eq!(track.kind, RtpCodecKind::Audio);
            assert_eq!(track.ssrc, Some(2000));
            assert_eq!(track.stream_id, "audio_trk_label");
        } else {
            panic!("missing audio track with ssrc:2000");
        }
        if let Some(track) = track_details_for_ssrc(&tracks, 3000) {
            assert_eq!(track.kind, RtpCodecKind::Video);
            assert_eq!(track.ssrc, Some(3000));
            assert_eq!(track.stream_id, "video_trk_label");
            assert_eq!(track.rtx_ssrc, Some(4000));
        } else {
            panic!("missing video track with ssrc:3000");
        }
        if track_details_for_ssrc(&tracks, 4000).is_some() {
            panic!("got the rtx track ssrc:4000 which should have been skipped");
        }
        if let Some(track) = track_details_for_ssrc(&tracks, 5000) {
            assert_eq!(track.kind, RtpCodecKind::Video);
            assert_eq!(track.ssrc, Some(5000));
            assert_eq!(track.track_id, "video_trk_id");
            assert_eq!(track.stream_id, "video_stream_id");
        } else {
            panic!("missing video track with ssrc:5000");
        }
    }

    // Inactive and recvonly sections carry no incoming track. The old function took an
    // `exclude_inactive` flag and could be asked to keep inactive sections; the current one
    // always skips both, which was the flag's `true` case.
    {
        let s = SessionDescription {
            media_descriptions: vec![
                media(
                    "video",
                    vec![
                        attr("mid", Some("1")),
                        attr("inactive", None),
                        attr("ssrc", Some("6000")),
                    ],
                ),
                media(
                    "video",
                    vec![
                        attr("mid", Some("1")),
                        attr("recvonly", None),
                        attr("ssrc", Some("7000")),
                    ],
                ),
            ],
            ..Default::default()
        };
        assert_eq!(
            track_details_from_sdp(&s, RidIdGrammar::Corrected).len(),
            0,
            "inactive and recvonly tracks should be ignored"
        );
    }

    Ok(())
}

#[test]
fn test_have_application_media_section() -> Result<()> {
    //"Audio only"
    {
        let s = SessionDescription {
            media_descriptions: vec![media(
                "audio",
                vec![attr("sendrecv", None), attr("ssrc", Some("2000"))],
            )],
            ..Default::default()
        };

        assert!(get_application_media(&s).is_none());
    }

    //"Application"
    //
    // The data channel section is now recognised by its format (`webrtc-datachannel`, RFC 8841),
    // not by the media name alone, and the SCTP port is read from that section.
    {
        let s = SessionDescription {
            media_descriptions: vec![MediaDescription {
                media_name: MediaName {
                    media: MEDIA_SECTION_APPLICATION.to_owned(),
                    protos: vec!["UDP".to_owned(), "DTLS".to_owned(), "SCTP".to_owned()],
                    formats: vec!["webrtc-datachannel".to_owned()],
                    ..Default::default()
                },
                attributes: vec![attr("sctp-port", Some("5000"))],
                ..Default::default()
            }],
            ..Default::default()
        };

        let application = get_application_media(&s).expect("the data channel section");
        assert_eq!(
            get_application_media_section_sctp_port(application),
            Ok(Some(5000))
        );
    }

    Ok(())
}

/// A data channel section as a peer writes it: `m=application <port> <proto>
/// webrtc-datachannel` with the given attributes.
fn data_section(port: isize, proto: &str, attributes: Vec<Attribute>) -> MediaDescription {
    MediaDescription {
        media_name: MediaName {
            media: MEDIA_SECTION_APPLICATION.to_owned(),
            port: RangedPort {
                value: port,
                range: None,
            },
            protos: proto.split('/').map(ToOwned::to_owned).collect(),
            formats: vec!["webrtc-datachannel".to_owned()],
        },
        attributes,
        ..Default::default()
    }
}

fn description(media_descriptions: Vec<MediaDescription>) -> SessionDescription {
    SessionDescription {
        media_descriptions,
        ..Default::default()
    }
}

/// RFC 8841 section 4.4.2: a data channel section is `m=application` with proto
/// `UDP/DTLS/SCTP` or `TCP/DTLS/SCTP` and the fmt `webrtc-datachannel`. The proto used not to
/// be looked at, so any `m=application ... webrtc-datachannel` line started SCTP over DTLS
/// over UDP.
#[test]
fn a_data_channel_section_is_told_by_its_proto_and_fmt() {
    for (proto, is_data) in [
        ("UDP/DTLS/SCTP", true),
        ("TCP/DTLS/SCTP", true),
        ("DTLS/SCTP", false),
        ("UDP/TLS/RTP/SAVPF", false),
        ("SCTP", false),
        ("UDP/DTLS/SCTP/X", false),
    ] {
        let section = data_section(9, proto, vec![attr("sctp-port", Some("5000"))]);
        assert_eq!(section.is_webrtc_datachannel(), is_data, "{proto}");
        assert_eq!(
            get_application_media(&description(vec![section])).is_some(),
            is_data,
            "{proto}"
        );
    }

    // Exactly one fmt, and that one (section 4.3).
    let mut two_formats = data_section(9, "UDP/DTLS/SCTP", vec![]);
    two_formats.media_name.formats.push("other".to_owned());
    assert!(!two_formats.is_webrtc_datachannel());
    let mut other_format = data_section(9, "UDP/DTLS/SCTP", vec![]);
    other_format.media_name.formats = vec!["5000".to_owned()];
    assert!(!other_format.is_webrtc_datachannel());
}

/// An `m=application` line that is neither a data channel section nor RTP is media this
/// endpoint does not know: the `DTLS/SCTP 5000` section of the drafts before RFC 8841 is
/// one. Application media over RTP (SMPTE ST 336) is not.
#[test]
fn an_application_section_that_is_neither_data_channel_nor_rtp_is_unknown() {
    let section = |proto: &str, fmt: &str| {
        let mut section = data_section(9, proto, vec![]);
        section.media_name.formats = vec![fmt.to_owned()];
        section
    };
    for (proto, fmt, unknown) in [
        ("DTLS/SCTP", "5000", true),
        ("UDP/DTLS/SCTP", "5000", true),
        ("UDP/DTLS/SCTP", "webrtc-datachannel", false),
        ("TCP/DTLS/SCTP", "webrtc-datachannel", false),
        ("UDP/TLS/RTP/SAVPF", "96", false),
        ("UDP/BFCP", "*", true),
    ] {
        assert_eq!(
            is_unknown_media_protocol(&section(proto, fmt)),
            unknown,
            "m=application 9 {proto} {fmt}"
        );
    }
    assert!(!is_unknown_media_protocol(&media("audio", vec![])));
    assert_eq!(
        unknown_media_name(&section("DTLS/SCTP", "5000")).map(|name| name.to_string()),
        Some("application 9 DTLS/SCTP 5000".to_owned())
    );
}

/// RFC 8841 section 5.2: `sctp-port-value = 1*5(DIGIT)`, in 0..=65535. Anything else is not
/// a port; it used to be read as "no port", which the caller turned into 5000.
#[test]
fn sctp_port_is_one_to_five_digits_up_to_65535() {
    let port_of = |value: Option<&str>| {
        get_application_media_section_sctp_port(&data_section(
            9,
            "UDP/DTLS/SCTP",
            vec![attr("sctp-port", value)],
        ))
    };
    for (value, port) in [
        ("5000", 5000),
        ("0", 0),
        ("1", 1),
        ("65535", 65535),
        ("05000", 5000),
    ] {
        assert_eq!(port_of(Some(value)), Ok(Some(port)), "{value:?}");
    }
    for value in [
        "65536", "70000", "123456", "+5000", "-1", "5000 ", " 5000", "5e3", "0x50", "port", "",
    ] {
        assert_eq!(
            port_of(Some(value)),
            Err(Error::ErrSDPSctpPortInvalid),
            "{value:?}"
        );
    }
    assert_eq!(port_of(None), Err(Error::ErrSDPSctpPortInvalid), "no value");

    // No attribute at all. The `a=sctpmap` of the drafts before RFC 8841 is not a source of
    // the port: it belongs to the `DTLS/SCTP` m= line, which is not a data channel section.
    assert_eq!(
        get_application_media_section_sctp_port(&data_section(9, "UDP/DTLS/SCTP", vec![])),
        Ok(None)
    );
    assert_eq!(
        get_application_media_section_sctp_port(&data_section(
            9,
            "UDP/DTLS/SCTP",
            vec![attr("sctpmap", Some("5000 webrtc-datachannel 1024"))]
        )),
        Ok(None)
    );
}

/// RFC 8841 section 5.1: "if the attribute is not present, the associated 'm=' line MUST be
/// considered invalid". A rejected section (port zero) carries no attributes and is fine.
#[test]
fn a_data_section_without_a_valid_sctp_port_is_invalid() {
    let valid = |section| validate_application_media_section(&description(vec![section]));
    assert_eq!(
        valid(data_section(
            9,
            "UDP/DTLS/SCTP",
            vec![attr("sctp-port", Some("5000"))]
        )),
        Ok(())
    );
    assert_eq!(
        valid(data_section(
            9,
            "UDP/DTLS/SCTP",
            vec![attr("sctp-port", Some("0"))]
        )),
        Ok(()),
        "zero is a port value: it closes the association"
    );
    assert_eq!(
        valid(data_section(9, "UDP/DTLS/SCTP", vec![])),
        Err(Error::ErrSDPSctpPortInvalid)
    );
    assert_eq!(
        valid(data_section(
            9,
            "TCP/DTLS/SCTP",
            vec![attr("sctp-port", Some("70000"))]
        )),
        Err(Error::ErrSDPSctpPortInvalid)
    );
    assert_eq!(valid(data_section(0, "UDP/DTLS/SCTP", vec![])), Ok(()));
    assert_eq!(
        validate_application_media_section(&description(vec![media("audio", vec![])])),
        Ok(())
    );
}

/// RFC 8841 section 6.1: the value is the largest message the sender of the description
/// takes, "a maximum message size value of zero ... indicates that the SCTP endpoint will
/// handle messages of any size", and without the attribute "the default value is 64K".
#[test]
fn max_message_size_zero_is_any_size_and_absent_is_the_default() {
    let size_of = |attributes| {
        get_application_media_section_max_message_size(&data_section(
            9,
            "UDP/DTLS/SCTP",
            attributes,
        ))
    };
    assert_eq!(
        size_of(vec![attr("max-message-size", Some("262144"))]),
        Some(262144)
    );
    assert_eq!(size_of(vec![attr("max-message-size", Some("0"))]), Some(0));
    assert_eq!(size_of(vec![]), None);
    assert_eq!(size_of(vec![attr("max-message-size", Some("big"))]), None);
    assert_eq!(
        size_of(vec![attr("max-message-size", Some("99999999999999999999"))]),
        Some(0),
        "more than 32 bits hold is no limit this endpoint could reach"
    );

    let with = |attributes: Vec<Attribute>| {
        let mut attributes = attributes;
        attributes.push(attr("sctp-port", Some("5000")));
        description(vec![data_section(9, "UDP/DTLS/SCTP", attributes)])
    };
    let local = with(vec![]);
    let limit = |remote: &SessionDescription| match negotiated_sctp(&local, remote) {
        SctpNegotiation::Association {
            remote_max_message_size,
            ..
        } => remote_max_message_size,
        other => panic!("no association: {other:?}"),
    };
    assert_eq!(limit(&with(vec![])), 65536, "absent: 64K");
    assert_eq!(limit(&with(vec![attr("max-message-size", Some("0"))])), 0);
    assert_eq!(
        limit(&with(vec![attr("max-message-size", Some("1200"))])),
        1200
    );
}

/// RFC 8841 sections 10.3 and 10.4: what the two data sections of an exchange negotiate. A
/// rejected section (m= port zero) on either side and an `a=sctp-port` of zero on either side
/// establish no association; the section used to be matched by media and fmt alone, so a
/// rejected one started the SCTP transport all the same.
#[test]
fn what_two_data_sections_negotiate() {
    let section = |port, sctp_port: &str| {
        description(vec![data_section(
            port,
            "UDP/DTLS/SCTP",
            vec![attr("sctp-port", Some(sctp_port))],
        )])
    };
    let rejected = || description(vec![data_section(0, "UDP/DTLS/SCTP", vec![])]);
    let none = || description(vec![media("audio", vec![])]);

    assert_eq!(
        negotiated_sctp(&section(9, "5000"), &section(9, "5001")),
        SctpNegotiation::Association {
            local_port: 5000,
            remote_port: 5001,
            remote_max_message_size: 65536,
        }
    );
    assert_eq!(
        negotiated_sctp(&section(9, "5000"), &rejected()),
        SctpNegotiation::Rejected
    );
    assert_eq!(
        negotiated_sctp(&rejected(), &section(9, "5000")),
        SctpNegotiation::Rejected
    );
    assert_eq!(
        negotiated_sctp(&rejected(), &rejected()),
        SctpNegotiation::Rejected
    );
    assert_eq!(
        negotiated_sctp(&section(9, "5000"), &section(9, "0")),
        SctpNegotiation::PortZero
    );
    assert_eq!(
        negotiated_sctp(&section(9, "0"), &section(9, "5000")),
        SctpNegotiation::PortZero
    );
    assert_eq!(
        negotiated_sctp(&section(9, "5000"), &none()),
        SctpNegotiation::NoSection
    );
    assert_eq!(
        negotiated_sctp(&none(), &section(9, "5000")),
        SctpNegotiation::NoSection
    );

    // A section rejected earlier, and the one offered after it: the live one counts.
    let mut both = rejected();
    both.media_descriptions.push(data_section(
        9,
        "UDP/DTLS/SCTP",
        vec![attr("sctp-port", Some("5002"))],
    ));
    assert_eq!(
        negotiated_sctp(&both, &both),
        SctpNegotiation::Association {
            local_port: 5002,
            remote_port: 5002,
            remote_max_message_size: 65536,
        }
    );
}

fn fingerprint_test(
    fingerprints: &[RTCDtlsFingerprint],
    me: &MediaEngine,
    transceivers: &mut [RTCRtpTransceiverInternal],
    media: &[MediaSection],
    sdpmedia_description_fingerprints: bool,
    expected_fingerprint_count: usize,
) -> Result<()> {
    let mut p = params(sdpmedia_description_fingerprints, None);
    p.ice_gathering_state = RTCIceGatheringState::New;
    p.connection_role = ConnectionRole::Active;
    p.is_extmap_allow_mixed = false;

    let s = populate(me, transceivers, media, p, fingerprints)?;

    let sdparray = s.marshal();

    assert_eq!(
        sdparray.matches("sha-256").count(),
        expected_fingerprint_count
    );

    Ok(())
}

#[test]
fn test_media_description_fingerprints() -> Result<()> {
    let me = default_media_engine();

    // The old test generated a certificate for its fingerprint; what is under test is where the
    // fingerprint lines go, so one fixed sha-256 fingerprint stands in for it.
    let fingerprints = vec![RTCDtlsFingerprint {
        algorithm: "sha-256".to_owned(),
        value: "AB:CD:EF".to_owned(),
    }];

    let encoding = |ssrc| RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            ssrc: Some(ssrc),
            ..Default::default()
        },
        codec: vp8(),
        ..Default::default()
    };

    // Both media transceivers send video, as the old test replaced each sender with one sending
    // a VP8 track and made the transceiver sendonly.
    let mut transceivers = vec![
        sendonly_transceiver(RtpCodecKind::Video, vec![encoding(1000)]),
        sendonly_transceiver(RtpCodecKind::Video, vec![encoding(2000)]),
    ];

    let media = vec![
        media_section("video", 0),
        media_section("audio", 1),
        MediaSection {
            mid: "application".to_owned(),
            data: true,
            transceiver_index: usize::MAX,
            ..Default::default()
        },
    ];

    //"Per-Media Description Fingerprints",
    fingerprint_test(&fingerprints, &me, &mut transceivers, &media, true, 3)?;

    //"Per-Session Description Fingerprints",
    fingerprint_test(&fingerprints, &me, &mut transceivers, &media, false, 1)?;

    Ok(())
}

#[test]
fn test_populate_sdp() -> Result<()> {
    //"Rid": the remote side's `send` rids are answered `recv` (RFC 8851 section 6.3), and the
    // `~` of a paused stream is written only with `rid_pause_marks` (RFC 8853 section 5.2:
    // the mark needs RFC 7728, which the engine does not implement).
    for rid_pause_marks in [false, true] {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];

        let remote_rid = |id: &str, paused: bool| SimulcastRid {
            id: id.to_owned(),
            direction: SimulcastDirection::Send,
            simulcast: true,
            paused,
            formats: vec![],
            restrictions: vec![("max-width".to_owned(), Some("1280".to_owned()))],
        };
        let media_sections = vec![MediaSection {
            rid_map: vec![remote_rid("ridkey", false), remote_rid("ridpaused", true)],
            ..media_section("video", 0)
        }];

        let sdp = populate(
            &me,
            &mut transceivers,
            &media_sections,
            PopulateSdpParams {
                rid_pause_marks,
                ..params(false, None)
            },
            &[],
        )?;

        let video = sdp
            .media_descriptions
            .iter()
            .find(|desc| desc.media_name.media == "video")
            .expect("a video section");
        let rids = get_rids(video, RidIdGrammar::Corrected);
        for id in ["ridkey", "ridpaused"] {
            let rid = rids
                .iter()
                .find(|rid| rid.id == id)
                .unwrap_or_else(|| panic!("rid {id} is written"));
            assert_eq!(rid.direction, SimulcastDirection::Recv, "rid {id}");
            assert!(rid.simulcast, "rid {id} is a simulcast stream");
            assert_eq!(
                rid.restrictions,
                vec![("max-width".to_owned(), Some("1280".to_owned()))],
                "rid {id} keeps its restrictions"
            );
        }
        let simulcast = video
            .attribute(SDP_ATTRIBUTE_SIMULCAST)
            .flatten()
            .expect("an a=simulcast line");
        let expected = if rid_pause_marks {
            "recv ridkey;~ridpaused"
        } else {
            "recv ridkey;ridpaused"
        };
        assert_eq!(simulcast, expected);
    }

    //"SetCodecPreferences"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];
        transceivers[0].set_codec_preferences(
            vec![RTCRtpCodecParameters {
                rtp_codec: vp8(),
                payload_type: 96,
            }],
            &me,
        )?;

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0)],
            params(false, None),
            &[],
        )?;

        // Test codecs
        let mut found_vp8 = false;
        for desc in &offer_sdp.media_descriptions {
            if desc.media_name.media != "video" {
                continue;
            }
            for a in &desc.attributes {
                if a.key.contains("rtpmap")
                    && let Some(value) = &a.value
                {
                    if value.contains("VP9") {
                        panic!("vp9 should not be present in sdp: {value}");
                    } else if value == "96 VP8/90000" {
                        found_vp8 = true;
                    }
                }
            }
        }
        assert!(found_vp8, "vp8 should be present in sdp");
    }

    //"Bundle all"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0)],
            params(false, None),
            &[],
        )?;

        assert_eq!(
            offer_sdp.attribute(ATTR_KEY_GROUP),
            Some(&"BUNDLE video".to_owned())
        );

        assert!(offer_sdp.has_attribute(ATTR_KEY_EXTMAP_ALLOW_MIXED));
    }

    //"Bundle matched"
    {
        let me = default_media_engine();
        let mut transceivers = vec![
            recvonly_transceiver(RtpCodecKind::Video),
            recvonly_transceiver(RtpCodecKind::Audio),
        ];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0), media_section("audio", 1)],
            params(false, Some("audio".to_owned())),
            &[],
        )?;

        assert_eq!(
            offer_sdp.attribute(ATTR_KEY_GROUP),
            Some(&"BUNDLE audio".to_owned())
        );
    }

    //"empty bundle group"
    {
        let me = default_media_engine();
        let mut transceivers = vec![recvonly_transceiver(RtpCodecKind::Video)];

        let offer_sdp = populate(
            &me,
            &mut transceivers,
            &[media_section("video", 0)],
            params(false, Some("".to_owned())),
            &[],
        )?;

        assert_eq!(offer_sdp.attribute(ATTR_KEY_GROUP), None);
    }

    // "Sender RTX"
    {
        let mut me = default_media_engine();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_RTX.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "apt=96".to_string(),
                    rtcp_feedback: vec![],
                },
                payload_type: 97,
            },
            RtpCodecKind::Video,
        )?;

        // Two simulcast layers, "f" and "h", each with its own RTX repair flow. The old test
        // added the second layer with `add_encoding`; a sender's layers are now its encodings.
        let layer = |rid: &str, ssrc: SSRC, rtx: SSRC| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(ssrc),
                rtx: Some(RTCRtpRtxParameters { ssrc: rtx }),
                ..Default::default()
            },
            codec: vp8(),
            ..Default::default()
        };
        let mut transceivers = vec![sendonly_transceiver(
            RtpCodecKind::Video,
            vec![layer("f", 1000, 1001), layer("h", 2000, 2001)],
        )];

        // The old crate always wrote `a=ssrc` lines for a simulcast sender; that is now opt-in.
        let mut p = params(false, None);
        p.write_ssrc_attributes_for_simulcast = true;
        let offer_sdp = populate(&me, &mut transceivers, &[media_section("video", 0)], p, &[])?;

        // Test codecs and FID groups
        let mut found_vp8 = false;
        let mut found_rtx = false;
        let mut found_ssrcs: Vec<&str> = Vec::new();
        let mut found_fids = Vec::new();
        for desc in &offer_sdp.media_descriptions {
            if desc.media_name.media != "video" {
                continue;
            }
            for a in &desc.attributes {
                if a.key.contains("rtpmap") {
                    if let Some(value) = &a.value {
                        if value == "96 VP8/90000" {
                            found_vp8 = true;
                        } else if value == "97 rtx/90000" {
                            found_rtx = true;
                        }
                    }
                } else if a.key == "ssrc" {
                    if let Some((ssrc, _)) = a.value.as_ref().and_then(|v| v.split_once(' ')) {
                        found_ssrcs.push(ssrc);
                    }
                } else if a.key == "ssrc-group"
                    && let Some(group) = a.value.as_ref().and_then(|v| v.strip_prefix("FID "))
                {
                    let Some((a, b)) = group.split_once(" ") else {
                        panic!("invalid FID format in sdp")
                    };

                    found_fids.extend([a, b]);
                }
            }
        }

        found_fids.sort();

        found_ssrcs.sort();
        // the sdp may have multiple attributes for each ssrc
        found_ssrcs.dedup();

        assert!(found_vp8, "vp8 should be present in sdp");
        assert!(found_rtx, "rtx should be present in sdp");
        assert_eq!(found_ssrcs.len(), 4, "all ssrcs should be present in sdp");
        assert_eq!(found_fids.len(), 4, "all fids should be present in sdp");

        assert_eq!(found_ssrcs, found_fids);
    }

    Ok(())
}

#[test]
fn test_populate_sdp_reject() -> Result<()> {
    let mut me = MediaEngine::default();
    me.register_codec(
        RTCRtpCodecParameters {
            rtp_codec: vp8(),
            payload_type: 2,
        },
        RtpCodecKind::Video,
    )?;

    let mut transceivers = vec![
        recvonly_transceiver(RtpCodecKind::Video),
        recvonly_transceiver(RtpCodecKind::Audio),
    ];

    let offer_sdp = populate(
        &me,
        &mut transceivers,
        &[media_section("video", 0), media_section("audio", 1)],
        params(false, None),
        &[],
    )?;

    let mut found_rejected_track = false;

    for desc in offer_sdp.media_descriptions {
        if desc.media_name.media != "audio" {
            continue;
        }
        found_rejected_track = true;

        assert!(
            !desc.connection_information.is_empty(),
            "connection_information should not be None, even for rejected tracks"
        );
        assert_eq!(
            desc.media_name.formats,
            vec!["0"],
            "Format for rejected track should be 0"
        );
        assert_eq!(
            desc.media_name.port.value, 0,
            "Port for rejected track should be 0"
        );
    }

    assert!(
        found_rejected_track,
        "There should've been a rejected track"
    );

    Ok(())
}

#[test]
fn test_get_rids() {
    // RFC 8851 section 6.2.2 step 3: a `pt=` keeps the formats of the m= line only.
    let mut m = media(
        "video",
        vec![
            attr("sendonly", None),
            attr(
                SDP_ATTRIBUTE_RID,
                Some("f send pt=97,98;max-width=1280;max-height=720"),
            ),
        ],
    );
    m.media_name.formats = vec!["97".to_owned()];

    let rids = get_rids(&m, RidIdGrammar::Corrected);

    let f = rids
        .iter()
        .find(|rid| rid.id == "f")
        .expect("rid values should contain 'f'");
    assert_eq!(f.direction, SimulcastDirection::Send);
    assert_eq!(f.formats, vec![97]);
    let restrictions = f.to_restrictions();
    assert_eq!(restrictions.payload_types, vec![97]);
    assert_eq!(restrictions.max_width, Some(1280));
    assert_eq!(restrictions.max_height, Some(720));

    // Without the format on the m= line, the line keeps no format and is discarded.
    m.media_name.formats = vec!["96".to_owned()];
    assert!(get_rids(&m, RidIdGrammar::Corrected).is_empty());
}

#[test]
fn test_codecs_from_media_description() -> Result<()> {
    //"Codec Only"
    {
        let codecs = codecs_from_media_description(&MediaDescription {
            media_name: MediaName {
                media: "audio".to_owned(),
                formats: vec!["111".to_owned()],
                ..Default::default()
            },
            attributes: vec![attr("rtpmap", Some("111 opus/48000/2"))],
            ..Default::default()
        })?;

        assert_eq!(
            codecs,
            vec![RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            }],
        );
    }

    //"Codec with fmtp/rtcp-fb"
    {
        let codecs = codecs_from_media_description(&MediaDescription {
            media_name: MediaName {
                media: "audio".to_owned(),
                formats: vec!["111".to_owned()],
                ..Default::default()
            },
            attributes: vec![
                attr("rtpmap", Some("111 opus/48000/2")),
                attr("fmtp", Some("111 minptime=10;useinbandfec=1")),
                attr("rtcp-fb", Some("111 goog-remb")),
                attr("rtcp-fb", Some("111 ccm fir")),
            ],
            ..Default::default()
        })?;

        assert_eq!(
            codecs,
            vec![RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                    rtcp_feedback: vec![
                        RTCPFeedback {
                            typ: "goog-remb".to_owned(),
                            parameter: "".to_owned()
                        },
                        RTCPFeedback {
                            typ: "ccm".to_owned(),
                            parameter: "fir".to_owned()
                        }
                    ]
                },
                payload_type: 111,
            }],
        );
    }

    Ok(())
}

#[test]
fn test_rtp_extensions_from_media_description() -> Result<()> {
    let extensions = rtp_extensions_from_media_description(&MediaDescription {
        media_name: MediaName {
            media: "audio".to_owned(),
            formats: vec!["111".to_owned()],
            ..Default::default()
        },
        attributes: vec![
            attr(
                "extmap",
                Some(&("1 ".to_owned() + sdp::extmap::ABS_SEND_TIME_URI)),
            ),
            attr(
                "extmap",
                Some(&("3 ".to_owned() + sdp::extmap::SDES_MID_URI)),
            ),
        ],
        ..Default::default()
    })?;

    assert_eq!(extensions[sdp::extmap::ABS_SEND_TIME_URI].id, 1);
    assert_eq!(extensions[sdp::extmap::SDES_MID_URI].id, 3);

    Ok(())
}
