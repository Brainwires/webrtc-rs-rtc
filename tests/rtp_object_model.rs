//! The W3C RTP object model (webrtc-pc 5.1 to 5.4): every transceiver has a sender and a
//! receiver whatever its direction and whether or not it has a track; `removeTrack` keeps the
//! sender; `replaceTrack` changes no msid and needs no negotiation; `stop()` is stopping first
//! and stopped once a rejecting exchange completes; the methods refuse what the spec refuses
//! with the errors it names. Signalling only: no transport is started.

mod jsep_common;

use std::time::{Duration, Instant};

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, port_of,
    video_track,
};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_OPUS, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
};
use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability, RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverId, RTCRtpTransceiverInit,
};
use rtci::sansio::Protocol;
use rtci::shared::error::Error;

const MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

/// Drains every queued event, returning how many were negotiation-needed.
fn negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
    let mut count = 0;
    while let Some(event) = pc.poll_event() {
        if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
            count += 1;
        }
    }
    count
}

/// Drains every queued event, returning the ids of the tracks that ended.
fn ended_tracks(pc: &mut RTCPeerConnection) -> Vec<String> {
    let mut ended = vec![];
    while let Some(event) = pc.poll_event() {
        if let RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(track_id)) = event {
            ended.push(track_id);
        }
    }
    ended
}

fn opus() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_OPUS.to_owned(),
        clock_rate: 48000,
        channels: 2,
        sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
        rtcp_feedback: vec![],
    }
}

fn audio_track(name: &str, ssrc: u32) -> MediaStreamTrack {
    MediaStreamTrack::new(
        format!("{name}-stream"),
        name.to_owned(),
        name.to_owned(),
        RtpCodecKind::Audio,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: opus(),
            ..Default::default()
        }],
    )
}

fn with_rid(rid: &str) -> RTCRtpEncodingParameters {
    RTCRtpEncodingParameters {
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn init(
    direction: RTCRtpTransceiverDirection,
    send_encodings: Vec<RTCRtpEncodingParameters>,
) -> Option<RTCRtpTransceiverInit> {
    Some(RTCRtpTransceiverInit {
        direction,
        streams: vec![],
        send_encodings,
    })
}

fn sender_track_id(pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId) -> Option<String> {
    pc.rtp_sender(id.into())
        .expect("every transceiver has a sender")
        .track()
        .map(|track| track.track_id().clone())
}

fn direction(pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId) -> RTCRtpTransceiverDirection {
    pc.rtp_transceiver(id).expect("transceiver").direction()
}

/// Two peers that negotiated one sendrecv video transceiver, each sending a track.
fn negotiated_both_ways()
-> Result<(RTCPeerConnection, RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("offered", 0x0a01_0101))?;
    answerer.add_track(video_track("answered", 0x0a02_0202))?;
    exchange(&mut offerer, &mut answerer)?;
    negotiation_needed(&mut offerer);
    negotiation_needed(&mut answerer);
    Ok((offerer, answerer, sender))
}

// --- 5.1 getSenders / getReceivers / addTransceiver -------------------------------------

#[test]
fn every_transceiver_has_a_sender_and_a_receiver_whatever_its_direction() -> TestResult {
    let mut pc = default_peer()?;
    for direction in [
        RTCRtpTransceiverDirection::Sendrecv,
        RTCRtpTransceiverDirection::Sendonly,
        RTCRtpTransceiverDirection::Recvonly,
        RTCRtpTransceiverDirection::Inactive,
    ] {
        pc.add_transceiver_from_kind(RtpCodecKind::Video, init(direction, vec![]))?;
    }
    assert_eq!(pc.get_senders().count(), 4, "getSenders ignores direction");
    assert_eq!(
        pc.get_receivers().count(),
        4,
        "getReceivers ignores direction"
    );
    for id in pc.get_transceivers().collect::<Vec<_>>() {
        let transceiver = pc.rtp_transceiver(id).expect("transceiver");
        assert!(transceiver.sender().is_some(), "transceiver {id}");
        assert!(transceiver.receiver().is_some(), "transceiver {id}");
        assert!(sender_track_id(&mut pc, id).is_none(), "made from a kind");
    }
    Ok(())
}

/// A transceiver a remote offer stopped (its section rejected) is `[[Stopped]]` until the
/// answer: still in getTransceivers, but its sender and receiver are not collected.
#[test]
fn a_stopped_transceivers_sender_and_receiver_are_not_collected() -> TestResult {
    let mut pc = default_peer()?;
    let offer = crlf(&format!(
        "{SESSION}a=group:BUNDLE 1
m=video 0 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=inactive
a=rtpmap:96 VP8/90000
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:1
a=sendrecv
a=rtpmap:96 VP8/90000
"
    ));
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let ids: Vec<_> = pc.get_transceivers().collect();
    assert_eq!(ids.len(), 2);
    assert!(
        pc.rtp_transceiver(ids[0])
            .expect("transceiver")
            .is_stopped()
    );
    assert_eq!(
        pc.rtp_transceiver(ids[0])
            .expect("transceiver")
            .current_direction(),
        Some(RTCRtpTransceiverDirection::Stopped)
    );
    assert_eq!(
        pc.get_senders().map(usize::from).collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(pc.get_receivers().count(), 1);
    Ok(())
}

#[test]
fn add_transceiver_from_a_kind_defaults_to_sendrecv() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    assert_eq!(direction(&mut pc, id), RTCRtpTransceiverDirection::Sendrecv);
    assert!(pc.rtp_transceiver(id).expect("transceiver").mid().is_none());
    assert!(
        negotiation_needed(&mut pc) > 0,
        "addTransceiver needs negotiation"
    );
    assert_eq!(
        pc.add_transceiver_from_kind(RtpCodecKind::Unspecified, None),
        Err(Error::ErrPeerConnAddTransceiverFromKindSupport)
    );
    Ok(())
}

#[test]
fn add_transceiver_from_a_track_takes_any_direction() -> TestResult {
    let mut pc = default_peer()?;
    for (n, direction) in [
        RTCRtpTransceiverDirection::Recvonly,
        RTCRtpTransceiverDirection::Inactive,
    ]
    .into_iter()
    .enumerate()
    {
        let id = pc.add_transceiver_from_track(
            video_track(&format!("t{n}"), 0x0b00_0000 + n as u32),
            init(direction, vec![]),
        )?;
        assert_eq!(self::direction(&mut pc, id), direction);
        assert_eq!(sender_track_id(&mut pc, id), Some(format!("t{n}")));
    }
    Ok(())
}

#[test]
fn add_transceiver_refuses_a_rid_that_is_not_rfc_8851_syntax() -> TestResult {
    let mut pc = default_peer()?;
    let result = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![with_rid("a"), with_rid("not a rid!")],
        ),
    );
    assert!(matches!(result, Err(Error::TypeError(_))), "{result:?}");
    assert_eq!(pc.get_transceivers().count(), 0);
    Ok(())
}

/// W3C addTransceiver: a rid "that does not conform to the grammar requirements specified in
/// Section 10 of [RFC8851]" is a TypeError; erratum 7132 (Verified) corrects that grammar to
/// `rid-id = 1*255(alpha-numeric)`, so a rid with `-` or `_`, or of more than 255
/// characters, is one too. 255 alphanumerics are taken.
#[test]
fn add_transceiver_refuses_a_rid_outside_the_corrected_grammar_with_a_type_error() -> TestResult {
    for rid in ["a-b".to_owned(), "a_b".to_owned(), "a".repeat(256)] {
        let mut pc = default_peer()?;
        let result = pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            init(
                RTCRtpTransceiverDirection::Sendonly,
                vec![with_rid("a"), with_rid(&rid)],
            ),
        );
        assert!(
            matches!(result, Err(Error::TypeError(_))),
            "rid {rid:?}: {result:?}"
        );
        assert_eq!(pc.get_transceivers().count(), 0);
    }
    let mut pc = default_peer()?;
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![with_rid("a"), with_rid(&"b".repeat(255))],
        ),
    )?;
    Ok(())
}

#[test]
fn add_transceiver_refuses_out_of_range_encodings() -> TestResult {
    let mut pc = default_peer()?;
    let small = RTCRtpEncodingParameters {
        scale_resolution_down_by: Some(0.5),
        ..Default::default()
    };
    let negative = RTCRtpEncodingParameters {
        max_framerate: Some(-1.0),
        ..Default::default()
    };
    for encoding in [small, negative] {
        let result = pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            init(RTCRtpTransceiverDirection::Sendonly, vec![encoding]),
        );
        assert!(matches!(result, Err(Error::RangeError(_))), "{result:?}");
    }
    Ok(())
}

#[test]
fn add_transceiver_strips_video_only_members_from_audio_encodings() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![RTCRtpEncodingParameters {
                scale_resolution_down_by: Some(2.0),
                max_framerate: Some(30.0),
                ..Default::default()
            }],
        ),
    )?;
    let mut sender = pc.rtp_sender(id.into()).expect("sender");
    let encoding = &sender.get_parameters().encodings[0];
    assert_eq!(encoding.scale_resolution_down_by, None);
    assert_eq!(encoding.max_framerate, None);
    Ok(())
}

#[test]
fn add_transceiver_fills_scale_resolution_down_by_and_drops_a_lone_rid() -> TestResult {
    let mut pc = default_peer()?;
    let layered = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![with_rid("q"), with_rid("h"), with_rid("f")],
        ),
    )?;
    let mixed = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![
                RTCRtpEncodingParameters {
                    scale_resolution_down_by: Some(3.0),
                    ..with_rid("lo")
                },
                with_rid("hi"),
            ],
        ),
    )?;
    let lone = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(RTCRtpTransceiverDirection::Sendonly, vec![with_rid("only")]),
    )?;
    let scales = |pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId| -> Vec<Option<f64>> {
        pc.rtp_sender(id.into())
            .expect("sender")
            .get_parameters()
            .encodings
            .iter()
            .map(|e| e.scale_resolution_down_by)
            .collect()
    };
    assert_eq!(
        scales(&mut pc, layered),
        vec![Some(4.0), Some(2.0), Some(1.0)]
    );
    assert_eq!(scales(&mut pc, mixed), vec![Some(3.0), Some(1.0)]);
    let mut sender = pc.rtp_sender(lone.into()).expect("sender");
    let encodings = &sender.get_parameters().encodings;
    assert_eq!(encodings.len(), 1);
    assert!(
        encodings[0].rtp_coding_parameters.rid.is_empty(),
        "a single encoding is not simulcast"
    );
    Ok(())
}

#[test]
fn add_transceiver_keeps_at_most_the_maximum_number_of_encodings() -> TestResult {
    let mut pc = default_peer()?;
    let encodings: Vec<_> = (0..rtci::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS + 3)
        .map(|n| with_rid(&format!("r{n}")))
        .collect();
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(RTCRtpTransceiverDirection::Sendonly, encodings),
    )?;
    let mut sender = pc.rtp_sender(id.into()).expect("sender");
    assert_eq!(
        sender.get_parameters().encodings.len(),
        rtci::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS
    );
    Ok(())
}

// --- 5.1 addTrack / removeTrack ------------------------------------------------------------

#[test]
fn add_track_refuses_a_track_a_sender_already_has() -> TestResult {
    let mut pc = default_peer()?;
    pc.add_track(video_track("video", 0x0c01_0101))?;
    assert_eq!(
        pc.add_track(video_track("video", 0x0c01_0101)),
        Err(Error::InvalidAccessError)
    );
    assert_eq!(pc.get_transceivers().count(), 1);
    Ok(())
}

#[test]
fn add_track_reuses_a_trackless_transceiver_of_its_kind() -> TestResult {
    let mut pc = default_peer()?;
    let audio =
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, Some(RTCRtpTransceiverInit::recvonly()))?;
    let video =
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let sender = pc.add_track(video_track("video", 0x0c02_0202))?;
    assert_eq!(RTCRtpTransceiverId::from(sender), video);
    assert_ne!(video, audio);
    assert_eq!(pc.get_transceivers().count(), 2, "no new transceiver");
    assert_eq!(
        direction(&mut pc, video),
        RTCRtpTransceiverDirection::Sendrecv
    );
    assert_eq!(sender_track_id(&mut pc, video).as_deref(), Some("video"));
    Ok(())
}

/// A transceiver whose sender has sent (sendrecv negotiated) is not reused by addTrack after
/// removeTrack: a new transceiver is made.
#[test]
fn add_track_does_not_reuse_a_transceiver_that_was_used_to_send() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated_both_ways()?;
    offerer.remove_track(sender)?;
    exchange(&mut offerer, &mut answerer)?;
    let again = offerer.add_track(video_track("again", 0x0c03_0303))?;
    assert_ne!(
        RTCRtpTransceiverId::from(again),
        RTCRtpTransceiverId::from(sender)
    );
    assert_eq!(offerer.get_transceivers().count(), 2);
    Ok(())
}

#[test]
fn remove_track_keeps_the_sender_without_a_track() -> TestResult {
    let (mut offerer, _answerer, sender) = negotiated_both_ways()?;
    let id = RTCRtpTransceiverId::from(sender);
    offerer.remove_track(sender)?;

    assert_eq!(offerer.get_senders().collect::<Vec<_>>(), vec![sender]);
    assert!(sender_track_id(&mut offerer, id).is_none());
    assert_eq!(
        direction(&mut offerer, id),
        RTCRtpTransceiverDirection::Recvonly
    );
    assert_eq!(negotiation_needed(&mut offerer), 1);
    let mut handle = offerer.rtp_sender(sender).expect("sender");
    assert_eq!(
        handle.ssrcs().collect::<Vec<_>>(),
        vec![0x0a01_0101],
        "the sender keeps its encodings"
    );
    assert_eq!(handle.get_parameters().encodings.len(), 1);
    assert!(handle.set_streams(vec!["other".to_owned()]).is_ok());

    // sendonly becomes inactive.
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_track(
        video_track("video", 0x0c04_0404),
        init(RTCRtpTransceiverDirection::Sendonly, vec![]),
    )?;
    pc.remove_track(id.into())?;
    assert_eq!(direction(&mut pc, id), RTCRtpTransceiverDirection::Inactive);
    Ok(())
}

/// The audit's "direction rewritten on a stopped transceiver, then a panic in
/// `rtp_sender(id).track()`": removeTrack aborts on a stopping transceiver and on a sender
/// without a track.
#[test]
fn remove_track_does_nothing_when_stopping_or_without_a_track() -> TestResult {
    let (mut offerer, _answerer, sender) = negotiated_both_ways()?;
    let id = RTCRtpTransceiverId::from(sender);
    offerer.rtp_transceiver(id).expect("transceiver").stop()?;
    negotiation_needed(&mut offerer);
    offerer.remove_track(sender)?;
    assert_eq!(
        direction(&mut offerer, id),
        RTCRtpTransceiverDirection::Stopped
    );
    assert_eq!(negotiation_needed(&mut offerer), 0);
    assert_eq!(
        sender_track_id(&mut offerer, id).as_deref(),
        Some("offered")
    );

    let mut pc = default_peer()?;
    let id =
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    negotiation_needed(&mut pc);
    pc.remove_track(id.into())?;
    assert_eq!(direction(&mut pc, id), RTCRtpTransceiverDirection::Recvonly);
    assert_eq!(negotiation_needed(&mut pc), 0);
    Ok(())
}

#[test]
fn a_closed_connection_refuses_the_object_model_methods() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0c05_0505))?;
    let id = RTCRtpTransceiverId::from(sender);
    pc.close()?;

    assert_eq!(
        pc.add_track(video_track("late", 0x0c05_0506)),
        Err(Error::ErrConnectionClosed)
    );
    assert_eq!(pc.remove_track(sender), Err(Error::ErrConnectionClosed));
    assert_eq!(
        pc.add_transceiver_from_kind(RtpCodecKind::Audio, None),
        Err(Error::ErrConnectionClosed)
    );
    assert_eq!(
        pc.add_transceiver_from_track(audio_track("late-audio", 0x0c05_0507), None),
        Err(Error::ErrConnectionClosed)
    );
    assert_eq!(
        pc.rtp_sender(sender).expect("sender").set_streams(vec![]),
        Err(Error::ErrConnectionClosed)
    );
    let mut transceiver = pc.rtp_transceiver(id).expect("transceiver");
    assert_eq!(
        transceiver.set_direction(RTCRtpTransceiverDirection::Inactive),
        Err(Error::ErrConnectionClosed)
    );
    assert_eq!(transceiver.stop(), Err(Error::ErrConnectionClosed));
    Ok(())
}

// --- 5.2 RTCRtpSender ---------------------------------------------------------------------

#[test]
fn replace_track_keeps_the_msid_and_ssrcs_and_needs_no_negotiation() -> TestResult {
    let (mut offerer, _answerer, sender) = negotiated_both_ways()?;
    let mut handle = offerer.rtp_sender(sender).expect("sender");
    handle.replace_track(Some(video_track("replacement", 0x0d01_0101)))?;
    assert_eq!(
        handle.track().map(|t| t.track_id().as_str()),
        Some("replacement")
    );
    assert_eq!(handle.ssrcs().collect::<Vec<_>>(), vec![0x0a01_0101]);
    assert_eq!(handle.streams(), ["offered-stream".to_owned()]);
    assert_eq!(negotiation_needed(&mut offerer), 0);

    let offer = offerer.create_offer(None)?;
    let section = &media_sections(&offer.sdp)[0];
    assert!(
        // The appdata is the sender's track id, which `replaceTrack` leaves alone.
        section
            .iter()
            .any(|l| l.starts_with("a=msid:offered-stream ") && !l.contains("replacement")),
        "{}",
        offer.sdp
    );
    assert!(!offer.sdp.contains("replacement-stream"), "{}", offer.sdp);
    Ok(())
}

#[test]
fn replace_track_with_none_stops_sending() -> TestResult {
    let (mut offerer, _answerer, sender) = negotiated_both_ways()?;
    let mut handle = offerer.rtp_sender(sender).expect("sender");
    handle.replace_track(None)?;
    assert!(handle.track().is_none());
    let mut packet = rtci::rtp::Packet::default();
    packet.header.ssrc = 0x0a01_0101;
    packet.header.payload_type = 96;
    assert_eq!(
        handle.write_rtp(Instant::now(), packet),
        Err(Error::ErrRTPSenderTrackRemoved)
    );
    assert_eq!(
        handle.replace_track(Some(audio_track("audio", 0x0d02_0202))),
        Err(Error::ErrRTPSenderNewTrackHasIncorrectKind)
    );
    Ok(())
}

#[test]
fn replace_track_on_a_stopping_transceiver_is_an_invalid_state_error() -> TestResult {
    let (mut offerer, _answerer, sender) = negotiated_both_ways()?;
    offerer
        .rtp_transceiver(sender.into())
        .expect("transceiver")
        .stop()?;
    assert_eq!(
        offerer
            .rtp_sender(sender)
            .expect("sender")
            .replace_track(Some(video_track("late", 0x0d03_0303))),
        Err(Error::InvalidStateError)
    );
    Ok(())
}

#[test]
fn set_streams_sets_exactly_the_given_streams() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0d04_0404))?;
    let mut handle = pc.rtp_sender(sender).expect("sender");
    handle.set_streams(vec!["s".to_owned(), "t".to_owned(), "s".to_owned()])?;
    assert_eq!(handle.streams(), ["s".to_owned(), "t".to_owned()]);
    handle.set_streams(vec![])?;
    assert!(handle.streams().is_empty());

    let offer = pc.create_offer(None)?;
    assert!(
        media_sections(&offer.sdp)[0]
            .iter()
            .any(|l| l == "a=msid:- video"),
        "no stream is signalled as `-`:\n{}",
        offer.sdp
    );
    Ok(())
}

/// W3C 5.1 `addTrack(track, ...streams)`: a new sender, and a reused trackless one, get
/// exactly the given streams as their associated media stream ids, signalled as `a=msid`.
#[test]
fn add_track_with_streams_associates_exactly_those_streams() -> TestResult {
    let mut pc = default_peer()?;
    let fresh = pc.add_track_with_streams(
        video_track("video", 0x0d05_0505),
        vec!["a".to_owned(), "b".to_owned()],
    )?;
    assert_eq!(
        pc.rtp_sender(fresh).expect("sender").streams(),
        ["a".to_owned(), "b".to_owned()]
    );

    let reused = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let sender =
        pc.add_track_with_streams(audio_track("audio", 0x0d05_0506), vec!["c".to_owned()])?;
    assert_eq!(
        RTCRtpTransceiverId::from(sender),
        reused,
        "the trackless sender is reused"
    );
    assert_eq!(
        pc.rtp_sender(sender).expect("sender").streams(),
        ["c".to_owned()]
    );

    let offer = pc.create_offer(None)?;
    let sections = media_sections(&offer.sdp);
    for (section, streams) in [(0, vec!["a", "b"]), (1, vec!["c"])] {
        let msids: Vec<&str> = sections[section]
            .iter()
            .filter_map(|l| l.strip_prefix("a=msid:"))
            .filter_map(|v| v.split_whitespace().next())
            .collect();
        assert_eq!(msids, streams, "{}", offer.sdp);
    }
    Ok(())
}

const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

/// A peer with the default codecs and the video header extensions `uris` only.
fn peer_with_extensions(uris: &[&str]) -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    for uri in uris {
        media_engine.register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: (*uri).to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )?;
    }
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

/// The `a=extmap` lines of the first video section, as (uri, id).
fn extmaps(sdp: &str) -> Vec<(String, String)> {
    let sections = media_sections(sdp);
    let video = sections
        .iter()
        .find(|s| s[0].starts_with("m=video"))
        .expect("a video section");
    video
        .iter()
        .filter_map(|l| l.strip_prefix("a=extmap:"))
        .filter_map(|v| {
            let (id, rest) = v.split_once(' ')?;
            let uri = rest.split_whitespace().next()?;
            Some((uri.to_owned(), id.split('/').next()?.to_owned()))
        })
        .collect()
}

/// W3C webrtc-pc 5.2 / 5.3: `getCapabilities(kind).headerExtensions` is "the list of
/// implemented header extensions for sending" ("for receiving"), "the most optimistic view of
/// the header extensions the user agent supports", whatever was negotiated: an answer that
/// accepts MID alone leaves abs-send-time and transport-cc in both lists. The later offer keeps
/// each extension's id (RFC 8285 section 6: the mapping stays for the session) and lists no
/// extension the first offer did not.
#[test]
fn get_capabilities_lists_the_registered_header_extensions_after_a_negotiation() -> TestResult {
    let all = [MID_URI, ABS_SEND_TIME_URI, TRANSPORT_CC_URI];
    let mut offerer = peer_with_extensions(&all)?;
    let mut answerer = peer_with_extensions(&[MID_URI])?;
    let id = offerer
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::default()))?;
    let uris = |pc: &mut RTCPeerConnection| -> (Vec<String>, Vec<String>) {
        let mut send: Vec<String> = pc
            .rtp_sender(id.into())
            .expect("sender")
            .get_capabilities(RtpCodecKind::Video)
            .expect("video")
            .header_extensions
            .into_iter()
            .map(|h| h.uri)
            .collect();
        let mut recv: Vec<String> = pc
            .rtp_receiver(id.into())
            .expect("receiver")
            .get_capabilities(RtpCodecKind::Video)
            .expect("video")
            .header_extensions
            .into_iter()
            .map(|h| h.uri)
            .collect();
        send.sort();
        recv.sort();
        (send, recv)
    };
    let before = uris(&mut offerer);
    let mut expected: Vec<String> = all.iter().map(|u| (*u).to_owned()).collect();
    expected.sort();
    assert_eq!(
        before,
        (expected.clone(), expected.clone()),
        "before the negotiation"
    );

    let (first_offer, answer) = exchange(&mut offerer, &mut answerer)?;
    let answered: Vec<String> = extmaps(&answer).into_iter().map(|(u, _)| u).collect();
    assert_eq!(
        answered,
        vec![MID_URI.to_owned()],
        "the answer accepts MID alone: {answer}"
    );
    assert_eq!(
        uris(&mut offerer),
        (expected.clone(), expected),
        "getCapabilities after the negotiation"
    );

    // RFC 8285 section 6: a later offer keeps the ids, and adds nothing new.
    let later = offerer.create_offer(None)?.sdp;
    let first = extmaps(&first_offer);
    for (uri, id) in extmaps(&later) {
        let earlier = first.iter().find(|(u, _)| *u == uri);
        assert_eq!(
            earlier.map(|(_, i)| i.as_str()),
            Some(id.as_str()),
            "{uri} keeps its id in the later offer:\n{first_offer}\n---\n{later}"
        );
    }
    Ok(())
}

/// W3C webrtc-pc 5.2 / 5.3: `getCapabilities` is "the list of implemented send codecs" ("receive
/// codecs"), "the most optimistic view of the codecs the user agent supports", whatever was
/// negotiated: after an exchange that negotiated VP8 alone (an answer with the offered formats
/// only, the default since 0.3.0) it still lists VP9, H.264, AV1 and H.265.
#[test]
fn get_capabilities_is_the_same_after_a_negotiation_that_narrowed_the_formats() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let id = offerer
        .add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let names = |pc: &mut RTCPeerConnection, id: RTCRtpTransceiverId| -> Vec<String> {
        let mut out: Vec<String> = pc
            .rtp_receiver(id.into())
            .expect("receiver")
            .get_capabilities(RtpCodecKind::Video)
            .expect("video")
            .codecs
            .iter()
            .map(|c| format!("{} {}", c.mime_type.to_ascii_lowercase(), c.sdp_fmtp_line))
            .collect();
        out.sort();
        out
    };
    let before = names(&mut offerer, id);
    let vp8 = offerer
        .rtp_sender(id.into())
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video")
        .codecs
        .into_iter()
        .filter(|c| c.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8))
        .map(|rtp_codec| RTCRtpCodecParameters {
            rtp_codec,
            payload_type: 0,
        })
        .collect();
    offerer
        .rtp_transceiver(id)
        .expect("transceiver")
        .set_codec_preferences(vp8)?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert!(
        !answer.contains("VP9/90000"),
        "VP8 alone is negotiated: {answer}"
    );
    let after = names(&mut offerer, id);
    assert_eq!(after, before, "getCapabilities after the negotiation");
    assert!(
        after.iter().any(|c| c.starts_with("video/vp9")),
        "{after:?}"
    );
    let sender_after: Vec<String> = offerer
        .rtp_sender(id.into())
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video")
        .codecs
        .iter()
        .map(|c| c.mime_type.to_ascii_lowercase())
        .collect();
    assert!(
        sender_after.iter().any(|m| m == "video/vp9"),
        "the sender's capabilities too: {sender_after:?}"
    );
    Ok(())
}

#[test]
fn get_capabilities_lists_the_engine_codecs_without_any_negotiation() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?;
    let id =
        pc.add_transceiver_from_kind(RtpCodecKind::Video, Some(RTCRtpTransceiverInit::recvonly()))?;
    let sender = pc.rtp_sender(id.into()).expect("sender");
    let capabilities = sender
        .get_capabilities(RtpCodecKind::Video)
        .expect("video capabilities");
    assert!(
        capabilities
            .codecs
            .iter()
            .any(|c| c.mime_type.eq_ignore_ascii_case(MIME_TYPE_VP8))
    );
    let rtx: Vec<_> = capabilities
        .codecs
        .iter()
        .filter(|c| c.mime_type.eq_ignore_ascii_case(MIME_TYPE_RTX))
        .collect();
    assert_eq!(rtx.len(), 1, "RTX is listed once");
    assert!(rtx[0].sdp_fmtp_line.is_empty(), "without an apt");
    assert_eq!(
        capabilities
            .header_extensions
            .iter()
            .map(|h| h.uri.as_str())
            .collect::<Vec<_>>(),
        vec![MID_URI]
    );
    assert!(sender.get_capabilities(RtpCodecKind::Unspecified).is_none());

    let receiver = pc.rtp_receiver(id.into()).expect("receiver");
    assert!(
        receiver
            .get_capabilities(RtpCodecKind::Audio)
            .expect("audio capabilities")
            .codecs
            .iter()
            .any(|c| c.mime_type.eq_ignore_ascii_case(MIME_TYPE_OPUS))
    );
    assert!(
        receiver
            .get_capabilities(RtpCodecKind::Unspecified)
            .is_none()
    );
    Ok(())
}

#[test]
fn get_parameters_keeps_its_transaction_until_set_parameters() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0d05_0505))?;
    let mut handle = pc.rtp_sender(sender).expect("sender");
    let first = handle.get_parameters().clone();
    assert_eq!(handle.get_parameters().transaction_id, first.transaction_id);
    assert!(
        !first.rtp_parameters.rtcp.cname.is_empty(),
        "rtcp.cname is the connection's CNAME"
    );
    handle.set_parameters(first.clone(), None)?;
    assert_eq!(
        handle.set_parameters(first.clone(), None),
        Err(Error::InvalidStateError),
        "set_parameters needs a get_parameters first"
    );
    let second = handle.get_parameters().clone();
    assert_ne!(second.transaction_id, first.transaction_id);
    assert_eq!(
        handle.set_parameters(first, None),
        Err(Error::InvalidModificationError),
        "a stale transaction id"
    );
    Ok(())
}

/// W3C 5.2 setParameters: encodings in another order than [[SendEncodings]] are an
/// InvalidModificationError; an encoding is told by its rid and SSRCs, so the members of the
/// encodings themselves may still change.
#[test]
fn set_parameters_refuses_reordered_encodings() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![with_rid("lo"), with_rid("hi")],
        ),
    )?;
    let mut handle = pc.rtp_sender(id.into()).expect("sender");
    let mut reordered = handle.get_parameters().clone();
    assert_eq!(reordered.encodings.len(), 2);
    reordered.encodings.swap(0, 1);
    assert_eq!(
        handle.set_parameters(reordered, None),
        Err(Error::InvalidModificationError)
    );
    let mut changed = handle.get_parameters().clone();
    changed.encodings[1].active = false;
    handle.set_parameters(changed, None)?;
    assert!(!handle.get_parameters().encodings[1].active);
    Ok(())
}

#[test]
fn set_parameters_refuses_what_the_spec_refuses() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(video_track("video", 0x0d06_0606))?;
    let mut handle = pc.rtp_sender(sender).expect("sender");

    let mut fewer = handle.get_parameters().clone();
    fewer.encodings.clear();
    assert_eq!(
        handle.set_parameters(fewer, None),
        Err(Error::InvalidModificationError),
        "the number of encodings differs"
    );

    let mut unknown_codec = handle.get_parameters().clone();
    unknown_codec.encodings[0].codec = RTCRtpCodec {
        mime_type: "video/NOT-A-CODEC".to_owned(),
        clock_rate: 90000,
        ..Default::default()
    };
    assert_eq!(
        handle.set_parameters(unknown_codec, None),
        Err(Error::InvalidModificationError),
        "a codec the sender cannot choose"
    );

    let mut small = handle.get_parameters().clone();
    small.encodings[0].scale_resolution_down_by = Some(0.5);
    assert!(matches!(
        handle.set_parameters(small, None),
        Err(Error::RangeError(_))
    ));

    let mut read_only = handle.get_parameters().clone();
    read_only.rtp_parameters.rtcp.cname = "changed".to_owned();
    assert_eq!(
        handle.set_parameters(read_only, None),
        Err(Error::InvalidModificationError),
        "rtcp is read-only"
    );

    let mut defaulted = handle.get_parameters().clone();
    defaulted.encodings[0].scale_resolution_down_by = None;
    handle.set_parameters(defaulted, None)?;
    assert_eq!(
        handle.get_parameters().encodings[0].scale_resolution_down_by,
        Some(1.0),
        "video defaults to 1.0"
    );
    Ok(())
}

#[test]
fn set_parameters_strips_video_only_members_from_audio() -> TestResult {
    let mut pc = default_peer()?;
    let sender = pc.add_track(audio_track("audio", 0x0d07_0707))?;
    let mut handle = pc.rtp_sender(sender).expect("sender");
    let mut parameters = handle.get_parameters().clone();
    parameters.encodings[0].scale_resolution_down_by = Some(2.0);
    parameters.encodings[0].max_framerate = Some(15.0);
    handle.set_parameters(parameters, None)?;
    let encoding = &handle.get_parameters().encodings[0];
    assert_eq!(encoding.scale_resolution_down_by, None);
    assert_eq!(encoding.max_framerate, None);
    Ok(())
}

// --- 5.3 RTCRtpReceiver -------------------------------------------------------------------

#[test]
fn jitter_buffer_target_is_stored_within_its_range() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    let mut receiver = pc.rtp_receiver(id.into()).expect("receiver");
    assert_eq!(receiver.jitter_buffer_target(), None);
    receiver.set_jitter_buffer_target(Some(Duration::from_millis(150)))?;
    assert_eq!(
        receiver.jitter_buffer_target(),
        Some(Duration::from_millis(150))
    );
    assert!(matches!(
        receiver.set_jitter_buffer_target(Some(Duration::from_millis(4001))),
        Err(Error::RangeError(_))
    ));
    assert_eq!(
        receiver.jitter_buffer_target(),
        Some(Duration::from_millis(150)),
        "unchanged after a refused value"
    );
    receiver.set_jitter_buffer_target(None)?;
    assert_eq!(receiver.jitter_buffer_target(), None);
    Ok(())
}

// --- 5.4 RTCRtpTransceiver ----------------------------------------------------------------

/// stop() makes the transceiver stopping: its direction reads "stopped", the receiver's
/// track ends, currentDirection still reads the negotiated direction, and an answer made
/// now still answers the section. Once an exchange rejects the section it is stopped and
/// removed.
/// W3C 5.4 `currentDirection`: null until an offer/answer exchange has negotiated the
/// transceiver, then the negotiated direction.
#[test]
fn current_direction_is_null_until_negotiated() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    let sender = offerer.add_track(video_track("video", 0x0c06_0606))?;
    let id = RTCRtpTransceiverId::from(sender);
    assert_eq!(
        offerer
            .rtp_transceiver(id)
            .expect("transceiver")
            .current_direction(),
        None
    );
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(Instant::now(), offer)?;
    assert_eq!(
        offerer
            .rtp_transceiver(id)
            .expect("transceiver")
            .current_direction(),
        None,
        "an offer alone negotiates nothing"
    );
    offerer.set_local_description(Instant::now(), RTCSessionDescription::rollback(None)?)?;
    exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        offerer
            .rtp_transceiver(id)
            .expect("transceiver")
            .current_direction(),
        Some(RTCRtpTransceiverDirection::Sendonly)
    );
    Ok(())
}

#[test]
fn stop_is_stopping_until_a_rejecting_exchange_completes() -> TestResult {
    let (mut offerer, mut answerer, sender) = negotiated_both_ways()?;
    let id = RTCRtpTransceiverId::from(sender);
    let receiver_track = offerer
        .rtp_receiver(id.into())
        .expect("receiver")
        .track()
        .track_id()
        .clone();
    offerer.rtp_transceiver(id).expect("transceiver").stop()?;

    let transceiver = offerer.rtp_transceiver(id).expect("transceiver");
    assert_eq!(transceiver.direction(), RTCRtpTransceiverDirection::Stopped);
    assert!(!transceiver.is_stopped(), "stopping, not stopped");
    assert_eq!(
        transceiver.current_direction(),
        Some(RTCRtpTransceiverDirection::Sendrecv)
    );
    assert_eq!(ended_tracks(&mut offerer), vec![receiver_track]);
    assert_eq!(offerer.get_senders().count(), 1, "still collected");

    // A second stop() does nothing.
    offerer.rtp_transceiver(id).expect("transceiver").stop()?;
    assert!(ended_tracks(&mut offerer).is_empty());

    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(port_of(&media_sections(&offer)[0]), 0, "{offer}");
    assert_eq!(port_of(&media_sections(&answer)[0]), 0, "{answer}");
    assert_eq!(offerer.get_transceivers().count(), 0);
    assert_eq!(offerer.take_removed_transceivers(), vec![id]);
    Ok(())
}

#[test]
fn an_answer_made_while_stopping_still_answers_the_section() -> TestResult {
    let mut offerer = default_peer()?;
    let mut answerer = default_peer()?;
    offerer.add_track(video_track("offered", 0x0e01_0101))?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let id = answerer.get_transceivers().next().expect("a transceiver");
    answerer.rtp_transceiver(id).expect("transceiver").stop()?;

    let answer = answerer.create_answer(None)?;
    let section = &media_sections(&answer.sdp)[0];
    assert_ne!(port_of(section), 0, "{}", answer.sdp);
    assert!(section.iter().any(|l| l == "a=inactive"), "{}", answer.sdp);
    Ok(())
}

/// RFC 9429 section 5.3.1 as a setting (`with_stopping_transceiver_rejected_in_answer`): the
/// answer rejects the section of a transceiver stopped after the offer arrived, and the
/// offerer, applying it, stops its own transceiver. The offerer's BUNDLE-tagged section keeps
/// the W3C form (answered `a=inactive`), so the group keeps its transport.
#[test]
fn an_answer_rejects_a_stopping_transceivers_section_when_asked() -> TestResult {
    use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
    for (stopped_index, rejected) in [(1usize, true), (0, false)] {
        let mut offerer = default_peer()?;
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut answerer = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_stopping_transceiver_rejected_in_answer(true)
                    .build(),
            )
            .build(Instant::now())?;
        let senders = [
            offerer.add_track(video_track("first", 0x0e02_0101))?,
            offerer.add_track(video_track("second", 0x0e02_0202))?,
        ];
        let now = Instant::now();
        let offer = offerer.create_offer(None)?;
        offerer.set_local_description(now, offer.clone())?;
        answerer.set_remote_description(now, offer)?;
        let id = answerer
            .get_transceivers()
            .nth(stopped_index)
            .expect("a transceiver");
        answerer.rtp_transceiver(id).expect("transceiver").stop()?;

        let answer = answerer.create_answer(None)?;
        let section = &media_sections(&answer.sdp)[stopped_index];
        assert_eq!(
            port_of(section) == 0,
            rejected,
            "section {stopped_index}:\n{}",
            answer.sdp
        );
        if !rejected {
            assert!(section.iter().any(|l| l == "a=inactive"), "{}", answer.sdp);
        }
        answerer.set_local_description(now, answer.clone())?;
        offerer.set_remote_description(now, answer)?;
        let offerer_side = RTCRtpTransceiverId::from(senders[stopped_index]);
        let stopped = offerer
            .rtp_transceiver(offerer_side)
            .is_none_or(|transceiver| transceiver.is_stopped());
        assert_eq!(
            stopped, rejected,
            "section {stopped_index}: the offerer's transceiver"
        );
        // The other section goes on.
        let other = RTCRtpTransceiverId::from(senders[1 - stopped_index]);
        assert!(
            offerer
                .rtp_transceiver(other)
                .is_some_and(|transceiver| !transceiver.is_stopped())
        );
    }
    Ok(())
}

#[test]
fn set_direction_on_a_stopping_transceiver_is_an_invalid_state_error() -> TestResult {
    let (mut offerer, _answerer, sender) = negotiated_both_ways()?;
    let mut transceiver = offerer.rtp_transceiver(sender.into()).expect("transceiver");
    transceiver.stop()?;
    assert_eq!(
        transceiver.set_direction(RTCRtpTransceiverDirection::Sendonly),
        Err(Error::InvalidStateError)
    );
    assert_eq!(transceiver.direction(), RTCRtpTransceiverDirection::Stopped);
    assert_eq!(
        offerer
            .rtp_transceiver(sender.into())
            .expect("transceiver")
            .set_direction(RTCRtpTransceiverDirection::Stopped),
        Err(Error::InvalidStateError)
    );

    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    assert_eq!(
        pc.rtp_transceiver(id)
            .expect("transceiver")
            .set_direction(RTCRtpTransceiverDirection::Stopped),
        Err(Error::ErrInvalidDirection),
        "\"stopped\" is not a direction to set"
    );
    Ok(())
}

fn video_codec(mime_type: &str, clock_rate: u32, channels: u16) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate,
            channels,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type: 0,
    }
}

#[test]
fn set_codec_preferences_matches_clock_rate_and_channels() -> TestResult {
    let mut pc = default_peer()?;
    let video = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let audio = pc.add_transceiver_from_kind(RtpCodecKind::Audio, None)?;
    assert_eq!(
        pc.rtp_transceiver(video)
            .expect("transceiver")
            .set_codec_preferences(vec![video_codec(MIME_TYPE_VP8, 48000, 0)]),
        Err(Error::InvalidModificationError),
        "VP8 at another clock rate is not a VP8 the engine has"
    );
    let mut mono = RTCRtpCodecParameters {
        rtp_codec: opus(),
        payload_type: 0,
    };
    mono.rtp_codec.channels = 1;
    assert_eq!(
        pc.rtp_transceiver(audio)
            .expect("transceiver")
            .set_codec_preferences(vec![mono]),
        Err(Error::InvalidModificationError),
        "opus with one channel is not the registered opus"
    );
    Ok(())
}

#[test]
fn set_codec_preferences_refuses_a_list_of_only_repair_formats() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    assert_eq!(
        pc.rtp_transceiver(id)
            .expect("transceiver")
            .set_codec_preferences(vec![video_codec(MIME_TYPE_RTX, 90000, 0)]),
        Err(Error::InvalidModificationError)
    );
    Ok(())
}

#[test]
fn set_codec_preferences_with_an_empty_list_resets_to_the_engine_codecs() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let all = media_sections(&pc.create_offer(None)?.sdp)[0][0].clone();
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .set_codec_preferences(vec![video_codec(MIME_TYPE_VP8, 90000, 0)])?;
    let narrowed = media_sections(&pc.create_offer(None)?.sdp)[0][0].clone();
    assert_ne!(narrowed, all);
    pc.rtp_transceiver(id)
        .expect("transceiver")
        .set_codec_preferences(vec![])?;
    let reset = media_sections(&pc.create_offer(None)?.sdp)[0][0].clone();
    assert_eq!(reset, all);
    Ok(())
}

// --- webrtc-extensions 5 -----------------------------------------------------------------

fn down_to(rid: &str, max_width: u32, max_height: u32) -> RTCRtpEncodingParameters {
    RTCRtpEncodingParameters {
        scale_resolution_down_to: Some(
            rtci::rtp_transceiver::rtp_sender::RTCResolutionRestriction {
                max_width,
                max_height,
            },
        ),
        ..with_rid(rid)
    }
}

/// webrtc-extensions 5 and 5.1: `scaleResolutionDownTo` overrides `scaleResolutionDownBy`;
/// the factor is the same for both dimensions, orientation agnostic, and never upscales.
#[test]
fn scale_resolution_down_to_gives_one_factor_and_never_upscales() {
    let encoding = RTCRtpEncodingParameters {
        scale_resolution_down_by: Some(4.0),
        ..down_to("", 640, 360)
    };
    assert_eq!(
        encoding.scale_down_factor(1280, 720),
        2.0,
        "scaleResolutionDownBy is ignored"
    );
    assert_eq!(
        encoding.scale_down_factor(720, 1280),
        2.0,
        "orientation agnostic"
    );
    assert_eq!(
        encoding.scale_down_factor(1280, 1280),
        3.5555555555555554,
        "one factor for both"
    );
    assert_eq!(
        encoding.scale_down_factor(320, 180),
        1.0,
        "never an upscale"
    );
    let by = RTCRtpEncodingParameters {
        scale_resolution_down_by: Some(4.0),
        ..Default::default()
    };
    assert_eq!(by.scale_down_factor(1280, 720), 4.0);
}

/// webrtc-extensions 5: in addTransceiver, `scaleResolutionDownTo` on some but not all
/// active encodings, or with a dimension of 0, is an OperationError; `adaptivePtime` with
/// `ptime` is an InvalidModificationError; an audio encoding loses `scaleResolutionDownTo`.
#[test]
fn add_transceiver_validates_the_extension_members() -> TestResult {
    let mut pc = default_peer()?;
    let video = |encodings| init(RTCRtpTransceiverDirection::Sendonly, encodings);
    let partly = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        video(vec![down_to("a", 640, 360), with_rid("b")]),
    );
    assert!(
        matches!(partly, Err(Error::ErrOperationError(_))),
        "{partly:?}"
    );
    let inactive_without = RTCRtpEncodingParameters {
        active: false,
        ..with_rid("b")
    };
    pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        video(vec![down_to("a", 640, 360), inactive_without]),
    )?;
    let zero = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        video(vec![down_to("a", 0, 360), down_to("b", 320, 180)]),
    );
    assert!(matches!(zero, Err(Error::ErrOperationError(_))), "{zero:?}");
    let both = RTCRtpEncodingParameters {
        ptime: Some(20),
        adaptive_ptime: true,
        ..Default::default()
    };
    assert_eq!(
        pc.add_transceiver_from_kind(
            RtpCodecKind::Audio,
            init(RTCRtpTransceiverDirection::Sendonly, vec![both])
        )
        .err(),
        Some(Error::InvalidModificationError)
    );
    let audio = pc.add_transceiver_from_kind(
        RtpCodecKind::Audio,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![RTCRtpEncodingParameters {
                ptime: Some(40),
                ..down_to("", 640, 360)
            }],
        ),
    )?;
    let parameters = pc
        .rtp_sender(audio.into())
        .expect("sender")
        .get_parameters()
        .clone();
    assert_eq!(parameters.encodings[0].scale_resolution_down_to, None);
    assert_eq!(parameters.encodings[0].ptime, Some(40));
    assert!(
        !parameters.encodings[0].adaptive_ptime,
        "fixed frame length by default"
    );
    Ok(())
}

/// webrtc-extensions 5: setParameters refuses the same with InvalidModificationError, and
/// keeps a valid `scaleResolutionDownTo` for getParameters to return.
#[test]
fn set_parameters_validates_the_extension_members() -> TestResult {
    let mut pc = default_peer()?;
    let id = pc.add_transceiver_from_kind(
        RtpCodecKind::Video,
        init(
            RTCRtpTransceiverDirection::Sendonly,
            vec![with_rid("a"), with_rid("b")],
        ),
    )?;
    let mut sender = pc.rtp_sender(id.into()).expect("sender");
    let mut partly = sender.get_parameters().clone();
    partly.encodings[0].scale_resolution_down_to = down_to("a", 640, 360).scale_resolution_down_to;
    assert_eq!(
        sender.set_parameters(partly, None),
        Err(Error::InvalidModificationError)
    );
    let mut adaptive = sender.get_parameters().clone();
    adaptive.encodings[0].ptime = Some(20);
    adaptive.encodings[0].adaptive_ptime = true;
    assert_eq!(
        sender.set_parameters(adaptive, None),
        Err(Error::InvalidModificationError)
    );
    let mut all = sender.get_parameters().clone();
    for encoding in &mut all.encodings {
        encoding.scale_resolution_down_to = down_to("", 640, 360).scale_resolution_down_to;
    }
    sender.set_parameters(all, None)?;
    assert!(
        sender
            .get_parameters()
            .encodings
            .iter()
            .all(|e| e.scale_resolution_down_to.is_some())
    );
    Ok(())
}
