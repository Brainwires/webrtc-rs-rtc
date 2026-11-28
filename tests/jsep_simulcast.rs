//! Simulcast (RFC 8853) and RTP stream identifiers (RFC 8851) in offers and answers: what is
//! written, what an answer may say, and what an applied answer leaves of a sender's
//! encodings (W3C webrtc-pc "set a session description").

mod jsep_common;

use std::time::Instant;

use jsep_common::{
    SESSION, TRANSPORT, TestResult, crlf, default_peer, exchange, media_sections, mid_of, vp8,
};
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::media_engine::MediaEngine;
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RTCRtpRidRestrictions, RtpCodecKind,
};
use rtci::shared::error::Error;

/// A track with one VP8 encoding per `(rid, max-width)`.
fn simulcast_track(layers: &[(&str, Option<u64>)]) -> MediaStreamTrack {
    let encodings = layers
        .iter()
        .enumerate()
        .map(|(i, (rid, max_width))| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: (*rid).to_owned(),
                ssrc: Some(0x0515_0000 + i as u32),
                rid_restrictions: RTCRtpRidRestrictions {
                    max_width: *max_width,
                    ..Default::default()
                },
                ..Default::default()
            },
            codec: vp8(),
            active: true,
            ..Default::default()
        })
        .collect();
    MediaStreamTrack::new(
        "simulcast-stream".to_owned(),
        "simulcast".to_owned(),
        "simulcast".to_owned(),
        RtpCodecKind::Video,
        encodings,
    )
}

/// A default peer sending `layers` as simulcast.
fn simulcast_sender(
    layers: &[(&str, Option<u64>)],
) -> Result<(RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let mut pc = default_peer()?;
    let sender = pc.add_track(simulcast_track(layers))?;
    Ok((pc, sender))
}

/// The rids of the sender's encodings, with their max-width, as `getParameters` gives them.
fn sent_layers(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId) -> Vec<(String, Option<u64>)> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings
        .iter()
        .map(|e| {
            (
                e.rtp_coding_parameters.rid.clone(),
                e.rtp_coding_parameters.rid_restrictions.max_width,
            )
        })
        .collect()
}

fn layers(expected: &[(&str, Option<u64>)]) -> Vec<(String, Option<u64>)> {
    expected
        .iter()
        .map(|(rid, width)| ((*rid).to_owned(), *width))
        .collect()
}

/// A remote offer of one VP8 video section, `direction`, with `extra` lines (rids, simulcast).
fn remote_offer(direction: &str, extra: &str) -> Result<RTCSessionDescription, Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=msid:remote-stream remote-track
a={direction}
a=rtpmap:96 VP8/90000
{extra}"
    )))
}

/// The lines of `sdp` that start with `prefix`.
fn lines_with<'a>(sdp: &'a str, prefix: &str) -> Vec<&'a str> {
    sdp.lines().filter(|l| l.starts_with(prefix)).collect()
}

/// `sdp` with `from` replaced by `to`, which must occur in it.
fn edited(sdp: &str, from: &str, to: &str) -> String {
    assert!(sdp.contains(from), "`{from}` is not in\n{sdp}");
    sdp.replace(from, to)
}

/// RFC 8851 section 5 / 6.3: the restrictions an application gives its encodings are written
/// on the offer's `a=rid ... send` lines, the answerer echoes them on its `recv` lines, and the
/// answerer's receiver exposes them.
#[test]
fn rid_restrictions_are_offered_echoed_and_exposed_on_the_receiver() -> TestResult {
    let (mut offerer, _) = simulcast_sender(&[("f", Some(1280)), ("h", Some(640))])?;
    let mut answerer = default_peer()?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;

    assert_eq!(
        lines_with(&offer, "a=rid:"),
        vec!["a=rid:f send max-width=1280", "a=rid:h send max-width=640"],
        "{offer}"
    );
    assert_eq!(
        lines_with(&answer, "a=rid:"),
        vec!["a=rid:f recv max-width=1280", "a=rid:h recv max-width=640"],
        "{answer}"
    );
    assert_eq!(
        lines_with(&answer, "a=simulcast:"),
        vec!["a=simulcast:recv f;h"]
    );

    let receiver = answerer.get_receivers().next().expect("a receiver");
    let receiver = answerer.rtp_receiver(receiver).expect("receiver");
    let exposed: Vec<(String, Option<u64>)> = receiver
        .track()
        .codings()
        .iter()
        .map(|c| {
            (
                c.rtp_coding_parameters.rid.clone(),
                c.rtp_coding_parameters.rid_restrictions.max_width,
            )
        })
        .collect();
    assert_eq!(exposed, layers(&[("f", Some(1280)), ("h", Some(640))]));
    Ok(())
}

/// RFC 8853 section 5.3.2: "The answerer MUST NOT add any simulcast streams": an answer to
/// `a=simulcast:recv f;x` from a sender of f, h, q lists f only, and W3C webrtc-pc leaves the
/// sender the encodings the answer kept.
#[test]
fn an_answer_sends_only_the_offered_rids_the_sender_has() -> TestResult {
    let (mut pc, sender) = simulcast_sender(&[("f", None), ("h", None), ("q", None)])?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:x recv\na=simulcast:recv f;x\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:f send"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send f"]
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", None)]));
    Ok(())
}

/// RFC 8853 section 5.3.2: an offer that asks for no simulcast gets an answer without
/// `a=simulcast` or `a=rid`, and the sender keeps its first encoding only (W3C webrtc-pc:
/// "If description indicates that simulcast is not supported or desired ... remove all
/// dictionaries ... except the first one").
#[test]
fn an_offer_without_simulcast_is_answered_with_the_first_encoding_only() -> TestResult {
    let (mut pc, sender) = simulcast_sender(&[("f", None), ("h", None)])?;
    let now = Instant::now();
    pc.set_remote_description(now, remote_offer("recvonly", "")?)?;
    let answer = pc.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=rid:").is_empty(),
        "{}",
        answer.sdp
    );
    assert!(
        lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "{}",
        answer.sdp
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", None)]));
    Ok(())
}

/// An offerer whose simulcast offer of f, h, q was answered by a default peer, with the answer
/// left unapplied for the test to edit.
fn offered_three_layers()
-> Result<(RTCPeerConnection, RTCRtpSenderId, String), Box<dyn std::error::Error>> {
    let (mut offerer, sender) =
        simulcast_sender(&[("f", Some(1280)), ("h", Some(640)), ("q", Some(320))])?;
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    Ok((offerer, sender, answer.sdp.replace("\r\n", "\n")))
}

/// RFC 8853 section 5.3.3 and W3C webrtc-pc "set a session description": a remote answer that
/// accepts two of three offered streams leaves the sender those two, and the next offer lists
/// only them.
#[test]
fn a_remote_answer_that_accepts_two_of_three_streams_removes_the_third() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer = edited(&answer, "a=rid:q recv max-width=320\n", "");
    let answer = edited(&answer, "a=simulcast:recv f;h;q", "a=simulcast:recv f;h");
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;

    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", Some(1280)), ("h", Some(640))])
    );
    let next = pc.create_offer(None)?;
    assert_eq!(
        lines_with(&next.sdp, "a=simulcast:"),
        vec!["a=simulcast:send f;h"],
        "{}",
        next.sdp
    );
    Ok(())
}

/// W3C webrtc-pc "set a session description": an answer without simulcast leaves the first
/// encoding.
#[test]
fn a_remote_answer_without_simulcast_leaves_the_first_encoding() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer: String = answer
        .lines()
        .filter(|l| !l.starts_with("a=rid:") && !l.starts_with("a=simulcast:"))
        .map(|l| format!("{l}\n"))
        .collect();
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", Some(1280))]));
    Ok(())
}

/// RFC 8851 section 6.4: an answered `a=rid` line may tighten a restriction (the encoding
/// takes the tighter one) but one that loosens it, or adds a `pt=` the offer did not have, is
/// discarded and its stream goes.
#[test]
fn an_answered_rid_may_tighten_but_not_loosen_the_offer() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer = edited(
        &answer,
        "a=rid:f recv max-width=1280",
        "a=rid:f recv max-width=960",
    );
    let answer = edited(
        &answer,
        "a=rid:h recv max-width=640",
        "a=rid:h recv max-width=1920",
    );
    let answer = edited(
        &answer,
        "a=rid:q recv max-width=320",
        "a=rid:q recv pt=96;max-width=320",
    );
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", Some(960))]));
    Ok(())
}

/// RFC 8851 section 8: the rid restrictions "impose additional restrictions beyond those
/// communicated in other techniques": an encoding is sent under the smaller of its answered
/// rid limits and the answer's VP8 `max-fr` / `max-fs` and `b=TIAS`.
#[test]
fn an_encoding_is_sent_under_the_tighter_of_its_rid_format_and_bandwidth_limits() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let answer = edited(
        &answer,
        "a=rtpmap:96 VP8/90000\n",
        "a=rtpmap:96 VP8/90000\na=fmtp:96 max-fr=15;max-fs=3600\n",
    );
    let at = answer.find("m=video").expect("a video section");
    let c_line = at + answer[at..].find("c=IN IP4 0.0.0.0\n").expect("a c= line");
    let answer = format!(
        "{}c=IN IP4 0.0.0.0\nb=TIAS:800000\n{}",
        &answer[..c_line],
        &answer[c_line + "c=IN IP4 0.0.0.0\n".len()..]
    );
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    let mut rtp_sender = pc.rtp_sender(sender).expect("sender");
    let f = rtp_sender.send_restrictions("f").expect("encoding f");
    assert_eq!(f.max_width, Some(1280), "the rid's width is the tighter");
    assert_eq!(f.max_height, Some(2704), "int(sqrt(3600 * 8)) macroblocks");
    assert_eq!(f.max_fps, Some(15), "VP8 max-fr");
    assert_eq!(f.max_fs, Some(3600 * 256), "VP8 max-fs in pixels");
    assert_eq!(f.max_br, Some(800_000), "b=TIAS");
    let q = rtp_sender.send_restrictions("q").expect("encoding q");
    assert_eq!(q.max_width, Some(320));
    assert!(rtp_sender.send_restrictions("x").is_none());
    Ok(())
}

/// RFC 8853 section 5.2 / 5.3.2: the pause mark `~` needs RFC 7728, which the engine does not
/// negotiate: by default it is not repeated in an answer, with `with_rid_pause_marks(true)` it
/// is.
#[test]
fn an_offered_pause_mark_is_answered_only_when_pause_marks_are_written() -> TestResult {
    for rid_pause_marks in [false, true] {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(
                SettingEngineBuilder::new()
                    .with_rid_pause_marks(rid_pause_marks)
                    .build(),
            )
            .with_media_engine(media_engine)
            .build(Instant::now())?;
        pc.add_track(simulcast_track(&[("f", None), ("h", None)]))?;
        pc.set_remote_description(
            Instant::now(),
            remote_offer(
                "recvonly",
                "a=rid:f recv\na=rid:h recv\na=simulcast:recv f;~h\n",
            )?,
        )?;
        let answer = pc.create_answer(None)?;
        let expected = if rid_pause_marks {
            "a=simulcast:send f;~h"
        } else {
            "a=simulcast:send f;h"
        };
        assert_eq!(
            lines_with(&answer.sdp, "a=simulcast:"),
            vec![expected],
            "pause marks {rid_pause_marks}:\n{}",
            answer.sdp
        );
    }
    Ok(())
}

/// RFC 8851 section 6.2.2 step 2: a rid-id on two `a=rid` lines discards both, so the answer
/// sends only the other stream.
#[test]
fn a_rid_id_offered_twice_is_not_answered() -> TestResult {
    let (mut pc, _) = simulcast_sender(&[("f", None), ("h", None)])?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:f recv max-width=640\na=rid:h recv\na=simulcast:recv f;h\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert_eq!(lines_with(&answer.sdp, "a=rid:"), vec!["a=rid:h send"]);
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send h"]
    );
    Ok(())
}

/// A remote offer of one video section, `direction`, offering VP8 (96) and a format this
/// endpoint does not have (98), with `extra` lines (rids, simulcast).
fn remote_offer_with_an_unknown_format(
    direction: &str,
    extra: &str,
) -> Result<RTCSessionDescription, Error> {
    RTCSessionDescription::offer(crlf(&format!(
        "{SESSION}a=group:BUNDLE 0
m=video 9 UDP/TLS/RTP/SAVPF 96 98
{TRANSPORT}a=mid:0
a=msid:remote-stream remote-track
a={direction}
a=rtpmap:96 VP8/90000
a=rtpmap:98 MUST8B-UNKNOWN/90000
{extra}"
    )))
}

/// RFC 8851 section 6.3 step 4: "If the answerer chooses to discard all the media formats
/// from an 'a=rid' line, the answerer MUST discard the entire 'a=rid' line. If the offer did
/// not contain a 'pt=' for a given 'a=rid' line, then the answer MUST NOT contain a 'pt=' in
/// the corresponding line." An offered `pt=` that names only the format the answer leaves out
/// drops the line (and its simulcast stream); one that names it with VP8 keeps VP8; one
/// without `pt=` is answered without. Both the answerer's `recv` lines (the offerer sends)
/// and its `send` lines (the offerer receives).
#[test]
fn a_rid_line_whose_formats_the_answer_discards_is_dropped() -> TestResult {
    let now = Instant::now();
    let mut receiving = default_peer()?;
    receiving.set_remote_description(
        now,
        remote_offer_with_an_unknown_format(
            "sendonly",
            "a=rid:f send pt=98\na=rid:h send pt=96,98\na=rid:q send\na=simulcast:send f;h;q\n",
        )?,
    )?;
    let answer = receiving.create_answer(None)?;
    assert!(
        !answer.sdp.contains("MUST8B-UNKNOWN"),
        "the unknown format is not answered:\n{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:h recv pt=96", "a=rid:q recv"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:recv h;q"]
    );

    let (mut sending, sender) = simulcast_sender(&[("f", None), ("h", None)])?;
    sending.set_remote_description(
        now,
        remote_offer_with_an_unknown_format(
            "recvonly",
            "a=rid:f recv pt=98\na=rid:h recv\na=simulcast:recv f;h\n",
        )?,
    )?;
    let answer = sending.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:h send"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send h"]
    );
    sending.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut sending, sender), layers(&[("h", None)]));
    Ok(())
}

/// RFC 8853 section 5.2: "Implementations of this specification MUST NOT use it at the
/// session level and MUST ignore it if received at the session level." A remote offer whose
/// only `a=simulcast` is at the session level, over a section with `a=rid` lines, is taken
/// and negotiates no simulcast: the answer has no `a=simulcast`, and a simulcast sender keeps
/// its first encoding (W3C webrtc-pc: "If description indicates that simulcast is not
/// supported or desired ... remove all dictionaries ... except the first one").
#[test]
fn a_session_level_simulcast_line_is_ignored() -> TestResult {
    let now = Instant::now();
    let session_offer = |direction: &str, rids: &str, simulcast: &str| {
        RTCSessionDescription::offer(crlf(&format!(
            "{SESSION}a=group:BUNDLE 0
a=simulcast:{simulcast}
m=video 9 UDP/TLS/RTP/SAVPF 96
{TRANSPORT}a=mid:0
a=msid:remote-stream remote-track
a={direction}
a=rtpmap:96 VP8/90000
{rids}"
        )))
    };

    let (mut sending, sender) = simulcast_sender(&[("f", None), ("h", None)])?;
    sending.set_remote_description(
        now,
        session_offer("recvonly", "a=rid:f recv\na=rid:h recv\n", "recv f;h")?,
    )?;
    let answer = sending.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "no simulcast is negotiated:\n{}",
        answer.sdp
    );
    sending.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut sending, sender), layers(&[("f", None)]));

    let mut receiving = default_peer()?;
    receiving.set_remote_description(
        now,
        session_offer("sendonly", "a=rid:f send\na=rid:h send\n", "send f;h")?,
    )?;
    let answer = receiving.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "no simulcast is negotiated:\n{}",
        answer.sdp
    );
    receiving.set_local_description(now, answer)?;
    Ok(())
}

/// RFC 8853 section 5.3.2: an offer with more than one `a=simulcast` line in a section is
/// answered without simulcast.
#[test]
fn several_simulcast_lines_are_answered_without_simulcast() -> TestResult {
    let (mut pc, _) = simulcast_sender(&[("f", None), ("h", None)])?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:h recv\na=simulcast:recv f\na=simulcast:recv h\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "{}",
        answer.sdp
    );
    Ok(())
}

/// RFC 9429 section 5.8.3: "All rid-ids referenced in an 'a=simulcast' line MUST exist as
/// 'a=rid' lines": a description that names one without its line is refused.
#[test]
fn a_simulcast_rid_without_its_rid_line_refuses_the_description() -> TestResult {
    let mut pc = default_peer()?;
    let result = pc.set_remote_description(
        Instant::now(),
        remote_offer("sendonly", "a=rid:f send\na=simulcast:send f;z\n")?,
    );
    assert!(
        matches!(result, Err(Error::SdpInvalidValue(ref reason)) if reason.contains("rid z")),
        "{result:?}"
    );
    Ok(())
}

/// RFC 8853 section 5.2: "a single rid-id MUST NOT occur more than once per 'a=simulcast'
/// line", and "each direction MUST NOT occur more than once"; RFC 9429 section 5.8: a line that
/// is not well formed rejects the whole description (the line used to be ignored).
#[test]
fn a_simulcast_line_that_repeats_a_rid_or_a_direction_refuses_the_description() -> TestResult {
    for line in [
        "a=simulcast:send f;f",
        "a=simulcast:send f,h;h",
        "a=simulcast:send f send h",
    ] {
        let mut pc = default_peer()?;
        let result = pc.set_remote_description(
            Instant::now(),
            remote_offer("sendonly", &format!("a=rid:f send\na=rid:h send\n{line}\n"))?,
        );
        assert!(
            matches!(result, Err(Error::SdpInvalidValue(ref reason)) if reason.contains("a=simulcast")),
            "{line}: {result:?}"
        );
    }
    Ok(())
}

/// W3C webrtc-pc addTransceiver: a rid outside the grammar is refused. The rid is sent as the
/// RtpStreamId of RFC 8852, which section 3.1 limits to 1 to 255 alphanumeric characters.
#[test]
fn a_rid_that_is_not_alphanumeric_is_refused() -> TestResult {
    for rid in ["a-b", "a_b", "é", &"a".repeat(256)] {
        let mut pc = default_peer()?;
        let result = pc.add_track(simulcast_track(&[("f", None), (rid, None)]));
        assert!(
            matches!(result, Err(Error::ErrRTPSenderRidInvalid)),
            "rid {rid:?}: {result:?}"
        );
    }
    let mut pc = default_peer()?;
    pc.add_track(simulcast_track(&[("f", None), (&"a".repeat(255), None)]))?;
    Ok(())
}

/// The rids `answerer`'s receiver exposes once it has answered the offer of a simulcast
/// sender of f and h, with `extra` (CRLF-ended lines) added to the offer after its
/// `a=simulcast` line.
fn received_rids_with(
    answerer: &mut RTCPeerConnection,
    extra: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let (mut offerer, _) = simulcast_sender(&[("f", None), ("h", None)])?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    let sdp = edited(
        &offer.sdp,
        "a=simulcast:send f;h\r\n",
        &format!("a=simulcast:send f;h\r\n{extra}"),
    );
    answerer.set_remote_description(now, RTCSessionDescription::offer(sdp)?)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer)?;
    let receiver = answerer.get_receivers().next().expect("a receiver");
    let receiver = answerer.rtp_receiver(receiver).expect("receiver");
    Ok(receiver
        .track()
        .codings()
        .iter()
        .map(|c| c.rtp_coding_parameters.rid.clone())
        .collect())
}

/// RFC 8851 section 10 as corrected by erratum 7132 (Verified): `rid-id =
/// 1*255(alpha-numeric)`. A remote sender's rid of 255 alphanumerics is received.
#[test]
fn a_remote_rid_of_255_alphanumerics_is_received() -> TestResult {
    let longest = "Az09".repeat(64)[..255].to_owned();
    let (mut offerer, _) = simulcast_sender(&[("f", None), (&longest, None)])?;
    let mut answerer = default_peer()?;
    let (offer, _) = exchange(&mut offerer, &mut answerer)?;
    assert!(offer.contains(&format!("a=rid:{longest} send")), "{offer}");
    let receiver = answerer.get_receivers().next().expect("a receiver");
    let receiver = answerer.rtp_receiver(receiver).expect("receiver");
    let rids: Vec<String> = receiver
        .track()
        .codings()
        .iter()
        .map(|c| c.rtp_coding_parameters.rid.clone())
        .collect();
    assert_eq!(rids, vec!["f".to_owned(), longest]);
    Ok(())
}

/// RFC 8851 section 6.2.2 step 1: "In the case of a syntax error, the 'a=rid' line is
/// discarded"; under erratum 7132 a rid-id with `-` is a syntax error.
#[test]
fn a_remote_rid_line_whose_id_has_a_dash_is_discarded() -> TestResult {
    let mut answerer = default_peer()?;
    let rids = received_rids_with(&mut answerer, "a=rid:a-b send\r\n")?;
    assert_eq!(rids, vec!["f", "h"]);
    Ok(())
}

/// As above for `_`.
#[test]
fn a_remote_rid_line_whose_id_has_an_underscore_is_discarded() -> TestResult {
    let mut answerer = default_peer()?;
    let rids = received_rids_with(&mut answerer, "a=rid:a_b send\r\n")?;
    assert_eq!(rids, vec!["f", "h"]);
    Ok(())
}

/// As above for a rid-id of more than 255 characters (`1*255`).
#[test]
fn a_remote_rid_line_whose_id_is_longer_than_255_is_discarded() -> TestResult {
    let mut answerer = default_peer()?;
    let rids = received_rids_with(
        &mut answerer,
        &format!("a=rid:{} send\r\n", "a".repeat(256)),
    )?;
    assert_eq!(rids, vec!["f", "h"]);
    Ok(())
}

/// RFC 8853 section 5.1 takes its `rid-id` from RFC 8851 (erratum 7132), and RFC 9429
/// section 5.8: a line that is not well formed rejects the whole description, as
/// `a_simulcast_line_that_repeats_a_rid_or_a_direction_refuses_the_description` does for the
/// other faults of the line.
#[test]
fn a_simulcast_line_naming_a_rid_outside_the_grammar_refuses_the_description() -> TestResult {
    for id in ["a-b".to_owned(), "a_b".to_owned(), "a".repeat(256)] {
        let mut pc = default_peer()?;
        let result = pc.set_remote_description(
            Instant::now(),
            remote_offer(
                "sendonly",
                &format!("a=rid:f send\na=rid:{id} send\na=simulcast:send f;{id}\n"),
            )?,
        );
        assert!(
            matches!(result, Err(Error::SdpInvalidValue(ref reason)) if reason.contains("a=simulcast")),
            "{id}: {result:?}"
        );
    }
    Ok(())
}

/// `SettingEngineBuilder::with_published_rid_id_grammar(true)` reads received rid-ids as RFC
/// 8851 section 10 was published (`1*(alpha-numeric / "-" / "_")`, any length): the lines the
/// corrected grammar discards are received, and an `a=simulcast` line naming them is applied.
#[test]
fn with_the_published_grammar_dashes_underscores_and_long_rids_are_taken() -> TestResult {
    let published = || -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;
        Ok(RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .with_setting_engine(
                SettingEngineBuilder::default()
                    .with_published_rid_id_grammar(true)
                    .build(),
            )
            .build(Instant::now())?)
    };
    let long = "a".repeat(256);
    let mut answerer = published()?;
    let rids = received_rids_with(
        &mut answerer,
        &format!("a=rid:a-b send\r\na=rid:a_b send\r\na=rid:{long} send\r\n"),
    )?;
    assert_eq!(
        rids,
        vec![
            "f".to_owned(),
            "h".to_owned(),
            "a-b".to_owned(),
            "a_b".to_owned(),
            long.clone()
        ]
    );

    for id in ["a-b".to_owned(), "a_b".to_owned(), long] {
        let mut pc = published()?;
        pc.set_remote_description(
            Instant::now(),
            remote_offer(
                "sendonly",
                &format!("a=rid:f send\na=rid:{id} send\na=simulcast:send f;{id}\n"),
            )?,
        )?;
    }
    Ok(())
}

/// RFC 8851 section 6.1: "any payload type listed in 'pt=' MUST be one of the formats of the
/// m= line": an encoding's `payload_types` keeps in the offer only the ones the section has,
/// and the offerer's answer to an offer `~` it does not support is not applied as a pause
/// (RFC 8853 section 5.3.3: no initial pause without RFC 7728).
#[test]
fn a_pt_restriction_keeps_the_formats_of_the_section_and_an_answered_pause_mark_is_ignored()
-> TestResult {
    let mut track = simulcast_track(&[("f", None), ("h", None)]);
    let mut encodings = track.codings().to_vec();
    encodings[0]
        .rtp_coding_parameters
        .rid_restrictions
        .payload_types = vec![96, 0];
    track = MediaStreamTrack::new(
        "simulcast-stream".to_owned(),
        "simulcast".to_owned(),
        "simulcast".to_owned(),
        RtpCodecKind::Video,
        encodings,
    );
    let mut offerer = default_peer()?;
    let sender = offerer.add_track(track)?;
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    assert_eq!(
        lines_with(&offer.sdp, "a=rid:"),
        vec!["a=rid:f send pt=96", "a=rid:h send"],
        "{}",
        offer.sdp
    );
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    let answer = edited(
        &answer.sdp.replace("\r\n", "\n"),
        "a=simulcast:recv f;h",
        "a=simulcast:recv f;~h",
    );
    offerer.set_remote_description(now, RTCSessionDescription::answer(crlf(&answer))?)?;
    let s = offerer.rtp_sender(sender);
    let mut s = s.expect("sender");
    let encodings = &s.get_parameters().encodings;
    assert_eq!(encodings.len(), 2);
    assert!(encodings.iter().all(|e| e.active), "no encoding is paused");
    Ok(())
}

fn w3c_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_w3c_simulcast_answer(true)
                .build(),
        )
        .build(Instant::now())?)
}

/// W3C webrtc-pc row 4.4.2-39, the W3C form as a setting: with `with_w3c_simulcast_answer` a
/// remote `a=simulcast` line that names a rid twice is taken with the rid at its first place
/// (by default it refuses the description: RFC 8853 section 5.2), and the answer's `a=rid`
/// lines carry no restrictions (by default they keep the offered ones: RFC 8851 section 6.3).
#[test]
fn the_w3c_answer_form_reduces_a_repeated_rid_and_sets_no_restrictions() -> TestResult {
    let mut pc = w3c_peer()?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "sendonly",
            "a=rid:f send max-width=1280\na=rid:h send max-width=640\na=simulcast:send f;h;f\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:f recv", "a=rid:h recv"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:recv f;h"]
    );

    // The default, for contrast: the same offer is refused, and restrictions are echoed.
    let mut pc = default_peer()?;
    assert!(
        pc.set_remote_description(
            Instant::now(),
            remote_offer(
                "sendonly",
                "a=rid:f send\na=rid:h send\na=simulcast:send f;h;f\n"
            )?,
        )
        .is_err()
    );
    let (mut offerer, _) = simulcast_sender(&[("f", Some(1280)), ("h", Some(640))])?;
    let mut answerer = w3c_peer()?;
    let (_, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        lines_with(&answer, "a=rid:"),
        vec!["a=rid:f recv", "a=rid:h recv"],
        "{answer}"
    );
    Ok(())
}

/// RFC 8853 section 5.3.1: an offerer may ask to receive simulcast; it is then "prepared to
/// receive" each stream. `set_receive_simulcast` writes the `recv` rids and `a=simulcast:recv`;
/// a simulcast sender answers with the streams it has, and the offerer's receiver takes them
/// as its layers.
#[test]
fn an_offer_can_ask_to_receive_simulcast() -> TestResult {
    let mut offerer = default_peer()?;
    let id = offerer.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(rtci::rtp_transceiver::RTCRtpTransceiverInit::recvonly()),
    )?;
    let mut transceiver = offerer.rtp_transceiver(id).expect("the transceiver");
    assert!(
        transceiver
            .set_receive_simulcast(vec!["f".to_owned()])
            .is_err()
    );
    assert!(
        transceiver
            .set_receive_simulcast(vec!["f".to_owned(), "f".to_owned()])
            .is_err()
    );
    transceiver.set_receive_simulcast(vec!["f".to_owned(), "h".to_owned(), "q".to_owned()])?;

    let (mut answerer, _) = simulcast_sender(&[("f", None), ("h", None), ("q", None)])?;
    let (offer, answer) = exchange(&mut offerer, &mut answerer)?;
    assert_eq!(
        lines_with(&offer, "a=rid:"),
        vec!["a=rid:f recv", "a=rid:h recv", "a=rid:q recv"],
        "{offer}"
    );
    assert_eq!(
        lines_with(&offer, "a=simulcast:"),
        vec!["a=simulcast:recv f;h;q"]
    );
    assert_eq!(
        lines_with(&answer, "a=simulcast:"),
        vec!["a=simulcast:send f;h;q"],
        "{answer}"
    );

    let receiver = offerer.get_receivers().next().expect("a receiver");
    let receiver = offerer.rtp_receiver(receiver).expect("receiver");
    let layers: Vec<String> = receiver
        .track()
        .codings()
        .iter()
        .map(|c| c.rtp_coding_parameters.rid.clone())
        .collect();
    assert_eq!(layers, vec!["f", "h", "q"]);
    Ok(())
}

/// RFC 9429 section 5.2.1: for a sender with several encodings, "an 'a=rid' line for each
/// encoding ... If the application has not set an rid ..., an rid-id value MUST be generated".
/// Encodings stated to be simulcast layers (`with_simulcast_layers`) are offered as layers
/// with generated rids (no user data, one byte each), rids the application set are kept;
/// encodings without rids and without that statement stay codec alternatives of one stream
/// (`codec_negotiation.rs::test_add_track_negotiates_non_first_codec`).
#[test]
fn simulcast_layers_without_rids_get_generated_rids() -> TestResult {
    use rtci::rtp_transceiver::RTCRtpTransceiverDirection;
    use rtci::rtp_transceiver::RTCRtpTransceiverInit;
    for (given, expected) in [
        (["", "", ""], ["0", "1", "2"]),
        (["", "1", ""], ["0", "1", "2"]),
        (["0", "", "hi"], ["0", "1", "hi"]),
    ] {
        let mut pc = default_peer()?;
        let encodings = given
            .iter()
            .map(|rid| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: (*rid).to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            })
            .collect();
        pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(
                RTCRtpTransceiverInit::with_direction(RTCRtpTransceiverDirection::Sendonly)
                    .with_simulcast_layers(encodings),
            ),
        )?;
        let offer = pc.create_offer(None)?.sdp;
        let rid_lines: Vec<String> = expected.iter().map(|r| format!("a=rid:{r} send")).collect();
        assert_eq!(
            lines_with(&offer, "a=rid:"),
            rid_lines,
            "{given:?}\n{offer}"
        );
        assert_eq!(
            lines_with(&offer, "a=simulcast:"),
            [format!("a=simulcast:send {}", expected.join(";"))],
            "{given:?}"
        );
    }
    Ok(())
}

/// The scale factors of the sender's encodings, in order.
fn sent_scales(pc: &mut RTCPeerConnection, sender: RTCRtpSenderId) -> Vec<Option<f64>> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings
        .iter()
        .map(|e| e.scale_resolution_down_by)
        .collect()
}

/// W3C webrtc-pc "set the RTCSessionDescription" (`proposedSendEncodings`): a remote offer to
/// receive simulcast promotes a sender with one rid-less encoding to the offered layers, in the
/// offer's order, scaled down by 2^(n - index - 1); the answer sends them; at most
/// `MAX_SEND_ENCODINGS` are taken; a rollback restores the rid-less encoding
/// (`[[LastStableRidlessSendEncodings]]`).
#[test]
fn a_remote_offer_to_receive_simulcast_promotes_a_unicast_sender() -> TestResult {
    let (mut pc, sender) = {
        let mut pc = default_peer()?;
        let sender = pc.add_track(jsep_common::video_track("unicast", 0x0516_0001))?;
        (pc, sender)
    };
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("", None)]));
    let now = Instant::now();
    let offer = || {
        remote_offer(
            "recvonly",
            "a=rid:q recv\na=rid:h recv\na=rid:f recv\na=simulcast:recv q;h;f\n",
        )
    };
    pc.set_remote_description(now, offer()?)?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("q", None), ("h", None), ("f", None)])
    );
    assert_eq!(
        sent_scales(&mut pc, sender),
        [Some(4.0), Some(2.0), Some(1.0)]
    );

    // Rolled back: the rid-less encoding again.
    pc.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("", None)]));

    // Answered: the layers are sent.
    pc.set_remote_description(now, offer()?)?;
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:q send", "a=rid:h send", "a=rid:f send"],
        "{}",
        answer.sdp
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender).len(), 3);

    // Truncated to the supported number of encodings.
    let mut pc = default_peer()?;
    let sender = pc.add_track(jsep_common::video_track("unicast", 0x0516_0002))?;
    let ids: Vec<String> = (0..20).map(|i| format!("r{i}")).collect();
    let mut extra: String = ids.iter().map(|id| format!("a=rid:{id} recv\n")).collect();
    extra.push_str(&format!("a=simulcast:recv {}\n", ids.join(";")));
    pc.set_remote_description(now, remote_offer("recvonly", &extra)?)?;
    assert_eq!(
        sent_layers(&mut pc, sender).len(),
        rtci::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS
    );
    Ok(())
}

/// W3C `proposedSendEncodings`: "Remove any RTCRtpEncodingParameters dictionaries in
/// proposedSendEncodings if their rid member is the same as a rid member of an earlier one",
/// in the W3C answer form, which takes an `a=simulcast` line that repeats a rid.
#[test]
fn proposed_send_encodings_drop_a_repeated_rid() -> TestResult {
    let mut pc = w3c_peer()?;
    let sender = pc.add_track(jsep_common::video_track("unicast", 0x0516_0003))?;
    pc.set_remote_description(
        Instant::now(),
        remote_offer(
            "recvonly",
            "a=rid:h recv\na=rid:f recv\na=simulcast:recv h;f;h\n",
        )?,
    )?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("h", None), ("f", None)])
    );
    Ok(())
}

/// A simulcast sender (encodings f and h) whose envelope a first remote offer and the local
/// answer established, and a later remote offer of `version` with `extra` lines.
fn envelope_f_h() -> Result<(RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    let (mut pc, sender) = simulcast_sender(&[("f", None), ("h", None)])?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:h recv\na=simulcast:recv f;h\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;
    Ok((pc, sender))
}

fn reoffer(version: u32, extra: &str) -> Result<RTCSessionDescription, Error> {
    let offer = remote_offer("recvonly", extra)?;
    RTCSessionDescription::offer(
        offer
            .sdp
            .replace(" 2 IN IP4", &format!(" {version} IN IP4")),
    )
}

/// W3C webrtc-pc Candidate Correction 37 (w3c/webrtc-pc PR #2794, merged 2022-12-08, "Don't
/// fail sRD(offer) over rid mismatch, just answer with unicast"; issue #2724): a later remote
/// offer that asks a sender with a simulcast envelope for rids outside it is applied, not
/// refused. The correction removed the step that failed it ("This specification does not
/// allow remotely initiated RID renegotiation"). The sender's [[SendEncodings]] stay (a found
/// transceiver takes proposedSendEncodings only "If the length of ... [[SendEncodings]] is 1,
/// and the lone encoding contains no rid member"); createAnswer leaves out "any RID not found
/// in the corresponding transceiver's [[Sender]].[[SendEncodings]]"; setLocalDescription of
/// the answer removes the layers it is missing, all but the first when it is missing all of
/// them (section 5.4.1: the envelope "may be narrowed ... but cannot be reexpanded"). Issue
/// #2762 (resolution 2022-10-18) records the same of browsers: "SRD never fails".
#[test]
fn a_remote_offer_that_adds_or_renames_rids_is_answered_within_the_envelope() -> TestResult {
    let (mut pc, sender) = envelope_f_h()?;
    let now = Instant::now();

    // Adds rid x: applied; answered with f and h; the encodings stay f and h.
    pc.set_remote_description(
        now,
        reoffer(
            3,
            "a=rid:f recv\na=rid:h recv\na=rid:x recv\na=simulcast:recv f;h;x\n",
        )?,
    )?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", None), ("h", None)])
    );
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:f send", "a=rid:h send"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send f;h"],
        "{}",
        answer.sdp
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", None), ("h", None)])
    );

    // Renames every rid: applied; answered with unicast; the first encoding is left.
    pc.set_remote_description(
        now,
        reoffer(4, "a=rid:a recv\na=rid:b recv\na=simulcast:recv a;b\n")?,
    )?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", None), ("h", None)])
    );
    let answer = pc.create_answer(None)?;
    assert!(
        lines_with(&answer.sdp, "a=rid:").is_empty()
            && lines_with(&answer.sdp, "a=simulcast:").is_empty(),
        "{}",
        answer.sdp
    );
    pc.set_local_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("f", None)]));
    Ok(())
}

/// The form of W3C webrtc-pc before Candidate Correction 37 (the Recommendation of 13 March
/// 2025 without its candidate corrections: "If applying description leads to modifying a
/// transceiver ... the process of applying description fails. This specification does not
/// allow remotely initiated RID renegotiation", then "If the description attempted to
/// renegotiate RIDs, as described above, then reject p with a newly created
/// InvalidAccessError"): with `with_remote_rid_renegotiation_refused(true)` a later remote
/// offer that asks the sender for a rid outside its envelope is refused with
/// InvalidAccessError and changes nothing; one naming fewer of its rids is applied.
#[test]
fn with_the_setting_a_remote_offer_that_adds_a_rid_is_an_invalid_access_error() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_remote_rid_renegotiation_refused(true)
                .build(),
        )
        .build(Instant::now())?;
    let sender = pc.add_track(simulcast_track(&[("f", None), ("h", None)]))?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        remote_offer(
            "recvonly",
            "a=rid:f recv\na=rid:h recv\na=simulcast:recv f;h\n",
        )?,
    )?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(now, answer)?;

    let expanded = pc.set_remote_description(
        now,
        reoffer(
            3,
            "a=rid:f recv\na=rid:h recv\na=rid:x recv\na=simulcast:recv f;h;x\n",
        )?,
    );
    assert_eq!(expanded.err(), Some(Error::InvalidAccessError));
    assert_eq!(
        pc.signaling_state(),
        rtci::peer_connection::state::RTCSignalingState::Stable
    );
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", None), ("h", None)])
    );
    pc.set_remote_description(now, reoffer(3, "a=rid:f recv\na=simulcast:recv f\n")?)?;
    Ok(())
}

/// The lines starting with `prefix` of each media section of `sdp`, by mid.
fn section_lines(sdp: &str, prefix: &str) -> Vec<(String, Vec<String>)> {
    media_sections(sdp)
        .iter()
        .map(|section| {
            (
                mid_of(section).unwrap_or_default().to_owned(),
                section
                    .iter()
                    .filter(|line| line.starts_with(prefix))
                    .cloned()
                    .collect(),
            )
        })
        .collect()
}

/// The first offer, and each later offer with when it was made.
type Offers = (String, Vec<(&'static str, String)>);

/// A simulcast offerer's first offer (f, h, q, applied) and the offers it creates later: while
/// that offer is pending (have-local-offer), and after a default peer's answer that accepts
/// every stream has been applied (stable, simulcast negotiated: the sender keeps all three
/// encodings), each with what it is.
fn first_and_subsequent_offers() -> Result<Offers, Box<dyn std::error::Error>> {
    let three = [("f", Some(1280)), ("h", Some(640)), ("q", Some(320))];
    let (mut offerer, sender) = simulcast_sender(&three)?;
    let mut answerer = default_peer()?;
    let now = Instant::now();
    let first = offerer.create_offer(None)?;
    offerer.set_local_description(now, first.clone())?;
    let mut later = vec![];
    // A subsequent offer made while the first is pending, applied in its turn: it is the last
    // created one now (RFC 9429 section 5.4), and the one the answerer answers.
    let pending = offerer.create_offer(None)?;
    later.push(("have-local-offer", pending.sdp.clone()));
    offerer.set_local_description(now, pending.clone())?;
    answerer.set_remote_description(now, pending)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    assert_eq!(
        sent_layers(&mut offerer, sender),
        layers(&three),
        "negotiated"
    );
    later.push(("stable, after the answer", offerer.create_offer(None)?.sdp));
    Ok((first.sdp, later))
}

/// Fails listing each later offer whose `prefix` lines differ from the first offer's.
fn assert_lines_stay_the_same(prefix: &str, expected: &[&str]) -> TestResult {
    let (first, later) = first_and_subsequent_offers()?;
    let lines = section_lines(&first, prefix);
    assert_eq!(
        lines,
        vec![(
            "0".to_owned(),
            expected.iter().map(|line| (*line).to_owned()).collect()
        )],
        "the first offer\n{first}"
    );
    let changed: Vec<String> = later
        .iter()
        .filter(|(_, sdp)| section_lines(sdp, prefix) != lines)
        .map(|(when, sdp)| format!("{when}: {:?}\n{sdp}", section_lines(sdp, prefix)))
        .collect();
    assert!(
        changed.is_empty(),
        "{prefix} lines of the first offer: {lines:?}; later offers that changed them:\n{}",
        changed.join("\n")
    );
    Ok(())
}

/// RFC 9429 section 5.2.2, subsequent offers (in have-local-offer, and in stable after the
/// answer: "following the steps mentioned for the "have-local-offer" state"): "For
/// RtpTransceivers that are still present, the "a=rid" lines MUST stay the same."
#[test]
fn the_rid_lines_of_a_subsequent_offer_stay_the_same() -> TestResult {
    assert_lines_stay_the_same(
        "a=rid:",
        &[
            "a=rid:f send max-width=1280",
            "a=rid:h send max-width=640",
            "a=rid:q send max-width=320",
        ],
    )
}

/// RFC 9429 section 5.2.2, subsequent offers: "For RtpTransceivers that are still present, any
/// "a=simulcast" line MUST stay the same."
#[test]
fn the_simulcast_line_of_a_subsequent_offer_stays_the_same() -> TestResult {
    assert_lines_stay_the_same("a=simulcast:", &["a=simulcast:send f;h;q"])
}

/// RFC 9429 section 5.2.2: "For RtpTransceivers that are still present, the "a=rid" lines MUST
/// stay the same", also after an answer that tightened a restriction (RFC 8851 section 6.4 step
/// 3, which the sender then sends under: `an_answered_rid_may_tighten_but_not_loosen_the_offer`).
/// RFC 8851 does not ask for the tighter value to be offered back: section 6.5 has a changed
/// stream take a new rid and an unchanged one keep its own.
#[test]
fn a_subsequent_offer_keeps_the_rid_line_an_answer_tightened() -> TestResult {
    let (mut pc, sender, answer) = offered_three_layers()?;
    let first = pc
        .pending_local_description()
        .expect("the applied offer")
        .sdp;
    let answer = edited(
        &answer,
        "a=rid:f recv max-width=1280",
        "a=rid:f recv max-width=960",
    );
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::answer(crlf(&answer))?,
    )?;
    // The sender sends under the answer's restriction.
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("f", Some(960)), ("h", Some(640)), ("q", Some(320))])
    );
    let next = pc.create_offer(None)?;
    assert_eq!(
        section_lines(&next.sdp, "a=rid:"),
        section_lines(&first, "a=rid:"),
        "{}",
        next.sdp
    );
    assert_eq!(
        section_lines(&next.sdp, "a=rid:")[0].1[0],
        "a=rid:f send max-width=1280"
    );
    Ok(())
}

/// The remote offer of WPT `webrtc/protocol/simulcast-answer.html` (`offer_sdp`): one recvonly
/// VP8 section that asks to receive simulcast streams foo, bar and baz.
const WPT_SIMULCAST_RECV_OFFER: &str = "v=0
o=- 3840232462471583827 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS
m=video 9 UDP/TLS/RTP/SAVPF 96
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:Li6+
a=ice-pwd:3C05CTZBRQVmGCAq7hVasHlT
a=ice-options:trickle
a=fingerprint:sha-256 5B:D3:8E:66:0E:7D:D3:F3:8E:E6:80:28:19:FC:55:AD:58:5D:B9:3D:A8:DE:45:4A:E7:87:02:F8:3C:0B:3B:B3
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=recvonly
a=rtcp-mux
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rid:foo recv
a=rid:bar recv
a=rid:baz recv
a=simulcast:recv foo;bar;baz
";

/// A peer without transceivers that applied `offer`, with the transceiver the offer created
/// (W3C webrtc-pc "set the RTCSessionDescription": "If no suitable transceiver was found ...
/// Create an RTCRtpSender, sender, from the media description using proposedSendEncodings")
/// set to sendonly, as the WPT does (`transceiver.direction = 'sendonly'`).
fn wpt_answerer(
    offer: &str,
) -> Result<(RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    wpt_answerer_on(default_peer()?, offer)
}

/// [`wpt_answerer`] on the peer `pc`.
fn wpt_answerer_on(
    mut pc: RTCPeerConnection,
    offer: &str,
) -> Result<(RTCPeerConnection, RTCRtpSenderId), Box<dyn std::error::Error>> {
    pc.set_remote_description(Instant::now(), RTCSessionDescription::offer(crlf(offer))?)?;
    let ids: Vec<_> = pc.get_transceivers().collect();
    assert_eq!(ids.len(), 1, "the offer creates one transceiver");
    let mut transceiver = pc.rtp_transceiver(ids[0]).expect("the transceiver");
    transceiver.set_direction(rtci::rtp_transceiver::RTCRtpTransceiverDirection::Sendonly)?;
    let sender = transceiver.sender().expect("its sender");
    Ok((pc, sender))
}

/// WPT `webrtc/protocol/simulcast-answer.html`, "createAnswer() with multiple send encodings
/// should create simulcast answer". W3C webrtc-pc "set the RTCSessionDescription": a remote
/// offer to receive simulcast gives the sender of the transceiver it creates
/// `proposedSendEncodings`, one per offered rid in the offer's order ("Create an RTCRtpSender
/// ... using proposedSendEncodings"); `createAnswer` then answers each with `a=rid ... send`
/// and `a=simulcast:send` (RFC 8853 section 5.3.2: the answerer "SHALL reverse directionality
/// ... and include it in the answer"). A rollback removes the transceiver again.
#[test]
fn a_transceiver_a_simulcast_offer_creates_sends_the_offered_streams() -> TestResult {
    let (mut pc, sender) = wpt_answerer(WPT_SIMULCAST_RECV_OFFER)?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("foo", None), ("bar", None), ("baz", None)])
    );
    assert_eq!(
        sent_scales(&mut pc, sender),
        [Some(4.0), Some(2.0), Some(1.0)]
    );
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=rid:"),
        vec!["a=rid:foo send", "a=rid:bar send", "a=rid:baz send"],
        "{}",
        answer.sdp
    );
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send foo;bar;baz"],
        "{}",
        answer.sdp
    );
    assert_eq!(lines_with(&answer.sdp, "a=sendonly"), vec!["a=sendonly"]);
    pc.set_local_description(Instant::now(), answer)?;
    assert_eq!(sent_layers(&mut pc, sender).len(), 3);

    let mut pc = default_peer()?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        RTCSessionDescription::offer(crlf(WPT_SIMULCAST_RECV_OFFER))?,
    )?;
    pc.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(pc.get_transceivers().count(), 0);
    Ok(())
}

/// WPT `webrtc/protocol/simulcast-answer.html`, "Using the ~rid SDP syntax in a remote offer
/// does not control the local encodings active flag": W3C `proposedSendEncodings` has an
/// encoding per offered stream, paused (`~bar`) or not, and leaves `active` alone.
#[test]
fn an_offered_pause_mark_leaves_the_proposed_encoding_active() -> TestResult {
    let offer = edited(
        WPT_SIMULCAST_RECV_OFFER,
        "a=simulcast:recv foo;bar;baz",
        "a=simulcast:recv foo;~bar;baz",
    );
    let (mut pc, sender) = wpt_answerer(&offer)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer)?;
    let mut s = pc.rtp_sender(sender).expect("sender");
    let bar = s
        .get_parameters()
        .encodings
        .iter()
        .find(|e| e.rtp_coding_parameters.rid == "bar")
        .cloned()
        .expect("an encoding for bar");
    assert!(bar.active);
    Ok(())
}

/// WPT `webrtc/protocol/simulcast-answer.html`, "Disabling encodings locally does not change
/// the SDP": after the answer, encodings made inactive by `set_parameters` are still offered
/// as they were (RFC 9429 section 5.2.2: the `a=simulcast` line "MUST stay the same"; without
/// RFC 7728 no stream is marked paused, RFC 8853 section 5.3.2). The peer states
/// `with_rid_pause_marks(false)`, the RFC default: the `Chrome` profile (row
/// `sdp.rid-pause-marks`) writes `~` for an inactive encoding, as libwebrtc does.
#[test]
fn encodings_made_inactive_leave_the_next_offer_alone() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let peer = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_rid_pause_marks(false)
                .build(),
        )
        .build(Instant::now())?;
    let (mut pc, sender) = wpt_answerer_on(peer, WPT_SIMULCAST_RECV_OFFER)?;
    let answer = pc.create_answer(None)?;
    pc.set_local_description(Instant::now(), answer)?;
    let mut s = pc.rtp_sender(sender).expect("sender");
    let mut parameters = s.get_parameters().clone();
    for encoding in &mut parameters.encodings {
        encoding.active = false;
    }
    s.set_parameters(parameters, None)?;
    let offer = pc.create_offer(None)?;
    assert_eq!(
        lines_with(&offer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send foo;bar;baz"],
        "{}",
        offer.sdp
    );
    Ok(())
}

/// W3C `addTrack` reusing a sender ("If sender is not null, run the following steps to use
/// that sender: Set sender.[[SenderTrack]] to track ..."): nothing else of the sender changes,
/// so a track added after a remote offer to receive simulcast, before the answer, is sent with
/// the encodings the offer proposed (`[[SendEncodings]]` is proposedSendEncodings since that
/// offer, "Create an RTCRtpSender ... using proposedSendEncodings"), and the answer sends them.
/// WPT `webrtc/simulcast/negotiation-encodings.https.html`, "sRD(simulcast offer), addTrack,
/// then rollback brings us back to having a single encoding", first half.
#[test]
fn a_track_added_after_a_simulcast_offer_keeps_the_proposed_encodings() -> TestResult {
    let mut pc = default_peer()?;
    pc.set_remote_description(
        Instant::now(),
        RTCSessionDescription::offer(crlf(WPT_SIMULCAST_RECV_OFFER))?,
    )?;
    let sender = pc.add_track(jsep_common::video_track("late", 0x0516_0089))?;
    assert_eq!(
        pc.get_transceivers().count(),
        1,
        "addTrack reuses the transceiver"
    );
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("foo", None), ("bar", None), ("baz", None)])
    );
    // The first takes the track's SSRC, as when the track comes before the offer.
    let first_ssrc = pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings[0]
        .rtp_coding_parameters
        .ssrc;
    assert_eq!(first_ssrc, Some(0x0516_0089));
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send foo;bar;baz"],
        "{}",
        answer.sdp
    );
    Ok(())
}

/// The same for W3C `replaceTrack`, which sets only `[[SenderTrack]]` too.
#[test]
fn a_track_replaced_in_after_a_simulcast_offer_keeps_the_proposed_encodings() -> TestResult {
    let (mut pc, sender) = wpt_answerer(WPT_SIMULCAST_RECV_OFFER)?;
    pc.rtp_sender(sender)
        .expect("sender")
        .replace_track(Some(jsep_common::video_track("replaced", 0x0516_0189)))?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("foo", None), ("bar", None), ("baz", None)])
    );
    let answer = pc.create_answer(None)?;
    assert_eq!(
        lines_with(&answer.sdp, "a=simulcast:"),
        vec!["a=simulcast:send foo;bar;baz"],
        "{}",
        answer.sdp
    );
    Ok(())
}

/// A rollback of that offer keeps the transceiver (the application touched it, RFC 9429
/// section 5.7) and, by the W3C text, its encodings: the sender of a transceiver a remote
/// offer created starts with `[[LastStableRidlessSendEncodings]]` "initialized to null"
/// ("create an RTCRtpSender"), the slot is only set when the connection reaches stable, and the
/// rollback restores it only "If [[LastStableRidlessSendEncodings]] is not null". WPT
/// `negotiation-encodings.https.html` ("sRD(simulcast offer), addTrack, then rollback brings
/// us back to having a single encoding") expects one rid-less encoding instead, which the text
/// does not say.
#[test]
fn a_rollback_keeps_the_proposed_encodings_of_a_transceiver_the_offer_created() -> TestResult {
    let mut pc = default_peer()?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        RTCSessionDescription::offer(crlf(WPT_SIMULCAST_RECV_OFFER))?,
    )?;
    let sender = pc.add_track(jsep_common::video_track("late", 0x0516_0289))?;
    pc.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(pc.get_transceivers().count(), 1);
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("foo", None), ("bar", None), ("baz", None)])
    );
    Ok(())
}

/// `with_rollback_resets_offer_created_senders(true)`, the WPT form
/// (`negotiation-encodings.https.html`, "sRD(simulcast offer), addTrack, then rollback brings
/// us back to having a single encoding", w3c/webrtc-pc#2764): the rollback returns that sender
/// to one encoding without a rid, the track's.
#[test]
fn a_rollback_can_return_an_offer_created_sender_to_one_encoding() -> TestResult {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_rollback_resets_offer_created_senders(true)
                .build(),
        )
        .build(Instant::now())?;
    let now = Instant::now();
    pc.set_remote_description(
        now,
        RTCSessionDescription::offer(crlf(WPT_SIMULCAST_RECV_OFFER))?,
    )?;
    let sender = pc.add_track(jsep_common::video_track("late", 0x0516_0389))?;
    assert_eq!(
        sent_layers(&mut pc, sender),
        layers(&[("foo", None), ("bar", None), ("baz", None)])
    );
    pc.set_remote_description(now, RTCSessionDescription::rollback(None)?)?;
    assert_eq!(pc.get_transceivers().count(), 1);
    assert_eq!(sent_layers(&mut pc, sender), layers(&[("", None)]));
    let ssrc = pc
        .rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .encodings[0]
        .rtp_coding_parameters
        .ssrc;
    assert_eq!(ssrc, Some(0x0516_0389));
    Ok(())
}

/// WPT `webrtc/simulcast/rid-manipulation.html`, "Remote reanswer altering rids does not throw
/// an exception": a sender added with `sendEncodings` 0, 1, 2 (`addTransceiver`, no track) is
/// answered `a=simulcast:recv 1;2`, then re-offers and is answered `a=simulcast:recv 0;2`, each
/// answer carrying `a=rid:0 recv`, `a=rid:1 recv` and `a=rid:2 recv` (the WPT's `midToRid`
/// writes all three). The second answer names rid 0, which the sender's envelope no longer has
/// and its re-offer did not offer. RFC 8851 section 6.4 step 1: "If no matching line can be
/// located in the offer, the "a=rid" line is ignored"; RFC 8853 section 5.3.3 only has the
/// offerer not send removed rid-ids. The answer is applied, not refused: rid 0 is ignored and
/// the envelope narrows to 2 (W3C webrtc-pc "set the RTCSessionDescription": "remove the
/// dictionaries that correspond to the missing layers").
#[test]
fn a_reanswer_naming_a_rid_outside_the_offer_ignores_it() -> TestResult {
    use rtci::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
    let mut pc1 = default_peer()?;
    let encodings = ["0", "1", "2"]
        .iter()
        .map(|rid| RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: (*rid).to_owned(),
                ..Default::default()
            },
            ..Default::default()
        })
        .collect();
    let id = pc1.add_transceiver_from_kind(
        RtpCodecKind::Video,
        Some(RTCRtpTransceiverInit {
            direction: RTCRtpTransceiverDirection::Sendrecv,
            streams: vec![],
            send_encodings: encodings,
        }),
    )?;
    let sender = pc1
        .rtp_transceiver(id)
        .expect("the transceiver")
        .sender()
        .expect("its sender");
    let mut pc2 = default_peer()?;
    let now = Instant::now();

    // One round of the WPT's `negotiateSfuAnswer(asimulcast)`.
    let mut sfu_answer =
        |pc1: &mut RTCPeerConnection,
         simulcast: &str|
         -> Result<(String, RTCSessionDescription), Box<dyn std::error::Error>> {
            let offer = pc1.create_offer(None)?;
            pc1.set_local_description(now, offer.clone())?;
            pc2.set_remote_description(now, offer.clone())?;
            let answer = pc2.create_answer(None)?;
            pc2.set_local_description(now, answer.clone())?;
            let mut sdp: String = answer
                .sdp
                .lines()
                .filter(|l| !l.starts_with("a=rid:") && !l.starts_with("a=simulcast:"))
                .map(|l| format!("{l}\n"))
                .collect();
            sdp.push_str(&format!(
                "a=rid:0 recv\na=rid:1 recv\na=rid:2 recv\n{simulcast}\n"
            ));
            Ok((offer.sdp, RTCSessionDescription::answer(crlf(&sdp))?))
        };

    let (offer, answer) = sfu_answer(&mut pc1, "a=simulcast:recv 1;2")?;
    assert_eq!(
        lines_with(&offer, "a=simulcast:"),
        vec!["a=simulcast:send 0;1;2"]
    );
    pc1.set_remote_description(now, answer)?;
    assert_eq!(
        sent_layers(&mut pc1, sender),
        layers(&[("1", None), ("2", None)])
    );

    let (offer, answer) = sfu_answer(&mut pc1, "a=simulcast:recv 0;2")?;
    assert_eq!(
        lines_with(&offer, "a=simulcast:"),
        vec!["a=simulcast:send 1;2"],
        "{offer}"
    );
    pc1.set_remote_description(now, answer)?;
    assert_eq!(sent_layers(&mut pc1, sender), layers(&[("2", None)]));
    Ok(())
}
