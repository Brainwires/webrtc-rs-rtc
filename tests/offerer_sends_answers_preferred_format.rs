//! The offerer's sender names the answer's most preferred format it can send, also when its
//! own codec preferences left that format out of the offer (signalling only; the wire is
//! `tests/additional_codec_sent_rtc2rtc.rs`). With the default codecs these passed on master
//! too (agent-test run 45983496952): no dynamic number is free for the answer to add VP8 on, so
//! the preferences matched nothing and the send codecs fell back to every format the engine
//! has; with free numbers the answer adds VP8 and master sent it (run 45990202513, the
//! minimal-engine test of `additional_codec_sent_rtc2rtc.rs`).
//!
//! RFC 9429 section 5.11 ("For each "m=" section, the following steps MUST be performed"):
//! "choose the media format to send as the most preferred media format from the remote
//! description that is also locally supported, as discussed in Sections 6.1 and 7 of
//! [RFC3264]". RFC 3264 section 7: the offerer "MUST send using a media format listed in the
//! answer, and it SHOULD use the first media format listed in the answer when it does send".
//! W3C webrtc-pc "set a session description", for an answer: [[SendCodecs]] are "the codecs
//! that description negotiates for sending and which the user agent is currently capable of
//! sending"; `setCodecPreferences` shapes the descriptions this endpoint generates, not what
//! it may send.
//!
//! The scenario is web-platform-tests `webrtc/protocol/additional-codecs.html`, "Listing an
//! additional codec in the answer causes it to be sent": the offerer's preferences keep VP8
//! only; the offer reaches the answerer with VP8 renamed to a codec nobody has and H.264 added
//! on 63, so the answer leads with H.264 on 63, a format the offerer never offered.

mod jsep_common;

use std::time::Instant;

use jsep_common::{TestResult, default_peer, media_sections, peer_adding_formats};
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_H264, MIME_TYPE_VP8};
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};
use rtci::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverId};

/// The capability of `mime` (the first one listed).
fn capability(
    pc: &mut RTCPeerConnection,
    sender: RTCRtpSenderId,
    mime: &str,
) -> RTCRtpCodecParameters {
    let codec = pc
        .rtp_sender(sender)
        .expect("sender")
        .get_capabilities(RtpCodecKind::Video)
        .expect("video")
        .codecs
        .into_iter()
        .find(|c| c.mime_type.eq_ignore_ascii_case(mime))
        .unwrap_or_else(|| panic!("a {mime} capability"));
    RTCRtpCodecParameters {
        rtp_codec: codec,
        payload_type: 0,
    }
}

/// The offerer, its sender, and its offer applied locally: one video transceiver whose codec
/// preferences are VP8 alone. Returns the offer munged as the WPT does it.
fn vp8_only_offer(
    pc1: &mut RTCPeerConnection,
) -> Result<(RTCRtpSenderId, String), Box<dyn std::error::Error>> {
    let id: RTCRtpTransceiverId = pc1.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let sender = pc1
        .rtp_transceiver(id)
        .expect("t")
        .sender()
        .expect("a sender");
    let vp8 = capability(pc1, sender, MIME_TYPE_VP8);
    let h264 = capability(pc1, sender, MIME_TYPE_H264);
    pc1.rtp_transceiver(id)
        .expect("t")
        .set_codec_preferences(vec![vp8])?;
    let offer = pc1.create_offer(None)?;
    pc1.set_local_description(Instant::now(), offer.clone())?;
    // "Add H264 to the SDP" on 63, and "Remove VP8" by renaming it.
    let mut sdp: String = offer
        .sdp
        .split('\n')
        .map(|l| {
            let l = l.trim();
            if l.starts_with("m=video") {
                format!("{l} 63")
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    if !sdp.ends_with("\r\n") {
        sdp.push_str("\r\n");
    }
    sdp.push_str("a=rtpmap:63 H264/90000\r\n");
    sdp.push_str(&format!("a=fmtp:63 {}\r\n", h264.rtp_codec.sdp_fmtp_line));
    Ok((sender, sdp.replace("VP8", "no-such-codec")))
}

/// The formats of the first section of `sdp`, by payload type and encoding name.
fn first_formats(sdp: &str) -> Vec<(String, String)> {
    let section = &media_sections(sdp)[0];
    section[0]
        .split_whitespace()
        .skip(3)
        .map(|pt| {
            let name = section
                .iter()
                .find_map(|l| l.strip_prefix(&format!("a=rtpmap:{pt} ")))
                .and_then(|v| v.split('/').next())
                .unwrap_or_default()
                .to_ascii_lowercase();
            (pt.to_owned(), name)
        })
        .collect()
}

/// The media format the sender sends a stream without a codec of its own with: the first
/// non-repair codec of its parameters (what `encoding_send_codec` takes).
fn sent_format(
    pc: &mut RTCPeerConnection,
    sender: RTCRtpSenderId,
) -> Option<RTCRtpCodecParameters> {
    pc.rtp_sender(sender)
        .expect("sender")
        .get_parameters()
        .rtp_parameters
        .codecs
        .iter()
        .find(|c| {
            let m = c.rtp_codec.mime_type.to_ascii_lowercase();
            !(m.ends_with("/rtx")
                || m.ends_with("/red")
                || m.ends_with("/ulpfec")
                || m.contains("/flexfec"))
        })
        .cloned()
}

/// WPT additional-codecs: the answerer (an engine peer with the default form, which adds its
/// other formats after the offered ones, VP8 among them) answers H.264 on 63 first; the
/// offerer sends H.264 on 63, not VP8.
#[test]
fn the_offerer_sends_the_answers_first_format_although_its_preferences_left_it_out() -> TestResult {
    let mut pc1 = default_peer()?;
    // The answerer adds its other formats (the setting).
    let mut pc2 = peer_adding_formats()?;
    let (sender, offer) = vp8_only_offer(&mut pc1)?;
    pc2.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc2.create_answer(None)?;
    pc2.set_local_description(Instant::now(), answer.clone())?;
    let answered = first_formats(&answer.sdp);
    assert_eq!(
        answered.first(),
        Some(&("63".to_owned(), "h264".to_owned())),
        "the answer leads with H.264 on 63: {}",
        answer.sdp
    );
    pc1.set_remote_description(Instant::now(), answer.clone())?;
    let sent = sent_format(&mut pc1, sender).expect("a send codec");
    assert!(
        sent.rtp_codec
            .mime_type
            .eq_ignore_ascii_case(MIME_TYPE_H264)
            && sent.payload_type == 63,
        "the offerer sends the answer's first format, H.264 on 63, not {} on {}:\n{}",
        sent.rtp_codec.mime_type,
        sent.payload_type,
        answer.sdp
    );
    Ok(())
}

/// The same with an answer in the browsers' form, H.264 on 63 alone (the answerer's codec
/// preferences say H.264 only, so it adds nothing).
#[test]
fn the_offerer_sends_a_format_only_the_answer_has() -> TestResult {
    let mut pc1 = default_peer()?;
    let mut pc2 = default_peer()?;
    let (sender, offer) = vp8_only_offer(&mut pc1)?;
    pc2.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let id = pc2.get_transceivers().next().expect("a transceiver");
    let mut fresh = default_peer()?;
    let fresh_id = fresh.add_transceiver_from_kind(RtpCodecKind::Video, None)?;
    let fresh_sender = fresh
        .rtp_transceiver(fresh_id)
        .expect("t")
        .sender()
        .expect("a sender");
    let h264 = capability(&mut fresh, fresh_sender, MIME_TYPE_H264);
    pc2.rtp_transceiver(id)
        .expect("t")
        .set_codec_preferences(vec![h264])?;
    let answer = pc2.create_answer(None)?;
    pc2.set_local_description(Instant::now(), answer.clone())?;
    let answered = first_formats(&answer.sdp);
    assert!(
        answered.iter().all(|(_, name)| name == "h264"),
        "the answer lists H.264 alone: {}",
        answer.sdp
    );
    pc1.set_remote_description(Instant::now(), answer.clone())?;
    let sent = sent_format(&mut pc1, sender).expect("a send codec");
    assert!(
        sent.rtp_codec
            .mime_type
            .eq_ignore_ascii_case(MIME_TYPE_H264)
            && sent.payload_type == 63,
        "{sent:?}\n{}",
        answer.sdp
    );
    Ok(())
}

/// The offerer's receive side keeps its preferences: what it receives is what it offered
/// (RFC 3264 section 6.1, the answerer "MUST send using a media format in the offer"), so its
/// next offer still lists VP8 alone.
#[test]
fn the_offerers_next_offer_still_follows_its_preferences() -> TestResult {
    let mut pc1 = default_peer()?;
    // The answerer adds its other formats (the setting).
    let mut pc2 = peer_adding_formats()?;
    let (_, offer) = vp8_only_offer(&mut pc1)?;
    pc2.set_remote_description(Instant::now(), RTCSessionDescription::offer(offer)?)?;
    let answer = pc2.create_answer(None)?;
    pc2.set_local_description(Instant::now(), answer.clone())?;
    pc1.set_remote_description(Instant::now(), answer)?;
    let next = pc1.create_offer(None)?.sdp;
    let names: Vec<String> = first_formats(&next).into_iter().map(|(_, n)| n).collect();
    assert_eq!(names, vec!["vp8".to_owned()], "{next}");
    Ok(())
}
