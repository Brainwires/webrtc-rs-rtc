//! Shared helpers for the `tests/jsep_*.rs` signalling tests: no transport is started, only
//! offers and answers are made and applied.
#![allow(dead_code)]

use std::time::Instant;

use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtp_transceiver::SSRC;
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The session and transport lines a remote offer needs before its media sections.
pub const SESSION: &str = "v=0
o=- 4215775240449105457 2 IN IP4 127.0.0.1
s=-
t=0 0
";

/// The ICE and DTLS lines a remote media section carries.
pub const TRANSPORT: &str = "c=IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uLifh0NuRHlkwz
a=fingerprint:sha-256 F2:1C:F2:9E:B4:BE:58:19:C9:48:1A:D9:C4:A7:5D:5A:1F:61:7C:17:6B:07:8E:39:A2:E2:B2:BB:BF:4B:D2:16
a=setup:actpass
a=rtcp-mux
";

/// `s` with CRLF line endings (RFC 8866 section 5).
pub fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// A peer with the default codecs.
pub fn default_peer() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())?)
}

/// A peer with the default codecs whose answers also list the formats the offer lacks
/// (`SettingEngineBuilder::with_answer_offered_formats_only(false)`; the default before 0.3.0,
/// the `StrictRfc` profile's form: RFC 9429 section 5.3.1 "MUST be added after all existing
/// formats").
pub fn peer_adding_formats() -> Result<RTCPeerConnection, Box<dyn std::error::Error>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    Ok(RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .with_setting_engine(
            rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
                .with_answer_offered_formats_only(false)
                .build(),
        )
        .build(Instant::now())?)
}

pub fn vp8() -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: String::new(),
        rtcp_feedback: vec![],
    }
}

/// A VP8 video track with one encoding on `ssrc`.
pub fn video_track(name: &str, ssrc: SSRC) -> MediaStreamTrack {
    MediaStreamTrack::new(
        format!("{name}-stream"),
        name.to_owned(),
        name.to_owned(),
        RtpCodecKind::Video,
        vec![RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(ssrc),
                ..Default::default()
            },
            codec: vp8(),
            ..Default::default()
        }],
    )
}

/// Offer from `offerer`, answer from `answerer`, both applied; returns (offer, answer) SDP.
pub fn exchange(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let now = Instant::now();
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer.clone())?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer.clone())?;
    Ok((offer.sdp, answer.sdp))
}

/// The media sections of `sdp`, each as its lines, the `m=` line first.
pub fn media_sections(sdp: &str) -> Vec<Vec<String>> {
    let mut sections: Vec<Vec<String>> = vec![];
    for line in sdp.lines() {
        if line.starts_with("m=") {
            sections.push(vec![line.to_owned()]);
        } else if let Some(current) = sections.last_mut() {
            current.push(line.to_owned());
        }
    }
    sections
}

/// The `a=mid` of a media section, if it has one.
pub fn mid_of(section: &[String]) -> Option<&str> {
    section.iter().find_map(|line| line.strip_prefix("a=mid:"))
}

/// The port of a media section's `m=` line.
pub fn port_of(section: &[String]) -> u16 {
    section[0]
        .split_whitespace()
        .nth(1)
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("an m= line with a port: {}", section[0]))
}
