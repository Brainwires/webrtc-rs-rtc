//! The typed attributes against the ABNF of the RFC that defines each: the examples those
//! RFCs give, the edges of every rule, and what must be refused.

use std::io::Cursor;

use shared::error::Error;

use super::mux::{self, AttributeLevel, MuxCategory};
use super::*;
use crate::description::common::BandwidthKind;
use crate::description::session::SessionDescription;
use crate::direction::Direction;
use crate::extmap::ExtMap;
use crate::util::ConnectionRole;

/// Every `good` value parses and prints back unchanged; every `bad` one is refused.
fn check<T: TypedAttribute>(good: &[&str], bad: &[&str]) {
    for value in good {
        match T::parse(value) {
            Ok(parsed) => assert_eq!(&parsed.to_string(), value, "a={}:{value}", T::NAME),
            Err(err) => panic!("a={}:{value} should parse: {err}", T::NAME),
        }
    }
    for value in bad {
        assert!(
            T::parse(value).is_err(),
            "a={}:{value:?} should be refused",
            T::NAME
        );
    }
}

fn parse(sdp: &str) -> SessionDescription {
    SessionDescription::unmarshal(&mut Cursor::new(sdp.as_bytes())).unwrap()
}

const HEAD: &str = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n";

fn with_media(session: &str, media: &str) -> SessionDescription {
    parse(&format!(
        "{HEAD}{session}m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\nc=IN IP4 0.0.0.0\r\n{media}"
    ))
}

// --- RFC 5888, RFC 9143: group, mid -------------------------------------------------------

#[test]
fn group_takes_any_semantics_token_and_any_number_of_tags() {
    check::<Group>(
        &[
            "BUNDLE 0 1 2",
            "BUNDLE",
            "LS 1 2",
            "FID 1 2",
            "SRF 1 2",
            "ANAT 1 2",
            "FEC 1 2",
            "FEC-FR S1 R1",
            "CS 1 2",
            "DDP L1 L2 L3",
            "DUP S1a S1b",
            "X-future a",
            "BUNDLE audio video-1 {x}",
        ],
        &[
            "",
            " BUNDLE",
            "BUNDLE ",
            "BUNDLE  0",
            "BUNDLE 0,1",
            "BUN DLE:0",
            "LS a/b",
            "é 1",
        ],
    );

    let group = Group::parse("BUNDLE 0 1").unwrap();
    assert!(group.is_bundle());
    assert!(group.contains("1"));
    assert!(!group.contains("2"));
    assert!(!Group::parse("LS 0 1").unwrap().is_bundle());
    // The semantics token is case-sensitive: this is not a BUNDLE group.
    assert!(!Group::parse("bundle 0 1").unwrap().is_bundle());
    // RFC 9143 section 7.3.1: an answer may carry an empty group.
    assert!(Group::parse("BUNDLE").unwrap().mids.is_empty());
}

#[test]
fn groups_are_read_at_the_session_level_per_semantics() {
    let sdp = with_media(
        "a=group:BUNDLE 0 1\r\na=group:LS 0 1\r\na=group:BUNDLE 2\r\n",
        "a=mid:0\r\n",
    );
    assert_eq!(sdp.groups().unwrap().len(), 3);
    let bundles = sdp.bundle_groups().unwrap();
    assert_eq!(bundles.len(), 2);
    assert_eq!(bundles[0].mids, vec!["0", "1"]);
    assert_eq!(bundles[1].mids, vec!["2"]);

    let broken = with_media("a=group:BUNDLE 0  1\r\n", "");
    assert!(broken.groups().is_err());
    let no_value = with_media("a=group\r\n", "");
    assert!(no_value.groups().is_err());
}

#[test]
fn mid_is_a_token() {
    check::<Mid>(
        &["0", "audio", "a1-b_2.c", "{6f1a}", "!#$%&'*+-.^_`{|}~"],
        &["", "a b", "a/b", "a:b", "é", "a,b", " 0", "0 "],
    );
    let sdp = with_media("", "a=mid:video-1\r\n");
    assert_eq!(
        sdp.media_descriptions[0].mid().unwrap().unwrap().as_str(),
        "video-1"
    );
    assert_eq!(
        with_media("", "").media_descriptions[0].mid().unwrap(),
        None
    );
    assert!(
        with_media("", "a=mid:a b\r\n").media_descriptions[0]
            .mid()
            .is_err()
    );
    assert!(Mid::new("ok").is_ok());
    assert!(Mid::new("not ok").is_err());
}

// --- RFC 8830: msid -----------------------------------------------------------------------

#[test]
fn msid_is_an_id_and_optional_appdata_of_64_token_chars_at_most() {
    let max = "a".repeat(64);
    let too_long = "a".repeat(65);
    check::<Msid>(
        &[
            // RFC 8830 section 2.
            "examplefoo examplebar",
            "examplefoo",
            "- track-1",
            "{9d8a6ccb-ab3c-4a2c-b4b3-7d5b0e2c7d11} {0fd0dd0d-55d5-4f6f-8a38-5d4b4c1a0b6e}",
            &max,
            &format!("{max} {max}"),
        ],
        &[
            "",
            " a",
            "a ",
            "a  b",
            "a b c",
            "a/b",
            "a b/c",
            &too_long,
            &format!("a {too_long}"),
        ],
    );
    let msid = Msid::parse("stream track").unwrap();
    assert_eq!(msid.id, "stream");
    assert_eq!(msid.appdata.as_deref(), Some("track"));
    assert_eq!(Msid::parse("stream").unwrap().appdata, None);
}

#[test]
fn a_media_section_has_one_msid_line_per_stream() {
    let media = with_media("", "a=msid:s1 t\r\na=msid:s2 t\r\na=msid:s3\r\n");
    let msids = media.media_descriptions[0].msids().unwrap();
    assert_eq!(msids.len(), 3);
    assert_eq!(
        msids.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        vec!["s1", "s2", "s3"]
    );
    assert_eq!(msids[2].appdata, None);
    assert!(
        with_media("", "a=msid:s1 t\r\na=msid:\r\n").media_descriptions[0]
            .msids()
            .is_err()
    );
}

#[test]
fn msid_semantic_is_read_in_the_forms_browsers_write() {
    // Chrome: a space after the colon, and the stream ids or nothing.
    let chrome = MsidSemantic::parse(" WMS stream1 stream2").unwrap();
    assert_eq!(chrome.semantic, "WMS");
    assert_eq!(chrome.ids, vec!["stream1", "stream2"]);
    assert!(MsidSemantic::parse(" WMS").unwrap().ids.is_empty());
    // Firefox: no space, and `*`.
    let firefox = MsidSemantic::parse("WMS *").unwrap();
    assert_eq!(firefox.ids, vec!["*"]);
    assert_eq!(firefox.to_string(), "WMS *");
    for bad in ["", " ", "  WMS", "WMS  a", "WMS a/b"] {
        assert!(MsidSemantic::parse(bad).is_err(), "{bad:?}");
    }
    let sdp = with_media("a=msid-semantic: WMS\r\n", "");
    assert_eq!(sdp.msid_semantic().unwrap().unwrap().semantic, "WMS");
}

// --- RFC 5576: ssrc, ssrc-group -----------------------------------------------------------

#[test]
fn ssrc_carries_one_source_attribute() {
    check::<Ssrc>(
        &[
            // RFC 5576 section 6.1 and 6.2.
            "12345 cname:another-user@example.com",
            "314159 cname:user@example.com",
            "0 cname:x",
            "4294967295 cname:x",
            "1 previous-ssrc:2",
            "1 previous-ssrc:2 3 4294967295",
            "1 fmtp:96 profile-level-id=42e01f; packetization-mode=1",
            "1 msid:stream track",
            "1 msid:- track",
            "1 mslabel:stream",
            "1 label:track",
            "1 x-flag",
            "1 cname:with spaces and: colons",
        ],
        &[
            "",
            "1",
            "1 ",
            " 1 cname:x",
            "4294967296 cname:x",
            "-1 cname:x",
            "01 cname:x",
            "x cname:y",
            "1 cname",
            "1 cname:",
            "1 previous-ssrc",
            "1 previous-ssrc:",
            "1 previous-ssrc:a",
            "1 previous-ssrc:2  3",
            "1 previous-ssrc:4294967296",
            "1 fmtp:96",
            "1 msid:a b c",
            "1 bad name:x",
        ],
    );

    let cname = Ssrc::parse("7 cname:host-1").unwrap();
    assert_eq!(cname.id, 7);
    assert_eq!(cname.cname(), Some("host-1"));
    assert!(cname.previous_ssrcs().is_none());
    assert!(cname.fmtp().is_none());
    assert!(cname.msid().is_none());

    let previous = Ssrc::parse("7 previous-ssrc:1 2 3").unwrap();
    assert_eq!(previous.previous_ssrcs().unwrap().unwrap(), vec![1, 2, 3]);

    let fmtp = Ssrc::parse("7 fmtp:96 a=1;b=2")
        .unwrap()
        .fmtp()
        .unwrap()
        .unwrap();
    assert_eq!(fmtp.format, "96");
    assert_eq!(fmtp.parameters, "a=1;b=2");

    let msid = Ssrc::parse("7 msid:s t").unwrap().msid().unwrap().unwrap();
    assert_eq!(
        (msid.id.as_str(), msid.appdata.as_deref()),
        ("s", Some("t"))
    );
}

#[test]
fn ssrc_group_keeps_the_order_of_its_sources() {
    check::<SsrcGroup>(
        &[
            "FID 1 2",
            "FEC 1 2",
            "FEC-FR 1 2",
            "DUP 1 2",
            "SIM 1 2 3",
            "FID",
            "FID 0 4294967295",
        ],
        &[
            "",
            "FID  1",
            "FID 1 ",
            "FID a",
            "FID 4294967296",
            "FID 01",
            "F/D 1",
            "FID 1,2",
        ],
    );
    let media = with_media(
        "",
        "a=ssrc-group:FID 10 20\r\na=ssrc-group:FEC-FR 10 30\r\na=ssrc:10 cname:c\r\na=ssrc:20 cname:c\r\n",
    );
    let media = &media.media_descriptions[0];
    let groups = media.ssrc_groups().unwrap();
    assert_eq!(groups[0].semantics, "FID");
    assert_eq!(groups[0].ssrcs, vec![10, 20]);
    assert_eq!(groups[1].ssrcs, vec![10, 30]);
    assert_eq!(media.ssrcs().unwrap().len(), 2);
}

// --- RFC 8851: rid ------------------------------------------------------------------------

#[test]
fn rid_follows_the_rfc_8851_grammar() {
    check::<Rid>(
        &[
            // RFC 8851 section 11 examples.
            "1 send pt=97;max-width=1280;max-height=720",
            "2 send pt=98;max-width=320;max-height=180",
            "0 recv max-width=1280;max-height=720;max-fps=30",
            "5 recv max-fs=3600;max-fps=15;max-br=300000",
            "1 send",
            "hi recv",
            "abc send pt=96,97,98",
            "1 send pt=96",
            "1 send max-bpp=0.5",
            "1 send max-pps=27648000",
            "2 send depend=0,1",
            "1 send max-width",
            "1 send x-custom=some value, with: punctuation",
            "1 send pt=96;x-flag;max-fps=30",
            "1 recv pt=0,127",
        ],
        &[
            "",
            "1",
            "1 ",
            "1 both",
            "1 SEND",
            "1  send",
            " 1 send",
            "a.b send",
            // Erratum 7132: `rid-id = 1*255(alpha-numeric)`.
            "a-b_c send pt=96,97,98",
            "a b send",
            "1 send ",
            "1 send pt=",
            "1 send pt",
            "1 send pt=96,",
            "1 send pt=128",
            "1 send pt=a",
            "1 send pt=96,96",
            "1 send max-width=1280;pt=96",
            "1 send max-width=abc",
            "1 send max-width=",
            "1 send max-width=1.5",
            "1 send max-bpp=1",
            "1 send max-bpp=.5",
            "1 send max-bpp=1.",
            "1 send depend",
            "1 send depend=",
            "1 send depend=a.b",
            "1 send max-fps=30;max-fps=15",
            "1 send max-fps=30;",
            "1 send ;max-fps=30",
            "1 send max_fps=30",
            "1 send x=a\tb",
        ],
    );
}

#[test]
fn rid_restrictions_have_accessors_and_keep_their_order() {
    let rid = Rid::parse(
        "hi send pt=96,97;max-width=1280;max-height=720;max-fps=30;max-fs=3600;max-br=1500000;max-pps=27648000;max-bpp=0.12;depend=lo,mid;x-new=1",
    )
    .unwrap();
    assert_eq!(rid.id, "hi");
    assert_eq!(rid.direction, RidDirection::Send);
    assert_eq!(rid.formats, vec![96, 97]);
    assert_eq!(rid.max_width(), Some(1280));
    assert_eq!(rid.max_height(), Some(720));
    assert_eq!(rid.max_fps(), Some(30));
    assert_eq!(rid.max_fs(), Some(3600));
    assert_eq!(rid.max_br(), Some(1_500_000));
    assert_eq!(rid.max_pps(), Some(27_648_000));
    assert_eq!(rid.max_bpp(), Some(0.12));
    assert_eq!(rid.depend(), vec!["lo", "mid"]);
    assert_eq!(rid.restriction("x-new"), Some(Some("1")));
    assert_eq!(rid.restriction("x-other"), None);
    assert_eq!(
        rid.restrictions
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>(),
        vec![
            "max-width",
            "max-height",
            "max-fps",
            "max-fs",
            "max-br",
            "max-pps",
            "max-bpp",
            "depend",
            "x-new"
        ]
    );

    let plain = Rid::parse("lo recv").unwrap();
    assert_eq!(plain.direction, RidDirection::Recv);
    assert!(plain.formats.is_empty());
    assert_eq!(plain.max_width(), None);
    assert!(plain.depend().is_empty());
    // A restriction named without a value is present and has no number.
    let bare = Rid::parse("lo recv max-width").unwrap();
    assert_eq!(bare.restriction("max-width"), Some(None));
    assert_eq!(bare.max_width(), None);

    assert_eq!(
        Rid::new("q", RidDirection::Send).unwrap().to_string(),
        "q send"
    );
    assert!(Rid::new("not ok", RidDirection::Send).is_err());
}

// --- RFC 8853, RFC 7728: simulcast --------------------------------------------------------

#[test]
fn simulcast_follows_the_rfc_8853_grammar() {
    check::<Simulcast>(
        &[
            // RFC 8853 section 5.1 and 5.6.
            "send 1;2,3 recv 4",
            "send 1,2,3;~4,~5 recv 6;~7,~8",
            "recv 1;4,5 send 6;7",
            "send 1;2 recv 3",
            "send 1;2",
            "recv 1",
            "send hi;mid;lo",
            "send ~hi;mid;~lo",
            "recv f,~h;q",
        ],
        &[
            "",
            "send",
            "send ",
            "send 1 send 2",
            "recv 1 recv 2",
            "send 1 recv",
            "send 1 recv 2 send 3",
            "both 1",
            "SEND 1",
            "send 1;",
            "send ;1",
            "send 1,,2",
            "send 1;;2",
            "send ~",
            "send ~~1",
            "send 1~",
            "send a.b",
            "send 1  recv 2",
            " send 1",
            "send 1;2;1",
            "send 1 recv 1",
            "send 1,~1",
        ],
    );
}

/// RFC 8851 section 10 as corrected by erratum 7132 (Verified 2022-10-13): `rid-id =
/// 1*255(alpha-numeric)`, "consistent with the rules for the RtpStreamId/RepairedRtpStreamId
/// SDES from RFC 8852 section 3". `a=simulcast` (RFC 8853 section 5.1) and `depend=` use the
/// same rid-id.
#[test]
fn a_rid_id_is_1_to_255_alphanumerics() {
    let longest = "a".repeat(255);
    for id in ["0", "Az09", longest.as_str()] {
        assert!(Rid::parse(&format!("{id} send")).is_ok(), "a=rid:{id} send");
        assert!(Rid::new(id, RidDirection::Send).is_ok(), "Rid::new({id})");
        assert!(
            Simulcast::parse(&format!("send {id};~b")).is_ok(),
            "a=simulcast:send {id};~b"
        );
        assert!(
            Rid::parse(&format!("x send depend={id}")).is_ok(),
            "depend={id}"
        );
    }
}

/// `id` is refused wherever a rid-id is read: on an `a=rid` line, by `Rid::new`, in either
/// direction of `a=simulcast` (paused or not) and in `depend=`.
fn assert_rid_id_refused(id: &str) {
    assert!(
        Rid::parse(&format!("{id} send")).is_err(),
        "a=rid:{id} send"
    );
    assert!(Rid::new(id, RidDirection::Send).is_err(), "Rid::new({id})");
    assert!(
        Simulcast::parse(&format!("send h;{id}")).is_err(),
        "a=simulcast:send h;{id}"
    );
    assert!(
        Simulcast::parse(&format!("recv ~{id}")).is_err(),
        "a=simulcast:recv ~{id}"
    );
    assert!(
        Rid::parse(&format!("h send depend={id}")).is_err(),
        "depend={id}"
    );
}

/// Erratum 7132: the published grammar's `"-"` is not in `rid-id`.
#[test]
fn a_rid_id_with_a_dash_is_refused() {
    assert_rid_id_refused("a-b");
    assert_rid_id_refused("-");
}

/// Erratum 7132: the published grammar's `"_"` is not in `rid-id`.
#[test]
fn a_rid_id_with_an_underscore_is_refused() {
    assert_rid_id_refused("a_b");
    assert_rid_id_refused("_");
}

/// Erratum 7132: `1*255`, the 255-octet limit of an SDES item (RFC 8852 section 3).
#[test]
fn a_rid_id_longer_than_255_is_refused() {
    assert_rid_id_refused(&"a".repeat(256));
}

/// `RidIdGrammar::Published` reads rid-ids as RFC 8851 section 10 was published, before
/// erratum 7132: `-` and `_` taken, any length.
#[test]
fn the_published_grammar_takes_dashes_underscores_and_any_length() {
    let long = "a".repeat(256);
    for id in ["a-b", "a_b", "-", long.as_str()] {
        let rid = Rid::parse_with(&format!("{id} send depend={id}"), RidIdGrammar::Published)
            .unwrap_or_else(|e| panic!("a=rid:{id}: {e}"));
        assert_eq!(rid.id, id);
        let simulcast = Simulcast::parse_with(&format!("send h;~{id}"), RidIdGrammar::Published)
            .unwrap_or_else(|e| panic!("a=simulcast:send h;~{id}: {e}"));
        assert_eq!(simulcast.send[1][0].rid, id);
        assert!(RidIdGrammar::Published.admits(id));
        assert!(!RidIdGrammar::Corrected.admits(id));
    }
    assert!(Rid::parse_with("a.b send", RidIdGrammar::Published).is_err());
    assert!(Simulcast::parse_with("send a.b", RidIdGrammar::Published).is_err());
}

#[test]
fn simulcast_separates_streams_alternatives_and_paused_ids() {
    let simulcast = Simulcast::parse("send 1,2,3;~4,~5 recv 6;~7,~8").unwrap();
    assert!(!simulcast.recv_first);
    assert_eq!(simulcast.send.len(), 2);
    assert_eq!(
        simulcast.send[0]
            .iter()
            .map(|id| (id.rid.as_str(), id.paused))
            .collect::<Vec<_>>(),
        vec![("1", false), ("2", false), ("3", false)]
    );
    assert_eq!(
        simulcast.send[1]
            .iter()
            .map(|id| (id.rid.as_str(), id.paused))
            .collect::<Vec<_>>(),
        vec![("4", true), ("5", true)]
    );
    assert_eq!(simulcast.recv.len(), 2);
    assert_eq!(simulcast.recv[1][0].rid, "7");
    assert!(simulcast.recv[1][0].paused);
    assert_eq!(
        simulcast.rids().collect::<Vec<_>>(),
        vec!["1", "2", "3", "4", "5", "6", "7", "8"]
    );

    let recv_first = Simulcast::parse("recv a send b").unwrap();
    assert!(recv_first.recv_first);
    assert!(Simulcast::parse("send a").unwrap().recv.is_empty());

    let media = with_media(
        "",
        "a=rid:h send\r\na=rid:l send\r\na=simulcast:send h;~l\r\n",
    );
    let media = &media.media_descriptions[0];
    assert_eq!(media.rids().unwrap().len(), 2);
    assert!(media.simulcast().unwrap().unwrap().send[1][0].paused);
}

// --- RFC 8285: extmap, extmap-allow-mixed -------------------------------------------------

#[test]
fn extmap_has_an_id_an_optional_direction_a_uri_and_attributes() {
    check::<ExtMap>(
        &[
            // RFC 8285 section 5 examples.
            "1 urn:ietf:params:rtp-hdrext:toffset",
            "2/sendrecv urn:ietf:params:rtp-hdrext:ssrc-audio-level",
            "3/sendonly urn:example:a",
            "4/recvonly urn:example:a",
            "5/inactive urn:example:a",
            "14 http://example.com/082005/ext.htm#ttime",
            "15 http://example.com/082005/ext.htm#xmeta short",
            "255 urn:example:a b c=d; e",
            "256 urn:example:appbits",
            "4096 urn:example:alternative-1",
            "4351 urn:example:alternative-2",
        ],
        &[
            "",
            "1",
            "1 ",
            " 1 urn:example:a",
            "0 urn:example:a",
            "257 urn:example:a",
            "4352 urn:example:a",
            "1/both urn:example:a",
            "1/ urn:example:a",
            "1/sendrecv/x urn:example:a",
            "a urn:example:a",
            "1 not-a-uri",
            "1 urn:example:a ",
        ],
    );
    let extmap = <ExtMap as TypedAttribute>::parse("2/recvonly urn:example:a x y").unwrap();
    assert_eq!(extmap.value, 2);
    assert_eq!(extmap.direction, Direction::RecvOnly);
    assert_eq!(
        extmap.uri.as_ref().map(|u| u.as_str()),
        Some("urn:example:a")
    );
    assert_eq!(extmap.ext_attr.as_deref(), Some("x y"));
}

#[test]
fn extmap_and_extmap_allow_mixed_are_read_at_both_levels() {
    let sdp = with_media(
        "a=extmap-allow-mixed\r\na=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n",
        "a=extmap:2/sendonly urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\na=extmap:3 urn:3gpp:video-orientation\r\n",
    );
    assert!(sdp.extmap_allow_mixed().unwrap());
    assert_eq!(sdp.extmaps().unwrap().len(), 1);
    let media = &sdp.media_descriptions[0];
    assert!(!media.extmap_allow_mixed().unwrap());
    let extmaps = media.extmaps().unwrap();
    assert_eq!(
        extmaps.iter().map(|e| e.value).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(extmaps[0].direction, Direction::SendOnly);

    let media = with_media("", "a=extmap-allow-mixed\r\n");
    assert!(media.media_descriptions[0].extmap_allow_mixed().unwrap());
    assert!(!media.extmap_allow_mixed().unwrap());
    // A property attribute with a value is malformed.
    let broken = with_media("a=extmap-allow-mixed:yes\r\n", "");
    assert!(broken.extmap_allow_mixed().is_err());
}

// --- RFC 3605, RFC 5761, RFC 8858, RFC 5506: rtcp, rtcp-mux, rtcp-mux-only, rtcp-rsize ------

#[test]
fn rtcp_is_a_port_and_an_optional_address() {
    check::<Rtcp>(
        &[
            // RFC 3605 section 2.1.
            "53020",
            "53020 IN IP4 126.16.64.4",
            "53020 IN IP6 2001:2345:6789:ABCD:EF01:2345:6789:ABCD",
            "9 IN IP4 0.0.0.0",
            "0",
            "65535",
        ],
        &[
            "",
            "65536",
            "-1",
            "9 IN",
            "9 IN IP4",
            "9 IN IP4 ",
            "9  IN IP4 0.0.0.0",
            "9 IN IP4 ::1",
            "9 IN IP4 1.2.3.4/127",
            "9 IN IP4 0.0.0.0 x",
            "abc",
        ],
    );
    let rtcp = Rtcp::parse("9 IN IP4 0.0.0.0").unwrap();
    assert_eq!(rtcp.port, 9);
    let address = rtcp.address.unwrap();
    assert_eq!(
        (
            address.network_type.as_str(),
            address.address_type.as_str(),
            address.address.as_str()
        ),
        ("IN", "IP4", "0.0.0.0")
    );
    assert_eq!(Rtcp::parse("9").unwrap().address, None);
}

#[test]
fn rtcp_property_attributes_are_flags_without_a_value() {
    let media = with_media(
        "",
        "a=rtcp-mux\r\na=rtcp-rsize\r\na=rtcp:9 IN IP4 0.0.0.0\r\n",
    );
    let media = &media.media_descriptions[0];
    assert!(media.rtcp_mux().unwrap());
    assert!(media.rtcp_rsize().unwrap());
    assert!(!media.rtcp_mux_only().unwrap());
    assert_eq!(media.rtcp().unwrap().unwrap().port, 9);

    let only = with_media("", "a=rtcp-mux\r\na=rtcp-mux-only\r\n");
    assert!(only.media_descriptions[0].rtcp_mux_only().unwrap());

    for broken in [
        "a=rtcp-mux:1\r\n",
        "a=rtcp-mux-only:\r\n",
        "a=rtcp-rsize:x\r\n",
    ] {
        let media = with_media("", broken);
        let media = &media.media_descriptions[0];
        assert!(
            media.rtcp_mux().is_err()
                || media.rtcp_mux_only().is_err()
                || media.rtcp_rsize().is_err(),
            "{broken}"
        );
    }
    // `flag` reads any property attribute by name.
    assert!(
        with_media("", "a=x-flag\r\n").media_descriptions[0]
            .flag("x-flag")
            .unwrap()
    );
}

// --- RFC 4585, RFC 5104 and later: rtcp-fb ------------------------------------------------

#[test]
fn rtcp_fb_follows_the_rfc_4585_and_rfc_5104_grammar() {
    check::<RtcpFb>(
        &[
            "96 ack",
            "96 ack rpsi",
            "96 ack app",
            "96 ack app some bytes",
            "96 nack",
            "96 nack pli",
            "96 nack sli",
            "96 nack rpsi",
            "96 nack app",
            "96 nack app foo",
            "96 nack rai",
            "96 nack tllei",
            "96 nack pslei",
            "96 nack ecn",
            "96 trr-int 100",
            "96 trr-int 0",
            "96 ccm fir",
            "96 ccm tmmbr",
            "96 ccm tmmbr smaxpr=120",
            "96 ccm tstr",
            "96 ccm vbcm",
            "96 ccm vbcm 1 2 3",
            "96 ccm future with bytes",
            "96 goog-remb",
            "96 transport-cc",
            "96 x_new-id param rest of the line",
            "* nack",
            "* ccm fir",
            "* transport-cc",
            "0 nack",
            "127 nack",
        ],
        &[
            "",
            "96",
            "96 ",
            "96  nack",
            " 96 nack",
            "128 nack",
            "256 nack",
            "-1 nack",
            "096 nack",
            "** nack",
            "x nack",
            "96 na/ck",
            "96 nack ",
            "96 nack p/li",
            "96 nack pli ",
            "96 trr-int",
            "96 trr-int x",
            "96 trr-int 100 200",
            "96 trr-int -1",
            "96 ccm",
        ],
    );
}

#[test]
fn rtcp_fb_names_every_feedback_type_the_specifications_define() {
    let kind = |value: &str| RtcpFb::parse(value).unwrap().kind();
    assert_eq!(kind("96 ack"), RtcpFbKind::Ack);
    assert_eq!(kind("96 ack rpsi"), RtcpFbKind::AckRpsi);
    assert_eq!(kind("96 ack app x"), RtcpFbKind::AckApp);
    assert_eq!(kind("96 nack"), RtcpFbKind::Nack);
    assert_eq!(kind("96 nack pli"), RtcpFbKind::NackPli);
    assert_eq!(kind("96 nack sli"), RtcpFbKind::NackSli);
    assert_eq!(kind("96 nack rpsi"), RtcpFbKind::NackRpsi);
    assert_eq!(kind("96 nack app"), RtcpFbKind::NackApp);
    assert_eq!(kind("96 nack rai"), RtcpFbKind::NackRai);
    assert_eq!(kind("96 nack tllei"), RtcpFbKind::NackTllei);
    assert_eq!(kind("96 nack pslei"), RtcpFbKind::NackPslei);
    assert_eq!(kind("96 nack ecn"), RtcpFbKind::NackEcn);
    assert_eq!(kind("96 trr-int 100"), RtcpFbKind::TrrInt(100));
    assert_eq!(kind("96 ccm fir"), RtcpFbKind::CcmFir);
    assert_eq!(kind("96 ccm tstr"), RtcpFbKind::CcmTstr);
    assert_eq!(kind("96 ccm tmmbr"), RtcpFbKind::CcmTmmbr { smaxpr: None });
    assert_eq!(
        kind("96 ccm tmmbr smaxpr=120"),
        RtcpFbKind::CcmTmmbr { smaxpr: Some(120) }
    );
    assert_eq!(kind("96 ccm vbcm"), RtcpFbKind::CcmVbcm(vec![]));
    assert_eq!(kind("96 ccm vbcm 1 22"), RtcpFbKind::CcmVbcm(vec![1, 22]));
    assert_eq!(kind("96 goog-remb"), RtcpFbKind::GoogRemb);
    assert_eq!(kind("96 transport-cc"), RtcpFbKind::TransportCc);
    // Well formed, and not one of the defined messages.
    for other in [
        "96 nack pli extra",
        "96 nack future",
        "96 ccm tmmbr smaxpr=x",
        "96 ccm tmmbr smaxpr=1234567890123456",
        "96 ccm vbcm 123456789",
        "96 ccm future",
        "96 goog-remb x",
        "96 x-new",
        "96 trr-int 99999999999",
    ] {
        assert_eq!(kind(other), RtcpFbKind::Other, "{other}");
    }

    let fb = RtcpFb::parse("* nack pli").unwrap();
    assert_eq!(fb.payload_type, RtcpFbPayloadType::All);
    assert!(fb.applies_to(0) && fb.applies_to(127));
    assert_eq!(fb.feedback(), "nack pli");
    let fb = RtcpFb::parse("96 ack app a b").unwrap();
    assert_eq!(fb.payload_type, RtcpFbPayloadType::PayloadType(96));
    assert!(fb.applies_to(96) && !fb.applies_to(97));
    assert_eq!(
        (fb.id.as_str(), fb.param.as_deref(), fb.rest.as_deref()),
        ("ack", Some("app"), Some("a b"))
    );
}

#[test]
fn rtcp_fb_lines_are_read_in_order_and_a_malformed_one_is_an_error() {
    let media = with_media(
        "",
        "a=rtcp-fb:* nack\r\na=rtcp-fb:96 nack pli\r\na=rtcp-fb:97 ccm fir\r\n",
    );
    let fbs = media.media_descriptions[0].rtcp_fbs().unwrap();
    assert_eq!(
        fbs.iter().map(|fb| fb.to_string()).collect::<Vec<_>>(),
        vec!["* nack", "96 nack pli", "97 ccm fir"]
    );
    let broken = with_media("", "a=rtcp-fb:96 nack\r\na=rtcp-fb:96\r\n");
    assert!(broken.media_descriptions[0].rtcp_fbs().is_err());
    // `codecs()` keeps what parses.
    assert_eq!(
        broken.media_descriptions[0].codecs()[&96].rtcp_feedback,
        vec!["nack"]
    );
}

// --- RFC 3611: rtcp-xr --------------------------------------------------------------------

#[test]
fn rtcp_xr_follows_the_rfc_3611_grammar() {
    check::<RtcpXr>(
        &[
            // RFC 3611 section 5.1 and 5.3.
            "",
            "rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics",
            "rcvr-rtt=sender",
            "pkt-loss-rle pkt-dup-rle pkt-rcpt-times",
            "pkt-loss-rle=20 pkt-dup-rle=30 pkt-rcpt-times=40",
            "stat-summary",
            "stat-summary=HL",
            "voip-metrics",
            "x-future-block=1,2",
        ],
        &[
            " ",
            "voip-metrics ",
            "voip-metrics  stat-summary",
            "rcvr-rtt",
            "rcvr-rtt=",
            "rcvr-rtt=both",
            "rcvr-rtt=all:",
            "rcvr-rtt=all:x",
            "pkt-loss-rle=",
            "pkt-loss-rle=x",
            "stat-summary=",
            "stat-summary=loss,",
            "stat-summary=ttl",
        ],
    );
    let xr =
        RtcpXr::parse("rcvr-rtt=all:10000 stat-summary=loss,HL pkt-loss-rle=5 voip-metrics x-new")
            .unwrap();
    assert_eq!(
        xr.formats,
        vec![
            RtcpXrFormat::RcvrRtt {
                mode: RtcpXrRttMode::All,
                max_size: Some(10000)
            },
            RtcpXrFormat::StatSummary(vec![RtcpXrStatFlag::Loss, RtcpXrStatFlag::Hl]),
            RtcpXrFormat::PktLossRle(Some(5)),
            RtcpXrFormat::VoipMetrics,
            RtcpXrFormat::Other("x-new".to_owned()),
        ]
    );
    // `a=rtcp-xr:` with nothing after the colon turns the reports off.
    let off = with_media("a=rtcp-xr:\r\n", "a=rtcp-xr:voip-metrics\r\n");
    assert!(off.rtcp_xr().unwrap().unwrap().formats.is_empty());
    assert_eq!(
        off.media_descriptions[0]
            .rtcp_xr()
            .unwrap()
            .unwrap()
            .formats
            .len(),
        1
    );
}

// --- RFC 8866 section 6: rtpmap, fmtp, ptime, maxptime, framerate -------------------------

#[test]
fn rtpmap_follows_the_rfc_8866_grammar() {
    check::<RtpMap>(
        &[
            "0 PCMU/8000",
            "96 L8/8000",
            "97 L16/8000",
            "98 L16/11025/2",
            "111 opus/48000/2",
            "96 VP8/90000",
            "99 h263-1998/90000",
            "101 telephone-event/8000",
            "127 H264/90000",
        ],
        &[
            "",
            "96",
            "96 ",
            "96 VP8",
            "96 VP8/",
            "96 VP8/0",
            "96 VP8/abc",
            "96 VP8/90000/",
            "96 VP8/90000/0",
            "96 VP8/90000/2/3",
            "96 VP8/090000",
            "96 /90000",
            "96 V P8/90000",
            "96  VP8/90000",
            " 96 VP8/90000",
            "128 VP8/90000",
            "096 VP8/90000",
            "-1 VP8/90000",
            "96 VP8/4294967296",
            "96 VP8/90000 ",
        ],
    );
    let opus = RtpMap::parse("111 opus/48000/2").unwrap();
    assert_eq!(opus.payload_type, 111);
    assert_eq!(opus.clock_rate, 48000);
    assert_eq!(opus.channels, Some(2));
    // RFC 8866 section 6.6: encoding names are compared without regard to case.
    assert!(opus.is_encoding("OPUS"));
    assert!(!opus.is_encoding("opus2"));
    assert_eq!(RtpMap::parse("0 PCMU/8000").unwrap().channels, None);
}

#[test]
fn fmtp_keeps_the_parameters_as_written_and_reads_them_in_order() {
    check::<Fmtp>(
        &[
            "96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1",
            "96 profile-level-id=42e01f; level-asymmetry-allowed=1; packetization-mode=1",
            "111 minptime=10;useinbandfec=1",
            "101 0-16",
            "63 111/111",
            "97 apt=96",
            "96  leading space; trailing space ",
            "webrtc-datachannel max-message-size=100000",
            "* x=1",
        ],
        &["", "96", "96 ", " 96 a=1", "9/6 a=1"],
    );

    let h264 = Fmtp::parse(
        "102 Level-Asymmetry-Allowed=1; packetization-mode = 1 ;profile-level-id=42e01f;flag;;",
    )
    .unwrap();
    assert_eq!(h264.payload_type(), Some(102));
    assert_eq!(
        h264.parameter_list(),
        vec![
            ("Level-Asymmetry-Allowed", Some("1")),
            ("packetization-mode", Some("1")),
            ("profile-level-id", Some("42e01f")),
            ("flag", None),
        ]
    );
    // Parameter names are matched without regard to case, values are untouched.
    assert_eq!(h264.parameter("level-asymmetry-allowed"), Some("1"));
    assert_eq!(h264.parameter("PROFILE-LEVEL-ID"), Some("42e01f"));
    assert_eq!(h264.parameter("flag"), None);
    assert_eq!(h264.parameter("absent"), None);
    // The text is not rewritten.
    assert_eq!(
        h264.to_string(),
        "102 Level-Asymmetry-Allowed=1; packetization-mode = 1 ;profile-level-id=42e01f;flag;;"
    );

    let events = Fmtp::parse("101 0-16").unwrap();
    assert_eq!(events.parameter_list(), vec![("0-16", None)]);
    let red = Fmtp::parse("63 111/111").unwrap();
    assert_eq!(red.parameter_list(), vec![("111/111", None)]);
    // A value may contain `=`: only the first one separates.
    let av1 = Fmtp::parse("45 x=a=b").unwrap();
    assert_eq!(av1.parameter("x"), Some("a=b"));
    assert_eq!(Fmtp::parse("data x=1").unwrap().payload_type(), None);
    assert_eq!(Fmtp::parse("128 x=1").unwrap().payload_type(), None);
}

#[test]
fn codec_attributes_are_read_per_line() {
    let media = with_media(
        "",
        "a=rtpmap:96 VP8/90000\r\na=rtpmap:97 rtx/90000\r\na=fmtp:97 apt=96\r\na=ptime:20\r\na=maxptime:60\r\na=framerate:29.97\r\n",
    );
    let media = &media.media_descriptions[0];
    assert_eq!(media.rtpmaps().unwrap().len(), 2);
    assert_eq!(media.fmtps().unwrap()[0].parameter("apt"), Some("96"));
    assert_eq!(media.ptime().unwrap().unwrap().value(), 20.0);
    assert_eq!(media.maxptime().unwrap().unwrap().as_str(), "60");
    assert_eq!(media.framerate().unwrap().unwrap().value(), 29.97);

    let broken = with_media("", "a=rtpmap:96 VP8\r\na=fmtp:96\r\na=ptime:0\r\n");
    let broken = &broken.media_descriptions[0];
    assert!(broken.rtpmaps().is_err());
    assert!(broken.fmtps().is_err());
    assert!(broken.ptime().is_err());
}

#[test]
fn ptime_maxptime_and_framerate_are_non_zero_integers_or_reals() {
    let good = ["20", "1", "2.5", "0.125", "29.97", "100"];
    let bad = [
        "", "0", "0.0", "020", "20.0", "2.50", "20.", ".5", "-20", "20ms", " 20", "2,5",
    ];
    check::<Ptime>(&good, &bad);
    check::<MaxPtime>(&good, &bad);
    check::<FrameRate>(&good, &bad);
    assert_eq!(Ptime::parse("2.5").unwrap().value(), 2.5);
}

// --- RFC 8866 sections 6.3, 6.8, 6.9, 6.14: tool, orient, type, quality ----------------------

#[test]
fn the_informational_attributes_follow_the_rfc_8866_grammar() {
    // 6.3: `tool-value = text`, a byte-string.
    check::<Tool>(&["foobar V3.2", "rtci", " spaced  out "], &[""]);
    // 6.9: five case-sensitive values.
    check::<ConferenceType>(
        &["broadcast", "meeting", "moderated", "test", "H332"],
        &[
            "",
            "Moderated",
            "h332",
            "conference",
            "test ",
            "meeting,test",
        ],
    );
    // 6.8: three case-sensitive values.
    check::<Orient>(
        &["portrait", "landscape", "seascape"],
        &["", "Portrait", "upside-down", "landscape "],
    );
    // 6.14: `zero-based-integer = "0" / integer`.
    check::<Quality>(&["0", "5", "10"], &["", "05", "-1", "5.5", "ten", " 5"]);
    assert_eq!(Quality::parse("10").unwrap().value(), 10);
}

/// The examples of RFC 8866 sections 6.3, 6.8, 6.9 and 6.14 are read at their levels, written
/// back unchanged and pass `validate`; each at the other level, or malformed, does not.
#[test]
fn the_informational_attributes_are_read_at_their_level_and_round_trip() {
    let text = format!(
        "{HEAD}a=tool:foobar V3.2\r\na=type:moderated\r\n\
         m=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\na=orient:portrait\r\na=quality:10\r\n"
    );
    let parsed = parse(&text);
    assert_eq!(parsed.marshal(), text);
    assert_eq!(parsed.tool().unwrap().unwrap().as_str(), "foobar V3.2");
    assert_eq!(
        parsed.conference_type().unwrap().unwrap().as_str(),
        "moderated"
    );
    let media = &parsed.media_descriptions[0];
    assert_eq!(media.orient().unwrap().unwrap().as_str(), "portrait");
    assert_eq!(media.quality().unwrap().unwrap().value(), 10);
    parsed.validate().unwrap();

    // Written from the typed values.
    let built = SessionDescription::new_jsep_session_description(false)
        .with_typed(&Tool::new("foobar V3.2").unwrap())
        .with_typed(&ConferenceType::new("test").unwrap());
    let written = built.marshal();
    assert!(
        written.contains("\r\na=tool:foobar V3.2\r\na=type:test\r\n"),
        "{written}"
    );

    for wrong in [
        // The other level.
        format!("{HEAD}a=orient:portrait\r\nm=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\n"),
        format!("{HEAD}a=quality:5\r\nm=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\n"),
        format!("{HEAD}m=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\na=tool:foobar\r\n"),
        format!("{HEAD}m=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\na=type:test\r\n"),
        // Malformed.
        format!("{HEAD}a=type:Moderated\r\nm=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\n"),
        format!("{HEAD}m=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\na=orient:upside-down\r\n"),
        format!("{HEAD}m=video 9 RTP/AVP 31\r\nc=IN IP4 0.0.0.0\r\na=quality:05\r\n"),
    ] {
        assert!(parse(&wrong).validate().is_err(), "{wrong}");
    }
    let malformed = parse(&format!("{HEAD}a=type:Moderated\r\n"));
    assert!(malformed.conference_type().is_err());
}

// --- RFC 6236: imageattr ------------------------------------------------------------------

#[test]
fn imageattr_follows_the_rfc_6236_grammar() {
    check::<ImageAttr>(
        &[
            // RFC 6236 section 3.1.1 and 4.
            "97 send [x=800,y=640,sar=1.1,q=0.6] [x=480,y=320] recv [x=330,y=250]",
            "97 recv [x=800,y=640,sar=1.1] send [x=330,y=250]",
            "99 send [x=176,y=144] [x=224,y=176] [x=272,y=224] [x=320,y=240] recv [x=176,y=144] [x=224,y=176] [x=272,y=224,q=0.6] [x=320,y=240]",
            "97 send [x=[480:16:800],y=[320:16:640],par=[1.2-1.3],q=0.6] [x=[176:8:208],y=[144:8:176],par=[1.2-1.3]] recv *",
            "100 recv [x=[320:640],y=[240:480]]",
            "100 send [x=[320,640,1280],y=[240,480,720]]",
            "100 send [x=320,y=240,sar=[0.5,1.0,1.3333]]",
            "100 send [x=320,y=240,sar=[0.9-1.1]]",
            "* send * recv *",
            "* recv *",
            "120 send * recv *",
            "100 send [x=320,y=240,q=1.0]",
            "100 send [x=320,y=240,q=0.5]",
            "100 send [x=1,y=999999]",
        ],
        &[
            "",
            "97",
            "97 send",
            "97 both *",
            "97 send * send *",
            "97 send * recv",
            "97 send [x=800]",
            "97 send [y=640,x=800]",
            "97 send [x=800,y=640",
            "97 send x=800,y=640",
            "97 send [x=0,y=640]",
            "97 send [x=0800,y=640]",
            "97 send [x=1000000,y=640]",
            "97 send [x=800,y=640,sar=1]",
            "97 send [x=800,y=640,sar=01.1]",
            "97 send [x=800,y=640,sar=0.0]",
            "97 send [x=800,y=640,sar=1.12345]",
            "97 send [x=800,y=640,q=1.5]",
            "97 send [x=800,y=640,q=0.123]",
            "97 send [x=800,y=640,q=2.0]",
            "97 send [x=800,y=640,par=1.2]",
            "97 send [x=800,y=640,par=[1.2,1.3]]",
            "97 send [x=800,y=640,z=1]",
            "97 send [x=[800],y=640]",
            "97 send [x=[1:2:3:4],y=640]",
            "97 send [x=[320:],y=640]",
            "128 send *",
            "x send *",
            " 97 send *",
            "97 send * ",
        ],
    );
}

#[test]
fn imageattr_exposes_sets_ranges_and_preferences() {
    let attr = ImageAttr::parse(
        "97 send [x=[480:16:800],y=[320,640],sar=[0.9-1.1],par=[1.2-1.3],q=0.6] [x=176,y=144] recv *",
    )
    .unwrap();
    assert_eq!(attr.payload_type, Some(97));
    assert_eq!(attr.recv, Some(ImageAttrList::Any));
    let Some(ImageAttrList::Sets(sets)) = &attr.send else {
        panic!("{attr:?}");
    };
    assert_eq!(sets.len(), 2);
    assert_eq!(
        sets[0].x,
        ImageAttrRange::Range {
            min: 480,
            step: Some(16),
            max: 800
        }
    );
    assert_eq!(sets[0].y, ImageAttrRange::List(vec![320, 640]));
    assert_eq!(
        sets[0].sar,
        Some(ImageAttrRange::Range {
            min: 0.9,
            step: None,
            max: 1.1
        })
    );
    assert_eq!(sets[0].par, Some((1.2, 1.3)));
    assert_eq!(sets[0].q, Some(0.6));
    assert_eq!(sets[1].x, ImageAttrRange::Value(176));
    assert_eq!(sets[1].q, None);

    // Any white space separates, as `1*WSP` allows; it is written back as one space.
    let spaced = ImageAttr::parse("*\tsend  [x=320,y=240]   recv\t*").unwrap();
    assert_eq!(spaced.payload_type, None);
    assert_eq!(spaced.to_string(), "* send [x=320,y=240] recv *");

    let media = with_media(
        "",
        "a=imageattr:96 send * recv *\r\na=imageattr:97 recv [x=320,y=240]\r\n",
    );
    assert_eq!(media.media_descriptions[0].imageattrs().unwrap().len(), 2);
}

// --- RFC 4796: content --------------------------------------------------------------------

#[test]
fn content_is_a_comma_separated_list_of_tokens() {
    check::<Content>(
        &[
            "slides",
            "speaker",
            "sl",
            "main",
            "alt",
            "main,slides",
            "x-new,alt",
        ],
        &["", "main,", ",main", "main, slides", "main slides", "ma/in"],
    );
    let media = with_media("", "a=content:main,slides\r\n");
    assert_eq!(
        media.media_descriptions[0].content().unwrap().unwrap().tags,
        vec!["main", "slides"]
    );
}

// --- b= -----------------------------------------------------------------------------------

#[test]
fn bandwidth_modifiers_have_kinds_and_units() {
    let sdp = parse(
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nb=CT:2000\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\nb=AS:1500\r\nb=TIAS:1400000\r\nb=RS:800\r\nb=RR:2400\r\nb=X-new:5\r\nb=FOO:6\r\n",
    );
    assert_eq!(sdp.bandwidth_of(BandwidthKind::ConferenceTotal), Some(2000));
    assert_eq!(sdp.bandwidth_of(BandwidthKind::ApplicationSpecific), None);
    assert_eq!(sdp.bandwidth[0].bits_per_second(), Some(2_000_000));

    let media = &sdp.media_descriptions[0];
    assert_eq!(
        media.bandwidth_of(BandwidthKind::ApplicationSpecific),
        Some(1500)
    );
    assert_eq!(media.bandwidth_of(BandwidthKind::Tias), Some(1_400_000));
    assert_eq!(media.bandwidth_of(BandwidthKind::RtcpSenders), Some(800));
    assert_eq!(media.bandwidth_of(BandwidthKind::RtcpReceivers), Some(2400));
    assert_eq!(media.bandwidth_of(BandwidthKind::ConferenceTotal), None);
    assert_eq!(
        media
            .bandwidth
            .iter()
            .map(|b| b.bits_per_second())
            .collect::<Vec<_>>(),
        vec![
            Some(1_500_000),
            Some(1_400_000),
            Some(800),
            Some(2400),
            None,
            None
        ]
    );
    // RFC 8866 section 5.8: an unknown modifier is ignored, which here means kept and
    // classed as `Other`.
    assert_eq!(media.bandwidth[4].kind(), BandwidthKind::Other);
    assert_eq!(media.bandwidth[5].kind(), BandwidthKind::Other);
    assert_eq!(mux::bandwidth("AS"), Some(MuxCategory::Sum));
    assert_eq!(mux::bandwidth("RS"), Some(MuxCategory::Sum));
    assert_eq!(mux::bandwidth("RR"), Some(MuxCategory::Sum));
    assert_eq!(mux::bandwidth("TIAS"), Some(MuxCategory::Special));
    assert_eq!(mux::bandwidth("CT"), Some(MuxCategory::Normal));
    assert_eq!(mux::bandwidth("FOO"), None);
}

// --- RFC 8839: ICE ------------------------------------------------------------------------

#[test]
fn candidate_follows_the_rfc_8839_grammar() {
    check::<Candidate>(
        &[
            // RFC 8839 section 5.1 and 9.
            "1 1 UDP 2130706431 203.0.113.141 8998 typ host",
            "2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 203.0.113.141 rport 8998",
            "1 1 UDP 2130706431 fe80::6676:baff:fe9c:ee4a 8998 typ host",
            "2 1 UDP 1694498815 2001:db8:8101:3a55:4858:a2a9:22ff:99b9 45664 typ srflx raddr fe80::6676:baff:fe9c:ee4a rport 8998",
            // What browsers write.
            "842163049 1 udp 1677729535 198.51.100.7 51123 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag 4ZcD network-id 1 network-cost 10",
            "1052312909 1 tcp 1518280447 192.0.2.10 9 typ host tcptype active generation 0",
            "0 1 UDP 2122252543 9b36eaac-bb2e-49bb-bb78-21c41c499900.local 49152 typ host",
            "3 2 UDP 100 192.0.2.1 3478 typ relay raddr 192.0.2.3 rport 45664",
            "a+b/c 256 TLS 0 192.0.2.1 0 typ prflx",
            "1 1 UDP 4294967295 192.0.2.1 65535 typ future-type",
            "1 1 UDP 1 192.0.2.1 1 typ host rport 9",
        ],
        &[
            "",
            "1 1 UDP 2130706431 203.0.113.141 8998",
            "1 1 UDP 2130706431 203.0.113.141 8998 typ",
            "1 1 UDP 2130706431 203.0.113.141 8998 host",
            "1 1 UDP 2130706431 203.0.113.141 8998 type host",
            "1  1 UDP 2130706431 203.0.113.141 8998 typ host",
            " 1 1 UDP 2130706431 203.0.113.141 8998 typ host",
            "1 1 UDP 2130706431 203.0.113.141 8998 typ host ",
            "a-b 1 UDP 1 192.0.2.1 1 typ host",
            "123456789012345678901234567890123 1 UDP 1 192.0.2.1 1 typ host",
            "1 0 UDP 1 192.0.2.1 1 typ host",
            "1 257 UDP 1 192.0.2.1 1 typ host",
            "1 1000 UDP 1 192.0.2.1 1 typ host",
            "1 x UDP 1 192.0.2.1 1 typ host",
            "1 1 U/DP 1 192.0.2.1 1 typ host",
            "1 1 UDP 4294967296 192.0.2.1 1 typ host",
            "1 1 UDP 12345678901 192.0.2.1 1 typ host",
            "1 1 UDP -1 192.0.2.1 1 typ host",
            "1 1 UDP 1 192.0.2.1 65536 typ host",
            "1 1 UDP 1 a_b 1 typ host",
            "1 1 UDP 1 [::1] 1 typ host",
            "1 1 UDP 1 fe80::1%eth0 1 typ host",
            "1 1 UDP 1 192.0.2.1 1 typ ho/st",
            "1 1 UDP 1 192.0.2.1 1 typ host raddr",
            "1 1 UDP 1 192.0.2.1 1 typ host raddr a_b rport 1",
            "1 1 UDP 1 192.0.2.1 1 typ host rport 65536",
            "1 1 UDP 1 192.0.2.1 1 typ host raddr 1.1.1.1 raddr 2.2.2.2",
            "1 1 UDP 1 192.0.2.1 1 typ host generation",
            "1 1 UDP 1 192.0.2.1 1 typ host gener/ation 0",
            "1 1 UDP 1 192.0.2.1 1 typ host x \u{e9}",
        ],
    );
}

#[test]
fn candidate_exposes_related_address_and_extensions() {
    let candidate = Candidate::parse(
        "842163049 1 udp 1677729535 198.51.100.7 51123 typ srflx raddr 10.0.0.2 rport 50000 generation 0 ufrag 4ZcD network-cost 999",
    )
    .unwrap();
    assert_eq!(candidate.foundation, "842163049");
    assert_eq!(candidate.component, 1);
    assert!(candidate.transport.eq_ignore_ascii_case("UDP"));
    assert_eq!(candidate.priority, 1_677_729_535);
    assert_eq!(candidate.address, "198.51.100.7");
    assert_eq!(candidate.port, 51123);
    assert_eq!(candidate.typ, "srflx");
    assert_eq!(candidate.related_address.as_deref(), Some("10.0.0.2"));
    assert_eq!(candidate.related_port, Some(50000));
    assert_eq!(candidate.extension("generation"), Some("0"));
    assert_eq!(candidate.extension("ufrag"), Some("4ZcD"));
    assert_eq!(candidate.extension("network-cost"), Some("999"));
    assert_eq!(candidate.extension("tcptype"), None);
    assert_eq!(candidate.extensions.len(), 3);

    let tcp = Candidate::parse("1 1 tcp 1 192.0.2.1 9 typ host tcptype passive").unwrap();
    assert_eq!(tcp.extension("tcptype"), Some("passive"));
    assert_eq!(tcp.related_address, None);
}

#[test]
fn ice_attributes_follow_the_rfc_8839_grammar() {
    let ufrag_max = "a".repeat(256);
    let pwd_min = "a".repeat(22);
    check::<IceUfrag>(
        &["8hhY", "4ZcD", "a+b/", "eceb5b58", &ufrag_max],
        &["", "abc", "ab-d", "ab d", "abcd ", &"a".repeat(257)],
    );
    check::<IcePwd>(
        &[
            "asd88fgpdd777uzjYhagZg",
            "2/1muCWoOi3uLifh0NuRHlkwz",
            &pwd_min,
            &"b".repeat(256),
        ],
        &[
            "",
            "short",
            &"a".repeat(21),
            &"a".repeat(257),
            "asd88fgpdd777uzjYhagZ-",
            "asd88fgpdd777uzjYhag Zg",
        ],
    );
    check::<IceOptions>(
        &[
            "trickle",
            "ice2",
            "trickle ice2",
            "trickle renomination",
            "rtp+ecn",
        ],
        &[
            "",
            "trickle ",
            " trickle",
            "trickle  ice2",
            "tri-ckle",
            "trickle,ice2",
        ],
    );
    check::<IcePacing>(
        &["50", "0", "5", "9999999999"],
        &["", "-1", "5ms", "12345678901", "5.0"],
    );
    check::<RemoteCandidates>(
        &[
            // RFC 8839 section 5.2.
            "1 192.0.2.3 45664",
            "1 192.0.2.3 45664 2 192.0.2.3 45665",
            "1 2001:db8::1 9",
        ],
        &[
            "",
            "1 192.0.2.3",
            "1 192.0.2.3 45664 2",
            "0 192.0.2.3 1",
            "1 a_b 1",
            "1 192.0.2.3 65536",
            "1  192.0.2.3 1",
        ],
    );

    let options = IceOptions::parse("trickle ice2").unwrap();
    assert!(options.contains("trickle") && options.contains("ice2"));
    assert!(!options.contains("renomination"));
    assert_eq!(IcePacing::parse("50").unwrap().0, 50);
    let remote = RemoteCandidates::parse("1 192.0.2.3 45664 2 192.0.2.3 45665").unwrap();
    assert_eq!(remote.candidates[1].component, 2);
    assert_eq!(remote.candidates[1].port, 45665);
}

#[test]
fn ice_attributes_are_read_at_their_levels() {
    let sdp = with_media(
        "a=ice-lite\r\na=ice-pacing:20\r\na=ice-options:trickle ice2\r\na=ice-ufrag:sess\r\na=ice-pwd:sessionpasswordsession1\r\n",
        "a=ice-ufrag:medi\r\na=ice-pwd:mediapasswordmediapass1\r\na=ice-options:trickle\r\na=candidate:1 1 UDP 2130706431 203.0.113.141 8998 typ host\r\na=candidate:2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 203.0.113.141 rport 8998\r\na=end-of-candidates\r\na=remote-candidates:1 192.0.2.9 4000\r\n",
    );
    assert!(sdp.ice_lite().unwrap());
    assert_eq!(sdp.ice_pacing().unwrap().unwrap().0, 20);
    assert_eq!(sdp.ice_ufrag().unwrap().unwrap().as_str(), "sess");
    assert_eq!(
        sdp.ice_pwd().unwrap().unwrap().as_str(),
        "sessionpasswordsession1"
    );
    assert_eq!(
        sdp.ice_options().unwrap().unwrap().tags,
        vec!["trickle", "ice2"]
    );

    let media = &sdp.media_descriptions[0];
    assert_eq!(media.ice_ufrag().unwrap().unwrap().as_str(), "medi");
    assert_eq!(media.ice_options().unwrap().unwrap().tags, vec!["trickle"]);
    let candidates = media.candidates().unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[1].typ, "srflx");
    assert!(media.end_of_candidates().unwrap());
    assert_eq!(
        media.remote_candidates().unwrap().unwrap().candidates[0].port,
        4000
    );

    let none = with_media("", "");
    assert!(!none.ice_lite().unwrap());
    assert!(!none.media_descriptions[0].end_of_candidates().unwrap());
    assert!(none.media_descriptions[0].candidates().unwrap().is_empty());

    let broken = with_media(
        "a=ice-lite:1\r\n",
        "a=ice-ufrag:x\r\na=candidate:1 1 UDP\r\na=end-of-candidates:\r\n",
    );
    assert!(broken.ice_lite().is_err());
    assert!(broken.media_descriptions[0].ice_ufrag().is_err());
    assert!(broken.media_descriptions[0].candidates().is_err());
    assert!(broken.media_descriptions[0].end_of_candidates().is_err());
}

// --- RFC 8122, RFC 4145, RFC 8842, RFC 8827 -----------------------------------------------

#[test]
fn fingerprint_follows_rfc_8122_and_has_the_length_of_its_hash() {
    let sha256 = "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF";
    let sha1 = "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB";
    check::<Fingerprint>(
        &[
            // RFC 8122 section 5.
            &format!("sha-256 {sha256}"),
            &format!("sha-1 {sha1}"),
            &format!("SHA-1 {sha1}"),
            &format!("sha-384 {}", ["AB"; 48].join(":")),
            &format!("sha-512 {}", ["CD"; 64].join(":")),
            &format!("sha-224 {}", ["00"; 28].join(":")),
            &format!("md5 {}", ["FF"; 16].join(":")),
            "x-future AB",
            "x-future AB:CD:EF",
        ],
        &[
            "",
            "sha-256",
            "sha-256 ",
            &format!(" sha-256 {sha256}"),
            &format!("sha-256  {sha256}"),
            &format!("sha-256 {sha256}:"),
            &format!("sha-256 {sha256} "),
            &format!("sha-256 {sha1}"),
            &format!("sha-1 {sha256}"),
            &format!("sha-256 {}", sha256.replace(':', "")),
            &format!("sha-256 {}", sha256.replace("4A:AD", "4A::AD")),
            &format!("sha-256 {}", sha256.replacen("4A", "4G", 1)),
            &format!("sha-256 {}", sha256.replacen("4A", "4", 1)),
            &format!("sha-256 {}", sha256.replacen("4A", "4AB", 1)),
            &format!("sha/256 {sha256}"),
        ],
    );

    let parsed = Fingerprint::parse(&format!("sha-256 {sha256}")).unwrap();
    assert_eq!(parsed.hash_function, "sha-256");
    assert_eq!(parsed.bytes.len(), 32);
    assert_eq!(&parsed.bytes[..3], &[0x4A, 0xAD, 0xB9]);
    // Lower-case hex is accepted and compares equal by bytes; it is written in upper case.
    let lower = Fingerprint::parse(&format!("sha-256 {}", sha256.to_lowercase())).unwrap();
    assert_eq!(lower.bytes, parsed.bytes);
    assert_eq!(lower.to_string(), format!("sha-256 {sha256}"));
}

#[test]
fn setup_tls_id_and_identity_follow_their_grammars() {
    check::<Setup>(
        &["active", "passive", "actpass", "holdconn"],
        &["", "Active", "act", "actpass ", "active passive"],
    );
    assert_eq!(Setup::parse("actpass").unwrap().0, ConnectionRole::Actpass);

    check::<TlsId>(
        &[
            // RFC 8842 section 4.
            "abc3de65cddef001be82",
            "ABCDEFGHIJKLMNOPQRST",
            "abc+def/ghi-jkl_mnop",
            &"a".repeat(255),
        ],
        &[
            "",
            "abc3de65cddef001be8",
            &"a".repeat(256),
            "abc3de65cddef001be8=",
            "abc3de65cddef001be8 2",
            "abc3de65cddef001be8.2",
        ],
    );

    check::<Identity>(
        &[
            "eyJpZHAiOnsiZG9tYWluIjoiZXhhbXBsZS5vcmcifX0=",
            "QUJD",
            "QQ==",
            "QUJD ext",
            "QUJD ext=value other=1,2",
        ],
        &[
            "",
            "QUJ",
            "QU-D",
            "QUJD ",
            "QUJD  ext",
            "QUJD e/xt",
            "QUJD ext=",
            "QUJD ext=a;b",
            " QUJD",
        ],
    );
    let identity = Identity::parse("QUJD a=1 b").unwrap();
    assert_eq!(identity.assertion, "QUJD");
    assert_eq!(
        identity.extensions,
        vec![
            ("a".to_owned(), Some("1".to_owned())),
            ("b".to_owned(), None)
        ]
    );

    let sdp = with_media(
        "a=identity:QUJD\r\na=fingerprint:sha-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\na=setup:actpass\r\na=tls-id:abc3de65cddef001be82\r\n",
        "a=setup:passive\r\na=tls-id:abc3de65cddef001be83\r\na=fingerprint:sha-1 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB\r\na=fingerprint:sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF\r\n",
    );
    assert_eq!(sdp.identity().unwrap().unwrap().assertion, "QUJD");
    assert_eq!(sdp.fingerprints().unwrap().len(), 1);
    assert_eq!(sdp.setup().unwrap().unwrap().0, ConnectionRole::Actpass);
    assert_eq!(
        sdp.tls_id().unwrap().unwrap().as_str(),
        "abc3de65cddef001be82"
    );
    let media = &sdp.media_descriptions[0];
    assert_eq!(media.setup().unwrap().unwrap().0, ConnectionRole::Passive);
    assert_eq!(
        media.tls_id().unwrap().unwrap().as_str(),
        "abc3de65cddef001be83"
    );
    assert_eq!(media.fingerprints().unwrap().len(), 2);

    let broken = with_media(
        "a=setup:both\r\n",
        "a=fingerprint:sha-256 4A\r\na=tls-id:short\r\n",
    );
    assert!(broken.setup().is_err());
    assert!(broken.media_descriptions[0].fingerprints().is_err());
    assert!(broken.media_descriptions[0].tls_id().is_err());
}

// --- RFC 8841: sctp-port, max-message-size, sctpmap ---------------------------------------

#[test]
fn sctp_attributes_follow_rfc_8841() {
    check::<SctpPort>(
        &["5000", "0", "65535"],
        &["", "65536", "05000", "-1", "5000 ", "x"],
    );
    check::<MaxMessageSize>(
        &[
            "100000",
            "0",
            "262144",
            "1073741823",
            "18446744073709551615",
        ],
        &["", "0100", "-1", "18446744073709551616", "1.5", "64k"],
    );
    check::<SctpMap>(
        &[
            "5000 webrtc-datachannel 1024",
            "5000 webrtc-datachannel",
            "0 x 0",
        ],
        &[
            "",
            "5000",
            "65536 webrtc-datachannel",
            "5000 webrtc datachannel 1024 x",
            "5000  webrtc-datachannel",
            "x webrtc-datachannel",
            "5000 webrtc-datachannel x",
        ],
    );
    assert_eq!(SctpPort::parse("5000").unwrap().0, 5000);
    assert_eq!(MaxMessageSize::parse("262144").unwrap().0, 262144);
    let map = SctpMap::parse("5000 webrtc-datachannel 1024").unwrap();
    assert_eq!(
        (map.port, map.app.as_str(), map.streams),
        (5000, "webrtc-datachannel", Some(1024))
    );

    let data = parse(&format!(
        "{HEAD}m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\na=bundle-only\r\n"
    ));
    let media = &data.media_descriptions[0];
    assert_eq!(media.sctp_port().unwrap().unwrap().0, 5000);
    assert_eq!(media.max_message_size().unwrap().unwrap().0, 262144);
    assert_eq!(media.sctpmap().unwrap(), None);
    assert!(media.bundle_only().unwrap());

    let old = parse(&format!(
        "{HEAD}m=application 9 DTLS/SCTP 5000\r\nc=IN IP4 0.0.0.0\r\na=sctpmap:5000 webrtc-datachannel 1024\r\n"
    ));
    assert_eq!(
        old.media_descriptions[0].sctpmap().unwrap().unwrap().port,
        5000
    );
    assert!(!old.media_descriptions[0].bundle_only().unwrap());
}

// --- direction, cryptex -------------------------------------------------------------------

#[test]
fn direction_is_read_once_per_level() {
    for (line, want) in [
        ("a=sendrecv\r\n", Some(Direction::SendRecv)),
        ("a=sendonly\r\n", Some(Direction::SendOnly)),
        ("a=recvonly\r\n", Some(Direction::RecvOnly)),
        ("a=inactive\r\n", Some(Direction::Inactive)),
        ("", None),
    ] {
        let sdp = with_media(line, line);
        assert_eq!(sdp.direction().unwrap(), want, "{line}");
        assert_eq!(
            sdp.media_descriptions[0].direction().unwrap(),
            want,
            "{line}"
        );
    }
    // RFC 8866 section 6.7: at most one per level; and a direction takes no value.
    let twice = with_media("", "a=sendrecv\r\na=recvonly\r\n");
    assert!(twice.media_descriptions[0].direction().is_err());
    let valued = with_media("a=sendonly:1\r\n", "");
    assert!(valued.direction().is_err());
    // The levels are independent.
    let both = with_media("a=inactive\r\n", "a=sendrecv\r\n");
    assert_eq!(both.direction().unwrap(), Some(Direction::Inactive));
    assert_eq!(
        both.media_descriptions[0].direction().unwrap(),
        Some(Direction::SendRecv)
    );
}

#[test]
fn cryptex_is_a_flag_at_either_level() {
    let sdp = with_media("a=cryptex\r\n", "");
    assert!(sdp.cryptex().unwrap());
    assert!(!sdp.media_descriptions[0].cryptex().unwrap());
    let media = with_media("", "a=cryptex\r\n");
    assert!(media.media_descriptions[0].cryptex().unwrap());
    assert!(
        with_media("", "a=cryptex:1\r\n").media_descriptions[0]
            .cryptex()
            .is_err()
    );
}

// --- generic access -----------------------------------------------------------------------

#[test]
fn typed_attributes_are_written_with_with_typed() {
    let media = crate::MediaDescription::default()
        .with_typed(&Mid::new("0").unwrap())
        .with_typed(&RtpMap::parse("96 VP8/90000").unwrap())
        .with_typed(&Rid::parse("h send pt=96;max-width=1280").unwrap())
        .with_typed(&Simulcast::parse("send h").unwrap());
    assert_eq!(
        media
            .attributes
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>(),
        vec![
            "mid:0",
            "rtpmap:96 VP8/90000",
            "rid:h send pt=96;max-width=1280",
            "simulcast:send h"
        ]
    );
    assert_eq!(media.typed::<Mid>().unwrap().unwrap().as_str(), "0");
    assert_eq!(media.typed_all::<Rid>().unwrap().len(), 1);
    assert_eq!(media.typed::<Msid>().unwrap(), None);

    let session = SessionDescription::default().with_typed(&Group::parse("BUNDLE 0").unwrap());
    assert_eq!(session.attributes[0].to_string(), "group:BUNDLE 0");
    assert_eq!(
        Group::parse("BUNDLE 0").unwrap().to_attribute().key,
        "group"
    );
}

#[test]
fn a_value_attribute_without_a_value_is_malformed() {
    let media = with_media("", "a=mid\r\na=rtpmap\r\na=candidate\r\n");
    let media = &media.media_descriptions[0];
    assert!(matches!(media.mid(), Err(Error::SdpInvalidSyntax(_))));
    assert!(media.rtpmaps().is_err());
    assert!(media.candidates().is_err());
}

// --- RFC 8859: multiplexing categories ----------------------------------------------------

#[test]
fn the_mux_table_is_sorted_and_has_no_duplicate() {
    for pair in mux::ATTRIBUTES.windows(2) {
        assert!(
            pair[0].name.as_bytes() < pair[1].name.as_bytes(),
            "{} before {}",
            pair[0].name,
            pair[1].name
        );
    }
    // Every row can be found again.
    for row in mux::ATTRIBUTES {
        assert_eq!(mux::attribute(row.name), Some(row));
    }
}

#[test]
fn the_mux_table_has_the_category_of_every_attribute_webrtc_uses() {
    use AttributeLevel::{Both, Media, Session};
    use MuxCategory::*;
    for (name, level, category) in [
        // RFC 8859 section 5.
        ("sendrecv", Both, Normal),
        ("sendonly", Both, Normal),
        ("recvonly", Both, Normal),
        ("inactive", Both, Normal),
        ("rtpmap", Media, IdenticalPerPt),
        ("fmtp", Media, IdenticalPerPt),
        ("ptime", Media, IdenticalPerPt),
        ("maxptime", Media, IdenticalPerPt),
        ("framerate", Media, IdenticalPerPt),
        ("rtcp-fb", Media, IdenticalPerPt),
        ("imageattr", Media, IdenticalPerPt),
        ("rtcp-mux", Media, Identical),
        ("rtcp-rsize", Media, Identical),
        ("rtcp", Media, Transport),
        ("rtcp-xr", Both, Normal),
        ("ice-lite", Session, Normal),
        ("ice-ufrag", Both, Transport),
        ("ice-pwd", Both, Transport),
        ("candidate", Media, Transport),
        ("remote-candidates", Media, Transport),
        ("fingerprint", Both, Transport),
        ("setup", Both, Transport),
        ("extmap", Both, Special),
        ("ssrc", Media, Normal),
        ("ssrc-group", Media, Normal),
        ("content", Media, Normal),
        ("crypto", Media, Transport),
        ("label", Media, Normal),
        ("group", Session, Normal),
        ("mid", Media, Normal),
        // Registered later, each by its own RFC.
        ("msid", Media, Normal),
        ("rid", Media, Special),
        ("simulcast", Media, Normal),
        ("extmap-allow-mixed", Both, Identical),
        ("rtcp-mux-only", Media, Identical),
        ("ice-options", Both, Normal),
        ("ice-pacing", Session, Normal),
        ("end-of-candidates", Both, Identical),
        ("tls-id", Both, Identical),
        ("sctp-port", Media, Caution),
        ("max-message-size", Media, Caution),
        ("identity", Session, Normal),
        ("cryptex", Both, Transport),
        ("bundle-only", Media, Normal),
    ] {
        let row = mux::attribute(name).unwrap_or_else(|| panic!("{name} is not in the table"));
        assert_eq!(row.level, Some(level), "{name}");
        assert_eq!(row.category, category, "{name}");
        assert_eq!(mux::category(name), Some(category));
    }
    // Other categories are in the table too.
    assert_eq!(mux::category("acap"), Some(Inherit));
    assert_eq!(mux::category("T38FaxVersion"), Some(Tbd));
    assert_eq!(mux::category("zrtp-hash"), Some(Transport));
    assert_eq!(mux::category("maxprate"), Some(Special));
    // Never registered, or not an attribute name.
    for unknown in [
        "msid-semantic",
        "sctpmap",
        "x-google-flag",
        "",
        "RTPMAP",
        "type:broadcast",
    ] {
        assert_eq!(mux::attribute(unknown), None, "{unknown}");
    }
    assert!(Session.allows_session() && !Session.allows_media());
    assert!(Media.allows_media() && !Media.allows_session());
    assert!(Both.allows_media() && Both.allows_session());
    assert!(!AttributeLevel::Source.allows_media() && !AttributeLevel::Source.allows_session());
}

#[test]
fn the_mux_tables_cover_source_attributes_feedback_and_grouping_semantics() {
    use MuxCategory::*;
    assert_eq!(mux::source_attribute("cname"), Some(Normal));
    assert_eq!(mux::source_attribute("previous-ssrc"), Some(Normal));
    assert_eq!(mux::source_attribute("fmtp"), Some(IdenticalPerPt));
    assert_eq!(mux::source_attribute("msid"), None);

    let fb = |value: &str| mux::rtcp_fb(&RtcpFb::parse(value).unwrap());
    for per_pt in [
        "96 ack",
        "96 ack rpsi",
        "96 nack",
        "96 nack pli",
        "96 nack sli",
        "96 nack rpsi",
        "96 nack rai",
        "96 nack tllei",
        "96 nack pslei",
        "96 trr-int 100",
        "96 ccm fir",
        "96 ccm tmmbr",
        "96 ccm tstr",
        "96 ccm vbcm",
    ] {
        assert_eq!(fb(per_pt), Some(IdenticalPerPt), "{per_pt}");
    }
    assert_eq!(fb("96 ack app"), Some(Special));
    assert_eq!(fb("96 nack app x"), Some(Special));
    assert_eq!(fb("96 nack ecn"), Some(Identical));
    assert_eq!(fb("96 goog-remb"), None);
    assert_eq!(fb("96 transport-cc"), None);

    for semantics in [
        "LS", "FID", "SRF", "FEC", "FEC-FR", "CS", "DDP", "DUP", "BUNDLE",
    ] {
        assert_eq!(mux::group_semantics(semantics), Some(Normal), "{semantics}");
    }
    assert_eq!(mux::group_semantics("ANAT"), Some(Caution));
    assert_eq!(mux::group_semantics("X"), None);
    for semantics in ["FID", "FEC", "FEC-FR", "DUP"] {
        assert_eq!(
            mux::ssrc_group_semantics(semantics),
            Some(Normal),
            "{semantics}"
        );
    }
    assert_eq!(mux::ssrc_group_semantics("SIM"), None);
    for tag in ["slides", "speaker", "sl", "main", "alt"] {
        assert_eq!(mux::content(tag), Some(Normal), "{tag}");
    }
    assert_eq!(mux::content("x"), None);
}

#[test]
fn attributes_built_with_the_whole_line_as_their_key_read_like_parsed_ones() {
    // `with_property_attribute("msid:s t")` and `with_extmap` build an attribute whose key
    // is the whole line; it prints as the same `a=` line, and reads the same.
    let media = crate::MediaDescription::default()
        .with_property_attribute("msid:stream track".to_owned())
        .with_extmap(ExtMap {
            value: 3,
            uri: url::Url::parse("urn:ietf:params:rtp-hdrext:sdes:mid").ok(),
            ..Default::default()
        })
        .with_property_attribute("rtcp-mux".to_owned())
        .with_property_attribute("rtpmap:96 VP8/90000".to_owned())
        .with_property_attribute("rtcp-fb:* nack".to_owned())
        .with_property_attribute("sendonly".to_owned());
    assert_eq!(media.msids().unwrap()[0].appdata.as_deref(), Some("track"));
    assert_eq!(media.extmaps().unwrap()[0].value, 3);
    assert!(media.rtcp_mux().unwrap());
    assert_eq!(media.direction().unwrap(), Some(Direction::SendOnly));
    assert_eq!(media.rtpmaps().unwrap()[0].encoding_name, "VP8");
    assert_eq!(media.codecs()[&96].rtcp_feedback, vec!["nack"]);
    assert_eq!(media.attributes[0].parts(), ("msid", Some("stream track")));
    assert_eq!(media.attributes[2].parts(), ("rtcp-mux", None));

    // `validate` reads them the same way, and refuses a name that is not a token or a
    // value that could not be written on one line.
    let session = |media: crate::MediaDescription| SessionDescription {
        connection_information: ConnectionInformationForTest::any(),
        media_descriptions: vec![media],
        ..Default::default()
    };
    assert!(session(media.clone()).validate().is_ok());
    assert!(
        session(
            media
                .clone()
                .with_property_attribute("msid:a b c".to_owned())
        )
        .validate()
        .is_err()
    );
    assert!(
        session(
            media
                .clone()
                .with_property_attribute("not a token".to_owned())
        )
        .validate()
        .is_err()
    );
    assert!(
        session(media.with_value_attribute("x-note".to_owned(), "two\r\nlines".to_owned()))
            .validate()
            .is_err()
    );
}

struct ConnectionInformationForTest;

impl ConnectionInformationForTest {
    fn any() -> Option<crate::description::common::ConnectionInformation> {
        crate::description::common::ConnectionInformation::parse("IN IP4 0.0.0.0").ok()
    }
}

/// RFC 5583 section 5.2.2 and the examples of section 6.5 (`a=depend:97 lay L1:96`, an MDC
/// section depending on none, several formats, a list of alternatives): parsed and printed
/// back; a format named twice ("exactly one dependency-tag ... per dependent-fmt"), a tag
/// without its formats, two tags for one format and a missing type are refused.
#[test]
fn depend_follows_the_rfc_5583_abnf() {
    check::<Depend>(
        &[
            "97 lay L1:96",
            "96 mdc",
            "100 lay L1:96,97; 101 lay L1:97",
            "104 lay L2:102,103",
            "98 x-other",
        ],
        &[
            "",
            "97",
            "97 lay L1",
            "97 lay L1:",
            "97 lay L1:96 L2:95",
            "97 lay L1:96; 97 lay L1:95",
        ],
    );
    let depend = Depend::parse("100 lay L1:96,97; 101 mdc").unwrap();
    assert_eq!(
        depend.of("100"),
        Some(&Dependency {
            fmt: "100".to_owned(),
            typ: DependencyType::Lay,
            on: Some(("L1".to_owned(), vec!["96".to_owned(), "97".to_owned()])),
        })
    );
    assert_eq!(depend.of("101").map(|d| &d.typ), Some(&DependencyType::Mdc));
}

/// `check_attribute`: one line by its grammar (RFC 9429 section 5.8). A known attribute's
/// value parses as its type, a property attribute has none, `a=rtcp-xr` may have none (RFC
/// 3611 section 5.1), and an unknown attribute is fine (RFC 8866 section 5.13).
#[test]
fn check_attribute_checks_one_line_by_its_grammar() {
    use crate::description::common::Attribute;
    let line =
        |key: &str, value: Option<&str>| Attribute::new(key.to_owned(), value.map(str::to_owned));
    for ok in [
        line("rtcp-xr", None),
        line("rtcp-xr", Some("rcvr-rtt=all")),
        line("rtcp-mux", None),
        line("x-unknown", Some("anything at all")),
        line("ice-options", Some("trickle ice2")),
    ] {
        assert!(check_attribute(&ok).is_ok(), "{ok:?}");
    }
    for bad in [
        line("rtcp-mux", Some("yes")),
        line("ice-options", Some("x-future")),
        line("rtpmap", Some("96 VP8")),
        line("mid", None),
    ] {
        assert!(check_attribute(&bad).is_err(), "{bad:?}");
    }
}
