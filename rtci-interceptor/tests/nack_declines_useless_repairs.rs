//! The NACK responder declines repairs that cannot be useful (RFC 8834 section 6.1: "It is
//! not appropriate to blindly retransmit RTP packets in response to a NACK. The importance of
//! lost packets and the likelihood of them arriving in time to be useful need to be
//! considered"; RFC 4588 section 7: "If congestion is not kept under control, then
//! retransmission SHOULD NOT be used", and the sender "MAY selectively retransmit only the
//! packets that it deems important and ignore NACK messages for other packets").
//!
//! Two rules, both settings of `NackResponderBuilder`:
//! - **age** (`with_max_repair_age`, 2 s): a packet written longer ago is not repaired; where
//!   an `rtx-time` (RFC 4588 8.1) is in force for the stream, that time is the bound instead;
//! - **backlog** (`with_repair_backlog_bound`, 2 s): requests waiting that would take that
//!   long at the target, after the target fell to half or less within two seconds, are given
//!   up.
//!
//! Giving a video stream up forgets everything sent on it so far, releases the retransmission
//! reserve at once and asks the application for a key frame (a Picture Loss Indication with
//! sender SSRC 0). Audio is declined by age and never asked for a key frame. See
//! `docs/capacity-collapse.md`.

use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, LocalKeyFrameRequest, NACK_MAX_REPAIR_AGE,
    NackResponderBuilder, Packet, ProbePacket, ProbeRequest, RTCPFeedback, Registry,
    RetransmissionRateLimit, RetransmissionReserve, Slot, StreamInfo, TaggedPacket,
};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::transport_feedbacks::transport_layer_nack::{
    TransportLayerNack, nack_pairs_from_sequence_numbers,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const VIDEO: u32 = 0x1234;
const VIDEO_RTX: u32 = 0x5678;
const AUDIO: u32 = 0x9abc;
const RTX_PAYLOAD_TYPE: u8 = 97;
/// Every original packet: a 12-byte header and 1000 bytes of payload.
const PAYLOAD: usize = 1000;
const HIGH: f64 = 2_500_000.0;
const LOW: f64 = 100_000.0;

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

fn nack_feedback() -> Vec<RTCPFeedback> {
    vec![RTCPFeedback {
        typ: "nack".to_string(),
        parameter: String::new(),
    }]
}

fn video(rtx: bool) -> StreamInfo {
    StreamInfo {
        ssrc: VIDEO,
        ssrc_rtx: rtx.then_some(VIDEO_RTX),
        payload_type_rtx: rtx.then_some(RTX_PAYLOAD_TYPE),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: nack_feedback(),
        ..Default::default()
    }
}

fn audio() -> StreamInfo {
    StreamInfo {
        ssrc: AUDIO,
        clock_rate: 48000,
        mime_type: "audio/opus".to_string(),
        payload_type: 111,
        rtcp_feedback: nack_feedback(),
        ..Default::default()
    }
}

fn responder(builder: NackResponderBuilder, streams: Vec<StreamInfo>) -> impl Interceptor {
    let mut chain = Registry::new()
        .with(Slot::NackResponder, builder.build())
        .build();
    for stream in &streams {
        chain.bind_local_stream(stream);
    }
    chain
}

/// A responder with no rate limit, so that only the rules under test decline anything.
fn unlimited() -> NackResponderBuilder {
    NackResponderBuilder::new().with_rate_limit(RetransmissionRateLimit::Unlimited)
}

fn tagged(now: Instant, message: AttributedPacket) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message,
    }
}

/// What left on the write leg and what reached the application on the read leg.
#[derive(Default, Debug)]
struct Seen {
    /// (media SSRC, original sequence number) of each retransmission.
    repaired: Vec<(u32, u16)>,
    /// The streams a key frame was asked of, in order.
    key_frames: Vec<u32>,
    /// Every retransmission reserve announced wire-ward, bits per second.
    reserves: Vec<f64>,
    /// Every target the application was told.
    targets: Vec<f64>,
    /// Padding-only packets on the RTX stream, with the probe cluster each is marked for.
    padding: Vec<Option<u32>>,
}

fn drain(chain: &mut impl Interceptor, seen: &mut Seen) {
    while let Some(written) = chain.poll_write() {
        if let Some(reserve) = written.message.custom::<RetransmissionReserve>() {
            seen.reserves.push(reserve.bits_per_second);
        }
        let Packet::Rtp(packet) = &written.message.packet else {
            continue;
        };
        if !written.message.has(&Attribute::Retransmission) {
            continue;
        }
        if packet.header.ssrc == VIDEO_RTX {
            if packet.payload.len() >= 2 {
                let original = u16::from_be_bytes([packet.payload[0], packet.payload[1]]);
                seen.repaired.push((VIDEO, original));
            } else {
                seen.padding.push(
                    written
                        .message
                        .custom::<ProbePacket>()
                        .map(|probe| probe.cluster),
                );
            }
        } else {
            // No RTX: the original packet again.
            seen.repaired
                .push((packet.header.ssrc, packet.header.sequence_number));
        }
    }
    while let Some(read) = chain.poll_read() {
        for attribute in &read.message.attributes {
            if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                seen.targets.push(*bits_per_second);
            }
        }
        let Packet::Rtcp(packets) = &read.message.packet else {
            continue;
        };
        for packet in packets {
            if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>() {
                assert_eq!(0, pli.sender_ssrc, "the engine's own request");
                assert!(
                    read.message.has(&Attribute::DeliverToApplication),
                    "the request must reach the application"
                );
                assert_eq!(
                    Some(&LocalKeyFrameRequest::RepairGivenUp),
                    read.message.custom::<LocalKeyFrameRequest>(),
                    "the request says the repair was given up"
                );
                seen.key_frames.push(pli.media_ssrc);
            }
        }
    }
}

/// Writes the original packets `sequence_numbers` of `ssrc`, `spacing` apart from `from`.
fn write(
    chain: &mut impl Interceptor,
    from: Instant,
    spacing: Duration,
    ssrc: u32,
    sequence_numbers: std::ops::Range<u16>,
) {
    for (index, sequence_number) in sequence_numbers.enumerate() {
        chain
            .handle_write(tagged(
                from + spacing * index as u32,
                AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: if ssrc == AUDIO { 111 } else { 96 },
                        sequence_number,
                        ssrc,
                        ..Default::default()
                    },
                    payload: vec![0u8; PAYLOAD].into(),
                })),
            ))
            .unwrap();
    }
}

/// The receiver asks for `sequence_numbers` of `ssrc` at `now`.
fn nack(chain: &mut impl Interceptor, now: Instant, ssrc: u32, sequence_numbers: &[u16]) {
    chain
        .handle_read(tagged(
            now,
            AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
                sender_ssrc: 1,
                media_ssrc: ssrc,
                nacks: nack_pairs_from_sequence_numbers(sequence_numbers),
            })])),
        ))
        .unwrap();
}

/// The congestion controller's target passes application-ward at `now`.
fn target(chain: &mut impl Interceptor, now: Instant, bits_per_second: f64) {
    chain
        .handle_read(tagged(
            now,
            AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::TargetBitrateChanged { bits_per_second }),
        ))
        .unwrap();
}

/// Runs the responder's own deadlines from `from` up to `until`.
fn run(chain: &mut impl Interceptor, from: Instant, until: Instant, seen: &mut Seen) {
    let mut now = from;
    drain(chain, seen);
    for _ in 0..100_000 {
        let Some(deadline) = chain.poll_timeout() else {
            return;
        };
        if deadline > until {
            return;
        }
        now = now.max(deadline);
        chain.handle_timeout(now).unwrap();
        drain(chain, seen);
    }
    panic!("the responder's deadline does not advance");
}

fn numbers(range: std::ops::Range<u16>) -> Vec<u16> {
    range.collect()
}

// ---------------------------------------------------------------------------------------
// Age
// ---------------------------------------------------------------------------------------

/// A video packet asked for later than the age bound after it was written is not repaired:
/// the stream is given up and the application asked for ONE key frame, however many old
/// packets the receiver names and however often it asks. A packet inside the bound is
/// repaired, and so is everything written after the give-up.
#[test]
fn a_request_for_a_video_packet_older_than_the_bound_gives_the_stream_up_for_a_key_frame() {
    for rtx in [true, false] {
        let mut chain = responder(unlimited(), vec![video(rtx)]);
        let epoch = Instant::now();
        let mut seen = Seen::default();
        write(&mut chain, epoch, ms(1), VIDEO, 0..20);
        drain(&mut chain, &mut seen);

        // Inside the bound (the newest of them exactly at it): repaired.
        nack(&mut chain, epoch + NACK_MAX_REPAIR_AGE, VIDEO, &[0, 1]);
        drain(&mut chain, &mut seen);
        assert_eq!(vec![(VIDEO, 0), (VIDEO, 1)], seen.repaired, "rtx {rtx}");
        assert!(seen.key_frames.is_empty(), "rtx {rtx}");

        // Past it: nothing is sent, one key frame is asked for.
        let late = epoch + NACK_MAX_REPAIR_AGE + ms(100);
        let mut seen = Seen::default();
        nack(&mut chain, late, VIDEO, &[2, 3, 4, 5]);
        nack(&mut chain, late + ms(60), VIDEO, &[2, 3, 4, 5, 6, 7]);
        nack(&mut chain, late + ms(120), VIDEO, &numbers(0..20));
        drain(&mut chain, &mut seen);
        assert!(seen.repaired.is_empty(), "rtx {rtx}: {:?}", seen.repaired);
        assert_eq!(vec![VIDEO], seen.key_frames, "rtx {rtx}");

        // What is written afterwards (the key frame) is repaired as ever.
        let mut seen = Seen::default();
        write(&mut chain, late + ms(200), ms(1), VIDEO, 20..40);
        nack(&mut chain, late + ms(300), VIDEO, &[25, 26]);
        drain(&mut chain, &mut seen);
        assert_eq!(vec![(VIDEO, 25), (VIDEO, 26)], seen.repaired, "rtx {rtx}");
        assert!(seen.key_frames.is_empty(), "rtx {rtx}");
    }
}

/// An audio packet past the bound is not retransmitted, and that is all: no key frame is
/// asked for (there is none), nothing is forgotten, a younger packet is repaired.
#[test]
fn an_old_audio_packet_is_declined_without_a_key_frame_request() {
    let mut chain = responder(unlimited(), vec![video(true), audio()]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    write(&mut chain, epoch, ms(20), AUDIO, 0..10);
    let late = epoch + NACK_MAX_REPAIR_AGE + ms(500);
    write(&mut chain, late - ms(100), ms(20), AUDIO, 10..12);
    drain(&mut chain, &mut seen);

    nack(&mut chain, late, AUDIO, &[3, 4, 10]);
    drain(&mut chain, &mut seen);
    assert_eq!(vec![(AUDIO, 10)], seen.repaired);
    assert!(seen.key_frames.is_empty(), "{:?}", seen.key_frames);
}

/// With the age bound off (`None`, what `PacerBacklog::Keep` gives the default chain) a
/// packet is repaired for as long as the buffer holds it.
#[test]
fn without_an_age_bound_an_old_packet_is_repaired() {
    let mut chain = responder(unlimited().with_max_repair_age(None), vec![video(true)]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    write(&mut chain, epoch, ms(1), VIDEO, 0..20);
    nack(&mut chain, epoch + Duration::from_secs(30), VIDEO, &[2, 3]);
    drain(&mut chain, &mut seen);
    assert_eq!(vec![(VIDEO, 2), (VIDEO, 3)], seen.repaired);
    assert!(seen.key_frames.is_empty());
}

/// RFC 4588 8.1: where an `rtx-time` is in force for the stream it takes the place of the
/// repair age, longer or shorter. A packet inside it is repaired (four seconds old under a
/// time of five, where the repair age alone would have given the stream up); one past it is
/// not retransmitted and that is all: no key frame is asked for and nothing is forgotten, a
/// younger packet named in the same request is repaired.
#[test]
fn an_rtx_time_takes_the_place_of_the_repair_age() {
    for (rtx_time, inside, past) in [
        (ms(5_000), ms(4_000), ms(5_100)),
        (ms(500), ms(400), ms(600)),
    ] {
        let mut chain = responder(
            unlimited().with_max_packet_age(Some(rtx_time)),
            vec![video(true)],
        );
        let epoch = Instant::now();
        let mut seen = Seen::default();
        write(&mut chain, epoch, ms(1), VIDEO, 0..10);
        nack(&mut chain, epoch + inside, VIDEO, &[0, 1]);
        drain(&mut chain, &mut seen);
        assert_eq!(vec![(VIDEO, 0), (VIDEO, 1)], seen.repaired, "{rtx_time:?}");

        let mut seen = Seen::default();
        write(&mut chain, epoch + past - ms(50), ms(1), VIDEO, 10..20);
        nack(&mut chain, epoch + past, VIDEO, &[2, 3, 15]);
        drain(&mut chain, &mut seen);
        assert_eq!(vec![(VIDEO, 15)], seen.repaired, "{rtx_time:?}");
        assert!(
            seen.key_frames.is_empty(),
            "{rtx_time:?}: {:?}",
            seen.key_frames
        );
    }
}

// ---------------------------------------------------------------------------------------
// Backlog
// ---------------------------------------------------------------------------------------

/// 150 packets (0.3 s of 4 Mbit/s) written at the high target; returns when the last was.
fn written_at_the_high_rate(chain: &mut impl Interceptor, epoch: Instant) -> Instant {
    target(chain, epoch, HIGH);
    write(chain, epoch, ms(2), VIDEO, 0..150);
    epoch + ms(300)
}

/// The target falls from 2.5 Mbit/s to 100 kbit/s and the receiver asks for 60 packets, half
/// a megabit: 4.9 s of the new target. None of it is sent: the stream is given up and one key
/// frame asked for. What is written afterwards is repaired within the target.
#[test]
fn a_backlog_of_repairs_after_the_target_halved_is_given_up_for_a_key_frame() {
    let mut chain = responder(NackResponderBuilder::new(), vec![video(true)]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    let at = written_at_the_high_rate(&mut chain, epoch);
    target(&mut chain, at, LOW);
    nack(&mut chain, at + ms(10), VIDEO, &numbers(0..60));
    run(&mut chain, at + ms(10), at + ms(1500), &mut seen);
    assert!(seen.repaired.is_empty(), "{:?}", seen.repaired);
    assert_eq!(vec![VIDEO], seen.key_frames);

    // The receiver goes on asking for what was given up: silence, and no second request.
    nack(&mut chain, at + ms(1500), VIDEO, &numbers(0..60));
    run(&mut chain, at + ms(1500), at + ms(1600), &mut seen);
    assert!(seen.repaired.is_empty());
    assert_eq!(vec![VIDEO], seen.key_frames);

    // The key frame, sized for the new target, and one loss in it.
    write(&mut chain, at + ms(1600), ms(20), VIDEO, 150..155);
    nack(&mut chain, at + ms(1800), VIDEO, &[152]);
    run(&mut chain, at + ms(1800), at + ms(3800), &mut seen);
    assert_eq!(vec![(VIDEO, 152)], seen.repaired);
    assert_eq!(vec![VIDEO], seen.key_frames);
}

/// The same backlog at a target that did not fall to half is ordinary loss: it is repaired
/// within the target, oldest first, and no key frame is asked for. Three cases: a target that
/// was always low; a fall longer ago than two seconds; a fall just now, by a third.
#[test]
fn a_backlog_at_a_target_that_did_not_just_halve_is_repaired() {
    for case in ["steady", "fell long ago", "fell by a third"] {
        let mut chain = responder(NackResponderBuilder::new(), vec![video(true)]);
        let epoch = Instant::now();
        let mut seen = Seen::default();
        // Written and asked for inside the age bound.
        let at = epoch + ms(2100);
        let (first, fall) = match case {
            "steady" => (LOW, epoch + ms(50)),
            "fell long ago" => (HIGH, epoch + ms(50)),
            _ => (LOW * 1.5, at + ms(300)),
        };
        target(&mut chain, epoch, first);
        write(&mut chain, at, ms(2), VIDEO, 0..150);
        target(&mut chain, fall, LOW);
        nack(&mut chain, at + ms(310), VIDEO, &numbers(0..60));
        run(&mut chain, at + ms(310), at + ms(1300), &mut seen);
        assert!(seen.key_frames.is_empty(), "{case}: {:?}", seen.key_frames);
        assert_eq!(
            Some(&(VIDEO, 0)),
            seen.repaired.first(),
            "{case}: repaired {:?}",
            seen.repaired
        );
    }
}

/// A few repairs after a fall are not a backlog: 10 packets are 0.8 s of the new target,
/// under the bound, and are repaired.
#[test]
fn repairs_under_the_backlog_bound_are_made_after_the_target_halved() {
    let mut chain = responder(NackResponderBuilder::new(), vec![video(true)]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    let at = written_at_the_high_rate(&mut chain, epoch);
    target(&mut chain, at, LOW);
    nack(&mut chain, at + ms(10), VIDEO, &numbers(0..10));
    run(&mut chain, at + ms(10), at + ms(1000), &mut seen);
    assert!(seen.key_frames.is_empty());
    assert!(!seen.repaired.is_empty(), "the repairs are made");
}

/// With the backlog bound off the collapse's backlog is served in order, as before the rule.
#[test]
fn without_a_backlog_bound_the_backlog_is_repaired_in_order() {
    let mut chain = responder(
        NackResponderBuilder::new().with_repair_backlog_bound(None),
        vec![video(true)],
    );
    let epoch = Instant::now();
    let mut seen = Seen::default();
    let at = written_at_the_high_rate(&mut chain, epoch);
    target(&mut chain, at, LOW);
    nack(&mut chain, at + ms(10), VIDEO, &numbers(0..60));
    run(&mut chain, at + ms(10), at + ms(1000), &mut seen);
    assert!(seen.key_frames.is_empty());
    assert_eq!(Some(&(VIDEO, 0)), seen.repaired.first());
}

/// A give-up forgets the targets from before it: the answer (the key frame, written for the
/// target now) is not given up in its turn for the same fall, however large a backlog its own
/// losses make, and is repaired. Only when the target halves again is a backlog a collapse
/// again.
#[test]
fn after_a_give_up_only_another_halving_gives_the_stream_up_again() {
    let mut chain = responder(NackResponderBuilder::new(), vec![video(true)]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    let at = written_at_the_high_rate(&mut chain, epoch);
    // 2.5 Mbit/s to 400 kbit/s: 120 packets are 2.4 s of it.
    target(&mut chain, at, 400_000.0);
    nack(&mut chain, at + ms(10), VIDEO, &numbers(0..120));
    drain(&mut chain, &mut seen);
    assert_eq!(vec![VIDEO], seen.key_frames);
    assert!(seen.repaired.is_empty());
    let given_up = at + ms(10);

    // The answer is written and 120 of its packets are asked for: 2.4 s of the target again,
    // 400 ms after the fall from 2.5 Mbit/s. The target has not moved since the give-up.
    write(&mut chain, given_up + ms(100), ms(1), VIDEO, 150..350);
    nack(&mut chain, given_up + ms(410), VIDEO, &numbers(150..270));
    run(
        &mut chain,
        given_up + ms(410),
        given_up + ms(800),
        &mut seen,
    );
    assert_eq!(
        vec![VIDEO],
        seen.key_frames,
        "no second request for the same fall"
    );
    assert!(
        seen.repaired.contains(&(VIDEO, 150)),
        "the key frame's packets are repaired: {:?}",
        seen.repaired
    );

    // The target falls again, to a quarter: what still waits (and 60 more) is 4.9 s of it or
    // more, a collapse by the rule.
    target(&mut chain, given_up + ms(800), LOW);
    nack(&mut chain, given_up + ms(810), VIDEO, &numbers(270..330));
    drain(&mut chain, &mut seen);
    assert_eq!(vec![VIDEO, VIDEO], seen.key_frames);
}

/// The backlog counts every stream's requests, but only video is given up: audio requests
/// that wait stay and are served, and no key frame is asked of the audio stream.
#[test]
fn a_collapsed_backlog_gives_up_video_and_keeps_the_audio_requests() {
    let mut chain = responder(NackResponderBuilder::new(), vec![video(true), audio()]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    let at = written_at_the_high_rate(&mut chain, epoch);
    write(&mut chain, at, ms(1), AUDIO, 0..10);
    target(&mut chain, at + ms(20), LOW);
    // Ten audio packets: the first leave within the reserve, the rest wait.
    nack(&mut chain, at + ms(30), AUDIO, &numbers(0..10));
    drain(&mut chain, &mut seen);
    let at_once = seen.repaired.len();
    assert!(
        (1..10).contains(&at_once),
        "some audio repairs wait: {at_once} left at once"
    );
    nack(&mut chain, at + ms(30), VIDEO, &numbers(0..60));
    run(&mut chain, at + ms(30), at + ms(600), &mut seen);
    // The receiver asks again for what it still misses.
    let waiting: Vec<u16> = (0..10)
        .filter(|sequence_number| !seen.repaired.contains(&(AUDIO, *sequence_number)))
        .collect();
    nack(&mut chain, at + ms(600), AUDIO, &waiting);
    run(&mut chain, at + ms(600), at + ms(1900), &mut seen);
    assert_eq!(vec![VIDEO], seen.key_frames);
    seen.repaired.sort_unstable();
    assert_eq!(
        (0..10).map(|n| (AUDIO, n)).collect::<Vec<_>>(),
        seen.repaired,
        "every audio request is served, no video packet is"
    );
}

// ---------------------------------------------------------------------------------------
// What a give-up leaves behind
// ---------------------------------------------------------------------------------------

/// The retransmission reserve is released at the give-up, not a second later: the
/// retransmissions made before it repaired what is now given up, and nothing follows them.
/// The application reads the whole target for its key frame.
#[test]
fn giving_a_stream_up_releases_the_retransmission_reserve_at_once() {
    let mut chain = responder(NackResponderBuilder::new(), vec![video(true)]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    let at = written_at_the_high_rate(&mut chain, epoch);
    // Three repairs at the high target: made, and the reserve stands for them.
    nack(&mut chain, at + ms(10), VIDEO, &[140, 141, 142]);
    drain(&mut chain, &mut seen);
    assert_eq!(3, seen.repaired.len());
    assert!(
        seen.reserves.last().is_some_and(|reserve| *reserve > 0.0),
        "a reserve for the repairs: {:?}",
        seen.reserves
    );

    target(&mut chain, at + ms(20), LOW);
    let mut seen = Seen::default();
    nack(&mut chain, at + ms(30), VIDEO, &numbers(0..60));
    drain(&mut chain, &mut seen);
    assert_eq!(vec![VIDEO], seen.key_frames);
    assert_eq!(
        Some(&0.0),
        seen.reserves.last(),
        "released with the give-up, 20 ms after the last retransmission"
    );
    assert_eq!(
        Some(&LOW),
        seen.targets.last(),
        "the application reads the whole target"
    );
}

/// A probe cluster asked for right after a give-up is still filled: the buffer is empty, but
/// the header of the newest packet it held is kept for the padding. (Without it a chain
/// without a pacer sends no probe, the cluster goes unanswered and probing stops.)
#[test]
fn a_probe_requested_after_a_give_up_is_still_sent() {
    let mut chain = responder(unlimited(), vec![video(true)]);
    let epoch = Instant::now();
    let mut seen = Seen::default();
    write(&mut chain, epoch, ms(1), VIDEO, 0..20);
    let late = epoch + NACK_MAX_REPAIR_AGE + ms(100);
    nack(&mut chain, late, VIDEO, &[2]);
    drain(&mut chain, &mut seen);
    assert_eq!(vec![VIDEO], seen.key_frames);

    chain
        .handle_read(
            ProbeRequest {
                cluster: 7,
                bits_per_second: 600_000.0,
                octets: 3_000,
            }
            .into_packet(late + ms(1)),
        )
        .unwrap();
    drain(&mut chain, &mut seen);
    assert!(
        seen.padding.len() >= 10,
        "3000 octets of padding: {} packets",
        seen.padding.len()
    );
    assert!(seen.padding.iter().all(|cluster| *cluster == Some(7)));
}
