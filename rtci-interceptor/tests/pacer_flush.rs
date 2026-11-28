//! What the pacer does with its queue when the path's capacity collapses.
//!
//! By default (`PacerBacklog::Flush`) a queue that is long because the target fell to half or
//! less of what the queued media was written for is given up: the media is discarded
//! (`PacerDiscard`), the retransmissions waiting are dropped (`RetransmissionsLeft`), the NACK
//! responder is told to forget what was sent before (`PacerFlush`) and the application is
//! asked for a key frame. The source is not paused: its next frame, at the target it reads
//! now, is the key frame. A queue that is long at a steady target is paused and delivered, as
//! before, and so is every long queue with `PacerBacklog::Keep`.
//!
//! One media packet here is 1500 octets on the wire: 12 000 bits.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, LocalKeyFrameRequest, NackResponderBuilder,
    PacerBacklog, PacerBuilder, PacerDiscard, PacerFlush, PacerPause, Packet, RTCPFeedback,
    RetransmissionsLeft, StreamInfo, TaggedPacket,
};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

const VIDEO: u32 = 0x1234;
const RTX: u32 = 0x5678;
const HIGH: f64 = 1_200_000.0;
const LOW: f64 = 100_000.0;

fn stream_info() -> StreamInfo {
    StreamInfo {
        ssrc: VIDEO,
        ssrc_rtx: Some(RTX),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: Some(97),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

/// A packet of the frame `frame` of the video stream.
fn media(now: Instant, sequence_number: u16, frame: u32) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: frame * 3000,
                ssrc: VIDEO,
                ..Default::default()
            },
            payload: Bytes::from(vec![0u8; 1488]),
        })),
    }
}

/// A retransmission on the RTX stream of the video packet `repaired`.
fn retransmission(now: Instant, sequence_number: u16, repaired: u16) -> TaggedPacket {
    let mut payload = repaired.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 1486]);
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 97,
                sequence_number,
                ssrc: RTX,
                ..Default::default()
            },
            payload: Bytes::from(payload),
        }))
        .with(Attribute::Retransmission),
    }
}

/// The congestion controller's target, as it reaches the pacer on the read leg.
fn target(now: Instant, bits_per_second: f64) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![]))
            .with(Attribute::TargetBitrateChanged { bits_per_second }),
    }
}

fn pacer(backlog: PacerBacklog) -> impl Interceptor {
    let mut pacer = PacerBuilder::new()
        .with_target_bitrate(HIGH)
        .with_backlog(backlog)
        .build();
    pacer.bind_local_stream(&stream_info());
    pacer
}

/// What the pacer handed application-ward.
#[derive(Default, Debug)]
struct Reads {
    /// The targets announced: (as the application reads it, the controller's while paused).
    targets: Vec<(f64, Option<f64>)>,
    /// (stream, sequence numbers) of each discard.
    discards: Vec<(u32, Vec<u16>)>,
    /// The streams a key frame was asked of.
    key_frames: Vec<u32>,
    /// The reason each of those requests carries.
    key_frame_origins: Vec<(u32, Option<LocalKeyFrameRequest>)>,
    /// The streams of each flush notice.
    flushes: Vec<Vec<u32>>,
    /// Retransmissions dropped: (SSRC, sequence number repaired).
    dropped: Vec<(u32, u16)>,
}

fn reads(chain: &mut impl Interceptor, into: &mut Reads) {
    while let Some(read) = chain.poll_read() {
        for attribute in &read.message.attributes {
            if let Attribute::TargetBitrateChanged { bits_per_second } = attribute {
                into.targets.push((
                    *bits_per_second,
                    read.message
                        .custom::<PacerPause>()
                        .map(|pause| pause.target_bits_per_second),
                ));
            }
        }
        if let Some(discard) = read.message.custom::<PacerDiscard>() {
            into.discards
                .push((discard.ssrc, discard.sequence_numbers.clone()));
        }
        if let Some(flush) = read.message.custom::<PacerFlush>() {
            into.flushes.push(flush.ssrcs.clone());
        }
        if let Some(left) = read.message.custom::<RetransmissionsLeft>() {
            into.dropped.extend(left.dropped.iter().copied());
        }
        if read.message.has(&Attribute::DeliverToApplication)
            && let Packet::Rtcp(packets) = &read.message.packet
        {
            for packet in packets {
                if let Some(pli) = packet.as_any().downcast_ref::<PictureLossIndication>() {
                    into.key_frames.push(pli.media_ssrc);
                    into.key_frame_origins.push((
                        pli.media_ssrc,
                        read.message.custom::<LocalKeyFrameRequest>().copied(),
                    ));
                }
            }
        }
    }
}

/// Runs the pacer's timers up to `until`, a millisecond at a time; returns the sequence
/// numbers of the video packets and of the RTX packets that left.
fn run_until(chain: &mut impl Interceptor, until: Instant) -> (Vec<u16>, Vec<u16>) {
    let mut video = Vec::new();
    let mut rtx = Vec::new();
    let mut collect = |chain: &mut dyn FnMut() -> Option<TaggedPacket>| {
        while let Some(packet) = chain() {
            if let Packet::Rtp(rtp) = &packet.message.packet {
                if rtp.header.ssrc == VIDEO {
                    video.push(rtp.header.sequence_number);
                } else {
                    rtx.push(rtp.header.sequence_number);
                }
            }
        }
    };
    collect(&mut || chain.poll_write());
    let mut last: Option<Instant> = None;
    while let Some(deadline) = chain.poll_timeout() {
        // Never the same instant twice: a deadline that does not advance cannot spin here.
        let now = last.map_or(deadline, |last| {
            deadline.max(last + Duration::from_millis(1))
        });
        if now > until {
            break;
        }
        chain.handle_timeout(now).unwrap();
        collect(&mut || chain.poll_write());
        last = Some(now);
    }
    (video, rtx)
}

/// Forty packets (ten frames) written at 1.2 Mbit/s and two retransmissions. Returns the
/// sequence numbers of the video still queued once what the budget allowed has left.
fn backlog_at_the_high_rate(chain: &mut impl Interceptor, epoch: Instant) -> Vec<u16> {
    chain.handle_read(target(epoch, HIGH)).unwrap();
    for sequence_number in 0..40u16 {
        chain
            .handle_write(media(
                epoch,
                sequence_number,
                u32::from(sequence_number / 4),
            ))
            .unwrap();
    }
    chain.handle_write(retransmission(epoch, 900, 500)).unwrap();
    chain.handle_write(retransmission(epoch, 901, 501)).unwrap();
    let (left, _) = run_until(chain, epoch);
    (0..40u16).filter(|seq| !left.contains(seq)).collect()
}

/// The target falls from 1.2 Mbit/s to 100 kbit/s with 0.4 s of video queued: at the new
/// target the queue would take almost 5 s. It is flushed, not waited out: every queued video
/// packet is discarded and named, the queued retransmissions are dropped, the responder is
/// told to forget the stream, one key frame is asked for, and the source is NOT paused (the
/// target it reads is the new one, not zero). The key frame it then writes leaves.
#[test]
fn a_collapse_of_the_target_flushes_the_queue_and_asks_for_a_key_frame() {
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    let mut seen = Reads::default();
    let queued = backlog_at_the_high_rate(&mut chain, epoch);
    assert!(queued.len() >= 36, "most of it waits: {queued:?}");
    reads(&mut chain, &mut seen);
    assert!(seen.flushes.is_empty() && seen.discards.is_empty());

    let fall = epoch + ms(10);
    chain.handle_read(target(fall, LOW)).unwrap();
    chain.handle_timeout(fall).unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);

    assert_eq!(vec![vec![VIDEO]], seen.flushes, "{seen:?}");
    let discarded: Vec<u16> = seen
        .discards
        .iter()
        .filter(|(ssrc, _)| *ssrc == VIDEO)
        .flat_map(|(_, sequence_numbers)| sequence_numbers.clone())
        .collect();
    // What had left by the fall is not discarded; everything else is.
    assert_eq!(
        queued, discarded,
        "the queued video is discarded, oldest first"
    );
    assert!(
        discarded.len() >= 35,
        "the queued video is discarded: {discarded:?}"
    );
    assert_eq!(vec![VIDEO], seen.key_frames, "one key frame asked for");
    assert_eq!(
        vec![(VIDEO, Some(LocalKeyFrameRequest::PacerFlush))],
        seen.key_frame_origins,
        "the request says it is the pacer's flush"
    );
    assert!(
        seen.dropped.contains(&(RTX, 501)),
        "the retransmissions waiting are dropped: {:?}",
        seen.dropped
    );
    assert_eq!(
        vec![(LOW, None)],
        seen.targets,
        "the source reads the new target, not a pause"
    );

    // Nothing of the old queue leaves any more.
    let (video, rtx) = run_until(&mut chain, epoch + ms(3_000));
    assert!(video.is_empty() && rtx.is_empty(), "{video:?} {rtx:?}");

    // The key frame the application writes in answer (two packets) leaves.
    let answer = epoch + ms(3_000);
    chain.handle_write(media(answer, 40, 100)).unwrap();
    chain.handle_write(media(answer, 41, 100)).unwrap();
    let (video, _) = run_until(&mut chain, epoch + ms(4_000));
    assert_eq!(vec![40, 41], video);
    let mut after = Reads::default();
    reads(&mut chain, &mut after);
    assert!(
        after.discards.is_empty() && after.flushes.is_empty() && after.key_frames.is_empty(),
        "{after:?}"
    );
}

/// The key frame written in answer to a flush is larger than a second of the fallen target
/// (twelve packets at 100 kbit/s: 1.44 s). It was written at that target: the queue it fills
/// is not a collapse. The source is paused while it leaves, nothing is discarded, no second
/// key frame is asked for, and every packet of it goes out.
#[test]
fn the_key_frame_that_answers_a_flush_is_delivered_not_flushed() {
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    backlog_at_the_high_rate(&mut chain, epoch);
    let fall = epoch + ms(10);
    chain.handle_read(target(fall, LOW)).unwrap();
    chain.handle_timeout(fall).unwrap();
    let mut flushed = Reads::default();
    reads(&mut chain, &mut flushed);
    assert_eq!(1, flushed.flushes.len());

    let answer = epoch + ms(50);
    for sequence_number in 40..52u16 {
        chain
            .handle_write(media(answer, sequence_number, 100))
            .unwrap();
    }
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert_eq!(
        vec![(0.0, Some(LOW))],
        seen.targets,
        "paused while the key frame leaves"
    );
    let (video, _) = run_until(&mut chain, epoch + ms(4_000));
    assert_eq!((40..52u16).collect::<Vec<_>>(), video, "all of it left");
    reads(&mut chain, &mut seen);
    assert!(
        seen.discards.is_empty() && seen.flushes.is_empty() && seen.key_frames.is_empty(),
        "{seen:?}"
    );
    assert_eq!(Some(&(LOW, None)), seen.targets.last(), "the pause ended");
}

/// A queue that is long at a steady target (a source above it), and one that is long after
/// the target fell by less than half, is paused and delivered, as before: no flush.
#[test]
fn a_long_queue_without_a_collapse_is_paused_not_flushed() {
    for fallen in [HIGH, 0.7 * HIGH] {
        let epoch = Instant::now();
        let mut chain = pacer(PacerBacklog::Flush);
        chain.handle_read(target(epoch, HIGH)).unwrap();
        // 0.9 s of the high target: under the pause mark there.
        for sequence_number in 0..90u16 {
            chain
                .handle_write(media(epoch, sequence_number, u32::from(sequence_number)))
                .unwrap();
        }
        chain.handle_read(target(epoch + ms(1), fallen)).unwrap();
        // More of it, past a second of either target.
        for sequence_number in 90..130u16 {
            chain
                .handle_write(media(
                    epoch + ms(1),
                    sequence_number,
                    u32::from(sequence_number),
                ))
                .unwrap();
        }
        let mut seen = Reads::default();
        reads(&mut chain, &mut seen);
        assert!(
            seen.targets.contains(&(0.0, Some(fallen))),
            "paused at {fallen}: {seen:?}"
        );
        assert!(
            seen.flushes.is_empty() && seen.discards.is_empty() && seen.key_frames.is_empty(),
            "at {fallen}: {seen:?}"
        );
        let (video, _) = run_until(&mut chain, epoch + ms(2_500));
        assert_eq!(130, video.len(), "everything written before the pause left");
    }
}

/// The target falls in steps. At the first (to 0.7 of what the queue was written for) the
/// queue is long but the target has not halved: the source is paused. The target goes on
/// falling during the pause; when it reaches half, the queue is flushed and the pause ends
/// with it: the source reads the target again and is asked for a key frame.
#[test]
fn a_target_that_halves_during_a_pause_flushes_the_queue_and_ends_the_pause() {
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    chain.handle_read(target(epoch, HIGH)).unwrap();
    for sequence_number in 0..90u16 {
        chain
            .handle_write(media(epoch, sequence_number, u32::from(sequence_number)))
            .unwrap();
    }
    let (left, _) = run_until(&mut chain, epoch);
    reads(&mut chain, &mut Reads::default());
    chain
        .handle_read(target(epoch + ms(1), 0.7 * HIGH))
        .unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert_eq!(vec![(0.0, Some(0.7 * HIGH))], seen.targets, "paused");
    assert!(seen.flushes.is_empty() && seen.discards.is_empty());

    chain
        .handle_read(target(epoch + ms(2), 0.4 * HIGH))
        .unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert_eq!(vec![vec![VIDEO]], seen.flushes, "{seen:?}");
    assert_eq!(vec![VIDEO], seen.key_frames);
    let discarded: Vec<u16> = seen
        .discards
        .iter()
        .flat_map(|(_, sequence_numbers)| sequence_numbers.clone())
        .collect();
    assert_eq!(90 - left.len(), discarded.len(), "the whole queue went");
    assert_eq!(
        vec![(0.4 * HIGH, None)],
        seen.targets,
        "the pause ended with the queue: the source reads the target"
    );
    let (video, _) = run_until(&mut chain, epoch + ms(2_000));
    assert!(video.is_empty(), "{video:?}");
}

/// Audio is not part of a flush. A call with a voice stream beside the video: at the
/// collapse the voice packet written with the backlog still leaves at once, the flush names
/// the video stream only, no key frame is asked of the audio stream, and the voice packets
/// written after it leave as they are written.
#[test]
fn a_flush_leaves_the_audio_stream_alone() {
    const AUDIO: u32 = 0x9abc;
    let voice = |now: Instant, sequence_number: u16| TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 111,
                sequence_number,
                timestamp: u32::from(sequence_number) * 960,
                ssrc: AUDIO,
                ..Default::default()
            },
            payload: Bytes::from(vec![0u8; 160]),
        })),
    };
    let audio_left = |chain: &mut dyn Interceptor| -> Vec<u16> {
        let mut left = Vec::new();
        while let Some(packet) = chain.poll_write() {
            if let Packet::Rtp(rtp) = &packet.message.packet
                && rtp.header.ssrc == AUDIO
            {
                left.push(rtp.header.sequence_number);
            }
        }
        left
    };
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    chain.bind_local_stream(&StreamInfo {
        ssrc: AUDIO,
        clock_rate: 48000,
        mime_type: "audio/opus".to_string(),
        payload_type: 111,
        ..Default::default()
    });
    backlog_at_the_high_rate(&mut chain, epoch);
    chain.handle_write(voice(epoch + ms(5), 1)).unwrap();
    assert_eq!(vec![1], audio_left(&mut chain), "behind a video backlog");
    let fall = epoch + ms(10);
    chain.handle_read(target(fall, LOW)).unwrap();
    chain.handle_timeout(fall).unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert_eq!(vec![vec![VIDEO]], seen.flushes, "{seen:?}");
    assert_eq!(vec![VIDEO], seen.key_frames, "{seen:?}");
    assert!(
        seen.discards.iter().all(|(ssrc, _)| *ssrc == VIDEO),
        "{seen:?}"
    );
    for (index, sequence_number) in (2..6u16).enumerate() {
        let now = fall + ms(20 * (index as u64 + 1));
        chain.handle_write(voice(now, sequence_number)).unwrap();
        assert_eq!(vec![sequence_number], audio_left(&mut chain));
    }
    let mut after = Reads::default();
    reads(&mut chain, &mut after);
    assert!(
        after.flushes.is_empty() && after.key_frames.is_empty() && after.discards.is_empty(),
        "{after:?}"
    );
}

/// A video stream with nothing queued at a collapse has its key frame asked for too (its
/// repairs are given up with the rest), with no `PacerDiscard` before the request: the
/// request carries `LocalKeyFrameRequest::PacerFlush` like the one of the stream whose media
/// was discarded, so the application can tell both from a receiver's PLI.
#[test]
fn every_request_of_a_flush_says_it_is_the_flushs() {
    const IDLE: u32 = 0x4321;
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    chain.bind_local_stream(&StreamInfo {
        ssrc: IDLE,
        ..stream_info()
    });
    backlog_at_the_high_rate(&mut chain, epoch);
    reads(&mut chain, &mut Reads::default());
    let fall = epoch + ms(10);
    chain.handle_read(target(fall, LOW)).unwrap();
    chain.handle_timeout(fall).unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert_eq!(1, seen.flushes.len(), "{seen:?}");
    assert!(
        seen.discards.iter().all(|(ssrc, _)| *ssrc == VIDEO),
        "nothing of the idle stream was queued: {seen:?}"
    );
    assert_eq!(
        vec![
            (VIDEO, Some(LocalKeyFrameRequest::PacerFlush)),
            (IDLE, Some(LocalKeyFrameRequest::PacerFlush)),
        ],
        seen.key_frame_origins,
        "{seen:?}"
    );
}

/// Ten retransmissions written at `at`, of packets sent before; what the pacer told the
/// application side, and the RTX sequence numbers that left within two seconds.
fn ten_repairs(chain: &mut impl Interceptor, at: Instant) -> (Reads, Vec<u16>) {
    for index in 0..10u16 {
        chain
            .handle_write(retransmission(at, 900 + index, 500 + index))
            .unwrap();
    }
    let mut seen = Reads::default();
    reads(chain, &mut seen);
    let (_, rtx) = run_until(chain, at + ms(2_000));
    reads(chain, &mut seen);
    (seen, rtx)
}

/// The repairs of what a collapse left behind are a backlog too. The target falls from
/// 1.2 Mbit/s to 100 kbit/s with nothing queued (the source followed), and half a second
/// later the receiver's NACKs arrive (behind a deep queue on the path they come a second
/// late): ten retransmissions, 1.2 s at the new target, of packets written for the old one.
/// They are flushed like queued media: dropped, the responder told to forget the stream, a
/// key frame asked for, and no pause.
#[test]
fn repairs_queued_within_the_queue_time_bound_of_a_collapse_are_flushed() {
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    chain.handle_read(target(epoch, HIGH)).unwrap();
    chain.handle_read(target(epoch + ms(10), LOW)).unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert!(
        seen.flushes.is_empty() && seen.key_frames.is_empty(),
        "nothing queued, nothing flushed: {seen:?}"
    );
    let (seen, rtx) = ten_repairs(&mut chain, epoch + ms(500));
    assert_eq!(vec![vec![VIDEO]], seen.flushes, "{seen:?}");
    assert_eq!(vec![VIDEO], seen.key_frames, "{seen:?}");
    assert!(
        seen.targets.iter().all(|(read, _)| *read != 0.0),
        "the source is not paused: {seen:?}"
    );
    assert!(
        seen.dropped.len() >= 8 && seen.dropped.len() + rtx.len() == 10,
        "the repairs waiting were dropped: {seen:?}, left {rtx:?}"
    );
}

/// The same repairs longer after the fall than the queue time bound (2 s) are a long queue
/// at a steady target: the source is paused and they are delivered.
#[test]
fn repairs_queued_later_than_the_queue_time_bound_after_a_fall_are_paused_and_delivered() {
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Flush);
    chain.handle_read(target(epoch, HIGH)).unwrap();
    chain.handle_read(target(epoch + ms(10), LOW)).unwrap();
    reads(&mut chain, &mut Reads::default());
    let (seen, rtx) = ten_repairs(&mut chain, epoch + ms(2_100));
    assert!(
        seen.flushes.is_empty() && seen.key_frames.is_empty() && seen.dropped.is_empty(),
        "{seen:?}"
    );
    assert!(
        seen.targets.contains(&(0.0, Some(LOW))),
        "the source is paused: {seen:?}"
    );
    assert_eq!(10, rtx.len(), "all of them left: {rtx:?}");
}

/// With `PacerBacklog::Keep` the collapse of the first test pauses the source and keeps the
/// queue: nothing is discarded, and all of it leaves in order.
#[test]
fn with_keep_a_collapse_pauses_the_source_and_delivers_the_queue() {
    let epoch = Instant::now();
    let mut chain = pacer(PacerBacklog::Keep);
    let queued = backlog_at_the_high_rate(&mut chain, epoch);
    reads(&mut chain, &mut Reads::default());
    let fall = epoch + ms(10);
    chain.handle_read(target(fall, LOW)).unwrap();
    chain.handle_timeout(fall).unwrap();
    let mut seen = Reads::default();
    reads(&mut chain, &mut seen);
    assert_eq!(vec![(0.0, Some(LOW))], seen.targets, "paused: {seen:?}");
    assert!(
        seen.flushes.is_empty() && seen.discards.is_empty() && seen.key_frames.is_empty(),
        "{seen:?}"
    );
    let (video, rtx) = run_until(&mut chain, epoch + ms(10_000));
    let mut delivered = video.clone();
    delivered.sort_unstable();
    assert!(
        queued.iter().all(|seq| delivered.contains(seq)),
        "the queue is delivered: {video:?}"
    );
    assert!(
        rtx.contains(&901),
        "and its retransmissions: {rtx:?} {video:?}"
    );
}

/// The NACK responder forgets what was sent before a flush: a NACK for a packet of before is
/// answered by nothing, one for a packet written after it is answered.
#[test]
fn after_a_flush_the_responder_repairs_only_what_was_written_since() {
    let epoch = Instant::now();
    let mut responder = NackResponderBuilder::new().build();
    responder.bind_local_stream(&stream_info());
    for sequence_number in 1..=5u16 {
        responder
            .handle_write(media(epoch, sequence_number, 1))
            .unwrap();
    }
    while responder.poll_write().is_some() {}

    let nack = |now: Instant, sequence_numbers: &[u16]| TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc: VIDEO,
            nacks: sequence_numbers
                .iter()
                .map(|sequence_number| NackPair {
                    packet_id: *sequence_number,
                    lost_packets: 0,
                })
                .collect(),
        })])),
    };
    let repaired = |responder: &mut rtci_interceptor::NackResponderInterceptor, now: Instant| {
        responder.handle_timeout(now).unwrap();
        let mut repaired = Vec::new();
        while let Some(packet) = responder.poll_write() {
            if let Packet::Rtp(rtp) = &packet.message.packet
                && rtp.header.ssrc == RTX
                && let Some(osn) = rtp.payload.get(..2)
            {
                repaired.push(u16::from_be_bytes([osn[0], osn[1]]));
            }
        }
        repaired
    };

    // Before the flush a NACK is answered.
    let first = epoch + ms(100);
    responder.handle_read(nack(first, &[2])).unwrap();
    while responder.poll_read().is_some() {}
    assert_eq!(vec![2], repaired(&mut responder, first));

    let flush = epoch + ms(200);
    responder
        .handle_read(TaggedPacket {
            now: flush,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
                PacerFlush { ssrcs: vec![VIDEO] },
            ))),
        })
        .unwrap();
    while responder.poll_read().is_some() {}
    responder.handle_write(media(flush, 6, 2)).unwrap();
    while responder.poll_write().is_some() {}

    let later = epoch + ms(400);
    responder.handle_read(nack(later, &[3, 4, 6])).unwrap();
    while responder.poll_read().is_some() {}
    assert_eq!(
        vec![6],
        repaired(&mut responder, later),
        "only the packet written after the flush is repaired"
    );
}
