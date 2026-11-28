//! What the pacer and the NACK responder do with a stream that may not send
//! (`StreamsNotSending`: its negotiated direction is `recvonly` or `inactive`). RFC 8866
//! section 6.7.4: "No media is sent over an inactive media stream"; that includes its
//! retransmissions (RFC 4588) and the padding sent on its RTX stream. RTCP goes on.
//!
//! One media packet here is 1500 octets on the wire: 12 000 bits.

use bytes::Bytes;
use rtci_interceptor::{
    Attribute, AttributedPacket, Interceptor, NackResponderBuilder, PacerBuilder, Packet,
    ProbeRequest, RTCPFeedback, StreamInfo, StreamsNotSending, TaggedPacket,
};
use rtcp::transport_feedbacks::transport_layer_nack::{NackPair, TransportLayerNack};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

const VIDEO: u32 = 0x1234;
const RTX: u32 = 0x5678;
const OTHER: u32 = 0x9abc;
/// 100 kbit/s: a 12 000-bit packet every 120 ms.
const RATE: f64 = 100_000.0;

fn stream_info(ssrc: u32, ssrc_rtx: Option<u32>) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_rtx,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: ssrc_rtx.map(|_| 97),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, ssrc: u32, sequence_number: u16, payload: Vec<u8>) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3000,
                ssrc,
                ..Default::default()
            },
            payload: Bytes::from(payload),
        })),
    }
}

fn media(now: Instant, ssrc: u32, sequence_number: u16) -> TaggedPacket {
    rtp(now, ssrc, sequence_number, vec![0u8; 1488])
}

/// A retransmission on the RTX stream of the video packet `repaired`.
fn retransmission(now: Instant, sequence_number: u16, repaired: u16) -> TaggedPacket {
    let mut payload = repaired.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0u8; 1486]);
    let mut packet = rtp(now, RTX, sequence_number, payload);
    packet.message = packet.message.with(Attribute::Retransmission);
    packet
}

/// A padding-only packet on the RTX stream.
fn padding(now: Instant, sequence_number: u16) -> TaggedPacket {
    let mut packet = rtp(now, RTX, sequence_number, vec![]);
    if let Packet::Rtp(rtp) = &mut packet.message.packet {
        rtp.header.padding = true;
    }
    packet.message = packet.message.with(Attribute::Retransmission);
    packet
}

/// The RTP (SSRC, sequence number) that left.
fn left(interceptor: &mut impl Interceptor) -> Vec<(u32, u16)> {
    std::iter::from_fn(|| interceptor.poll_write())
        .filter_map(|packet| match packet.message.packet {
            Packet::Rtp(rtp) => Some((rtp.header.ssrc, rtp.header.sequence_number)),
            _ => None,
        })
        .collect()
}

/// The pacer holds media, a retransmission and padding of the stream when it is told the
/// stream may not send: all of it is dropped at that instant, and so is what is written of
/// the stream afterwards; another stream's queued media still leaves. Told the stream may
/// send again, what is written of it leaves.
#[test]
fn the_pacer_drops_what_it_holds_of_a_stream_that_may_not_send() {
    let start = Instant::now();
    let mut pacer = PacerBuilder::new().with_target_bitrate(RATE).build();
    pacer.bind_local_stream(&stream_info(VIDEO, Some(RTX)));
    pacer.bind_local_stream(&stream_info(OTHER, None));
    for seq in 0..10 {
        pacer.handle_write(media(start, VIDEO, seq)).unwrap();
    }
    pacer.handle_write(retransmission(start, 500, 3)).unwrap();
    pacer.handle_write(media(start, OTHER, 0)).unwrap();
    pacer.handle_write(padding(start, 501)).unwrap();
    let at_once = left(&mut pacer);
    assert!(at_once.len() <= 2, "{at_once:?}");
    assert!(pacer.queued() >= 10, "queued: {}", pacer.queued());

    pacer
        .handle_write(
            StreamsNotSending {
                ssrcs: vec![VIDEO, RTX],
            }
            .into_packet(start),
        )
        .unwrap();
    // Written after: a retransmission and padding of the stream, nothing leaves of them.
    pacer.handle_write(retransmission(start, 502, 4)).unwrap();
    pacer.handle_write(padding(start, 503)).unwrap();
    let mut after = left(&mut pacer);
    for ms in (0..3_000).step_by(10) {
        pacer
            .handle_timeout(start + Duration::from_millis(ms))
            .unwrap();
        after.extend(left(&mut pacer));
    }
    assert!(
        after.iter().all(|(ssrc, _)| *ssrc == OTHER),
        "only the other stream leaves: {after:?}"
    );
    assert!(
        at_once.iter().chain(&after).any(|(ssrc, _)| *ssrc == OTHER),
        "the other stream's packet left: {at_once:?} {after:?}"
    );
    assert_eq!(pacer.queued(), 0);
    assert!(
        pacer.not_sending_dropped() >= 12,
        "dropped: {}",
        pacer.not_sending_dropped()
    );

    // Sending again.
    let now = start + Duration::from_secs(3);
    pacer
        .handle_write(StreamsNotSending { ssrcs: vec![] }.into_packet(now))
        .unwrap();
    pacer.handle_write(media(now, VIDEO, 10)).unwrap();
    pacer.handle_write(retransmission(now, 504, 10)).unwrap();
    let mut again = left(&mut pacer);
    for ms in (0..1_000).step_by(10) {
        pacer
            .handle_timeout(now + Duration::from_millis(ms))
            .unwrap();
        again.extend(left(&mut pacer));
    }
    assert_eq!(again, vec![(VIDEO, 10), (RTX, 504)]);
}

fn nack(media_ssrc: u32, packet_id: u16) -> TaggedPacket {
    TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerNack {
            sender_ssrc: 1,
            media_ssrc,
            nacks: vec![NackPair {
                packet_id,
                lost_packets: 0,
            }],
        })])),
    }
}

/// The NACK responder answers no NACK for a stream that may not send and pads no probe
/// cluster on its RTX stream; what it sent of the stream before is forgotten, so a NACK for
/// it once the stream sends again is answered by nothing (a packet from before the direction
/// changed would be stale media).
#[test]
fn the_nack_responder_repairs_and_pads_nothing_of_a_stream_that_may_not_send() {
    let start = Instant::now();
    let make = || {
        let mut responder = NackResponderBuilder::new().build();
        responder.bind_local_stream(&stream_info(VIDEO, Some(RTX)));
        for seq in 0..5 {
            responder.handle_write(media(start, VIDEO, seq)).unwrap();
        }
        assert_eq!(left(&mut responder).len(), 5);
        responder
    };
    let at = start + Duration::from_millis(100);
    let nack_at = |mut packet: TaggedPacket| {
        packet.now = at;
        packet
    };
    let probe = || {
        ProbeRequest {
            cluster: 1,
            bits_per_second: 1_000_000.0,
            octets: 5_000,
        }
        .into_packet(at)
    };

    // Sending: the NACK is answered on the RTX stream, the probe padded on it.
    let mut responder = make();
    responder.handle_read(nack_at(nack(VIDEO, 2))).unwrap();
    responder.handle_timeout(at).unwrap();
    assert!(
        left(&mut responder).iter().any(|(ssrc, _)| *ssrc == RTX),
        "a sending stream is repaired"
    );
    responder.handle_read(probe()).unwrap();
    responder.handle_timeout(at).unwrap();
    assert!(
        left(&mut responder).iter().any(|(ssrc, _)| *ssrc == RTX),
        "a probe is padded on a sending stream's RTX"
    );

    // Not sending: neither.
    let mut responder = make();
    responder
        .handle_write(
            StreamsNotSending {
                ssrcs: vec![VIDEO, RTX],
            }
            .into_packet(start),
        )
        .unwrap();
    responder.handle_read(nack_at(nack(VIDEO, 2))).unwrap();
    responder.handle_read(probe()).unwrap();
    responder.handle_timeout(at).unwrap();
    assert_eq!(
        left(&mut responder),
        vec![],
        "nothing of a stream that may not send"
    );

    // Sending again: a packet from before is not sent again.
    responder
        .handle_write(StreamsNotSending { ssrcs: vec![] }.into_packet(at))
        .unwrap();
    responder.handle_read(nack_at(nack(VIDEO, 3))).unwrap();
    responder.handle_timeout(at).unwrap();
    assert_eq!(
        left(&mut responder),
        vec![],
        "a packet sent before the direction changed is not repaired"
    );
}
