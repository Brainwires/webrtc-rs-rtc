//! Entry points for stateful fuzz targets.
//!
//! [`depacketize_sequence`] feeds one depacketizer a sequence of fuzzed payloads, so the state a
//! depacketizer keeps between packets (H.264 FU-A reassembly, AV1's fragment carry-over) builds
//! up the way it does on a real stream. No clock, no randomness. Gated behind `cfg(fuzzing)`;
//! not part of the supported API.
use bytes::Bytes;

use crate::codec::av1::Av1Depacketizer;
use crate::codec::h264::H264Packet;
use crate::codec::h265::H265Packet;
use crate::codec::opus::OpusPacket;
use crate::codec::vp8::Vp8Packet;
use crate::codec::vp9::Vp9Packet;
use crate::packetizer::Depacketizer;

/// The depacketizer the first input byte selects.
fn depacketizer(selector: u8) -> Box<dyn Depacketizer> {
    match selector % 8 {
        0 => Box::new(H264Packet::default()),
        1 => {
            let mut packet = H264Packet::default();
            packet.is_avc = true;
            Box::new(packet)
        }
        2 => Box::new(H265Packet::default()),
        3 => {
            let mut packet = H265Packet::default();
            packet.with_donl(true);
            Box::new(packet)
        }
        4 => Box::new(Vp8Packet::default()),
        5 => Box::new(Vp9Packet::default()),
        6 => Box::new(Av1Depacketizer::new()),
        _ => Box::new(OpusPacket),
    }
}

/// Stateful target: one depacketizer fed fuzzed payloads in sequence.
///
/// The first byte picks the codec: H.264 (Annex B or AVC output), H.265 (with or without DONL),
/// VP8, VP9, AV1 or Opus. Each payload after it is a flags byte (bit 0 is the RTP marker), a
/// two-byte length and the payload. Every payload goes through `is_partition_head`,
/// `depacketize` and `is_partition_tail` on the same depacketizer.
pub fn depacketize_sequence(mut data: &[u8]) {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let mut depacketizer = depacketizer(selector);

    let mut packets = 0;
    while data.len() >= 3 {
        let marker = data[0] & 0x01 != 0;
        let len = usize::from(u16::from_be_bytes([data[1], data[2]])).min(data.len() - 3);
        let payload = Bytes::copy_from_slice(&data[3..3 + len]);
        data = &data[3 + len..];
        packets += 1;
        if packets > 1024 {
            break;
        }

        let _ = depacketizer.is_partition_head(&payload);
        let _ = depacketizer.depacketize(&payload);
        let _ = depacketizer.is_partition_tail(marker, &payload);
    }
}
