//! Entry points for fuzz targets and benchmarks.
//!
//! Each function drives one encode or decode step over a raw byte slice, so a fuzzer or a
//! benchmark can reach the packet codec without establishing an association first. Gated behind
//! `cfg(fuzzing)` or the `bench` feature; not part of the supported API and not subject to the
//! crate's stability guarantees.
use bytes::Bytes;
use shared::error::Result;

use crate::chunk::Chunk;
use crate::chunk::ErrorCause;
use crate::chunk::chunk_abort::ChunkAbort;
use crate::chunk::chunk_cookie_ack::ChunkCookieAck;
use crate::chunk::chunk_cookie_echo::ChunkCookieEcho;
use crate::chunk::chunk_error::ChunkError;
use crate::chunk::chunk_forward_tsn::{ChunkForwardTsn, ChunkForwardTsnStream};
use crate::chunk::chunk_header::ChunkHeader;
use crate::chunk::chunk_heartbeat::ChunkHeartbeat;
use crate::chunk::chunk_heartbeat_ack::ChunkHeartbeatAck;
use crate::chunk::chunk_init::ChunkInit;
use crate::chunk::chunk_payload_data::ChunkPayloadData;
use crate::chunk::chunk_reconfig::ChunkReconfig;
use crate::chunk::chunk_selective_ack::ChunkSelectiveAck;
use crate::chunk::chunk_shutdown::ChunkShutdown;
use crate::chunk::chunk_shutdown_ack::ChunkShutdownAck;
use crate::chunk::chunk_shutdown_complete::ChunkShutdownComplete;
use crate::packet::{Packet, PartialDecode};
use crate::param::Param;
use crate::param::param_chunk_list::ParamChunkList;
use crate::param::param_forward_tsn_supported::ParamForwardTsnSupported;
use crate::param::param_header::ParamHeader;
use crate::param::param_heartbeat_info::ParamHeartbeatInfo;
use crate::param::param_outgoing_reset_request::ParamOutgoingResetRequest;
use crate::param::param_random::ParamRandom;
use crate::param::param_reconfig_response::ParamReconfigResponse;
use crate::param::param_requested_hmac_algorithm::ParamRequestedHmacAlgorithm;
use crate::param::param_state_cookie::ParamStateCookie;
use crate::param::param_supported_extensions::ParamSupportedExtensions;
use crate::param::param_uknown::ParamUnknown;

fn to_bytes(data: &[u8]) -> Bytes {
    Bytes::copy_from_slice(data)
}

pub fn packet_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = Packet::unmarshal(&raw)?;
    Ok(())
}

/// Differential/roundtrip helper: unmarshal a raw SCTP packet and marshal it
/// back to the wire. Exposed so fuzzers and benchmarks can exercise the
/// marshalling path (which is otherwise `pub(crate)`).
pub fn packet_marshal(data: &[u8]) -> Result<Vec<u8>> {
    let pkt = Packet::unmarshal(&to_bytes(data))?;
    Ok(pkt.marshal()?.to_vec())
}

/// Build the wire bytes of a representative DATA packet carrying `num_chunks`
/// payload-data chunks of `payload_len` bytes each. Used to seed marshalling
/// micro-benchmarks with a valid (correctly check-summed) packet.
#[doc(hidden)]
pub fn sample_data_packet(payload_len: usize, num_chunks: usize) -> Vec<u8> {
    use crate::chunk::chunk_payload_data::PayloadProtocolIdentifier;
    use crate::packet::CommonHeader;

    let chunks: Vec<Box<dyn Chunk>> = (0..num_chunks)
        .map(|i| {
            Box::new(ChunkPayloadData {
                beginning_fragment: true,
                ending_fragment: true,
                tsn: i as u32 + 1,
                stream_identifier: 0,
                stream_sequence_number: i as u16,
                payload_type: PayloadProtocolIdentifier::Binary,
                user_data: Bytes::from(vec![0x42u8; payload_len]),
                ..Default::default()
            }) as Box<dyn Chunk>
        })
        .collect();

    let pkt = Packet {
        common_header: CommonHeader {
            source_port: 5000,
            destination_port: 5000,
            verification_tag: 0x1234_5678,
        },
        chunks,
    };
    pkt.marshal().unwrap().to_vec()
}

/// Marshal a fixed, pre-parsed packet `iterations` times into a fresh buffer.
/// Isolated marshalling micro-benchmark surface for `perf`/`poop` (parsing is
/// done once, outside the timed loop).
#[doc(hidden)]
pub fn bench_packet_marshal(data: &[u8], iterations: u64) -> Result<usize> {
    use crate::packet::PACKET_HEADER_SIZE;
    use bytes::BytesMut;

    let pkt = Packet::unmarshal(&to_bytes(data))?;
    let mut last = 0;
    for _ in 0..iterations {
        let mut buf = BytesMut::with_capacity(data.len() + PACKET_HEADER_SIZE);
        last = pkt.marshal_to(&mut buf)?;
        std::hint::black_box(&buf);
    }
    Ok(last)
}

pub fn packet_partial_decode_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = PartialDecode::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_header_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeader::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_abort_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkAbort::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_cookie_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkCookieAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_cookie_echo_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkCookieEcho::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_error_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkError::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_forward_tsn_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkForwardTsn::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_forward_tsn_stream_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkForwardTsnStream::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_heartbeat_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeartbeat::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_heartbeat_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkHeartbeatAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_init_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkInit::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_payload_data_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkPayloadData::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_reconfig_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkReconfig::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_selective_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkSelectiveAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdown::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_ack_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdownAck::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_chunk_shutdown_complete_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ChunkShutdownComplete::unmarshal(&raw)?;
    Ok(())
}

pub fn chunk_error_cause_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ErrorCause::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_header_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamHeader::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_forward_tsn_supported_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamForwardTsnSupported::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_supported_extensions_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamSupportedExtensions::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_random_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamRandom::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_requested_hmac_algorithm_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamRequestedHmacAlgorithm::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_chunk_list_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamChunkList::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_state_cookie_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamStateCookie::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_heartbeat_info_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamHeartbeatInfo::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_outgoing_reset_request_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamOutgoingResetRequest::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_reconfig_response_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamReconfigResponse::unmarshal(&raw)?;
    Ok(())
}

pub fn param_param_unknown_unmarshal(data: &[u8]) -> Result<()> {
    let raw = to_bytes(data);
    let _ = ParamUnknown::unmarshal(&raw)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_data_packet_roundtrips() {
        // sample_data_packet builds a valid, check-summed packet; packet_marshal
        // unmarshals then re-marshals it, so the bytes must round-trip exactly.
        let pkt = sample_data_packet(1200, 2);
        assert_eq!(packet_marshal(&pkt).unwrap(), pkt);
        // exercise the perf-harness entry point as well.
        assert!(bench_packet_marshal(&pkt, 3).is_ok());
    }
}

/// Rewrites the CRC-32C field (bytes 8..12) of a raw SCTP packet so it verifies. Without this a
/// fuzzer almost never gets past the checksum to the chunk parsers.
pub fn fix_checksum(data: &[u8]) -> Vec<u8> {
    let mut packet = data.to_vec();
    if packet.len() >= 12 {
        packet[8..12].fill(0);
        let checksum = crc32c::crc32c(&packet);
        packet[8..12].copy_from_slice(&checksum.to_le_bytes());
    }
    packet
}

/// [`packet_unmarshal`] on a packet whose checksum has been made valid.
pub fn packet_unmarshal_fixed_checksum(data: &[u8]) -> Result<()> {
    packet_unmarshal(&fix_checksum(data))
}

/// Stateful target: drives a server endpoint, and the association it accepts, with a sequence of
/// datagrams. The input is split into datagrams by a 2-byte big-endian length prefix; each gets
/// a valid checksum. Every association event, timer and transmit is drained so the whole receive
/// path (INIT handling, DATA, SACK, FORWARD-TSN, RECONFIG, ...) is reachable. `start` is the
/// base instant (sans-I/O: the harness supplies the time).
pub fn endpoint_handle_datagrams(mut data: &[u8], start: std::time::Instant) {
    use crate::{DatagramEvent, Endpoint, EndpointConfig, ServerConfig};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    let local: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let remote: SocketAddr = "127.0.0.1:5001".parse().unwrap();
    let mut endpoint = Endpoint::new(
        local,
        shared::TransportProtocol::UDP,
        Arc::new(EndpointConfig::default()),
        Some(Arc::new(ServerConfig::default())),
    );
    let mut association = None;
    let mut step = 0u64;

    while data.len() >= 2 {
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        data = &data[2..];
        let len = len.min(data.len());
        let datagram = fix_checksum(&data[..len]);
        data = &data[len..];
        step += 1;
        let now = start + Duration::from_millis(step * 10);

        match endpoint.handle(now, remote, None, Bytes::from(datagram)) {
            Some((_, DatagramEvent::NewAssociation(a))) => association = Some(a),
            Some((_, DatagramEvent::AssociationEvent(event))) => {
                if let Some(a) = association.as_mut() {
                    a.handle_event(event);
                }
            }
            None => {}
        }
        if let Some(a) = association.as_mut() {
            a.handle_timeout(now);
            while a.poll().is_some() {}
            while a.poll_transmit(now).is_some() {}
        }
    }
}
