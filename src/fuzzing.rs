//! Entry points for stateful fuzz targets.
//!
//! [`data_channel_handle_dcep`] drives the peer connection's data-channel handler — the layer
//! that turns SCTP messages into channels — with fuzzed SCTP user messages: DCEP
//! `DATA_CHANNEL_OPEN` on new and already-used stream ids, ACKs, user data, and the SCTP events
//! that close streams and report buffered amounts, interleaved with locally created channels and
//! the SCTP connected procedure that assigns their stream ids. No clock beyond `start` plus
//! input-chosen offsets, no randomness. Gated behind `cfg(fuzzing)`; not part of the supported
//! API.
use std::time::{Duration, Instant};

use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message as DcepMessage;
use datachannel::message::message_channel_ack::DataChannelAck;
use datachannel::message::message_channel_open::{ChannelType, DataChannelOpen};
use sansio::Protocol;
use sctp::PayloadProtocolIdentifier;
use shared::TransportContext;
use shared::marshal::Marshal;

use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::registry::DataChannelRegistry;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::statistics::accumulator::RTCStatsAccumulator;

const ASSOCIATION: usize = 1;

fn byte(arg: &[u8], i: usize) -> u8 {
    arg.get(i).copied().unwrap_or(0)
}

/// Splits the next op argument off `data`: a one-byte length, then that many bytes.
fn take_arg<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let len = usize::from(len).min(rest.len());
    let (arg, rest) = rest.split_at(len);
    *data = rest;
    arg
}

fn ppi(selector: u8) -> PayloadProtocolIdentifier {
    match selector % 7 {
        0 => PayloadProtocolIdentifier::Dcep,
        1 => PayloadProtocolIdentifier::String,
        2 => PayloadProtocolIdentifier::Binary,
        3 => PayloadProtocolIdentifier::StringEmpty,
        4 => PayloadProtocolIdentifier::BinaryEmpty,
        _ => PayloadProtocolIdentifier::from(u32::from(selector)),
    }
}

fn channel_type(selector: u8) -> ChannelType {
    match selector % 6 {
        0 => ChannelType::Reliable,
        1 => ChannelType::ReliableUnordered,
        2 => ChannelType::PartialReliableRexmit,
        3 => ChannelType::PartialReliableRexmitUnordered,
        4 => ChannelType::PartialReliableTimed,
        _ => ChannelType::PartialReliableTimedUnordered,
    }
}

struct Harness {
    ctx: DataChannelHandlerContext,
    channels: DataChannelRegistry,
    stats: RTCStatsAccumulator,
    dcep_timeout: Option<Duration>,
    role: RTCDtlsRole,
    max_channels: Option<u16>,
    now: Instant,
}

impl Harness {
    fn with_handler(&mut self, f: impl FnOnce(&mut DataChannelHandler<'_>)) {
        let mut handler = DataChannelHandler::new(
            &mut self.ctx,
            &mut self.channels,
            &mut self.stats,
            self.dcep_timeout,
            self.role,
            self.max_channels,
        );
        f(&mut handler);
        while handler.poll_read().is_some() {}
        while handler.poll_write().is_some() {}
        while handler.poll_event().is_some() {}
    }

    /// A stream id: one a channel already uses, or a fuzzed one.
    fn stream_id(&self, selector: u8, raw: u16) -> u16 {
        let used: Vec<u16> = self.channels.values().filter_map(|c| c.stream_id).collect();
        if selector & 0x80 == 0 && !used.is_empty() {
            used[usize::from(selector) % used.len()]
        } else {
            raw
        }
    }

    fn sctp_message(&mut self, stream_id: u16, ppi: PayloadProtocolIdentifier, payload: BytesMut) {
        let now = self.now;
        self.with_handler(|handler| {
            let _ = handler.handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                    association_handle: ASSOCIATION,
                    stream_id,
                    ppi,
                    payload,
                    negotiated: false,
                })),
            });
        });
    }

    fn event(&mut self, event: RTCEventInternal) {
        let now = self.now;
        self.with_handler(|handler| {
            let _ = handler.handle_event(TaggedRTCEventInternal { now, event });
        });
    }

    /// A channel created by the application, in-band or negotiated out of band.
    fn create_channel(&mut self, arg: &[u8]) {
        let flags = byte(arg, 0);
        let negotiated =
            (flags & 0x01 != 0).then(|| u16::from_be_bytes([byte(arg, 1), byte(arg, 2)]));
        if negotiated.is_some_and(|id| self.channels.stream_id_in_use(&id)) {
            return;
        }
        let params = DataChannelParameters {
            label: String::from_utf8_lossy(arg.get(4..).unwrap_or(&[])).into_owned(),
            protocol: String::new(),
            ordered: flags & 0x02 == 0,
            max_packet_life_time: (flags & 0x04 != 0).then_some(u16::from(byte(arg, 3))),
            max_retransmits: (flags & 0x08 != 0).then_some(u16::from(byte(arg, 3))),
            negotiated,
        };
        self.channels.insert(RTCDataChannelInternal::new(params));
    }
}

/// Stateful target: the peer connection's data-channel handler fed fuzzed SCTP messages.
///
/// The first byte picks the DTLS role (which sets stream-id parity), the negotiated stream
/// limit and the DCEP handshake timeout. The rest is a sequence of ops, each an op byte followed
/// by a length-prefixed argument:
///
/// - a raw SCTP user message (stream id, PPI and payload from the input);
/// - a well-formed `DATA_CHANNEL_OPEN` with fuzzed type, priority, reliability, label and
///   protocol, or a `DATA_CHANNEL_ACK`, on a stream already in use or a new one;
/// - a channel created by the application, then the SCTP connected procedure;
/// - the application sending on a channel; stream reset, buffer and close events; time.
pub fn data_channel_handle_dcep(mut data: &[u8], start: Instant) {
    let Some((&config, rest)) = data.split_first() else {
        return;
    };
    data = rest;
    let mut h = Harness {
        ctx: DataChannelHandlerContext::new(start),
        channels: DataChannelRegistry::new(),
        stats: RTCStatsAccumulator::new(),
        dcep_timeout: (config & 0x02 != 0).then_some(Duration::from_secs(1)),
        role: match config & 0x0c {
            0x00 => RTCDtlsRole::Client,
            0x04 => RTCDtlsRole::Server,
            0x08 => RTCDtlsRole::Auto,
            _ => RTCDtlsRole::Unspecified,
        },
        max_channels: match config >> 4 {
            0 => None,
            n => Some(u16::from(n) * 2),
        },
        now: start,
    };

    let mut ops = 0;
    while let Some((&op, rest)) = data.split_first() {
        data = rest;
        ops += 1;
        if ops > 256 {
            break;
        }
        let arg = take_arg(&mut data);
        match op % 12 {
            0 => {
                let stream_id = h.stream_id(
                    byte(arg, 0),
                    u16::from_be_bytes([byte(arg, 1), byte(arg, 2)]),
                );
                let payload = BytesMut::from(arg.get(4..).unwrap_or(&[]));
                h.sctp_message(stream_id, ppi(byte(arg, 3)), payload);
            }
            1 => {
                let stream_id = h.stream_id(
                    byte(arg, 0),
                    u16::from_be_bytes([byte(arg, 1), byte(arg, 2)]),
                );
                let split = usize::from(byte(arg, 9)).min(arg.len().saturating_sub(10));
                let text = arg.get(10..).unwrap_or(&[]);
                let open = DcepMessage::DataChannelOpen(DataChannelOpen {
                    channel_type: channel_type(byte(arg, 3)),
                    priority: u16::from_be_bytes([byte(arg, 4), byte(arg, 5)]),
                    reliability_parameter: u32::from_be_bytes([
                        0,
                        byte(arg, 6),
                        byte(arg, 7),
                        byte(arg, 8),
                    ]),
                    label: text[..split.min(text.len())].to_vec(),
                    protocol: text[split.min(text.len())..].to_vec(),
                });
                if let Ok(payload) = open.marshal() {
                    h.sctp_message(stream_id, PayloadProtocolIdentifier::Dcep, payload);
                }
            }
            2 => {
                let stream_id = h.stream_id(
                    byte(arg, 0),
                    u16::from_be_bytes([byte(arg, 1), byte(arg, 2)]),
                );
                if let Ok(payload) = DcepMessage::DataChannelAck(DataChannelAck {}).marshal() {
                    h.sctp_message(stream_id, PayloadProtocolIdentifier::Dcep, payload);
                }
            }
            3 => h.create_channel(arg),
            4 => h.event(RTCEventInternal::SCTPHandshakeComplete(ASSOCIATION)),
            5 => {
                let ids: Vec<usize> = h.channels.values().map(|c| c.id).collect();
                let id = if ids.is_empty() {
                    usize::from(byte(arg, 0))
                } else {
                    ids[usize::from(byte(arg, 0)) % ids.len()]
                };
                let now = h.now;
                let message = RTCDataChannelMessage {
                    is_string: byte(arg, 1) & 0x01 != 0,
                    data: BytesMut::from(arg.get(2..).unwrap_or(&[])),
                };
                h.with_handler(|handler| {
                    let _ = handler.handle_write(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                            ApplicationMessage {
                                data_channel_id: id,
                                data_channel_event: DataChannelEvent::Message(message),
                            },
                        )),
                    });
                });
            }
            6 => {
                let stream_id = h.stream_id(byte(arg, 0), u16::from(byte(arg, 1)));
                h.event(RTCEventInternal::SCTPStreamClosed(ASSOCIATION, stream_id));
            }
            7 => {
                let stream_id = h.stream_id(byte(arg, 0), u16::from(byte(arg, 1)));
                let n = usize::from(u16::from_be_bytes([byte(arg, 2), byte(arg, 3)]));
                h.event(RTCEventInternal::SCTPBufferReleased(
                    ASSOCIATION,
                    stream_id,
                    n,
                ));
            }
            8 => {
                let stream_id = h.stream_id(byte(arg, 0), u16::from(byte(arg, 1)));
                h.event(if byte(arg, 2) & 0x01 != 0 {
                    RTCEventInternal::SCTPBufferedAmountHigh(ASSOCIATION, stream_id)
                } else {
                    RTCEventInternal::SCTPBufferedAmountLow(ASSOCIATION, stream_id)
                });
            }
            9 => {
                h.now += Duration::from_millis(u64::from(byte(arg, 0)) * 20);
                let now = h.now;
                h.with_handler(|handler| {
                    let _ = handler.handle_timeout(now);
                    let _ = handler.poll_timeout();
                });
            }
            10 => {
                let ids: Vec<usize> = h.channels.values().map(|c| c.id).collect();
                if !ids.is_empty() {
                    let id = ids[usize::from(byte(arg, 0)) % ids.len()];
                    if let Some(dc) = h.channels.get_mut(&id) {
                        let _ = dc.close();
                    }
                }
            }
            _ => h.event(RTCEventInternal::DTLSClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed OPEN from the peer creates a channel, and an application channel gets a
    /// stream id at the connected procedure: the ops reach the open handling.
    #[test]
    fn open_and_connected_procedure_create_channels() {
        let start = Instant::now();
        let mut h = Harness {
            ctx: DataChannelHandlerContext::new(start),
            channels: DataChannelRegistry::new(),
            stats: RTCStatsAccumulator::new(),
            dcep_timeout: Some(Duration::from_secs(1)),
            role: RTCDtlsRole::Client,
            max_channels: None,
            now: start,
        };
        let open = DcepMessage::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: 0,
            reliability_parameter: 0,
            label: b"chat".to_vec(),
            protocol: vec![],
        })
        .marshal()
        .unwrap();
        h.sctp_message(1, PayloadProtocolIdentifier::Dcep, open);
        assert_eq!(h.channels.len(), 1);
        h.create_channel(&[0, 0, 0, 0, b'x']);
        h.event(RTCEventInternal::SCTPHandshakeComplete(ASSOCIATION));
        assert!(h.channels.values().all(|c| c.stream_id.is_some()));
        assert_eq!(h.channels.len(), 2);
    }
}
