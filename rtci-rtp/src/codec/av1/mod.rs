use bytes::{BufMut, Bytes, BytesMut};

use crate::codec::av1::leb128::BytesMutExt;
use crate::codec::av1::obu::{
    OBU_HAS_SIZE_BIT, OBU_TYPE_SEQUENCE_HEADER, Obu, obu_has_extension, obu_type, parse_obus,
};
use crate::codec::av1::packetizer::{
    AGGREGATION_HEADER_SIZE, MAX_NUM_OBUS_TO_OMIT_SIZE, get_aggregation_header, packet_layer,
    packetize,
};
use crate::packetizer::Payloader;
use shared::error::Result;

#[cfg(test)]
mod av1_layers_test;
#[cfg(test)]
mod av1_receive_test;
#[cfg(test)]
mod av1_test;
mod depacketizer;
mod leb128;
mod obu;
mod packetizer;
mod temporal_unit;

pub use depacketizer::Av1Depacketizer;
pub use temporal_unit::{Av1LayerData, repeat_sequence_header_per_layer, split_temporal_unit};

#[derive(Default, Clone, Debug)]
/// Packetizes AV1 temporal units into RTP payloads.
///
/// One call takes one temporal unit in low overhead format (or, with spatial layers, one
/// layer's frame of it) and never mixes layers in a packet (AV1 RTP section 5): a packet ends
/// where the OBUs' `temporal_id` / `spatial_id` change, and at a sequence header, which starts
/// its own packet. Temporal delimiter, tile list and padding OBUs are dropped and the OBU size
/// fields removed.
pub struct Av1Payloader {
    /// Repeats the temporal unit's sequence header in front of every spatial layer after the
    /// first. For an "S" mode (simulcast encodings in one RTP stream) "a sequence header OBU
    /// SHOULD be aggregated with each spatial layer", so that a forwarder can drop the other
    /// encodings and still leave a decodable stream (AV1 RTP sections 5 and 6.1). Off by
    /// default: an encoder that writes a sequence header per layer needs no help, and with
    /// inter-layer prediction the base layer's is enough.
    pub sequence_header_per_spatial_layer: bool,
}

/// The packets of one frame of a temporal unit, from [`Av1Payloader::payload_frames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Av1FramePayloads {
    /// `spatial_id` of the frame's OBUs (0 when none has an extension header).
    pub spatial_id: u8,
    /// `temporal_id` of the frame's OBUs (0 when none has an extension header).
    pub temporal_id: u8,
    /// The frame's RTP payloads, in order.
    pub payloads: Vec<Bytes>,
}

impl Av1Payloader {
    /// Packetizes one temporal unit and returns its packets grouped by frame: one group per
    /// run of packets of one spatial layer.
    ///
    /// This is the unit the Dependency Descriptor describes (AV1 RTP appendix A: "an RTP
    /// frame"): `start_of_frame` belongs on a group's first payload and `end_of_frame` on its
    /// last. The RTP marker belongs on the last payload of the last group only (AV1 RTP
    /// section 4.2). A packet of OBUs without an extension header (a sequence header, metadata)
    /// is counted with the frame that follows it.
    ///
    /// # Errors
    ///
    /// The same as [`Payloader::payload`].
    pub fn payload_frames(
        &mut self,
        mtu: usize,
        temporal_unit: &Bytes,
    ) -> Result<Vec<Av1FramePayloads>> {
        let mut frames: Vec<Av1FramePayloads> = vec![];
        // Packets of no layer, waiting for the frame they lead.
        let mut pending: Vec<Bytes> = vec![];
        for (layer, payload) in self.payload_with_layers(mtu, temporal_unit)? {
            let Some(layer) = layer else {
                pending.push(payload);
                continue;
            };
            let (temporal_id, spatial_id) = (layer >> 2, layer & 0x03);
            match frames.last_mut() {
                Some(frame) if frame.spatial_id == spatial_id => {
                    frame.payloads.append(&mut pending);
                    frame.payloads.push(payload);
                }
                _ => {
                    let mut payloads = std::mem::take(&mut pending);
                    payloads.push(payload);
                    frames.push(Av1FramePayloads {
                        spatial_id,
                        temporal_id,
                        payloads,
                    });
                }
            }
        }
        if !pending.is_empty() {
            match frames.last_mut() {
                Some(frame) => frame.payloads.append(&mut pending),
                None => frames.push(Av1FramePayloads {
                    spatial_id: 0,
                    temporal_id: 0,
                    payloads: pending,
                }),
            }
        }
        Ok(frames)
    }

    /// Based on <https://chromium.googlesource.com/external/webrtc/+/4e513346ec56c829b3a6010664998469fc237b35/modules/rtp_rtcp/source/rtp_packetizer_av1.cc>
    /// Reference: <https://aomediacodec.github.io/av1-rtp-spec/#45-payload-structure>
    ///
    /// Each payload comes with the layer of its OBUs (`temporal_id << 2 | spatial_id`), or
    /// `None` when none of them has an extension header.
    fn payload_with_layers(
        &mut self,
        mtu: usize,
        payload: &Bytes,
    ) -> Result<Vec<(Option<u8>, Bytes)>> {
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |Z|Y|1 0|N|-|-|-|  OBU element 1 size (leb128)  |               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               |
        // |                                                               |
        // :                                                               :
        // :                      OBU element 1 data                       :
        // :                                                               :
        // |                                                               |
        // |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                               |                               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
        // |                                                               |
        // :                                                               :
        // :                      OBU element 2 data                       :
        // :                                                               :
        // |                                                               |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        // Parse the payload into series of OBUs.
        let mut obus = parse_obus(payload)?;
        if self.sequence_header_per_spatial_layer {
            repeat_sequence_header(&mut obus);
        }

        // Packetize the OBUs, possibly aggregating multiple OBUs into a single packet,
        // or splitting a single OBU across multiple packets.
        let packets_metadata = packetize(&obus, mtu);

        let mut payloads = vec![];

        // Split the payload into RTP packets according to the packetization scheme.
        for packet_index in 0..packets_metadata.len() {
            let packet = &packets_metadata[packet_index];
            let mut obu_offset = packet.first_obu_offset;
            let aggregation_header = get_aggregation_header(&obus, &packets_metadata, packet_index);

            let mut out = BytesMut::with_capacity(AGGREGATION_HEADER_SIZE + packet.packet_size);
            out.put_u8(aggregation_header);

            // Store all OBU elements except the last one.
            for i in 0..packet.num_obu_elements - 1 {
                let obu = &obus[packet.first_obu_index + i];
                let fragment_size = obu.size - obu_offset;
                out.put_leb128(fragment_size as u32);
                if obu_offset == 0 {
                    out.put_u8(obu.header & !OBU_HAS_SIZE_BIT);
                }
                if obu_offset <= 1 && obu_has_extension(obu.header) {
                    out.put_u8(obu.extension_header);
                }
                let payload_offset = if obu_offset > obu.header_size() {
                    obu_offset - obu.header_size()
                } else {
                    0
                };
                let payload_size = obu.payload.len() - payload_offset;
                out.put_slice(
                    obu.payload
                        .slice(payload_offset..payload_offset + payload_size)
                        .as_ref(),
                );
                // All obus are stored from the beginning, except, may be, the first one.
                obu_offset = 0;
            }

            // Store the last OBU element.
            let last_obu = &obus[packet.first_obu_index + packet.num_obu_elements - 1];
            let mut fragment_size = packet.last_obu_size;
            if packet.num_obu_elements > MAX_NUM_OBUS_TO_OMIT_SIZE {
                out.put_leb128(fragment_size as u32);
            }
            if obu_offset == 0 && fragment_size > 0 {
                out.put_u8(last_obu.header & !OBU_HAS_SIZE_BIT);
                fragment_size -= 1;
            }
            if obu_offset <= 1 && obu_has_extension(last_obu.header) && fragment_size > 0 {
                out.put_u8(last_obu.extension_header);
                fragment_size -= 1;
            }
            let payload_offset = if obu_offset > last_obu.header_size() {
                obu_offset - last_obu.header_size()
            } else {
                0
            };
            out.put_slice(
                last_obu
                    .payload
                    .slice(payload_offset..payload_offset + fragment_size)
                    .as_ref(),
            );

            payloads.push((packet_layer(&obus, packet), out.freeze()));
        }

        Ok(payloads)
    }
}

/// Puts a copy of the unit's sequence header in front of the first OBU of every spatial layer
/// that does not already start with one.
fn repeat_sequence_header(obus: &mut Vec<Obu>) {
    let is_sequence_header = |obu: &Obu| obu_type(obu.header) == OBU_TYPE_SEQUENCE_HEADER;
    let Some(sequence_header) = obus.iter().find(|obu| is_sequence_header(obu)).cloned() else {
        return;
    };
    let mut spatial_id = None;
    let mut i = 0;
    while i < obus.len() {
        if obu_has_extension(obus[i].header) {
            let obu_spatial_id = (obus[i].extension_header >> 3) & 0x03;
            let first_of_layer = spatial_id.is_some_and(|s| s != obu_spatial_id);
            spatial_id = Some(obu_spatial_id);
            // The OBUs of no layer just before it belong with the layer they lead.
            let mut start = i;
            while start > 0 && !obu_has_extension(obus[start - 1].header) {
                start -= 1;
            }
            if first_of_layer && !obus[start..i].iter().any(is_sequence_header) {
                obus.insert(start, sequence_header.clone());
                i += 1;
            }
        }
        i += 1;
    }
}

impl Payloader for Av1Payloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        Ok(self
            .payload_with_layers(mtu, payload)?
            .into_iter()
            .map(|(_, payload)| payload)
            .collect())
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}
