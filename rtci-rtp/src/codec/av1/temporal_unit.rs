//! An AV1 temporal unit split into the data of its spatial layers (AV1 specification 7.5: the
//! OBUs of a temporal unit's frames carry their layer in the OBU extension header). RFC 9605
//! section 6.1.3 needs each layer in its own SFrame ciphertext, so a spatially scalable
//! temporal unit is split before encryption; after decryption the layers' data, lowest first,
//! is concatenated again.

#[cfg(test)]
#[path = "temporal_unit_test.rs"]
mod temporal_unit_test;

use bytes::{Bytes, BytesMut};
use shared::error::{Error, Result};

use crate::codec::av1::leb128::read_leb128;
use crate::codec::av1::obu::{
    OBU_TYPE_SEQUENCE_HEADER, OBU_TYPE_TEMPORAL_DELIMITER, obu_has_extension, obu_has_size,
    obu_type,
};

/// The OBUs of one spatial layer of a temporal unit, as they were in the unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Av1LayerData {
    /// `spatial_id` of the layer's OBUs (0 when none has an extension header).
    pub spatial_id: u8,
    /// `temporal_id` of the layer's OBUs (0 when none has an extension header).
    pub temporal_id: u8,
    /// The OBUs, byte for byte (headers and size fields included).
    pub data: Bytes,
}

/// The spatial layers of `temporal_unit` (low overhead bitstream format, AV1 specification
/// 5.2), lowest first, each with its OBUs unchanged. OBUs without an extension header (the
/// temporal delimiter, a sequence header, metadata) go with the layer whose OBUs follow them,
/// those at the end with the last layer. A unit without extension headers is one layer.
///
/// # Errors
///
/// A header or a size past the end, a temporal delimiter after the first OBU (a second
/// temporal unit), or a spatial layer that comes after a higher one. An OBU without a size
/// field runs to the end of the unit.
pub fn split_temporal_unit(temporal_unit: &Bytes) -> Result<Vec<Av1LayerData>> {
    let mut layers: Vec<Av1LayerData> = vec![];
    // The current layer: where its data starts, its spatial and temporal id.
    let mut current: Option<(usize, u8, u8)> = None;
    // Where the OBUs of no layer since the current layer's last OBU start.
    let mut pending: Option<usize> = None;
    for (offset, header) in obu_spans(temporal_unit)? {
        if obu_type(header) == OBU_TYPE_TEMPORAL_DELIMITER && offset > 0 {
            return fail("more than one temporal unit");
        }
        if !obu_has_extension(header) {
            pending.get_or_insert(offset);
            continue;
        }
        let extension = temporal_unit[offset + 1];
        let (temporal_id, spatial_id) = (extension >> 5, (extension >> 3) & 0b11);
        match current {
            None => current = Some((0, spatial_id, temporal_id)),
            Some((_, current_spatial_id, _)) if current_spatial_id == spatial_id => {}
            Some((_, current_spatial_id, _)) if current_spatial_id > spatial_id => {
                return fail("a spatial layer after a higher one");
            }
            Some((start, current_spatial_id, current_temporal_id)) => {
                // The OBUs of no layer just before this one lead it.
                let boundary = pending.unwrap_or(offset);
                layers.push(Av1LayerData {
                    spatial_id: current_spatial_id,
                    temporal_id: current_temporal_id,
                    data: temporal_unit.slice(start..boundary),
                });
                current = Some((boundary, spatial_id, temporal_id));
            }
        }
        pending = None;
    }
    let (start, spatial_id, temporal_id) = current.unwrap_or((0, 0, 0));
    if start < temporal_unit.len() {
        layers.push(Av1LayerData {
            spatial_id,
            temporal_id,
            data: temporal_unit.slice(start..),
        });
    }
    Ok(layers)
}

/// For an "S" mode (spatial layers that do not predict from each other: simulcast in one RTP
/// stream), puts a copy of the unit's sequence header in front of every layer after the first
/// that has none, so that a forwarder can keep any one layer and leave it decodable (AV1 RTP
/// section 6.1: "a sequence header OBU SHOULD be aggregated with each spatial layer"). A unit
/// without a sequence header (not a key picture) is left as it is.
///
/// # Errors
///
/// A layer's data that is not OBUs.
pub fn repeat_sequence_header_per_layer(layers: &mut [Av1LayerData]) -> Result<()> {
    let mut sequence_header = None;
    for layer in layers.iter_mut() {
        let own = sequence_header_of(&layer.data)?;
        match (&own, &sequence_header) {
            (Some(_), _) => sequence_header = own,
            (None, Some(header)) => {
                let mut data = BytesMut::with_capacity(header.len() + layer.data.len());
                data.extend_from_slice(header);
                data.extend_from_slice(&layer.data);
                layer.data = data.freeze();
            }
            (None, None) => {}
        }
    }
    Ok(())
}

/// The first sequence header OBU of `data`, byte for byte.
fn sequence_header_of(data: &Bytes) -> Result<Option<Bytes>> {
    let spans = obu_spans(data)?;
    Ok(spans
        .iter()
        .enumerate()
        .find(|(_, (_, header))| obu_type(*header) == OBU_TYPE_SEQUENCE_HEADER)
        .map(|(i, (start, _))| {
            let end = spans.get(i + 1).map_or(data.len(), |(next, _)| *next);
            data.slice(*start..end)
        }))
}

fn fail<T>(what: &str) -> Result<T> {
    Err(Error::Other(format!("AV1 temporal unit: {what}")))
}

/// Where each OBU of `data` starts, with its header byte. An OBU without a size field runs to
/// the end.
fn obu_spans(data: &[u8]) -> Result<Vec<(usize, u8)>> {
    let mut spans = vec![];
    let mut offset = 0usize;
    while offset < data.len() {
        let header = data[offset];
        let header_size = if obu_has_extension(header) { 2 } else { 1 };
        if offset + header_size > data.len() {
            return fail("an OBU header past the end");
        }
        let end = if obu_has_size(header) {
            let (size, leb128_size) = read_leb128(&data[offset + header_size..])
                .ok_or(Error::ErrPayloadTooSmallForObuPayloadSize)?;
            let end = offset + header_size + leb128_size + size as usize;
            if end > data.len() {
                return fail("an OBU size past the end");
            }
            end
        } else {
            data.len()
        };
        spans.push((offset, header));
        offset = end;
    }
    Ok(spans)
}
