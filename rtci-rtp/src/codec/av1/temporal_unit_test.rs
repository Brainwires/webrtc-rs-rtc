use bytes::Bytes;

use super::{Av1LayerData, repeat_sequence_header_per_layer, split_temporal_unit};

const TEMPORAL_DELIMITER: u8 = 2;
const SEQUENCE_HEADER: u8 = 1;
const METADATA: u8 = 5;
const FRAME: u8 = 6;

/// An OBU with a size field: `layer` is (temporal_id, spatial_id) for an extension header.
fn obu(obu_type: u8, layer: Option<(u8, u8)>, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![obu_type << 3 | 0b010 | if layer.is_some() { 0b100 } else { 0 }];
    if let Some((temporal_id, spatial_id)) = layer {
        out.push(temporal_id << 5 | spatial_id << 3);
    }
    assert!(payload.len() < 128);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

fn layer(spatial_id: u8, temporal_id: u8, obus: &[Vec<u8>]) -> Av1LayerData {
    Av1LayerData {
        spatial_id,
        temporal_id,
        data: Bytes::from(obus.concat()),
    }
}

/// An L2T2 picture in temporal layer 1: the delimiter and the sequence header lead layer 0,
/// metadata between the layers leads layer 1; joining the layers gives the unit back.
#[test]
fn a_temporal_unit_splits_into_its_spatial_layers() {
    let td = obu(TEMPORAL_DELIMITER, None, &[]);
    let sh = obu(SEQUENCE_HEADER, None, &[0x11; 4]);
    let s0 = obu(FRAME, Some((1, 0)), &[0xa0; 20]);
    let meta = obu(METADATA, None, &[0x22; 3]);
    let s1a = obu(FRAME, Some((1, 1)), &[0xa1; 30]);
    let s1b = obu(FRAME, Some((1, 1)), &[0xa2; 10]);
    let unit = Bytes::from(
        [
            td.clone(),
            sh.clone(),
            s0.clone(),
            meta.clone(),
            s1a.clone(),
            s1b.clone(),
        ]
        .concat(),
    );
    let layers = split_temporal_unit(&unit).unwrap();
    assert_eq!(
        layers,
        vec![layer(0, 1, &[td, sh, s0]), layer(1, 1, &[meta, s1a, s1b])]
    );
    let joined: Vec<u8> = layers.iter().flat_map(|l| l.data.to_vec()).collect();
    assert_eq!(joined, unit.to_vec());
}

#[test]
fn a_unit_without_extension_headers_is_one_layer() {
    let unit = Bytes::from(
        [
            obu(TEMPORAL_DELIMITER, None, &[]),
            obu(FRAME, None, &[0x33; 12]),
        ]
        .concat(),
    );
    assert_eq!(
        split_temporal_unit(&unit).unwrap(),
        vec![Av1LayerData {
            spatial_id: 0,
            temporal_id: 0,
            data: unit.clone(),
        }]
    );
    assert!(split_temporal_unit(&Bytes::new()).unwrap().is_empty());
}

/// OBUs of no layer after the last layer's go with it; an OBU without a size field runs to the
/// end of the unit.
#[test]
fn trailing_obus_and_an_unsized_last_obu_belong_to_the_last_layer() {
    let s0 = obu(FRAME, Some((0, 0)), &[0xb0; 5]);
    let s1 = obu(FRAME, Some((0, 1)), &[0xb1; 5]);
    let mut unsized_metadata = vec![METADATA << 3];
    unsized_metadata.extend([0x44; 6]);
    let unit = Bytes::from([s0.clone(), s1.clone(), unsized_metadata.clone()].concat());
    assert_eq!(
        split_temporal_unit(&unit).unwrap(),
        vec![layer(0, 0, &[s0]), layer(1, 0, &[s1, unsized_metadata])]
    );
}

#[test]
fn units_that_cannot_be_split_are_refused() {
    let s0 = obu(FRAME, Some((0, 0)), &[0xc0; 5]);
    let s1 = obu(FRAME, Some((0, 1)), &[0xc1; 5]);
    // A layer below one already seen.
    assert!(split_temporal_unit(&Bytes::from([s1.clone(), s0.clone()].concat())).is_err());
    // A second temporal unit.
    let td = obu(TEMPORAL_DELIMITER, None, &[]);
    assert!(
        split_temporal_unit(&Bytes::from(
            [td.clone(), s0.clone(), td, s0.clone()].concat()
        ))
        .is_err()
    );
    // A size past the end, and an extension header cut off.
    let mut short = s0.clone();
    short.truncate(s0.len() - 1);
    assert!(split_temporal_unit(&Bytes::from(short)).is_err());
    assert!(split_temporal_unit(&Bytes::from(vec![FRAME << 3 | 0b110])).is_err());
}

/// An S2T1 key picture: the sequence header leads layer 0 only; repeated, it leads layer 1 too,
/// and a layer that has its own keeps it. A delta picture (no sequence header) is unchanged.
#[test]
fn an_s_mode_repeats_the_sequence_header_in_front_of_each_layer() {
    let td = obu(TEMPORAL_DELIMITER, None, &[]);
    let sh = obu(SEQUENCE_HEADER, None, &[0x11; 4]);
    let s0 = obu(FRAME, Some((0, 0)), &[0xd0; 8]);
    let s1 = obu(FRAME, Some((0, 1)), &[0xd1; 8]);
    let unit = Bytes::from([td.clone(), sh.clone(), s0.clone(), s1.clone()].concat());
    let mut layers = split_temporal_unit(&unit).unwrap();
    repeat_sequence_header_per_layer(&mut layers).unwrap();
    assert_eq!(
        layers,
        vec![
            layer(0, 0, &[td.clone(), sh.clone(), s0.clone()]),
            layer(1, 0, &[sh.clone(), s1.clone()])
        ]
    );
    // Already there: unchanged.
    let before = layers.clone();
    repeat_sequence_header_per_layer(&mut layers).unwrap();
    assert_eq!(layers, before);
    let delta = Bytes::from([td.clone(), s0.clone(), s1.clone()].concat());
    let mut layers = split_temporal_unit(&delta).unwrap();
    repeat_sequence_header_per_layer(&mut layers).unwrap();
    assert_eq!(layers, vec![layer(0, 0, &[td, s0]), layer(1, 0, &[s1])]);
}
