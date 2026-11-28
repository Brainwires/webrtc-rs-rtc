use bytes::Bytes;

use super::{join_superframe, split_superframe};

fn frame(fill: u8, len: usize) -> Bytes {
    Bytes::from(vec![fill; len])
}

/// Annex B: frames, then the index `marker, sizes (little-endian), marker`; the marker is
/// 0b110, bytes_per_framesize_minus_1 (2 bits), frames_in_superframe_minus_1 (3 bits).
#[test]
fn a_superframe_is_its_frames_and_an_index() {
    let frames = [frame(0x80, 3), frame(0x81, 5)];
    let chunk = join_superframe(&frames).unwrap();
    let mut expected = vec![0x80u8; 3];
    expected.extend([0x81; 5]);
    expected.extend([0b1100_0001, 3, 5, 0b1100_0001]);
    assert_eq!(chunk.as_ref(), expected.as_slice());
    assert_eq!(split_superframe(&chunk).unwrap(), frames.to_vec());
}

#[test]
fn the_size_field_is_as_wide_as_the_largest_frame_needs() {
    for (len, bytes_per_size) in [
        (255, 1),
        (256, 2),
        (65_535, 2),
        (65_536, 3),
        (16_777_216, 4),
    ] {
        let frames = [frame(0x82, 2), frame(0x83, len), frame(0x84, 1)];
        let chunk = join_superframe(&frames).unwrap();
        let marker = *chunk.last().unwrap();
        assert_eq!(
            usize::from((marker >> 3) & 0b11) + 1,
            bytes_per_size,
            "{len}"
        );
        assert_eq!(marker & 0b111, 2);
        assert_eq!(chunk.len(), len + 3 + 2 + 3 * bytes_per_size);
        assert_eq!(split_superframe(&chunk).unwrap(), frames.to_vec(), "{len}");
    }
}

#[test]
fn a_chunk_without_an_index_is_one_frame() {
    let single = frame(0x86, 40);
    assert_eq!(
        join_superframe(std::slice::from_ref(&single)).unwrap(),
        single
    );
    assert_eq!(split_superframe(&single).unwrap(), vec![single]);
    // The last byte looks like a marker, the byte where the index would start does not.
    let mut lookalike = vec![0x86u8; 40];
    lookalike.push(0b1100_0001);
    let lookalike = Bytes::from(lookalike);
    assert_eq!(
        split_superframe(&lookalike).unwrap(),
        vec![lookalike.clone()]
    );
    assert!(split_superframe(&Bytes::new()).unwrap().is_empty());
    // A single frame that ends like a marker is written as a superframe of one frame.
    let joined = join_superframe(std::slice::from_ref(&lookalike)).unwrap();
    assert_eq!(joined.len(), lookalike.len() + 3);
    assert_eq!(split_superframe(&joined).unwrap(), vec![lookalike]);
}

#[test]
fn an_index_that_does_not_describe_the_chunk_is_refused() {
    let chunk = join_superframe(&[frame(0x80, 3), frame(0x81, 5)]).unwrap();
    // A byte more in front: the sizes no longer fill the chunk.
    let mut longer = vec![0u8];
    longer.extend_from_slice(&chunk);
    assert!(split_superframe(&Bytes::from(longer)).is_err());
    // A size larger than the chunk.
    let mut oversize = chunk.to_vec();
    let at = oversize.len() - 2;
    oversize[at] = 200;
    assert!(split_superframe(&Bytes::from(oversize)).is_err());
    // A frame of size 0.
    let mut empty = chunk.to_vec();
    let at = empty.len() - 3;
    empty[at] = 0;
    assert!(split_superframe(&Bytes::from(empty)).is_err());
}

#[test]
fn join_refuses_what_an_index_cannot_describe() {
    assert!(join_superframe(&[]).is_err());
    assert!(join_superframe(&[frame(1, 2), Bytes::new()]).is_err());
    let nine: Vec<Bytes> = (0..9).map(|i| frame(i, 2)).collect();
    assert!(join_superframe(&nine).is_err());
    let eight = &nine[..8];
    assert_eq!(
        split_superframe(&join_superframe(eight).unwrap()).unwrap(),
        eight.to_vec()
    );
}
