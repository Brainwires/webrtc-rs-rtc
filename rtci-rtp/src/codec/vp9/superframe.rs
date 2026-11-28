//! VP9 superframes (VP9 bitstream specification, Annex B): several frames in one chunk, followed
//! by an index of their sizes. A spatially scalable VP9 encoder writes each picture as one
//! superframe whose frames are the spatial layers, lowest first; RFC 9605 section 6.1.3 needs
//! each layer in its own SFrame ciphertext, so the superframe is split before encryption and
//! joined again after decryption.

#[cfg(test)]
#[path = "superframe_test.rs"]
mod superframe_test;

use bytes::{BufMut, Bytes, BytesMut};
use shared::error::{Error, Result};

/// The most frames a superframe index describes (`frames_in_superframe_minus_1` is 3 bits).
pub const VP9_MAX_SUPERFRAME_FRAMES: usize = 8;

/// The top three bits of the superframe marker byte (`superframe_marker`, 0b110).
const SUPERFRAME_MARKER: u8 = 0b1100_0000;

/// The frames of `chunk`: those its superframe index lists, in order, or the chunk itself when
/// it has no index (Annex B.3: the index is recognised by its marker byte at the end, repeated
/// at the start of the index). An empty chunk has no frame.
///
/// # Errors
///
/// An index whose frame sizes do not make up the chunk exactly with the index, or that lists a
/// frame of size 0.
pub fn split_superframe(chunk: &Bytes) -> Result<Vec<Bytes>> {
    let Some(&marker) = chunk.last() else {
        return Ok(vec![]);
    };
    if marker & 0b1110_0000 != SUPERFRAME_MARKER {
        return Ok(vec![chunk.clone()]);
    }
    let bytes_per_size = usize::from((marker >> 3) & 0b11) + 1;
    let frames = usize::from(marker & 0b111) + 1;
    let index_size = 2 + bytes_per_size * frames;
    if chunk.len() < index_size || chunk[chunk.len() - index_size] != marker {
        // Not an index: the last byte of a frame that happens to look like a marker.
        return Ok(vec![chunk.clone()]);
    }
    let index = &chunk[chunk.len() - index_size + 1..chunk.len() - 1];
    let mut out = Vec::with_capacity(frames);
    let mut offset = 0usize;
    for size in index.chunks_exact(bytes_per_size) {
        let size = size
            .iter()
            .rev()
            .fold(0usize, |value, &byte| (value << 8) | usize::from(byte));
        if size == 0 || offset + size > chunk.len() - index_size {
            return Err(Error::Other(
                "VP9 superframe: the index does not describe the chunk".to_owned(),
            ));
        }
        out.push(chunk.slice(offset..offset + size));
        offset += size;
    }
    if offset != chunk.len() - index_size {
        return Err(Error::Other(
            "VP9 superframe: the frames do not fill the chunk".to_owned(),
        ));
    }
    Ok(out)
}

/// `frames` as one chunk: a single frame as it is, two to eight frames followed by a superframe
/// index (with the smallest size field that holds the largest frame). A single frame whose last
/// byte looks like a superframe marker gets an index of its own, so that it is not taken for a
/// superframe.
///
/// # Errors
///
/// No frame, an empty frame, more than eight frames, or a frame of 2^32 bytes or more.
pub fn join_superframe(frames: &[Bytes]) -> Result<Bytes> {
    let fail = |what: &str| Err(Error::Other(format!("VP9 superframe: {what}")));
    match frames {
        [] => return fail("no frame"),
        [frame]
            if frame
                .last()
                .is_some_and(|&b| b & 0b1110_0000 != SUPERFRAME_MARKER) =>
        {
            return Ok(frame.clone());
        }
        _ if frames.len() > VP9_MAX_SUPERFRAME_FRAMES => return fail("at most eight frames"),
        _ if frames.iter().any(Bytes::is_empty) => return fail("an empty frame"),
        _ => {}
    }
    let largest = frames.iter().map(Bytes::len).max().unwrap_or(0);
    let Ok(largest) = u32::try_from(largest) else {
        return fail("a frame of 2^32 bytes or more");
    };
    let bytes_per_size = (4 - largest.leading_zeros() as usize / 8).max(1);
    let marker = SUPERFRAME_MARKER | ((bytes_per_size as u8 - 1) << 3) | (frames.len() as u8 - 1);
    let mut out = BytesMut::with_capacity(
        frames.iter().map(Bytes::len).sum::<usize>() + 2 + bytes_per_size * frames.len(),
    );
    for frame in frames {
        out.put_slice(frame);
    }
    out.put_u8(marker);
    for frame in frames {
        out.put_slice(&(frame.len() as u32).to_le_bytes()[..bytes_per_size]);
    }
    out.put_u8(marker);
    Ok(out.freeze())
}
