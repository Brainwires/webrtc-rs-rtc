#[cfg(test)]
mod fragment_buffer_test;

use crate::content::*;
use crate::handshake::handshake_header::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

use std::collections::HashMap;
use std::io::{BufWriter, Cursor};

// 2 mb max buffer size
const FRAGMENT_BUFFER_MAX_SIZE: usize = 2_000_000;

/// Most fragments one handshake message may arrive in. A peer fragments at its path MTU, so
/// even a large certificate chain needs a few dozen; anything past this is dropped rather than
/// buffered, so a stream of tiny fragments cannot grow the reassembly work without bound.
pub(crate) const MAX_FRAGMENTS_PER_MESSAGE: usize = 256;

/// Most handshake messages buffered at once, counted by message sequence. A flight holds a
/// handful; fragments for further sequence numbers are dropped until earlier ones are popped.
pub(crate) const MAX_BUFFERED_MESSAGES: usize = 32;

pub(crate) struct Fragment {
    record_layer_header: RecordLayerHeader,
    handshake_header: HandshakeHeader,
    data: Vec<u8>,
}

pub(crate) struct FragmentBuffer {
    // map of MessageSequenceNumbers that hold slices of fragments
    cache: HashMap<u16, Vec<Fragment>>,

    current_message_sequence_number: u16,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        FragmentBuffer {
            cache: HashMap::new(),
            current_message_sequence_number: 0,
        }
    }

    // Attempts to push a DTLS packet to the FragmentBuffer
    // when it returns true it means the FragmentBuffer has inserted and the buffer shouldn't be handled
    // when an error returns it is fatal, and the DTLS connection should be stopped
    pub fn push(&mut self, mut buf: &[u8]) -> Result<bool> {
        let current_size = self.size();
        if current_size + buf.len() >= FRAGMENT_BUFFER_MAX_SIZE {
            return Err(Error::ErrFragmentBufferOverflow {
                new_size: current_size + buf.len(),
                max_size: FRAGMENT_BUFFER_MAX_SIZE,
            });
        }

        let mut reader = Cursor::new(buf);
        let record_layer_header = RecordLayerHeader::unmarshal(&mut reader)?;

        // Fragment isn't a handshake, we don't need to handle it
        if record_layer_header.content_type != ContentType::Handshake {
            return Ok(false);
        }

        buf = &buf[RECORD_LAYER_HEADER_SIZE..];
        while !buf.is_empty() {
            let mut reader = Cursor::new(buf);
            let handshake_header = HandshakeHeader::unmarshal(&mut reader)?;

            // Bound what an unauthenticated sender can make us hold: drop (rather than fail on)
            // fragments past the per-message and per-buffer caps, so spoofed records cannot
            // tear the handshake down either.
            let at_message_cap = !self.cache.contains_key(&handshake_header.message_sequence)
                && self.cache.len() >= MAX_BUFFERED_MESSAGES;
            let at_fragment_cap = self
                .cache
                .get(&handshake_header.message_sequence)
                .is_some_and(|frags| frags.len() >= MAX_FRAGMENTS_PER_MESSAGE);

            // end index should be the length of handshake header but if the handshake
            // was fragmented, we should keep them all
            let mut end = HANDSHAKE_HEADER_LENGTH + handshake_header.length as usize;
            if end > buf.len() {
                end = buf.len();
            }

            if !(at_message_cap || at_fragment_cap) {
                // Discard all headers, when rebuilding the packet we will re-build
                let data = buf[HANDSHAKE_HEADER_LENGTH..end].to_vec();
                self.cache
                    .entry(handshake_header.message_sequence)
                    .or_default()
                    .push(Fragment {
                        record_layer_header,
                        handshake_header,
                        data,
                    });
            }
            buf = &buf[end..];
        }

        Ok(true)
    }

    pub fn pop(&mut self) -> Result<(Vec<u8>, u16)> {
        let seq_num = self.current_message_sequence_number;
        // message_seq is 16 bits and no handshake comes near using them all, but a peer can
        // push empty messages that each consume one; the last one is never handed out, so the
        // counter cannot overflow.
        let Some(next_seq_num) = seq_num.checked_add(1) else {
            return Err(Error::ErrEmptyFragment);
        };
        if !self.cache.contains_key(&seq_num) {
            return Err(Error::ErrEmptyFragment);
        }

        let (content, epoch) = if let Some(frags) = self.cache.get_mut(&seq_num) {
            let Some(raw_message) = assemble_message(frags) else {
                return Err(Error::ErrEmptyFragment);
            };

            let mut first_header = frags[0].handshake_header;
            first_header.fragment_offset = 0;
            first_header.fragment_length = first_header.length;

            let mut raw_header = vec![];
            {
                let mut writer = BufWriter::<&mut Vec<u8>>::new(raw_header.as_mut());
                if first_header.marshal(&mut writer).is_err() {
                    return Err(Error::ErrEmptyFragment);
                }
            }

            let message_epoch = frags[0].record_layer_header.epoch;

            raw_header.extend_from_slice(&raw_message);

            (raw_header, message_epoch)
        } else {
            return Err(Error::ErrEmptyFragment);
        };

        self.cache.remove(&seq_num);
        self.current_message_sequence_number = next_seq_num;

        Ok((content, epoch))
    }

    fn size(&self) -> usize {
        self.cache
            .values()
            .map(|fragment| fragment.iter().map(|f| f.data.len()).sum::<usize>())
            .sum()
    }
}

/// Reassembles one handshake message from its fragments: start at offset 0 and follow each
/// fragment's end to the next, until the message length is reached (or a zero-length fragment
/// ends it). The first fragment buffered for an offset wins, as before.
///
/// Iterative: the previous recursive version used one stack frame per fragment, so a peer that
/// sent enough tiny fragments could overflow the stack and abort the process.
fn assemble_message(frags: &[Fragment]) -> Option<Vec<u8>> {
    let mut by_offset: HashMap<u32, &Fragment> = HashMap::with_capacity(frags.len());
    for f in frags {
        by_offset
            .entry(f.handshake_header.fragment_offset)
            .or_insert(f);
    }

    let mut raw_message = vec![];
    let mut target_offset = 0u32;
    // Each step consumes a distinct offset, so this ends within `frags.len()` steps even if
    // fragment lengths point back at an offset already visited.
    for _ in 0..frags.len() {
        let f = by_offset.remove(&target_offset)?;
        raw_message.extend_from_slice(&f.data);
        let fragment_end = f
            .handshake_header
            .fragment_offset
            .checked_add(f.handshake_header.fragment_length)?;
        if fragment_end == f.handshake_header.length || f.handshake_header.fragment_length == 0 {
            return Some(raw_message);
        }
        target_offset = fragment_end;
    }
    None
}
