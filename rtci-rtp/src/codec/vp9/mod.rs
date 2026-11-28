#[cfg(test)]
mod vp9_depacketizer_fields_test;
#[cfg(test)]
mod vp9_descriptor_test;
#[cfg(test)]
mod vp9_layers_test;
#[cfg(test)]
mod vp9_test;

mod superframe;
pub use superframe::{VP9_MAX_SUPERFRAME_FRAMES, join_superframe, split_superframe};

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::fmt;
use std::sync::Arc;

/// The mandatory octet and a 15-bit picture ID
const VP9HEADER_SIZE: usize = 3;
const MAX_VP9REF_PICS: usize = 3;
/// The number of reference frame slots a VP9 decoder keeps (VP9 bitstream specification 3).
const VP9_REF_SLOTS: usize = 8;

/// The highest spatial layer id the three-bit `SID` field carries (RFC 9628 section 4.2).
pub const VP9_MAX_SPATIAL_ID: u8 = 7;
/// The highest temporal layer id the three-bit `TID` field carries (RFC 9628 section 4.2).
pub const VP9_MAX_TEMPORAL_ID: u8 = 7;
/// The largest reference index (`P_DIFF`) the seven-bit field carries.
pub const VP9_MAX_P_DIFF: u8 = 127;

/// InitialPictureIDFn is a function that returns random initial picture ID.
pub type InitialPictureIDFn = Arc<dyn (Fn() -> u16) + Send + Sync>;

/// One picture of a VP9 picture group (RFC 9628 section 4.2.1): its temporal layer, whether it
/// is a switching up point, and the pictures it predicts from.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Vp9PictureGroupEntry {
    /// `TID` of the picture.
    pub temporal_id: u8,
    /// `U`: pictures of higher temporal layers after this one do not depend on pictures of
    /// higher temporal layers before it.
    pub switching_up_point: bool,
    /// The picture's reference indices (`P_DIFF`, at most three): how many pictures back each
    /// reference is.
    pub reference_diffs: Vec<u8>,
}

/// The VP9 scalability structure (SS, RFC 9628 section 4.2.1): the number of spatial layers,
/// their resolutions, and for a fixed prediction pattern the picture group (PG).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Vp9ScalabilityStructure {
    /// The number of spatial layers in the stream, 1 to 8 (`N_S` + 1).
    pub spatial_layers: u8,
    /// Width and height of each spatial layer's frames, lowest layer first. Empty when the SS
    /// carries no resolutions (`Y`=0); otherwise one entry per spatial layer.
    pub resolutions: Vec<(u16, u16)>,
    /// The picture group, in order from the key picture on. Empty when the SS describes none
    /// (`G`=0): one temporal layer in non-flexible mode, or dependencies given per packet in
    /// flexible mode.
    pub picture_group: Vec<Vp9PictureGroupEntry>,
}

impl Vp9ScalabilityStructure {
    /// Checks that the structure can be written: 1 to 8 spatial layers, a resolution for each
    /// or none, at most 255 pictures in the group with at most three references each, and a
    /// first picture in temporal layer 0 (RFC 9628 section 4.2.1).
    pub fn validate(&self) -> Result<()> {
        let fail = |what: &str| Err(Error::Other(format!("VP9 scalability structure: {what}")));
        if self.spatial_layers == 0 || self.spatial_layers > VP9_MAX_SPATIAL_ID + 1 {
            return fail("1 to 8 spatial layers");
        }
        if !self.resolutions.is_empty() && self.resolutions.len() != self.spatial_layers as usize {
            return fail("one resolution per spatial layer, or none");
        }
        if self.picture_group.len() > 255 {
            return fail("at most 255 pictures in a picture group");
        }
        for entry in &self.picture_group {
            if entry.temporal_id > VP9_MAX_TEMPORAL_ID {
                return fail("TID is three bits");
            }
            if entry.reference_diffs.len() > MAX_VP9REF_PICS {
                return fail("at most three reference indices per picture");
            }
        }
        if self
            .picture_group
            .first()
            .is_some_and(|e| e.temporal_id != 0)
        {
            return fail("the first picture of the group has TID 0");
        }
        Ok(())
    }

    /// The number of octets [`marshal_to`](Self::marshal_to) writes.
    pub fn marshal_size(&self) -> usize {
        let mut size = 1 + 4 * self.resolutions.len();
        if !self.picture_group.is_empty() {
            size += 1;
            for entry in &self.picture_group {
                size += 1 + entry.reference_diffs.len();
            }
        }
        size
    }

    /// Appends the SS as it appears in a payload descriptor with `V`=1. The reserved bits are
    /// written as 0.
    ///
    /// # Errors
    ///
    /// Whatever [`validate`](Self::validate) refuses.
    pub fn marshal_to(&self, out: &mut BytesMut) -> Result<()> {
        self.validate()?;
        //      +-+-+-+-+-+-+-+-+
        // V:   | N_S |Y|G|-|-|-|
        //      +-+-+-+-+-+-+-+-+
        let mut b = (self.spatial_layers - 1) << 5;
        if !self.resolutions.is_empty() {
            b |= 0x10; // Y
        }
        if !self.picture_group.is_empty() {
            b |= 0x08; // G
        }
        out.put_u8(b);
        for (width, height) in &self.resolutions {
            out.put_u16(*width);
            out.put_u16(*height);
        }
        if !self.picture_group.is_empty() {
            out.put_u8(self.picture_group.len() as u8); // N_G
            for entry in &self.picture_group {
                // | TID |U| R |-|-|
                let mut b = entry.temporal_id << 5;
                if entry.switching_up_point {
                    b |= 0x10;
                }
                b |= (entry.reference_diffs.len() as u8) << 2;
                out.put_u8(b);
                for diff in &entry.reference_diffs {
                    out.put_u8(*diff);
                }
            }
        }
        Ok(())
    }
}

/// What the encoder knows about one VP9 frame (one spatial layer of a picture) and the payload
/// descriptor carries (RFC 9628 section 4.2).
///
/// The default describes the only frame of a picture in temporal layer 0: `end_of_picture` is
/// set, the rest is 0 / unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vp9FrameInfo {
    /// `TID`, the frame's temporal layer (0 to 7). Every frame of a picture has the same one,
    /// except in a pattern with shifted temporal layers, which only flexible mode can carry.
    pub temporal_id: u8,
    /// `SID`, the frame's spatial layer (0 to 7). The frames of a picture are sent in
    /// increasing order.
    pub spatial_id: u8,
    /// `U`: pictures of higher temporal layers after this one do not depend on pictures of
    /// higher temporal layers before it.
    pub switching_up_point: bool,
    /// `D`: the frame predicts from the frame of spatial layer `SID`-1 of the same picture.
    pub inter_layer_dependency: bool,
    /// `Z`: no frame of a higher spatial layer, in this picture or a later one, depends on
    /// this frame.
    pub not_reference_for_upper_layers: bool,
    /// The frame is the picture's last. The next frame starts a picture with the next picture
    /// ID, and the RTP marker belongs on this frame's last packet (RFC 9628 section 4.1).
    pub end_of_picture: bool,
    /// Whether the frame is a key frame. `None` reads it from the frame's uncompressed header;
    /// set it when the payloader cannot (the frame is encrypted end to end).
    pub key_frame: Option<bool>,
    /// `P`: whether the frame predicts from another picture. `None` derives it from the
    /// frame's uncompressed header (the reference slots it reads).
    pub inter_picture_predicted: Option<bool>,
    /// Flexible mode's reference indices (`P_DIFF`): how many pictures back each picture the
    /// frame predicts from is, at most three values of 1 to 127. Empty derives them from the
    /// frame's uncompressed header.
    pub reference_diffs: Vec<u8>,
}

impl Default for Vp9FrameInfo {
    fn default() -> Self {
        Self {
            temporal_id: 0,
            spatial_id: 0,
            switching_up_point: false,
            inter_layer_dependency: false,
            not_reference_for_upper_layers: false,
            end_of_picture: true,
            key_frame: None,
            inter_picture_predicted: None,
            reference_diffs: vec![],
        }
    }
}

/// Vp9Payloader payloads VP9 packets.
///
/// By default it uses the non-flexible mode, as browsers expect from a sender
/// without SVC (RFC 9628 section 4.2): it reads each frame's uncompressed
/// header, marks a frame that predicts from another picture with `P=1` (a key
/// or intra-only frame with `P=0`), and puts a scalability structure with the
/// frame size on a key frame's first packet. `flexible_mode` selects the
/// flexible mode instead: no scalability structure unless one is set, and the
/// reference indices (`P_DIFF`) of every predicted frame, read from the
/// header's reference slots.
///
/// The mode only changes at a key picture, as the RFC requires. A stream
/// whose first frame is not VP9 at all starts in flexible mode, as before,
/// and stays there until a key frame parses; such a frame is sent with `P=1`
/// (unknown, so not offered as a switch point) unless it is the stream's
/// first.
///
/// [`Payloader::payload`] sends a picture of one frame without layer indices.
/// [`Vp9Payloader::payload_layer_frame`] takes the frame's layer information
/// from the encoder and writes the layer indices (`TID`, `U`, `SID`, `D`,
/// `TL0PICIDX`), `Z`, and one picture ID for all the frames of a picture.
#[derive(Default, Clone)]
pub struct Vp9Payloader {
    picture_id: u16,
    initialized: bool,

    /// Supplies the starting picture id; randomized when absent.
    pub initial_picture_id_fn: Option<InitialPictureIDFn>,
    /// Sends in flexible mode (`F=1`) instead of non-flexible mode.
    pub flexible_mode: bool,
    /// The `TL0PICIDX` of the first picture of temporal layer 0; random when absent (RFC 9628
    /// section 4.2: "SHOULD start on a random number").
    pub initial_tl0_pic_idx: Option<u8>,

    /// The SS to send on key pictures.
    scalability_structure: Option<Vp9ScalabilityStructure>,
    /// The mode in use (`Some(true)`: flexible), fixed at the last key picture.
    mode: Option<bool>,
    /// Pictures completed so far, unwrapped.
    picture_number: u64,
    /// `picture_number` of the last key picture.
    key_picture_number: u64,
    /// The temporal layers of the picture group sent at the last key picture.
    picture_group_tids: Vec<u8>,
    /// `TL0PICIDX` of the last picture of temporal layer 0.
    tl0_pic_idx: u8,
    /// The picture each reference slot was last refreshed by.
    slots: [Option<u64>; VP9_REF_SLOTS],
    /// The spatial layer of the last frame sent of a picture that has not ended.
    open_picture_sid: Option<u8>,
    /// [`Payloader::set_next_frame_info`]: the layer information of the next frame
    /// [`Payloader::payload`] is given.
    next_frame_info: Option<Vp9FrameInfo>,
    /// Whether any frame has been sent.
    started: bool,
}

impl fmt::Debug for Vp9Payloader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vp9Payloader")
            .field("picture_id", &self.picture_id)
            .field("initialized", &self.initialized)
            .field("flexible_mode", &self.flexible_mode)
            .field("mode", &self.mode)
            .field("scalability_structure", &self.scalability_structure)
            .field("tl0_pic_idx", &self.tl0_pic_idx)
            .finish()
    }
}

impl Payloader for Vp9Payloader {
    /// Payload fragments an Vp9Payloader packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        /*
         * https://www.rfc-editor.org/rfc/rfc9628#section-4.2
         *
         * Flexible mode (F=1)
         *        0 1 2 3 4 5 6 7
         *       +-+-+-+-+-+-+-+-+
         *       |I|P|L|F|B|E|V|Z| (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  I:   |M| PICTURE ID  | (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  M:   | EXTENDED PID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  L:   | tid |U| SID |D| (CONDITIONALLY RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+                             -\
         *  P,F: | P_DIFF      |N| (CONDITIONALLY REQUIRED)    - up to 3 times
         *       +-+-+-+-+-+-+-+-+                             -/
         *  V:   | SS            |
         *       | ..            |
         *       +-+-+-+-+-+-+-+-+
         *
         * Non-flexible mode (F=0)
         *        0 1 2 3 4 5 6 7
         *       +-+-+-+-+-+-+-+-+
         *       |I|P|L|F|B|E|V|Z| (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  I:   |M| PICTURE ID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  M:   | EXTENDED PID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  L:   | tid |U| SID |D| (CONDITIONALLY RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *       |   tl0picidx   | (CONDITIONALLY REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  V:   | SS            |
         *       | ..            |
         *       +-+-+-+-+-+-+-+-+
         */
        let info = self.next_frame_info.take();
        self.payload_frame(mtu, payload, info.as_ref())
    }

    /// RFC 9628 section 4.1: the marker is set on "the final packet of the highest spatial
    /// layer frame", the picture's last. After a frame that leaves its picture open
    /// (`end_of_picture` unset) no packet of that frame carries it.
    fn marker_rule(&self) -> crate::packetizer::MarkerRule {
        if self.open_picture_sid.is_some() {
            crate::packetizer::MarkerRule::Never
        } else {
            crate::packetizer::MarkerRule::LastPacketOfFrame
        }
    }

    fn set_next_frame_info(&mut self, info: &dyn std::any::Any) {
        if let Some(info) = info.downcast_ref::<Vp9FrameInfo>() {
            self.next_frame_info = Some(info.clone());
        }
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

impl Vp9Payloader {
    /// Sets the scalability structure sent on the first packet of every key picture (RFC 9628
    /// section 4.2.1), or with `None` goes back to the default: in non-flexible mode one
    /// spatial layer of the key frame's size and a picture group of one picture, in flexible
    /// mode no SS.
    ///
    /// In non-flexible mode the picture group is what tells a receiver the temporal structure,
    /// and [`payload_layer_frame`](Self::payload_layer_frame) refuses a frame whose `TID` is
    /// not the one its picture maps to. It takes effect at the next key picture, the only
    /// place an SS may change.
    ///
    /// # Errors
    ///
    /// A structure [`Vp9ScalabilityStructure::validate`] refuses.
    pub fn set_scalability_structure(
        &mut self,
        structure: Option<Vp9ScalabilityStructure>,
    ) -> Result<()> {
        if let Some(structure) = &structure {
            structure.validate()?;
        }
        self.scalability_structure = structure;
        Ok(())
    }

    /// The picture ID the next picture is sent with (meaningful once a frame has been sent,
    /// or with `initial_picture_id_fn` set).
    pub fn picture_id(&self) -> u16 {
        self.picture_id
    }

    /// Fragments one VP9 frame of a layered stream, describing it with `info`.
    ///
    /// Every packet carries the layer indices (`L`=1). The frames of a picture are passed in
    /// increasing `spatial_id` order, the last with `end_of_picture`; they share one picture
    /// ID, and in non-flexible mode one `TL0PICIDX`, incremented for a picture of temporal
    /// layer 0. The caller sets the RTP marker on the last packet of the frame with
    /// `end_of_picture` and on no other (RFC 9628 section 4.1).
    ///
    /// # Errors
    ///
    /// Layer information the descriptor cannot carry or the RFC forbids: `TID` or `SID`
    /// above 7; `D` on spatial layer 0; a frame that is not inter-picture predicted outside
    /// temporal layer 0; spatial layers out of order within a picture; more than three
    /// reference indices, or one outside 1 to 127; in non-flexible mode a `TID` that is not
    /// the one the picture group gives the picture; an MTU with no room for the descriptor
    /// (and, on a key picture's first packet, the scalability structure).
    pub fn payload_layer_frame(
        &mut self,
        mtu: usize,
        frame: &Bytes,
        info: &Vp9FrameInfo,
    ) -> Result<Vec<Bytes>> {
        self.payload_frame(mtu, frame, Some(info))
    }

    fn payload_frame(
        &mut self,
        mtu: usize,
        frame: &Bytes,
        info: Option<&Vp9FrameInfo>,
    ) -> Result<Vec<Bytes>> {
        let fail = |what: String| Err(Error::Other(format!("VP9 payloader: {what}")));
        if let Some(info) = info {
            if info.temporal_id > VP9_MAX_TEMPORAL_ID || info.spatial_id > VP9_MAX_SPATIAL_ID {
                return fail(format!(
                    "TID {} / SID {} do not fit three bits",
                    info.temporal_id, info.spatial_id
                ));
            }
            if info.inter_layer_dependency && info.spatial_id == 0 {
                return fail("D must be 0 on spatial layer 0".to_owned());
            }
            if info.reference_diffs.len() > MAX_VP9REF_PICS
                || info
                    .reference_diffs
                    .iter()
                    .any(|d| *d == 0 || *d > VP9_MAX_P_DIFF)
            {
                return fail("at most three reference indices, each 1 to 127".to_owned());
            }
            if let Some(open_sid) = self.open_picture_sid
                && info.spatial_id <= open_sid
            {
                return fail(format!(
                    "SID {} after SID {open_sid} in one picture",
                    info.spatial_id
                ));
            }
        }

        if frame.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        if !self.initialized {
            if self.initial_picture_id_fn.is_none() {
                self.initial_picture_id_fn =
                    Some(Arc::new(|| -> u16 { rand::random::<u16>() & 0x7FFF }));
            }
            self.picture_id = if let Some(f) = &self.initial_picture_id_fn {
                f() & 0x7FFF
            } else {
                0
            };
            // The first picture of temporal layer 0 increments it to the initial value.
            self.tl0_pic_idx = self
                .initial_tl0_pic_idx
                .unwrap_or_else(rand::random::<u8>)
                .wrapping_sub(1);
            self.initialized = true;
        }

        let header = Vp9FrameHeader::parse(frame);
        let first_of_picture = self.open_picture_sid.is_none();
        let spatial_id = info.map_or(0, |i| i.spatial_id);
        let temporal_id = info.map_or(0, |i| i.temporal_id);
        let key_frame = info
            .and_then(|i| i.key_frame)
            .unwrap_or_else(|| header.is_some_and(|h| h.key_frame));
        // A key picture: its base spatial layer frame is a key frame (RFC 9628 4.2).
        let key_picture_start = key_frame && first_of_picture && spatial_id == 0;

        // "The value of the F bit MUST only change on the first packet of a key picture."
        let flexible = match self.mode {
            Some(mode) if !key_picture_start => mode,
            // Nothing is known about the frame (it is not VP9, and the caller did not say what
            // it is): there is no frame size for an SS, so flexible mode it is.
            _ => {
                self.flexible_mode
                    || (header.is_none() && info.is_none_or(|i| i.key_frame.is_none()))
            }
        };

        // P and, for flexible mode, the reference indices.
        let derived = self.references(header.as_ref(), key_frame);
        let predicted = info
            .and_then(|i| i.inter_picture_predicted)
            .unwrap_or(derived.0);
        let mut reference_diffs: Vec<u8> = vec![];
        if predicted && flexible {
            reference_diffs = match info {
                Some(info) if !info.reference_diffs.is_empty() => info.reference_diffs.clone(),
                _ => derived.1,
            };
            if reference_diffs.is_empty() {
                // "At least one reference index MUST be specified"; the previous picture when
                // the frame does not say.
                reference_diffs.push(1);
            }
        }
        if !predicted && temporal_id != 0 {
            // "When P is set to zero, the TID field (if present) MUST also be set to 0."
            return fail(format!(
                "a frame without inter-picture prediction has TID {temporal_id}"
            ));
        }

        // Non-flexible mode: the picture's TID is the one its place in the picture group has.
        let picture_group_tids = if key_picture_start {
            self.key_picture_structure(flexible, header.as_ref())
                .map(|s| s.picture_group.iter().map(|e| e.temporal_id).collect())
                .unwrap_or_default()
        } else {
            self.picture_group_tids.clone()
        };
        if !flexible && info.is_some() && !picture_group_tids.is_empty() {
            let since_key = if key_picture_start {
                0
            } else {
                self.picture_number.wrapping_sub(self.key_picture_number)
            };
            let expected =
                picture_group_tids[(since_key % picture_group_tids.len() as u64) as usize];
            if expected != temporal_id {
                return fail(format!(
                    "TID {temporal_id} where the picture group has TID {expected}"
                ));
            }
        }

        // The scalability structure goes on the first packet of a key picture.
        let mut ss = BytesMut::new();
        if key_picture_start
            && let Some(structure) = self.key_picture_structure(flexible, header.as_ref())
        {
            structure.marshal_to(&mut ss)?;
        }

        // TL0PICIDX counts the pictures of temporal layer 0.
        let tl0_pic_idx = if !flexible && info.is_some() && first_of_picture && temporal_id == 0 {
            self.tl0_pic_idx.wrapping_add(1)
        } else {
            self.tl0_pic_idx
        };

        // The descriptor after its first octet, the same on every packet of the frame.
        let mut descriptor = BytesMut::with_capacity(8);
        descriptor.put_u8((self.picture_id >> 8) as u8 | 0x80);
        descriptor.put_u8((self.picture_id & 0xFF) as u8);
        let mut b0 = 0x80; // I
        if predicted {
            b0 |= 0x40; // P
        }
        if flexible {
            b0 |= 0x10; // F
        }
        match info {
            Some(info) => {
                b0 |= 0x20; // L
                let mut layer = (info.temporal_id << 5) | (info.spatial_id << 1);
                if info.switching_up_point {
                    layer |= 0x10; // U
                }
                if info.inter_layer_dependency {
                    layer |= 0x01; // D
                }
                descriptor.put_u8(layer);
                if !flexible {
                    descriptor.put_u8(tl0_pic_idx);
                }
                if info.not_reference_for_upper_layers {
                    b0 |= 0x01; // Z
                }
            }
            // Without layers: one spatial layer, so nothing above depends on the frame. (The
            // flexible mode of before did not say so, and still does not.)
            None if !flexible => b0 |= 0x01,
            None => {}
        }
        for (i, diff) in reference_diffs.iter().enumerate() {
            let more = i + 1 < reference_diffs.len();
            descriptor.put_u8((diff << 1) | more as u8);
        }

        let header_size = 1 + descriptor.len();
        if mtu <= header_size + ss.len() {
            // No room for a single octet of the frame. Without layer information this has
            // always meant "no packets"; a caller that describes its frames is told.
            return match info {
                Some(_) => fail(format!(
                    "an MTU of {mtu} has no room for a descriptor of {} octets",
                    header_size + ss.len()
                )),
                None => Ok(vec![]),
            };
        }

        let mut payloads = vec![];
        let mut index = 0;
        while index < frame.len() {
            let with_ss = index == 0 && !ss.is_empty();
            let room = mtu - header_size - if with_ss { ss.len() } else { 0 };
            let fragment = std::cmp::min(room, frame.len() - index);

            let mut out = BytesMut::with_capacity(mtu.min(header_size + ss.len() + fragment));
            let mut b = b0;
            if index == 0 {
                b |= 0x08; // B
            }
            if index + fragment == frame.len() {
                b |= 0x04; // E
            }
            if with_ss {
                b |= 0x02; // V
            }
            out.put_u8(b);
            out.put(&descriptor[..]);
            if with_ss {
                out.put(&ss[..]);
            }
            out.put(&frame[index..index + fragment]);
            payloads.push(out.freeze());
            index += fragment;
        }

        // The frame is sent: account for it.
        self.started = true;
        self.mode = Some(flexible);
        self.tl0_pic_idx = tl0_pic_idx;
        if key_picture_start {
            self.key_picture_number = self.picture_number;
            self.picture_group_tids = picture_group_tids;
        }
        if key_frame {
            self.slots = [Some(self.picture_number); VP9_REF_SLOTS];
        } else if let Some(refresh) = header.and_then(|h| h.refresh_frame_flags) {
            for (i, slot) in self.slots.iter_mut().enumerate() {
                if refresh & (1 << i) != 0 {
                    *slot = Some(self.picture_number);
                }
            }
        }
        if info.is_none_or(|i| i.end_of_picture) {
            self.open_picture_sid = None;
            self.picture_number += 1;
            self.picture_id = (self.picture_id + 1) & 0x7FFF;
        } else {
            self.open_picture_sid = Some(spatial_id);
        }

        Ok(payloads)
    }

    /// Whether the frame predicts from another picture (`P`), and which ones (flexible mode's
    /// `P_DIFF`s), as far as its uncompressed header tells.
    fn references(&self, header: Option<&Vp9FrameHeader>, key_frame: bool) -> (bool, Vec<u8>) {
        if key_frame {
            return (false, vec![]);
        }
        let Some(header) = header else {
            // Not a VP9 frame. Nothing precedes the stream's first frame; any other may
            // depend on what came before, and must not be offered as a switch point.
            return (self.started, vec![]);
        };
        if header.intra_only {
            return (false, vec![]);
        }
        let slots: Vec<u8> = match (header.show_existing, header.ref_frame_idx) {
            (Some(slot), _) => vec![slot],
            (None, Some(refs)) => refs.to_vec(),
            // An inter frame whose header ends before its reference indices.
            (None, None) => return (true, vec![]),
        };
        let mut diffs: Vec<u8> = vec![];
        let mut predicted = false;
        for slot in slots {
            match self.slots[slot as usize] {
                // A reference to a frame of this picture is inter-layer prediction (the D
                // bit), not inter-picture prediction.
                Some(picture) if picture == self.picture_number => {}
                Some(picture) => {
                    predicted = true;
                    // The furthest a reference index reaches is 127 pictures.
                    let diff = (self.picture_number - picture).min(VP9_MAX_P_DIFF as u64) as u8;
                    if !diffs.contains(&diff) {
                        diffs.push(diff);
                    }
                }
                // A slot nothing sent on this stream has written: an older picture.
                None => predicted = true,
            }
        }
        (predicted, diffs)
    }

    /// The SS a key picture starting now carries: the one set, or in non-flexible mode the
    /// default (one spatial layer of the key frame's size; one picture per group, predicted
    /// from the picture before).
    fn key_picture_structure(
        &self,
        flexible: bool,
        header: Option<&Vp9FrameHeader>,
    ) -> Option<Vp9ScalabilityStructure> {
        if let Some(structure) = &self.scalability_structure {
            return Some(structure.clone());
        }
        if flexible {
            return None;
        }
        let resolutions = match header.and_then(|h| h.size) {
            // WIDTH and HEIGHT are 16 bits; a larger frame is announced without them.
            Some((width, height)) if width <= 0xFFFF && height <= 0xFFFF => {
                vec![(width as u16, height as u16)]
            }
            _ => vec![],
        };
        Some(Vp9ScalabilityStructure {
            spatial_layers: 1,
            resolutions,
            picture_group: vec![Vp9PictureGroupEntry {
                temporal_id: 0,
                switching_up_point: true,
                reference_diffs: vec![1],
            }],
        })
    }
}

/// What the payloader needs from a VP9 frame's uncompressed header (VP9
/// bitstream specification 6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Vp9FrameHeader {
    /// `frame_type == KEY_FRAME`.
    pub(crate) key_frame: bool,
    /// `intra_only`: a frame that is not a key frame and predicts from no other.
    pub(crate) intra_only: bool,
    /// `show_existing_frame`: the slot of the frame shown again; there is no new frame.
    pub(crate) show_existing: Option<u8>,
    /// A key frame's width and height.
    pub(crate) size: Option<(u32, u32)>,
    /// The reference slots the frame is stored in. `None` on a key frame (all of them) and
    /// when the header ends before the field.
    pub(crate) refresh_frame_flags: Option<u8>,
    /// The reference slots an inter frame predicts from. `None` when the header ends before
    /// them.
    pub(crate) ref_frame_idx: Option<[u8; 3]>,
}

/// Reads bits, most significant first.
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BitReader<'_> {
    fn bits(&mut self, n: usize) -> Option<u32> {
        let mut v = 0u32;
        for _ in 0..n {
            let byte = *self.data.get(self.pos / 8)?;
            v = (v << 1) | ((byte >> (7 - (self.pos % 8))) & 1) as u32;
            self.pos += 1;
        }
        Some(v)
    }
}

impl Vp9FrameHeader {
    /// Parses the header; `None` when the bytes are not a VP9 frame.
    pub(crate) fn parse(frame: &[u8]) -> Option<Self> {
        let mut r = BitReader {
            data: frame,
            pos: 0,
        };
        if r.bits(2)? != 2 {
            return None; // frame_marker
        }
        let low = r.bits(1)?;
        let high = r.bits(1)?;
        let profile = (high << 1) | low;
        if profile == 3 {
            r.bits(1)?; // reserved_zero
        }
        if r.bits(1)? == 1 {
            // show_existing_frame: a repeat of an earlier frame, no new data.
            return Some(Self {
                show_existing: Some(r.bits(3)? as u8),
                ..Default::default()
            });
        }
        let key_frame = r.bits(1)? == 0;
        let show_frame = r.bits(1)? == 1;
        let error_resilient_mode = r.bits(1)? == 1;
        if key_frame {
            if r.bits(24)? != 0x49_83_42 {
                return None; // frame_sync_code
            }
            Self::color_config(&mut r, profile)?;
            let width = r.bits(16)? + 1;
            let height = r.bits(16)? + 1;
            return Some(Self {
                key_frame,
                size: Some((width, height)),
                ..Default::default()
            });
        }

        // An inter or intra-only frame. Its first octet is all the non-flexible mode needs;
        // a header that ends early leaves the reference fields unknown.
        let mut header = Self::default();
        let rest = (|| -> Option<()> {
            header.intra_only = !show_frame && r.bits(1)? == 1;
            if !error_resilient_mode {
                r.bits(2)?; // reset_frame_context
            }
            if header.intra_only {
                if r.bits(24)? != 0x49_83_42 {
                    return None; // frame_sync_code
                }
                if profile > 0 {
                    Self::color_config(&mut r, profile)?;
                }
                header.refresh_frame_flags = Some(r.bits(8)? as u8);
            } else {
                header.refresh_frame_flags = Some(r.bits(8)? as u8);
                let mut refs = [0u8; 3];
                for slot in &mut refs {
                    *slot = r.bits(3)? as u8;
                    r.bits(1)?; // ref_frame_sign_bias
                }
                header.ref_frame_idx = Some(refs);
            }
            Some(())
        })();
        // A header cut short leaves the reference fields unknown.
        let _ = rest;
        Some(header)
    }

    /// `color_config()` of the uncompressed header.
    fn color_config(r: &mut BitReader<'_>, profile: u32) -> Option<()> {
        if profile >= 2 {
            r.bits(1)?; // ten_or_twelve_bit
        }
        let color_space = r.bits(3)?;
        if color_space != 7 {
            r.bits(1)?; // color_range
            if profile == 1 || profile == 3 {
                r.bits(3)?; // subsampling_x, subsampling_y, reserved_zero
            }
        } else if profile == 1 || profile == 3 {
            r.bits(1)?; // reserved_zero
        }
        Some(())
    }
}

/// Vp9Packet represents the VP9 header that is stored in the payload of an RTP Packet
///
/// Every field describes the packet last given to [`Depacketizer::depacketize`]: a field the
/// packet did not carry reads 0 / `false` / empty. In particular the scalability structure
/// fields are those of a packet with `V`=1 only; a consumer that needs the stream's current
/// structure keeps [`Vp9Packet::scalability_structure`] of the last packet that had one.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp9Packet {
    /// picture ID is present
    pub i: bool,
    /// inter-picture predicted frame.
    pub p: bool,
    /// layer indices present
    pub l: bool,
    /// flexible mode. Read as `false` when `I` is 0, whatever the bit says (RFC 9628 section
    /// 4.2: F is ignored without a picture ID).
    pub f: bool,
    /// start of frame. beginning of new vp9 frame
    pub b: bool,
    /// end of frame
    pub e: bool,
    /// scalability structure (SS) present
    pub v: bool,
    /// Not a reference frame for upper spatial layers
    pub z: bool,

    /// Recommended headers
    /// 7 or 15 bits, picture ID.
    pub picture_id: u16,
    /// Whether the picture ID was sent in 15 bits (`M`=1) rather than 7. The width can change
    /// during a session; reference indices are computed modulo the width in use (RFC 9628
    /// section 4.2).
    pub picture_id_15_bits: bool,

    /// Conditionally recommended headers
    /// Temporal layer ID
    pub tid: u8,
    /// Switching up point
    pub u: bool,
    /// Spatial layer ID
    pub sid: u8,
    /// Inter-layer dependency used
    pub d: bool,

    /// Conditionally required headers
    /// Reference index (F=1)
    pub pdiff: Vec<u8>,
    /// Temporal layer zero index (F=0)
    pub tl0picidx: u8,

    /// Scalability structure headers
    /// N_S + 1 indicates the number of spatial layers present in the VP9 stream
    pub ns: u8,
    /// Each spatial layer's frame resolution present
    pub y: bool,
    /// PG description present flag.
    pub g: bool,
    /// N_G indicates the number of pictures in a Picture Group (PG)
    pub ng: u8,
    /// Frame width for each spatial layer.
    pub width: Vec<u16>,
    /// Frame height for each spatial layer.
    pub height: Vec<u16>,
    /// Temporal layer ID of pictures in a Picture Group
    pub pgtid: Vec<u8>,
    /// Switching up point of pictures in a Picture Group
    pub pgu: Vec<bool>,
    /// Reference indices of pictures in a Picture Group
    pub pgpdiff: Vec<Vec<u8>>,
}

impl Depacketizer for Vp9Packet {
    /// depacketize parses the passed byte slice and stores the result in the Vp9Packet this method is called upon
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.is_empty() {
            return Err(Error::ErrShortPacket);
        }

        // One depacketizer reads a whole stream: nothing of the previous packet's descriptor
        // is left for this one. (The reference indices used to accumulate across packets, and
        // a picture group across scalability structures.)
        *self = Self::default();

        let reader = &mut packet.clone();
        let b = reader.get_u8();

        self.i = (b & 0x80) != 0;
        self.p = (b & 0x40) != 0;
        self.l = (b & 0x20) != 0;
        // "If the I bit is set to zero, then this bit MUST also be set to zero and ignored by
        // receivers" (RFC 9628 4.2).
        self.f = (b & 0x10) != 0 && self.i;
        self.b = (b & 0x08) != 0;
        self.e = (b & 0x04) != 0;
        self.v = (b & 0x02) != 0;
        self.z = (b & 0x01) != 0;

        let mut payload_index = 1;

        if self.i {
            payload_index = self.parse_picture_id(reader, payload_index)?;
        }

        if self.l {
            payload_index = self.parse_layer_info(reader, payload_index)?;
        }

        if self.f && self.p {
            payload_index = self.parse_ref_indices(reader, payload_index)?;
        }

        if self.v {
            payload_index = self.parse_ssdata(reader, payload_index)?;
        }

        Ok(packet.slice(payload_index..))
    }

    /// is_partition_head checks whether if this is a head of the VP9 partition
    ///
    /// A picture starts at a packet with `B`=1 whose frame does not depend on a lower spatial
    /// layer of the same picture: with `D`=1 the frame it depends on comes first, so a run of
    /// packets that begins there has lost it.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        let Some(&b) = payload.first() else {
            return false;
        };
        if b & 0x08 == 0 {
            return false;
        }
        if b & 0x20 != 0 {
            // The layer indices follow the picture ID (one or two octets, when I is set).
            let mut index = 1;
            if b & 0x80 != 0 {
                index += match payload.get(1) {
                    Some(m) if m & 0x80 != 0 => 2,
                    _ => 1,
                };
            }
            if payload.get(index).is_some_and(|layer| layer & 0x01 != 0) {
                return false;
            }
        }
        true
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }

    fn has_key_frames(&self) -> bool {
        true
    }

    /// The first packet of a picture ([`is_partition_head`](Depacketizer::is_partition_head):
    /// `B`=1, not dependent on a lower spatial layer) of the base spatial layer whose `P` bit
    /// is clear (RFC 9628 section 4.2: "P: Inter-picture predicted frame. When set to zero,
    /// the frame does not utilize inter-picture prediction"). An upper spatial layer's frame
    /// with `P`=0 (a layer synchronization frame) is not one: the picture's lower layers and
    /// the other layers' earlier pictures are still needed.
    fn is_key_frame_start(&self, payload: &Bytes) -> bool {
        let Some(&b) = payload.first() else {
            return false;
        };
        if b & 0x40 != 0 || !self.is_partition_head(payload) {
            return false;
        }
        if b & 0x20 != 0 {
            let mut index = 1;
            if b & 0x80 != 0 {
                index += match payload.get(1) {
                    Some(m) if m & 0x80 != 0 => 2,
                    _ => 1,
                };
            }
            // L: |  T  |U|  S  |D|
            return payload
                .get(index)
                .is_some_and(|layer| (layer >> 1) & 0x07 == 0);
        }
        true
    }
}

impl Vp9Packet {
    // Picture ID:
    //
    //      +-+-+-+-+-+-+-+-+
    // I:   |M| PICTURE ID  |   M:0 => picture id is 7 bits.
    //      +-+-+-+-+-+-+-+-+   M:1 => picture id is 15 bits.
    // M:   | EXTENDED PID  |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_picture_id(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }
        let b = reader.get_u8();
        payload_index += 1;
        // PID present?
        if (b & 0x80) != 0 {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }
            // M == 1, PID is 15bit
            self.picture_id = (((b & 0x7f) as u16) << 8) | (reader.get_u8() as u16);
            self.picture_id_15_bits = true;
            payload_index += 1;
        } else {
            self.picture_id = (b & 0x7F) as u16;
        }

        Ok(payload_index)
    }

    fn parse_layer_info(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        payload_index = self.parse_layer_info_common(reader, payload_index)?;

        if self.f {
            Ok(payload_index)
        } else {
            self.parse_layer_info_non_flexible_mode(reader, payload_index)
        }
    }

    // Layer indices (flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_common(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }
        let b = reader.get_u8();
        payload_index += 1;

        self.tid = b >> 5;
        self.u = b & 0x10 != 0;
        self.sid = (b >> 1) & 0x7;
        self.d = b & 0x01 != 0;

        // Every value of the three-bit SID is a spatial layer (RFC 9628 4.2).
        Ok(payload_index)
    }

    // Layer indices (non-flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //      |   tl0picidx   |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_non_flexible_mode(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }
        self.tl0picidx = reader.get_u8();
        payload_index += 1;
        Ok(payload_index)
    }

    // Reference indices:
    //
    //      +-+-+-+-+-+-+-+-+                P=1,F=1: At least one reference index
    // P,F: | P_DIFF      |N|  up to 3 times          has to be specified.
    //      +-+-+-+-+-+-+-+-+                    N=1: An additional P_DIFF follows
    //                                                current P_DIFF.
    //
    fn parse_ref_indices(
        &mut self,
        reader: &mut dyn Buf,
        mut payload_index: usize,
    ) -> Result<usize> {
        let mut b = 1u8;
        while (b & 0x1) != 0 {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }
            b = reader.get_u8();
            payload_index += 1;

            // RFC 9628 4.2: up to three reference indices (P_DIFF) per picture; a fourth is
            // the error, not the third. (A P_DIFF of 0 is invalid; it is kept as received for
            // the consumer to judge.)
            self.pdiff.push(b >> 1);
            if self.pdiff.len() > MAX_VP9REF_PICS {
                return Err(Error::ErrTooManyPDiff);
            }
        }

        Ok(payload_index)
    }

    // Scalability structure (SS):
    //
    //      +-+-+-+-+-+-+-+-+
    // V:   | N_S |Y|G|-|-|-|
    //      +-+-+-+-+-+-+-+-+              -|
    // Y:   |     WIDTH     | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+               . N_S + 1 times
    //      |     HEIGHT    | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+              -|
    // G:   |      N_G      | (OPTIONAL)
    //      +-+-+-+-+-+-+-+-+                           -|
    // N_G: |  T  |U| R |-|-| (OPTIONAL)                 .
    //      +-+-+-+-+-+-+-+-+              -|            . N_G times
    //      |    P_DIFF     | (OPTIONAL)    . R times    .
    //      +-+-+-+-+-+-+-+-+              -|           -|
    //
    fn parse_ssdata(&mut self, reader: &mut dyn Buf, mut payload_index: usize) -> Result<usize> {
        if reader.remaining() == 0 {
            return Err(Error::ErrShortPacket);
        }

        let b = reader.get_u8();
        payload_index += 1;

        self.ns = b >> 5;
        self.y = b & 0x10 != 0;
        // `N_S |Y|G|-|-|-|`: G is bit 3 alone. The three low bits are reserved and must not
        // be read as G (RFC 9628 4.2.1).
        self.g = b & 0x08 != 0;

        let ns = (self.ns + 1) as usize;

        if self.y {
            if reader.remaining() < 4 * ns {
                return Err(Error::ErrShortPacket);
            }

            self.width = vec![0u16; ns];
            self.height = vec![0u16; ns];
            for i in 0..ns {
                self.width[i] = reader.get_u16();
                self.height[i] = reader.get_u16();
            }
            payload_index += 4 * ns;
        }

        if self.g {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }

            self.ng = reader.get_u8();
            payload_index += 1;
        }

        for i in 0..self.ng as usize {
            if reader.remaining() == 0 {
                return Err(Error::ErrShortPacket);
            }
            let b = reader.get_u8();
            payload_index += 1;

            self.pgtid.push(b >> 5);
            self.pgu.push(b & 0x10 != 0);

            let r = ((b >> 2) & 0x3) as usize;
            if reader.remaining() < r {
                return Err(Error::ErrShortPacket);
            }

            self.pgpdiff.push(vec![]);
            for _ in 0..r {
                let b = reader.get_u8();
                payload_index += 1;

                self.pgpdiff[i].push(b);
            }
        }

        Ok(payload_index)
    }

    /// The scalability structure this packet carried (`V`=1), if any.
    pub fn scalability_structure(&self) -> Option<Vp9ScalabilityStructure> {
        if !self.v {
            return None;
        }
        Some(Vp9ScalabilityStructure {
            spatial_layers: self.ns + 1,
            resolutions: self
                .width
                .iter()
                .copied()
                .zip(self.height.iter().copied())
                .collect(),
            picture_group: (0..self.pgtid.len())
                .map(|i| Vp9PictureGroupEntry {
                    temporal_id: self.pgtid[i],
                    switching_up_point: self.pgu[i],
                    reference_diffs: self.pgpdiff[i].clone(),
                })
                .collect(),
        })
    }

    /// The picture ID of the picture `reference_diff` pictures back (a `P_DIFF` of this
    /// packet), computed modulo the width this packet's picture ID was sent in (RFC 9628
    /// section 4.2).
    pub fn referenced_picture_id(&self, reference_diff: u8) -> u16 {
        let mask = if self.picture_id_15_bits {
            0x7FFF
        } else {
            0x7F
        };
        self.picture_id.wrapping_sub(reference_diff as u16) & mask
    }
}

/// What a [`Vp9LayerFilter`] decided for one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp9Forward {
    /// Whether to forward the packet.
    pub forward: bool,
    /// The RTP marker bit to forward it with. When the layers above the selected one are
    /// dropped, the picture ends at the selected layer's last packet for this receiver, and
    /// the marker moves there (RFC 9628 section 4.1).
    pub marker: bool,
}

/// Decides which packets of a layered VP9 stream to forward for a target spatial and temporal
/// layer, from the payload descriptor alone (RFC 9628 sections 4.2 and 9).
///
/// A middlebox keeps one per receiver and gives it every packet of the stream in order. The
/// rules it applies:
///
/// * a frame above the temporal layer in use is dropped; the temporal layer goes up after a
///   forwarded picture that is a switching up point (`U`=1) or starts a key picture, and down
///   at once;
/// * of the spatial layers below the one in use, a frame is forwarded unless it says no
///   higher layer depends on it (`Z`=1);
/// * the spatial layer goes up at a frame of the wanted layer that does not predict from an
///   earlier picture (`P`=0) and whose lower-layer dependency (`D`), if any, was forwarded,
///   in a picture whose frame of the layer in use is such a frame too (a key picture): in any
///   other picture the marker has already been given to the layer in use;
/// * it goes down as soon as a frame of the lower layer is decodable for this receiver: at
///   once when the lower layers were being forwarded (full SVC), at that layer's next `P`=0
///   frame otherwise (K-SVC, simulcast in one stream), which the caller asks for with a PLI
///   or FIR when [`Vp9LayerFilter::needs_key_frame`] says so.
///
/// Nothing is forwarded before a frame the receiver can start from (`P`=0 and `D`=0). A
/// stream without layer indices (`L`=0) is forwarded whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vp9LayerFilter {
    target_sid: u8,
    target_tid: u8,
    current_sid: u8,
    current_tid: u8,
    /// Per spatial layer: the receiver was sent every frame of it (within the temporal layers
    /// in use) since one it could start from.
    decodable: [bool; 8],
    /// The picture in progress and the spatial layers of it that were forwarded (a bit mask).
    picture: Option<(Option<u16>, u8)>,
    /// The marker was forwarded for the picture in progress: nothing more of it can follow.
    picture_closed: bool,
    /// The frame in progress (its spatial layer) and what was decided for it.
    frame: Option<(u8, bool)>,
}

impl Vp9LayerFilter {
    /// A filter that selects spatial layer `target_sid` and the temporal layers up to
    /// `target_tid`.
    pub fn new(target_sid: u8, target_tid: u8) -> Self {
        Self {
            target_sid: target_sid.min(VP9_MAX_SPATIAL_ID),
            target_tid: target_tid.min(VP9_MAX_TEMPORAL_ID),
            current_sid: 0,
            current_tid: 0,
            decodable: [false; 8],
            picture: None,
            picture_closed: false,
            frame: None,
        }
    }

    /// Changes the target layers. Each takes effect at the next point where the stream allows
    /// it (see the type's description).
    pub fn set_target(&mut self, target_sid: u8, target_tid: u8) {
        self.target_sid = target_sid.min(VP9_MAX_SPATIAL_ID);
        self.target_tid = target_tid.min(VP9_MAX_TEMPORAL_ID);
        self.current_tid = self.current_tid.min(self.target_tid);
    }

    /// The target spatial and temporal layer.
    pub fn target(&self) -> (u8, u8) {
        (self.target_sid, self.target_tid)
    }

    /// The spatial and temporal layer forwarded at the moment.
    pub fn current(&self) -> (u8, u8) {
        (self.current_sid, self.current_tid)
    }

    /// Whether the selection cannot be reached without a frame the receiver can start from:
    /// nothing has been forwarded yet, or a lower spatial layer is wanted whose frames were
    /// not being forwarded. The caller should request a key frame.
    pub fn needs_key_frame(&self) -> bool {
        !self.decodable[self.current_sid as usize]
            || (self.target_sid < self.current_sid && !self.decodable[self.target_sid as usize])
    }

    /// Decides for one packet: `descriptor` is its parsed payload descriptor (a [`Vp9Packet`]
    /// after [`Depacketizer::depacketize`]) and `marker` its RTP marker bit.
    pub fn forward(&mut self, descriptor: &Vp9Packet, marker: bool) -> Vp9Forward {
        if !descriptor.l {
            // No layer indices: nothing to select on.
            return Vp9Forward {
                forward: true,
                marker,
            };
        }
        let sid = descriptor.sid;
        let picture_id = descriptor.i.then_some(descriptor.picture_id);

        // A new picture: a new picture ID or, without one, a frame that starts at a spatial
        // layer no higher than the last one seen.
        let new_picture = match (self.picture, self.frame) {
            (Some((id, _)), Some((last_sid, _))) => {
                id != picture_id || (picture_id.is_none() && descriptor.b && sid <= last_sid)
            }
            _ => true,
        };
        if new_picture {
            self.picture = Some((picture_id, 0));
            self.picture_closed = false;
            self.frame = None;
        }

        // A decision holds for all packets of a frame.
        let decided = match self.frame {
            Some((frame_sid, forward)) if frame_sid == sid && !descriptor.b => Some(forward),
            _ => None,
        };
        let forward = decided.unwrap_or_else(|| self.decide(descriptor));
        self.frame = Some((sid, forward));

        // The picture ends for this receiver at the last packet of the selected spatial layer,
        // unless a switch up may still add a frame to it: that takes a picture whose frames
        // predict from no earlier one.
        let ends_here = forward
            && descriptor.e
            && sid == self.current_sid
            && (self.current_sid >= self.target_sid || descriptor.p);
        let marker = forward && (marker || ends_here);
        self.picture_closed |= marker;
        Vp9Forward { forward, marker }
    }

    /// Decides for a frame, at its first packet.
    fn decide(&mut self, d: &Vp9Packet) -> bool {
        let sid = d.sid;
        let s = sid as usize;
        let forwarded_sids = self.picture.map_or(0, |(_, mask)| mask);
        // The frame's dependency on the layer below, in this picture, is met.
        let lower_ok = !d.d || (sid > 0 && forwarded_sids & (1 << (sid - 1)) != 0);
        let decodable = (!d.p || self.decodable[s]) && lower_ok;

        if d.tid > self.current_tid {
            // Frames in the temporal layers in use never depend on this one.
            return false;
        }

        let wanted = if sid == self.current_sid {
            true
        } else if sid < self.current_sid {
            // A reference for the layers above, or the layer a switch down is waiting for.
            !d.z || sid == self.target_sid
        } else {
            // A switch up: possible where the frame predicts from no earlier picture, unless
            // the receiver was already told the picture is complete.
            sid <= self.target_sid && !d.p && !self.picture_closed
        };
        let forward = wanted && decodable;

        if forward {
            self.decodable[s] = true;
            if let Some((_, mask)) = &mut self.picture {
                *mask |= 1 << sid;
            }
            if sid > self.current_sid || (sid == self.target_sid && sid < self.current_sid) {
                // Up at a frame that predicts from no earlier picture; down as soon as the
                // lower layer is decodable (the frames above it in this picture are dropped).
                self.current_sid = sid;
            }
            // "Subsequent pictures with temporal-layer ID values higher than T will not
            // depend on any picture before the current picture ... with a temporal-layer ID
            // value greater than T"; a key picture (it carries the SS) resets every layer.
            if d.u || (d.v && !d.p) {
                self.current_tid = self.target_tid;
            }
        } else {
            self.decodable[s] = false;
        }
        forward
    }
}
