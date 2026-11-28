//! W3C webrtc-encoded-transform section 3, the SFrame transforms: `RTCRtpSFrameEncryptor` and
//! `RTCRtpSFrameDecryptor` (and, being the same objects without an owner, `SFrameEncryptorStream`
//! and `SFrameDecryptorStream`), over [`rtci::sframe`](crate::sframe).
//!
//! The engine has no encoder or decoder, so the frames are the application's: a sender's
//! application runs [`RTCRtpSFrameEncryptor::transform`] on each encoded frame and sends the
//! result with the SFrame payload format (`rtci::rtp::codec::sframe::SFramePayloader`), a
//! receiver's application reassembles (`SFrameReassembler`) and runs
//! [`RTCRtpSFrameDecryptor::transform`]. Setting such a transform on a sender or a receiver is
//! [`RTCRtpTransceiver::set_transform_use_sframe`](crate::rtp_transceiver::RTCRtpTransceiver::set_transform_use_sframe)
//! `(true)`: `[[useSFrame]]` (the constructors' "Set this.\[\[useSFrame\]\] to true").
//!
//! RFC 9605 section 6.1.3: "the sender MUST encapsulate each layer in a different SFrame
//! ciphertext", so that a forwarder can drop layers. A temporal layer is a whole picture, one
//! frame, one ciphertext. The spatial layers of a VP9 or AV1 picture come out of the encoder as
//! one access unit (a superframe, a temporal unit): once the application declares the stream's
//! scalability mode ([`RTCRtpSFrameEncryptor::set_scalability`]), `transform` refuses a unit
//! of several spatial layers, [`RTCRtpSFrameEncryptor::transform_access_unit`] splits it and
//! encrypts each layer on its own, and [`join_layer_frames`] puts a receiver's decrypted
//! layers back together for the decoder.
//!
//! # Scalable video: how an application hands layer frames
//!
//! RFC 9605 section 4.2: a per-frame ciphertext spans several packets, its header in the first
//! and its authentication tag in the last. A forwarder that drops the packets of one layer
//! from a ciphertext holding two leaves a truncated ciphertext that no longer authenticates,
//! so the duty of section 6.1.3 is the sender's: one ciphertext per layer, each sent as its
//! own SFrame RTP frame with the Dependency Descriptor of that layer frame (its own frame
//! number and template: `spatial_id`, `temporal_id`).
//!
//! What a layer is, per codec:
//!
//! - VP8, H.264: temporal layers only (the engine has no H.264 SVC). Each encoded frame is one
//!   picture of one temporal layer: call [`RTCRtpSFrameEncryptor::transform`] once per frame.
//!   `set_scalability` refuses a mode of several spatial layers for them.
//! - VP9: a temporal layer is a picture; the spatial layers of a picture are the frames of
//!   its superframe (VP9 bitstream specification Annex B), lowest first. The bitstream names
//!   no spatial id: a frame's position is its layer.
//! - AV1: a temporal unit has one `temporal_id`; its spatial layers are its OBUs grouped by
//!   the extension header's `spatial_id`.
//!
//! A sender of VP9 or AV1 spatial layers declares the stream once
//! (`set_scalability("video/VP9", Some(mode))`) and then either
//!
//! 1. hands the frame of one layer at a time, as an encoder that emits per-layer frames (and
//!    a browser's encoded transform) does: [`RTCRtpSFrameEncryptor::transform_layer_frame`]
//!    with the Dependency Descriptor template the frame is written with (for AV1 the OBUs'
//!    ids are checked against it), or `transform`; or
//! 2. hands the encoder's access unit (the superframe, the temporal unit):
//!    [`RTCRtpSFrameEncryptor::transform_access_unit`] splits it and returns one
//!    [`RTCSFrameLayer`] per spatial layer, lowest first, each with distinct SFrame counters;
//!    the application sends each as its own frame under that layer's descriptor.
//!
//! With the mode declared, `transform` refuses an access unit of several spatial layers
//! (TypeError): it returns one ciphertext and so could only be labelled with one layer's
//! descriptor. Without a declared mode nothing is parsed and every frame is encrypted as it
//! is; the engine does not own the encryptor, so the check is only as good as the declaration.
//! Per-packet SFrame needs no split (the VP9 and AV1 payload formats never put two layers in
//! one packet).
//!
//! A receiver decrypts each forwarded layer frame on its own, groups the plaintexts of one RTP
//! timestamp by the frame metadata's `spatial_index` (the Dependency Descriptor's), lowest
//! first, and passes them to [`join_layer_frames`] for the access unit its decoder takes.

use crate::sframe::{CipherSuite, ErrorKind, SFrameContext};
use bytes::{Bytes, BytesMut};
use rtp::codec::dependency_descriptor::FrameDependencyTemplate;
use rtp::codec::svc::ScalabilityMode;
use shared::error::{Error, Result};

/// `SFrameType`: how a sender's SFrame ciphertext is carried (draft-ietf-avtcore-rtp-sframe:
/// one SFrame per media frame, or one per RTP packet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RTCSFrameType {
    /// "per-frame", the default.
    #[default]
    PerFrame,
    /// "per-packet".
    PerPacket,
}

/// `SFrameTransformErrorEventType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RTCSFrameTransformErrorType {
    /// "authentication": the authentication tag did not validate.
    Authentication,
    /// "keyID": no decryption key for the frame's key id.
    KeyId,
    /// "syntax": the data does not follow the SFrame format.
    Syntax,
}

/// `SFrameTransformErrorEvent`: why a frame could not be decrypted, with the key id when the
/// header named one. The frame is the one the application passed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCSFrameTransformError {
    /// `errorType`.
    pub error_type: RTCSFrameTransformErrorType,
    /// `keyID`.
    pub key_id: Option<u64>,
}

fn sframe_error(error: crate::sframe::Error) -> Error {
    Error::Other(format!("sframe: {error}"))
}

/// A codec whose access units hold several spatial layers, each a frame of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayeredCodec {
    /// A superframe (VP9 bitstream specification Annex B), one frame per spatial layer, lowest
    /// first.
    Vp9,
    /// A temporal unit, the layer of each OBU in its extension header.
    Av1,
}

impl LayeredCodec {
    fn from_mime_type(mime_type: &str) -> Option<Self> {
        match mime_type.to_ascii_lowercase().as_str() {
            "video/vp9" => Some(Self::Vp9),
            "video/av1" => Some(Self::Av1),
            _ => None,
        }
    }
}

/// One spatial layer of an access unit as its own SFrame ciphertext (RFC 9605 section 6.1.3),
/// from [`RTCRtpSFrameEncryptor::transform_access_unit`]. Each is sent as its own SFrame RTP
/// frame, with the Dependency Descriptor of its layer frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RTCSFrameLayer {
    /// The layer: for AV1 the `spatial_id` of its OBUs, for VP9 its position in the
    /// superframe.
    pub spatial_id: u8,
    /// The layer's SFrame ciphertext.
    pub ciphertext: Vec<u8>,
}

/// `RTCRtpSFrameEncryptor` (and `SFrameEncryptorStream`): SFrame-encrypts the frames of a
/// sender with the cipher suite of its options and the key `setEncryptionKey` set.
pub struct RTCRtpSFrameEncryptor {
    context: SFrameContext,
    sframe_type: RTCSFrameType,
    key_id: Option<u64>,
    /// The declared codec and number of spatial layers, when there is more than one, and
    /// whether the layers are independent (an "S" mode).
    layering: Option<(LayeredCodec, u8, bool)>,
}

impl RTCRtpSFrameEncryptor {
    /// `new RTCRtpSFrameEncryptor(options)`: the SFrame initialization algorithm with
    /// `cipherSuite` and `type`.
    ///
    /// # Errors
    ///
    /// When the default crypto provider is missing or cannot do `cipher_suite`.
    pub fn new(cipher_suite: CipherSuite, sframe_type: RTCSFrameType) -> Result<Self> {
        Ok(Self {
            context: SFrameContext::with_default_provider(cipher_suite).map_err(sframe_error)?,
            sframe_type,
            key_id: None,
            layering: None,
        })
    }

    /// `[[cipherSuite]]`.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite()
    }

    /// The `type` of the options: per-frame or per-packet sending.
    pub fn sframe_type(&self) -> RTCSFrameType {
        self.sframe_type
    }

    /// `setEncryptionKey(key, keyId)`: frames are encrypted with `key` under `key_id` from now
    /// on (RFC 9605 section 4.4: the base key, from which the SFrame key and salt derive).
    ///
    /// # Errors
    ///
    /// An empty key, or a key id that was used for sending before (a new key needs a new
    /// id: reusing one would repeat nonces, RFC 9605 section 9.1).
    pub fn set_encryption_key(&mut self, key: &[u8], key_id: u64) -> Result<()> {
        self.context
            .add_send_key(key_id, key)
            .map_err(sframe_error)?;
        if let Some(previous) = self.key_id.replace(key_id)
            && previous != key_id
        {
            self.context.remove_key(previous);
        }
        Ok(())
    }

    /// The SFrame transform algorithm for the "encrypt" role: `frame` (an encoded frame's
    /// data, or the payload of one packet for per-packet sending) as an SFrame ciphertext.
    ///
    /// # Errors
    ///
    /// `InvalidStateError` before `setEncryptionKey`; a key whose counter is exhausted.
    /// `TypeError` when the declared scalability mode has several spatial layers and `frame`
    /// holds more than one of them (RFC 9605 section 6.1.3: each layer is its own ciphertext;
    /// [`transform_access_unit`](Self::transform_access_unit) splits it), or cannot be read as
    /// the declared codec.
    pub fn transform(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        let key_id = self.key_id.ok_or(Error::InvalidStateError)?;
        // Without a declared mode of several spatial layers (or per packet) a frame is one
        // layer as it is: nothing to parse, and the ciphertext is the one before RFC 9605
        // section 6.1.3 was checked.
        if self.layering.is_some() && self.sframe_type == RTCSFrameType::PerFrame {
            let layers = self.layers(frame)?.len();
            if layers > 1 {
                return Err(several_layers(layers));
            }
        }
        self.context
            .encrypt(key_id, b"", frame)
            .map_err(sframe_error)
    }

    /// Declares the stream the frames are of: its codec (`mime_type`, as in the sender's
    /// negotiated codec) and its scalability mode (`None` for none). With a mode of more than
    /// one spatial layer the encryptor checks that each ciphertext holds one layer (RFC 9605
    /// section 6.1.3): [`transform`](Self::transform) refuses a frame of several, and
    /// [`transform_access_unit`](Self::transform_access_unit) splits one.
    ///
    /// # Errors
    ///
    /// `TypeError` for a mode of several spatial layers with a codec other than VP9 and AV1,
    /// the codecs that carry spatial layers (webrtc-svc section 5).
    pub fn set_scalability(
        &mut self,
        mime_type: &str,
        mode: Option<ScalabilityMode>,
    ) -> Result<()> {
        self.layering = match mode {
            Some(mode) if mode.spatial_layers() > 1 => {
                let codec = LayeredCodec::from_mime_type(mime_type).ok_or_else(|| {
                    Error::TypeError(format!("{mime_type} cannot carry scalability mode {mode}"))
                })?;
                Some((codec, mode.spatial_layers(), mode.is_simulcast()))
            }
            _ => None,
        };
        Ok(())
    }

    /// RFC 9605 section 6.1.3 for an access unit holding all the spatial layers of a picture
    /// (a VP9 superframe, an AV1 temporal unit): the unit split into its layers, lowest
    /// first, each encrypted on its own. Without a declared mode of several spatial layers
    /// the unit is one layer, encrypted as [`transform`](Self::transform) does.
    ///
    /// For an AV1 "S" mode (independent layers, simulcast in one stream) a key picture's
    /// sequence header is repeated in front of every layer that has none (AV1 RTP section
    /// 6.1, SHOULD), so that a forwarder can keep any one layer. With inter-layer prediction
    /// ("L" modes) the base layer's is enough and nothing is added. A VP9 superframe is split
    /// as it is: in VP9 each layer frame carries its own uncompressed header.
    ///
    /// # Errors
    ///
    /// As [`transform`](Self::transform); `TypeError` for a unit that cannot be read as the
    /// declared codec, or a VP9 superframe of more frames than the mode has spatial layers.
    pub fn transform_access_unit(&mut self, unit: &[u8]) -> Result<Vec<RTCSFrameLayer>> {
        let key_id = self.key_id.ok_or(Error::InvalidStateError)?;
        self.layers(unit)?
            .into_iter()
            .map(|(spatial_id, data)| {
                Ok(RTCSFrameLayer {
                    spatial_id,
                    ciphertext: self
                        .context
                        .encrypt(key_id, b"", &data)
                        .map_err(sframe_error)?,
                })
            })
            .collect()
    }

    /// [`transform`](Self::transform) for the frame of one layer, with the Dependency
    /// Descriptor template it is described by (`layer`, the one given to the descriptor
    /// writer). With a declared mode of several spatial layers the frame must hold one layer,
    /// and for AV1 its OBUs must be of the template's spatial and temporal layer.
    ///
    /// # Errors
    ///
    /// As [`transform`](Self::transform); `TypeError` for a frame of another layer than the
    /// template's, or a template above the declared spatial layers.
    pub fn transform_layer_frame(
        &mut self,
        frame: &[u8],
        layer: &FrameDependencyTemplate,
    ) -> Result<Vec<u8>> {
        if let Some((codec, spatial_layers, _)) = self.layering {
            if layer.spatial_id >= spatial_layers {
                return Err(Error::TypeError(format!(
                    "spatial layer {} of a mode of {spatial_layers}",
                    layer.spatial_id
                )));
            }
            if codec == LayeredCodec::Av1 {
                let layers = rtp::codec::av1::split_temporal_unit(&Bytes::copy_from_slice(frame))
                    .map_err(unreadable)?;
                if let [only] = layers.as_slice()
                    && (only.spatial_id, only.temporal_id) != (layer.spatial_id, layer.temporal_id)
                {
                    return Err(Error::TypeError(format!(
                        "an AV1 frame of layer S{}T{} described as S{}T{}",
                        only.spatial_id, only.temporal_id, layer.spatial_id, layer.temporal_id
                    )));
                }
            }
        }
        self.transform(frame)
    }

    /// The spatial layers of `unit` under the declared mode: one, the unit itself, without a
    /// mode of several. Per-packet SFrame encrypts RTP payloads, and the VP9 and AV1 payload
    /// formats never put two layers in one packet (RFC 9628 section 4.2, AV1 RTP section 5):
    /// a payload is one layer.
    fn layers(&self, unit: &[u8]) -> Result<Vec<(u8, Bytes)>> {
        let whole = || vec![(0, Bytes::copy_from_slice(unit))];
        let Some((codec, spatial_layers, simulcast)) = self.layering else {
            return Ok(whole());
        };
        if self.sframe_type == RTCSFrameType::PerPacket {
            return Ok(whole());
        }
        let unit = Bytes::copy_from_slice(unit);
        let layers: Vec<(u8, Bytes)> = match codec {
            LayeredCodec::Vp9 => {
                let frames = rtp::codec::vp9::split_superframe(&unit).map_err(unreadable)?;
                if frames.len() > spatial_layers as usize {
                    return Err(Error::TypeError(format!(
                        "a VP9 superframe of {} frames in a mode of {spatial_layers} spatial layers",
                        frames.len()
                    )));
                }
                (0u8..).zip(frames).collect()
            }
            LayeredCodec::Av1 => {
                let mut layers = rtp::codec::av1::split_temporal_unit(&unit).map_err(unreadable)?;
                if simulcast {
                    rtp::codec::av1::repeat_sequence_header_per_layer(&mut layers)
                        .map_err(unreadable)?;
                }
                layers
                    .into_iter()
                    .map(|layer| (layer.spatial_id, layer.data))
                    .collect()
            }
        };
        Ok(if layers.is_empty() { whole() } else { layers })
    }
}

fn several_layers(count: usize) -> Error {
    Error::TypeError(format!(
        "a frame of {count} spatial layers: RFC 9605 section 6.1.3 puts each layer in its own \
         SFrame ciphertext (transform_access_unit splits the access unit)"
    ))
}

fn unreadable(error: Error) -> Error {
    Error::TypeError(format!("the frame is not of the declared codec: {error}"))
}

/// The decrypted layers of one picture (one RTP timestamp), lowest first, as the access unit
/// the decoder of `mime_type` takes: for VP9 a superframe (Annex B; one layer is the frame
/// itself), for AV1 the layers' OBUs one after the other. A receiver whose forwarder dropped
/// the upper layers passes the layers it has. For other codecs, one layer only.
///
/// # Errors
///
/// No layer; for VP9 more than eight; several for a codec without spatial layers.
pub fn join_layer_frames(mime_type: &str, layers: &[Bytes]) -> Result<Bytes> {
    match (LayeredCodec::from_mime_type(mime_type), layers) {
        (_, []) => Err(Error::TypeError("no layer to join".to_owned())),
        (Some(LayeredCodec::Vp9), _) => rtp::codec::vp9::join_superframe(layers),
        (Some(LayeredCodec::Av1), _) => {
            let mut unit = BytesMut::with_capacity(layers.iter().map(Bytes::len).sum());
            for layer in layers {
                unit.extend_from_slice(layer);
            }
            Ok(unit.freeze())
        }
        (None, [layer]) => Ok(layer.clone()),
        (None, _) => Err(Error::TypeError(format!(
            "{mime_type} has no spatial layers to join"
        ))),
    }
}

/// `RTCRtpSFrameDecryptor` (and `SFrameDecryptorStream`): decrypts a receiver's SFrame
/// ciphertexts with the keys `addDecryptionKey` added.
pub struct RTCRtpSFrameDecryptor {
    context: SFrameContext,
}

impl RTCRtpSFrameDecryptor {
    /// `new RTCRtpSFrameDecryptor(options)`.
    ///
    /// # Errors
    ///
    /// When the default crypto provider is missing or cannot do `cipher_suite`.
    pub fn new(cipher_suite: CipherSuite) -> Result<Self> {
        Ok(Self {
            context: SFrameContext::with_default_provider(cipher_suite).map_err(sframe_error)?,
        })
    }

    /// `[[cipherSuite]]`.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.context.cipher_suite()
    }

    /// `addDecryptionKey(key, keyId)`.
    ///
    /// # Errors
    ///
    /// An empty key, or a key id already used for sending in this context.
    pub fn add_decryption_key(&mut self, key: &[u8], key_id: u64) -> Result<()> {
        self.context.add_recv_key(key_id, key).map_err(sframe_error)
    }

    /// `removeDecryptionKey(keyId)`: frames under `key_id` no longer decrypt. Whether there
    /// was such a key.
    pub fn remove_decryption_key(&mut self, key_id: u64) -> bool {
        self.context.remove_key(key_id)
    }

    /// The SFrame transform algorithm for the "decrypt" role: the plaintext of `frame`, or
    /// the `error` event the spec fires for it (`authentication`, `keyID` or `syntax`). A frame
    /// that fails otherwise (a replayed counter) is dropped with no event: `None` in both.
    pub fn transform(
        &mut self,
        frame: &[u8],
    ) -> std::result::Result<Vec<u8>, Option<RTCSFrameTransformError>> {
        self.context.decrypt(b"", frame).map_err(|error| {
            error.kind().map(|kind| RTCSFrameTransformError {
                error_type: match kind {
                    ErrorKind::Authentication => RTCSFrameTransformErrorType::Authentication,
                    ErrorKind::KeyId => RTCSFrameTransformErrorType::KeyId,
                    ErrorKind::Syntax => RTCSFrameTransformErrorType::Syntax,
                },
                key_id: error.key_id(),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An AV1 OBU of type `obu_type` with a size field, in layer `(temporal_id, spatial_id)`.
    fn av1_obu(obu_type: u8, layer: Option<(u8, u8)>, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![obu_type << 3 | 0b010 | if layer.is_some() { 0b100 } else { 0 }];
        if let Some((temporal_id, spatial_id)) = layer {
            out.push(temporal_id << 5 | spatial_id << 3);
        }
        out.push(payload.len() as u8);
        out.extend_from_slice(payload);
        out
    }

    fn mode(name: &str) -> Option<ScalabilityMode> {
        Some(name.parse().expect("a scalability mode"))
    }

    /// RFC 9605 section 6.1.3 with a declared mode of two spatial layers: `transform` refuses a
    /// VP9 superframe or an AV1 temporal unit of two layers, `transform_access_unit` gives one
    /// ciphertext per layer, each decrypting to that layer's data, and `join_layer_frames`
    /// rebuilds the unit from them. One layer, and a temporal-only mode (a superframe of a
    /// hidden and a shown frame of one layer), pass `transform` as they are.
    #[test]
    fn each_spatial_layer_is_its_own_ciphertext() -> Result<()> {
        let suite = CipherSuite::Aes128GcmSha256_128;
        let vp9_layers = [Bytes::from(vec![0x82u8; 40]), Bytes::from(vec![0x83u8; 90])];
        let superframe = rtp::codec::vp9::join_superframe(&vp9_layers)?;
        let av1_layers = [
            Bytes::from([av1_obu(2, None, &[]), av1_obu(6, Some((0, 0)), &[0xa0; 30])].concat()),
            Bytes::from(av1_obu(6, Some((0, 1)), &[0xa1; 60])),
        ];
        let temporal_unit = Bytes::from(av1_layers.concat());

        for (mime, unit, layers) in [
            ("video/VP9", &superframe, &vp9_layers),
            ("video/AV1", &temporal_unit, &av1_layers),
        ] {
            // A receiver per sender: both senders start at counter 0 (the replay window).
            let mut decryptor = RTCRtpSFrameDecryptor::new(suite)?;
            decryptor.add_decryption_key(&[5u8; 16], 1)?;
            let mut encryptor = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::PerFrame)?;
            encryptor.set_encryption_key(&[5u8; 16], 1)?;
            // Before a mode is declared the unit is one frame.
            assert_eq!(encryptor.transform_access_unit(unit)?.len(), 1, "{mime}");
            encryptor.set_scalability(mime, mode("L2T1"))?;
            assert!(
                matches!(encryptor.transform(unit), Err(Error::TypeError(_))),
                "{mime}: a unit of two layers is refused"
            );
            let encrypted = encryptor.transform_access_unit(unit)?;
            assert_eq!(
                encrypted.iter().map(|l| l.spatial_id).collect::<Vec<_>>(),
                vec![0, 1],
                "{mime}"
            );
            // Two ciphertexts, two SFrame headers: the sender's key id, a counter each.
            let headers: Vec<crate::sframe::Header> = encrypted
                .iter()
                .map(|l| crate::sframe::Header::decode(&l.ciphertext).map(|(header, _)| header))
                .collect::<std::result::Result<_, _>>()
                .map_err(sframe_error)?;
            assert!(headers.iter().all(|h| h.kid == 1), "{mime}: {headers:?}");
            assert_eq!(headers[1].ctr, headers[0].ctr + 1, "{mime}: {headers:?}");
            let plaintexts: Vec<Bytes> = encrypted
                .iter()
                .map(|l| decryptor.transform(&l.ciphertext).map(Bytes::from))
                .collect::<std::result::Result<_, _>>()
                .expect("each layer decrypts");
            assert_eq!(plaintexts, layers.to_vec(), "{mime}");
            assert_eq!(&join_layer_frames(mime, &plaintexts)?, unit, "{mime}");
            assert_eq!(join_layer_frames(mime, &plaintexts[..1])?, layers[0]);
            // A single layer passes transform.
            let ciphertext = encryptor.transform(&layers[0])?;
            assert_eq!(
                decryptor.transform(&ciphertext).ok(),
                Some(layers[0].to_vec())
            );
        }

        // Temporal scalability only: a VP9 superframe (here a hidden and a shown frame) is one
        // layer and one ciphertext.
        let mut encryptor = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::PerFrame)?;
        encryptor.set_encryption_key(&[5u8; 16], 2)?;
        encryptor.set_scalability("video/VP9", mode("L1T3"))?;
        encryptor.transform(&superframe)?;
        // Per-packet SFrame: a payload is one layer (the payload formats never mix them).
        let mut per_packet = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::PerPacket)?;
        per_packet.set_encryption_key(&[5u8; 16], 3)?;
        per_packet.set_scalability("video/VP9", mode("L2T1"))?;
        per_packet.transform(&superframe)?;
        // AV1 S2T1: the key picture's sequence header leads each layer's plaintext.
        let sequence_header = av1_obu(1, None, &[0x0a; 6]);
        let s_unit = [
            av1_obu(2, None, &[]),
            sequence_header.clone(),
            av1_obu(6, Some((0, 0)), &[0xc0; 10]),
            av1_obu(6, Some((0, 1)), &[0xc1; 10]),
        ]
        .concat();
        let mut s_mode = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::PerFrame)?;
        s_mode.set_encryption_key(&[5u8; 16], 4)?;
        s_mode.set_scalability("video/AV1", mode("S2T1"))?;
        let mut s_decryptor = RTCRtpSFrameDecryptor::new(suite)?;
        s_decryptor.add_decryption_key(&[5u8; 16], 4)?;
        let layers = s_mode.transform_access_unit(&s_unit)?;
        assert_eq!(layers.len(), 2);
        let upper = s_decryptor
            .transform(&layers[1].ciphertext)
            .expect("layer 1 decrypts");
        assert!(
            upper.starts_with(&sequence_header),
            "an S mode's upper layer starts with the sequence header"
        );
        // VP8 carries no spatial layers.
        assert!(matches!(
            per_packet.set_scalability("video/VP8", mode("L2T1")),
            Err(Error::TypeError(_))
        ));
        Ok(())
    }

    /// `transform_layer_frame`: one layer frame with its descriptor template; an AV1 frame of
    /// another layer than the template's, a frame of two layers, or a template above the
    /// mode's layers is refused.
    #[test]
    fn a_layer_frame_must_be_the_layer_its_descriptor_names() -> Result<()> {
        let suite = CipherSuite::Aes128GcmSha256_128;
        let mut encryptor = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::PerFrame)?;
        encryptor.set_encryption_key(&[6u8; 16], 1)?;
        encryptor.set_scalability("video/AV1", mode("L2T3"))?;
        let template = |spatial_id, temporal_id| FrameDependencyTemplate {
            spatial_id,
            temporal_id,
            ..Default::default()
        };
        let s1t2 = av1_obu(6, Some((2, 1)), &[0xb1; 20]);
        encryptor.transform_layer_frame(&s1t2, &template(1, 2))?;
        for (frame, layer) in [
            (s1t2.clone(), template(1, 1)),
            (s1t2.clone(), template(0, 2)),
            (
                [av1_obu(6, Some((2, 0)), &[1; 5]), s1t2.clone()].concat(),
                template(0, 2),
            ),
            (s1t2, template(2, 2)),
        ] {
            assert!(matches!(
                encryptor.transform_layer_frame(&frame, &layer),
                Err(Error::TypeError(_))
            ));
        }
        Ok(())
    }

    /// Streams without spatial layers are untouched by RFC 9605 section 6.1.3's check: with no
    /// declared mode, a mode of one spatial layer (VP8, H.264 and VP9 temporal layers), or
    /// per-packet SFrame, `transform` and `transform_access_unit` give byte for byte what the
    /// SFrame context gives for the frame as it is (the encryptor's code before the check).
    #[test]
    fn without_spatial_layers_the_ciphertext_is_the_frame_encrypted_as_it_is() -> Result<()> {
        let suite = CipherSuite::Aes128GcmSha256_128;
        let key = [7u8; 16];
        let superframe = rtp::codec::vp9::join_superframe(&[
            Bytes::from(vec![0x82u8; 40]),
            Bytes::from(vec![0x83u8; 90]),
        ])?;
        let temporal_unit = [
            av1_obu(2, None, &[]),
            av1_obu(6, Some((0, 0)), &[0xa0; 30]),
            av1_obu(6, Some((0, 1)), &[0xa1; 60]),
        ]
        .concat();
        let frames: [&[u8]; 4] = [
            b"an encoded frame",
            &superframe,
            &temporal_unit,
            &[0x12; 300],
        ];
        let cases: [(RTCSFrameType, &str, Option<Option<ScalabilityMode>>); 7] = [
            (RTCSFrameType::PerFrame, "video/VP9", None),
            (RTCSFrameType::PerFrame, "video/AV1", Some(None)),
            (RTCSFrameType::PerFrame, "video/VP9", mode("L1T3").map(Some)),
            (RTCSFrameType::PerFrame, "video/VP8", mode("L1T3").map(Some)),
            (
                RTCSFrameType::PerFrame,
                "video/H264",
                mode("L1T2").map(Some),
            ),
            (
                RTCSFrameType::PerPacket,
                "video/AV1",
                mode("L3T3").map(Some),
            ),
            (
                RTCSFrameType::PerPacket,
                "video/VP9",
                mode("S2T1").map(Some),
            ),
        ];
        for (sframe_type, mime, declared) in cases {
            let mut encryptor = RTCRtpSFrameEncryptor::new(suite, sframe_type)?;
            encryptor.set_encryption_key(&key, 9)?;
            if let Some(declared) = declared {
                encryptor.set_scalability(mime, declared)?;
            }
            let mut reference =
                SFrameContext::with_default_provider(suite).map_err(sframe_error)?;
            reference.add_send_key(9, &key).map_err(sframe_error)?;
            for frame in frames {
                let expected = reference.encrypt(9, b"", frame).map_err(sframe_error)?;
                assert_eq!(
                    encryptor.transform(frame)?,
                    expected,
                    "{sframe_type:?} {mime} {declared:?}"
                );
                let expected = reference.encrypt(9, b"", frame).map_err(sframe_error)?;
                assert_eq!(
                    encryptor.transform_access_unit(frame)?,
                    vec![RTCSFrameLayer {
                        spatial_id: 0,
                        ciphertext: expected
                    }],
                    "{sframe_type:?} {mime} {declared:?}"
                );
            }
        }
        Ok(())
    }

    /// The codecs that carry spatial layers (webrtc-svc section 5) are VP9 and AV1: a mode of
    /// several spatial layers is refused for VP8 and for H.264 (the engine has no H.264 SVC),
    /// whose temporal modes are accepted (each frame is one temporal layer already).
    #[test]
    fn spatial_modes_are_declared_for_vp9_and_av1_only() -> Result<()> {
        let suite = CipherSuite::Aes128GcmSha256_128;
        let mut encryptor = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::PerFrame)?;
        for (mime, name, accepted) in [
            ("video/VP8", "L1T3", true),
            ("video/VP8", "L2T1", false),
            ("video/VP8", "S2T1", false),
            ("video/H264", "L1T3", true),
            ("video/H264", "L3T3", false),
            ("video/H264", "S2T3", false),
            ("video/VP9", "L3T3", true),
            ("video/VP9", "S3T3", true),
            ("video/AV1", "L2T2", true),
            ("video/av1", "S2T3", true),
        ] {
            assert_eq!(
                encryptor.set_scalability(mime, mode(name)).is_ok(),
                accepted,
                "{mime} {name}"
            );
        }
        Ok(())
    }

    /// webrtc-encoded-transform 3: an encryptor and a decryptor of one cipher suite round-trip
    /// a frame under the key id the encryptor was given; the decryptor reports `keyID` for an
    /// unknown key (with the id), `authentication` for a tampered frame and `syntax` for data
    /// that is not SFrame; a removed key no longer decrypts; no key, no encryption.
    #[test]
    fn sframe_transforms_encrypt_decrypt_and_report_the_three_errors() -> Result<()> {
        let suite = CipherSuite::Aes128GcmSha256_128;
        let mut encryptor = RTCRtpSFrameEncryptor::new(suite, RTCSFrameType::default())?;
        assert_eq!(encryptor.sframe_type(), RTCSFrameType::PerFrame);
        assert!(matches!(
            encryptor.transform(b"frame"),
            Err(Error::InvalidStateError)
        ));
        encryptor.set_encryption_key(&[7u8; 16], 3)?;
        let ciphertext = encryptor.transform(b"an encoded frame")?;
        assert_ne!(ciphertext, b"an encoded frame".to_vec());

        let mut decryptor = RTCRtpSFrameDecryptor::new(suite)?;
        assert_eq!(
            decryptor.transform(&ciphertext),
            Err(Some(RTCSFrameTransformError {
                error_type: RTCSFrameTransformErrorType::KeyId,
                key_id: Some(3),
            }))
        );
        decryptor.add_decryption_key(&[7u8; 16], 3)?;
        assert_eq!(
            decryptor.transform(&ciphertext),
            Ok(b"an encoded frame".to_vec())
        );

        let mut tampered = encryptor.transform(b"another frame")?;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            decryptor
                .transform(&tampered)
                .map_err(|e| e.map(|e| e.error_type)),
            Err(Some(RTCSFrameTransformErrorType::Authentication))
        );
        assert_eq!(
            decryptor
                .transform(&[])
                .map_err(|e| e.map(|e| e.error_type)),
            Err(Some(RTCSFrameTransformErrorType::Syntax))
        );

        assert!(decryptor.remove_decryption_key(3));
        let next = encryptor.transform(b"a third frame")?;
        assert_eq!(
            decryptor
                .transform(&next)
                .map_err(|e| e.map(|e| e.error_type)),
            Err(Some(RTCSFrameTransformErrorType::KeyId))
        );

        // A new key under a new id: frames go under it.
        encryptor.set_encryption_key(&[9u8; 16], 4)?;
        decryptor.add_decryption_key(&[9u8; 16], 4)?;
        let rekeyed = encryptor.transform(b"after the new key")?;
        assert_eq!(
            decryptor.transform(&rekeyed),
            Ok(b"after the new key".to_vec())
        );
        Ok(())
    }
}
