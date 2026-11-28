//! RTP sender module providing WebRTC RTPSender functionality.
//!
//! This module implements the RTPSender interface which controls how media tracks
//! are encoded and transmitted to remote peers.
//!
//! # Overview
//!
//! An RTP sender manages the transmission of a single media track, providing control over:
//! - Codec selection and parameters
//! - Encoding parameters (bitrate, resolution, framerate)
//! - Simulcast and layered encoding configurations
//! - Direct RTP/RTCP packet transmission
//!
//! # Examples
//!
//! ## Getting the sender's track
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::RTCRtpSenderId;
//! # fn example(sender_id: RTCRtpSenderId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Get sender and access its track
//! if let Some(sender) = peer_connection.rtp_sender(sender_id) {
//!     // `None` for a sender without a track (W3C `track` is nullable).
//!     if let Some(track) = sender.track() {
//!         println!("Track ID: {}", track.track_id());
//!         println!("Track kind: {:?}", track.kind());
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting and modifying send parameters
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::RTCRtpSenderId;
//! # fn example(sender_id: RTCRtpSenderId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     // Get current parameters
//!     let mut params = sender.get_parameters().clone();
//!     
//!     // Modify encoding parameters
//!     for encoding in &mut params.encodings {
//!         encoding.max_bitrate = 1_000_000; // 1 Mbps
//!         encoding.max_framerate = Some(30.0);
//!     }
//!     
//!     // Apply the changes
//!     sender.set_parameters(params, None)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Replacing a track
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::media_stream::MediaStreamTrack;
//! # use rtci::rtp_transceiver::RTCRtpSenderId;
//! # fn example(
//! #     sender_id: RTCRtpSenderId,
//! #     new_track: MediaStreamTrack
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     // Replace with new track (same kind required); `None` stops sending.
//!     sender.replace_track(Some(new_track))?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Writing raw RTP packets
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::rtp_transceiver::RTCRtpSenderId;
//! # use rtp::packet::Packet;
//! # use shared::error::Error;
//! # fn example(
//! #     sender_id: RTCRtpSenderId,
//! #     mut rtp_packet: Packet
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! if let Some(mut sender) = peer_connection.rtp_sender(sender_id) {
//!     // Write RTP packet directly
//!     // The sender will set the correct payload type and SSRC
//!     rtp_packet.header.ssrc = sender
//!         .ssrcs()
//!         .last()
//!         .ok_or(Error::ErrSenderWithNoSSRCs)?;
//!     sender.write_rtp(Instant::now(), rtp_packet)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Configuring simulcast with transceiver init
//!
//! ```no_run
//! # use std::time::Instant;
//! # use rtci::peer_connection::RTCPeerConnectionBuilder;
//! # use rtci::media_stream::MediaStreamTrack;
//! # use rtci::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # use rtci::rtp_transceiver::rtp_sender::{
//! #     RTCRtpEncodingParameters, RTCRtpCodingParameters
//! # };
//! # fn example(video_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
//!
//! // Configure simulcast with three layers
//! let mut init = RTCRtpTransceiverInit {
//!     direction: RTCRtpTransceiverDirection::Sendrecv,
//!     ..Default::default()
//! };
//!
//! // High quality layer
//! init.send_encodings.push(RTCRtpEncodingParameters {
//!     rtp_coding_parameters: RTCRtpCodingParameters {
//!         rid: "h".to_string(),
//!         ..Default::default()
//!     },
//!     max_bitrate: 2_000_000, // 2 Mbps
//!     scale_resolution_down_by: Some(1.0),
//!     ..Default::default()
//! });
//!
//! // Medium quality layer
//! init.send_encodings.push(RTCRtpEncodingParameters {
//!     rtp_coding_parameters: RTCRtpCodingParameters {
//!         rid: "m".to_string(),
//!         ..Default::default()
//!     },
//!     max_bitrate: 1_000_000, // 1 Mbps
//!     scale_resolution_down_by: Some(2.0),
//!     ..Default::default()
//! });
//!
//! // Low quality layer
//! init.send_encodings.push(RTCRtpEncodingParameters {
//!     rtp_coding_parameters: RTCRtpCodingParameters {
//!         rid: "l".to_string(),
//!         ..Default::default()
//!     },
//!     max_bitrate: 500_000, // 500 kbps
//!     scale_resolution_down_by: Some(4.0),
//!     ..Default::default()
//! });
//!
//! peer_connection.add_transceiver_from_track(video_track, Some(init))?;
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! * [W3C RTCRtpSender](https://www.w3.org/TR/webrtc/#rtcrtpsender-interface)
//! * [MDN RTCRtpSender](https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender)

#[cfg(test)]
mod rtp_sender_test;

pub mod dtmf;
pub(crate) mod internal;
pub(crate) mod rtcp_parameters;
pub(crate) mod rtp_capabilities;
pub(crate) mod rtp_codec;
pub(crate) mod rtp_codec_parameters;
pub(crate) mod rtp_coding_parameters;
pub(crate) mod rtp_encoding_parameters;
pub(crate) mod rtp_header_extension_capability;
pub(crate) mod rtp_header_extension_parameters;
pub(crate) mod rtp_parameters;
pub(crate) mod rtp_receiver_parameters;
pub(crate) mod rtp_send_parameters;
pub(crate) mod set_parameter_options;

use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use crate::peer_connection::transport::RTCDtlsTransport;
use crate::rtp_transceiver::RTCRtpSenderId;
use crate::rtp_transceiver::rtp_sender::rtp_codec::encoding_send_codec;
use log::trace;
use sansio::Protocol;
use shared::error::{Error, Result};
use std::time::Instant;

pub(crate) use rtcp_parameters::negotiates_ccfb;
pub use rtcp_parameters::{
    RTCP_FB_ACK_CCFB, TYPE_RTCP_FB_ACK, TYPE_RTCP_FB_CCM, TYPE_RTCP_FB_GOOG_REMB,
    TYPE_RTCP_FB_NACK, TYPE_RTCP_FB_TRANSPORT_CC,
};
pub use rtcp_parameters::{RTCPFeedback, RTCRtcpParameters};
pub use rtp_capabilities::RTCRtpCapabilities;
pub use rtp_codec::{RTCRtpCodec, RtpCodecKind};
pub use rtp_codec_parameters::RTCRtpCodecParameters;
pub use rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRidRestrictions, RTCRtpRtxParameters,
};
pub use rtp_encoding_parameters::{RTCResolutionRestriction, RTCRtpEncodingParameters};
pub use rtp_header_extension_capability::{
    RTCRtpHeaderExtensionCapability, RTCRtpHeaderExtensionEncryption,
    RTCRtpHeaderExtensionToNegotiate,
};
pub use rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
pub use rtp_parameters::RTCRtpParameters;
pub use rtp_receiver_parameters::RTCRtpReceiveParameters;
pub use rtp_send_parameters::RTCRtpSendParameters;
pub use set_parameter_options::RTCSetParameterOptions;

/// The most encodings a sender has (W3C webrtc 5.1 `addTransceiver`: "the maximum number of
/// total simultaneous encodings the user agent may support"): `sendEncodings` past this many
/// are dropped from the end.
pub const MAX_SEND_ENCODINGS: usize = 16;

/// RTCRtpSender controls the encoding and transmission of media tracks to remote peers.
///
/// This struct provides a handle to the RTP sender within a peer connection,
/// allowing control over parameters, track replacement, and direct RTP/RTCP packet writing.
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcrtpsender-interface
pub struct RTCRtpSender<'a> {
    pub(crate) id: RTCRtpSenderId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpSender<'_> {
    /// The DTLS transport over which this sender's RTP packets are sent.
    ///
    /// ## Nullability
    ///
    /// `None` until this sender's transceiver has been associated by negotiation. The spec
    /// sources this from the `[[SenderTransport]]` slot, which is per-sender and is filled while
    /// applying a local or remote description — so the predicate is that transceiver's mid, not
    /// a connection-wide flag.
    ///
    /// Deliberately *not* keyed on whether the DTLS endpoint has been built: an offerer
    /// associates its transceivers at `setLocalDescription`, before the answer starts DTLS, and a
    /// browser reports a transport there too. The handle simply reports
    /// [`RTCDtlsTransportState::New`](crate::peer_connection::transport::RTCDtlsTransportState)
    /// until the handshake begins.
    ///
    /// Under bundling every sender and receiver shares one transport, so all of these compare
    /// equal by [`id()`](crate::peer_connection::transport::RTCDtlsTransport::id).
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-transport)
    pub fn transport(&self) -> Option<RTCDtlsTransport<'_>> {
        // `[[SenderTransport]]` is assigned when this sender's transceiver is associated by
        // negotiation — the point at which the transceiver acquires a mid. Before that the slot
        // is null, which is what the spec means by "prior to construction of the
        // `RTCDtlsTransport` object".
        let mid = self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .as_ref()?;

        Some(RTCDtlsTransport {
            peer_connection: self.peer_connection,
            transport: self
                .peer_connection
                .pipeline_context
                .transports
                .transport_id_for(mid),
        })
    }
    fn sender(&self) -> &internal::RTCRtpSenderInternal {
        // Every transceiver has a sender from its creation, and the handle borrows the peer
        // connection mutably, so the transceivers cannot change under it.
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender()
            .as_ref()
            .expect("every transceiver has a sender")
    }

    fn sender_mut(&mut self) -> &mut internal::RTCRtpSenderInternal {
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender")
    }

    /// The track this sender sends (W3C `[[SenderTrack]]`), with the sender's encodings as
    /// its codings: `None` when the sender has no track, as after
    /// [`add_transceiver_from_kind`], [`remove_track`] or [`replace_track`]`(None)`.
    ///
    /// [`add_transceiver_from_kind`]: crate::peer_connection::RTCPeerConnection::add_transceiver_from_kind
    /// [`remove_track`]: crate::peer_connection::RTCPeerConnection::remove_track
    /// [`replace_track`]: Self::replace_track
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-track)
    pub fn track(&self) -> Option<&MediaStreamTrack> {
        self.sender().attached_track()
    }

    /// The sender's track, to change the state the application owns (`enabled`, constraints).
    pub fn track_mut(&mut self) -> Option<&mut MediaStreamTrack> {
        self.sender_mut().attached_track_mut()
    }

    /// The SSRCs of the sender's encodings, whether or not it has a track. Empty for a
    /// sender that has not needed encodings yet (see
    /// [`ensure_transceiver_sender`](crate::peer_connection::RTCPeerConnection::ensure_transceiver_sender)).
    pub fn ssrcs(&self) -> impl Iterator<Item = crate::rtp_transceiver::SSRC> + '_ {
        self.sender()
            .send_encodings()
            .iter()
            .filter_map(|encoding| encoding.rtp_coding_parameters.ssrc)
    }

    /// The ids of the MediaStreams this sender's track is signalled in (W3C
    /// `[[AssociatedMediaStreamIds]]`), as [`set_streams`](Self::set_streams) or the track's
    /// own stream id set them; empty for none (the description then says `a=msid:-`).
    pub fn streams(&self) -> &[MediaStreamId] {
        self.sender().associated_streams()
    }

    /// The RTP capabilities of the engine for sending `kind`: every codec the media engine
    /// has registered for it (the retransmission format once, without an `sdpFmtpLine`) and
    /// the header extensions registered for sending. Nothing negotiated is read: the answer
    /// is the same before and after negotiation and for every sender (W3C
    /// `RTCRtpSender.getCapabilities`, a static method). `None` for a kind that is neither
    /// audio nor video.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec type (audio or video) to query capabilities for
    pub fn get_capabilities(&self, kind: RtpCodecKind) -> Option<RTCRtpCapabilities> {
        internal::RTCRtpSenderInternal::get_capabilities(kind, &self.peer_connection.media_engine)
    }

    /// An RTP payloader for `codec` (one of this sender's negotiated codecs) built with the
    /// connection's packetization settings ([`MediaEngine::payloader`]): under the `Chrome`
    /// behaviour profile a VP8 frame is cut without regard to its partitions, as libwebrtc
    /// does; by default each partition starts a packet (RFC 7741 section 3).
    /// [`RTCRtpCodec::payloader`] alone always gives the default form.
    ///
    /// [`MediaEngine::payloader`]: crate::peer_connection::configuration::media_engine::MediaEngine::payloader
    /// [`RTCRtpCodec::payloader`]: crate::rtp_transceiver::rtp_sender::RTCRtpCodec::payloader
    ///
    /// # Errors
    ///
    /// `Error::ErrNoPayloaderForCodec` for a codec without a payloader.
    pub fn payloader(
        &self,
        codec: &crate::rtp_transceiver::rtp_sender::RTCRtpCodec,
    ) -> Result<Box<dyn rtp::packetizer::Payloader>> {
        self.peer_connection.media_engine.payloader(codec)
    }

    /// Updates the RTP send parameters for this sender.
    ///
    /// `parameters` is what [`get_parameters`](Self::get_parameters) last returned, with the
    /// changes wanted in its encodings: `active`, `max_bitrate`, `max_framerate`,
    /// `scale_resolution_down_by` and `codec`.
    ///
    /// # Errors
    ///
    /// The W3C `setParameters` steps:
    /// - [`Error::InvalidStateError`] when the transceiver is stopping or stopped, or
    ///   `get_parameters` has not been called since the last `set_parameters`
    /// - [`Error::InvalidModificationError`] when the transaction id is not the one
    ///   `get_parameters` returned; when the number of encodings, their order, a rid or an
    ///   SSRC differs; when a read-only member (`header_extensions`, `rtcp`, `codecs`) was
    ///   changed; or when an encoding's `codec` was set to one that is not among the
    ///   negotiated send codecs (before negotiation: the codecs the engine can send)
    /// - [`Error::RangeError`] for a `scale_resolution_down_by` below 1.0 or a negative
    ///   `max_framerate`
    pub fn set_parameters(
        &mut self,
        parameters: RTCRtpSendParameters,
        set_parameter_options: Option<RTCSetParameterOptions>,
    ) -> Result<()> {
        // W3C webrtc 5.2 setParameters, step 4: a stopped (or stopping) transceiver's sender
        // takes no parameters.
        if self.peer_connection.rtp_transceivers[self.id.0].stopped() {
            return Err(Error::InvalidStateError);
        }
        let active = |pc: &RTCPeerConnection,
                      id: usize|
         -> Vec<(crate::rtp_transceiver::SSRC, bool)> {
            pc.rtp_transceivers[id]
                .sender()
                .as_ref()
                .map(|sender| {
                    sender
                        .send_encodings()
                        .iter()
                        .filter_map(|e| e.rtp_coding_parameters.ssrc.map(|ssrc| (ssrc, e.active)))
                        .collect()
                })
                .unwrap_or_default()
        };
        let before = active(self.peer_connection, self.id.0);
        self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender")
            .set_parameters(
                parameters,
                set_parameter_options,
                &self.peer_connection.media_engine,
            )?;
        // RFC 8853 section 5.2: a stream that is not sent is in an RFC 7728 local pause
        // (announced with PAUSED); an encoding made inactive pauses its stream, made active
        // again resumes it. Only a stream that negotiated pause and resume has the state.
        let now = self.peer_connection.pipeline_context.now;
        for (ssrc, active) in active(self.peer_connection, self.id.0) {
            if before.contains(&(ssrc, !active)) {
                let control = if active {
                    interceptor::PauseResumeControl::LocalResume(ssrc)
                } else {
                    interceptor::PauseResumeControl::LocalPause(ssrc)
                };
                self.peer_connection
                    .interceptor
                    .handle_write(control.into_packet(now))?;
            }
        }
        // The encodings' priority, maxBitrate or active flag may have changed: the target is
        // divided again (W3C webrtc-priority 3.2, webrtc 5.2.5).
        self.peer_connection.reallocate_target_bitrate();
        Ok(())
    }

    /// The share of the congestion controller's target each of the sender's encodings is
    /// given, by SSRC, in bits per second: what its encoder is to aim for. The target is
    /// divided among the active encodings of every sending transceiver by `priority` (each
    /// level twice the share of the level below, RFC 8835 section 4.1, W3C webrtc-priority
    /// 3.2) and capped at each one's `max_bitrate` (W3C webrtc 5.2.5), the rest going to the
    /// others. Empty until the congestion controller (the default interceptors) set a target,
    /// and for a sender that does not send. Each outbound stream's `targetBitrate` statistic
    /// reports the same share.
    ///
    /// Zero means **pause**: the default chain's pacer holds more than its queue can send in
    /// half its queue time bound (1 s by default), and the encoder is to produce nothing until
    /// the target comes back. It resumes then without a key frame (nothing it encoded was
    /// lost). Media written anyway may be discarded whole frames at a time
    /// (`RTCPeerConnectionEvent::OnPacerDiscard`, with a key-frame request).
    pub fn target_bitrates(&self) -> Vec<(crate::rtp_transceiver::SSRC, f64)> {
        self.sender().allocated_bitrates().to_vec()
    }

    /// webrtc-svc 3.2.3: "the user agent MAY configure a different scalability mode" than
    /// the one requested, when the negotiated codec cannot carry it, and `getParameters` after
    /// negotiation returns "the currently configured" mode. The engine does not encode: the
    /// application's encoder reports the mode it configured for encoding `encoding` (its index
    /// in `getParameters().encodings`) here, `None` for none, and `getParameters` returns it
    /// from then on.
    ///
    /// # Errors
    ///
    /// - `TypeError` for a mode that is not in the webrtc-svc table, or one the encoding's
    ///   negotiated codec (or, with none chosen, no send codec) cannot carry
    /// - `RangeError` for an index past the sender's encodings
    /// - `InvalidStateError` on an audio sender, which has no scalability mode
    pub fn set_configured_scalability_mode(
        &mut self,
        encoding: usize,
        mode: Option<&str>,
    ) -> Result<()> {
        use rtp::codec::svc::ScalabilityMode;
        use std::str::FromStr;
        let sender = self.sender();
        if sender.kind() != RtpCodecKind::Video {
            return Err(Error::InvalidStateError);
        }
        if let Some(name) = mode {
            let parsed = ScalabilityMode::from_str(name)
                .map_err(|_| Error::TypeError(format!("{name:?} is not a scalability mode")))?;
            let codec = sender
                .send_encodings()
                .get(encoding)
                .map(|e| e.codec.mime_type.clone())
                .unwrap_or_default();
            let carried = if codec.is_empty() {
                let codecs = &self.peer_connection.media_engine;
                codecs
                    .get_codecs_by_kind(RtpCodecKind::Video)
                    .iter()
                    .any(|c| parsed.supported_by(&c.rtp_codec.mime_type))
            } else {
                parsed.supported_by(&codec)
            };
            if !carried {
                return Err(Error::TypeError(format!(
                    "no codec of the encoding can carry scalability mode {name}"
                )));
            }
        }
        self.sender_mut()
            .set_configured_scalability_mode(encoding, mode.map(str::to_owned))
    }

    /// Returns the sender's current RTP send parameters.
    ///
    /// The returned parameters describe how the track is encoded and transmitted,
    /// including codecs, encodings, and header extensions. Calls until the next
    /// [`set_parameters`](Self::set_parameters) return the same parameters, with the same
    /// transaction id.
    ///
    /// `rtp_parameters.codecs` are the codecs negotiated for sending, with the payload types
    /// of the remote description (W3C `[[SendCodecs]]`); its first media codec is the one an
    /// encoding that names no codec is sent with. A remote description changes them, so after
    /// applying an answer the application reads them again and encodes that codec with that
    /// payload type: [`write_rtp`](Self::write_rtp) rewrites a payload type that is not
    /// negotiated to the negotiated one but never changes the payload, so bytes of another
    /// codec would go out labelled as this one
    /// ([`rewritten_from_another_codec_rtp_packets`](Self::rewritten_from_another_codec_rtp_packets)
    /// counts them).
    pub fn get_parameters(&mut self) -> &RTCRtpSendParameters {
        let transceiver = &mut self.peer_connection.rtp_transceivers[self.id.0];
        let negotiated = transceiver.current_direction();
        let negotiated_not_sending = negotiated
            != crate::rtp_transceiver::RTCRtpTransceiverDirection::Unspecified
            && !negotiated.has_send();
        let sender = transceiver
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender");
        sender.set_negotiated_not_sending(negotiated_not_sending);
        let transceiver = &mut self.peer_connection.rtp_transceivers[self.id.0];
        let negotiated = transceiver.negotiated_header_extensions().to_vec();
        transceiver
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender")
            .get_parameters(&self.peer_connection.media_engine, &negotiated)
    }

    /// The resolution an encoder that produces `width` x `height` for this sender is to send
    /// (RFC 9429 section 3.6.2): the frame sizes the remote description's `a=imageattr recv`
    /// lines permit for the sender's codec, for as long as they are in it. The input when no
    /// line limits it; a downscaled resolution with the same picture aspect ratio when the
    /// input exceeds the maximum; `Err(ErrImageAttrUnsatisfiable)` when no line can be
    /// satisfied (below a minimum, non-square pixels only): the encoding "MUST NOT be
    /// transmitted". The engine has no encoder; the application's encoder applies this.
    ///
    /// Not a W3C method: a fork addition.
    pub fn send_resolution(&mut self, width: u32, height: u32) -> Result<(u32, u32)> {
        let payload_type = self
            .get_parameters()
            .rtp_parameters
            .codecs
            .first()
            .map(|codec| codec.payload_type);
        let mid = self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .clone();
        let attributes = mid
            .and_then(|mid| {
                let parsed = self.peer_connection.remote_description()?.parsed.as_ref()?;
                parsed
                    .media_descriptions
                    .iter()
                    .find(|m| crate::peer_connection::sdp::get_mid_value(m) == Some(&mid))
                    .map(|m| m.imageattrs().unwrap_or_default())
            })
            .unwrap_or_default();
        match payload_type {
            None => Ok((width, height)),
            Some(payload_type) => {
                crate::peer_connection::sdp::imageattr::imageattr_send_resolution(
                    &attributes,
                    payload_type,
                    width,
                    height,
                )
                .ok_or(Error::ErrImageAttrUnsatisfiable)
            }
        }
    }

    /// The limits the encoding `rid` (`""`: the first encoding) is to be sent under: its
    /// `a=rid` restrictions (as the remote answer left them) combined with the receiver limits
    /// of the remote description's format parameters for the codec it is sent with (VP8
    /// `max-fr`, `max-fs`; H.264 `max-fs`, `max-mbps`, `max-br`) and the section's `b=TIAS` /
    /// `b=AS`, the smaller of each pair (RFC 8851 section 8: the rid restrictions "impose
    /// additional restrictions beyond those communicated in other techniques"). `a=imageattr`
    /// is [`send_resolution`](Self::send_resolution)'s. `None` when the sender has no such
    /// encoding. The engine has no encoder; the application's encoder applies this.
    ///
    /// Not a W3C method: a fork addition.
    pub fn send_restrictions(&mut self, rid: &str) -> Option<RTCRtpRidRestrictions> {
        let parameters = self.get_parameters();
        let encoding = parameters
            .encodings
            .iter()
            .find(|e| rid.is_empty() || e.rtp_coding_parameters.rid == rid)?;
        let restrictions = encoding.rtp_coding_parameters.rid_restrictions.clone();
        let codec = parameters.rtp_parameters.codecs.first().cloned();
        let mid = self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .clone();
        let section = mid.and_then(|mid| {
            let parsed = self.peer_connection.remote_description()?.parsed.as_ref()?;
            parsed
                .media_descriptions
                .iter()
                .find(|m| crate::peer_connection::sdp::get_mid_value(m) == Some(&mid))
                .cloned()
        });
        let (mime_type, fmtp) = match &codec {
            Some(codec) => {
                let prefix = format!("{} ", codec.payload_type);
                let remote_fmtp = section.as_ref().and_then(|m| {
                    m.attributes
                        .iter()
                        .filter(|a| a.key == "fmtp")
                        .find_map(|a| a.value.as_deref()?.strip_prefix(&prefix))
                        .map(str::to_owned)
                });
                (
                    codec.rtp_codec.mime_type.clone(),
                    remote_fmtp.unwrap_or_else(|| codec.rtp_codec.sdp_fmtp_line.clone()),
                )
            }
            None => (String::new(), String::new()),
        };
        Some(
            crate::peer_connection::sdp::send_limits::combined_send_restrictions(
                &restrictions,
                &mime_type,
                &fmtp,
                section
                    .as_ref()
                    .and_then(crate::peer_connection::sdp::send_limits::section_bandwidth),
            ),
        )
    }

    /// Replaces the track this sender sends, without negotiation (W3C `replaceTrack`).
    ///
    /// `Some(track)`: the sender sends `track` from now on. Its encodings and their SSRCs,
    /// the `a=msid` it is signalled with and its associated streams are not changed, so no
    /// negotiation is needed; [`track`](Self::track) returns the new track with the sender's
    /// encodings as its codings. A sender that no description carries yet, or that has no
    /// encodings, takes the new track's own codings (the SSRCs the application chose) instead.
    ///
    /// `None`: the sender stops sending (an RTCP BYE goes out for each of its streams) and
    /// its track becomes null; [`write_rtp`](Self::write_rtp) is refused until it has a track
    /// again.
    ///
    /// # Errors
    ///
    /// - [`Error::ErrRTPSenderNewTrackHasIncorrectKind`] when the track is not of the
    ///   sender's kind (W3C `TypeError`)
    /// - [`Error::InvalidStateError`] when the transceiver is stopping or stopped
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack)
    pub fn replace_track(&mut self, track: Option<MediaStreamTrack>) -> Result<()> {
        self.peer_connection.replace_sender_track(self.id.0, track)
    }

    /// Sets the ids of the MediaStreams this sender's track is signalled in, to exactly
    /// `streams` without duplicates; an empty list is no stream (`a=msid:-`). The
    /// negotiation-needed flag is updated: a description has to carry the change.
    ///
    /// # Errors
    ///
    /// [`Error::ErrConnectionClosed`] when the connection is closed (W3C `InvalidStateError`).
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-setstreams)
    pub fn set_streams(&mut self, streams: Vec<MediaStreamId>) -> Result<()> {
        if self.peer_connection.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        self.sender_mut().set_streams(streams);
        // https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-setstreams: update the
        // negotiation-needed flag.
        self.peer_connection
            .on_transceiver_stopped_or_streams_changed();
        Ok(())
    }

    /// Writes an RTP packet to the network.
    ///
    /// This method allows direct writing of RTP packets, automatically setting
    /// the correct payload type and SSRC based on the sender's configuration.
    ///
    /// When the MID header extension (`urn:ietf:params:rtp-hdrext:sdes:mid`) is negotiated,
    /// the packet is given the transceiver's mid, and when RtpStreamId
    /// (`urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`) is, the rid of its encoding (RFC 9143
    /// section 15, RFC 8852): the application does not stamp them. A packet that already
    /// carries the extension keeps its value.
    ///
    /// # Parameters
    ///
    /// * `packet` - The RTP packet to send
    ///
    /// # Errors
    ///
    /// [`Error::ErrRTPSenderTrackRemoved`] after the sender's track was removed
    /// ([`remove_track`](crate::peer_connection::RTCPeerConnection::remove_track),
    /// [`replace_track`](Self::replace_track)`(None)`), until it has a track again. A sender
    /// made without a track for a sending transceiver is not refused: the engine makes no
    /// media of its own, and forwards what the application writes with the sender's SSRCs
    /// ([`ssrcs`](Self::ssrcs)). Otherwise
    /// returns an error if no matching encoding is found, the codec is unsupported (neither the
    /// packet's payload type nor its encoding's codec is negotiated on this sender leg), or
    /// internal handle_write returns error.
    ///
    /// # Payload type
    ///
    /// A packet whose payload type names a codec negotiated for this sender (its
    /// [`get_parameters`](Self::get_parameters)`().rtp_parameters.codecs`, the remote
    /// description's numbers, RFC 3264 sections 5.1 and 6.1) is sent with it. A packet whose
    /// payload type is not negotiated is rewritten to the payload type negotiated for its
    /// encoding's codec (the encoding's `codec`, or the first media codec of the parameters
    /// when it names none). **Only the number changes, never the payload**: the engine does
    /// not encode or transcode. A comfort noise or telephone event payload type that is not
    /// negotiated is dropped instead, and a packet is refused with
    /// [`Error::ErrRTPTransceiverCodecUnsupported`] when no codec is negotiated for its encoding.
    ///
    /// So after applying an answer (or an offer, when answering), the application re-reads the
    /// sender's negotiated codec, the first media codec of
    /// [`get_parameters`](Self::get_parameters)`().rtp_parameters.codecs`, and encodes that
    /// codec with that payload type. An encoder that keeps producing a codec the answer did
    /// not negotiate (one chosen from `setCodecPreferences` or the local offer) has its packets
    /// sent labelled as the negotiated codec, which the receiver cannot decode (RFC 3264
    /// section 7: the offerer "MUST send using a media format listed in the answer"). Each
    /// rewrite is counted: [`rewritten_payload_type_rtp_packets`](Self::rewritten_payload_type_rtp_packets)
    /// (every rewrite, the same codec renumbered included) and
    /// [`rewritten_from_another_codec_rtp_packets`](Self::rewritten_from_another_codec_rtp_packets)
    /// (the written number names a different format: the dangerous case). An application can
    /// assert the second stays 0. A written number that the negotiation gave to a different
    /// codec is not rewritten, and not counted: it is sent as that codec.
    pub fn write_rtp(&mut self, now: Instant, packet: rtp::Packet) -> Result<()> {
        self.write_rtp_inner(now, packet, true)
    }

    /// How many RTP packets [`write_rtp`](Self::write_rtp) (and the `write_rtp_with_*`
    /// methods) accepted with a payload type that is not negotiated for this sender, and sent
    /// with the payload type of their encoding's negotiated codec instead: every rewrite. It
    /// counts the legitimate one too, a packet written with the number this endpoint's own
    /// offer (or registration) gave the same codec, when the answer numbered it otherwise;
    /// [`rewritten_from_another_codec_rtp_packets`](Self::rewritten_from_another_codec_rtp_packets)
    /// counts the ones whose number names a different codec. A packet refused or dropped
    /// (inactive encoding, `maxBitrate`, `maxFramerate`, a comfort noise or telephone event
    /// format that is not negotiated) is not counted. The sum over the connection's senders is
    /// [`RTCPeerConnection::rewritten_payload_type_rtp_packets`]. Not a W3C attribute:
    /// webrtc-stats has no member for it; a fork addition.
    pub fn rewritten_payload_type_rtp_packets(&self) -> u64 {
        self.sender().rewritten_payload_type_rtp_packets()
    }

    /// Of the packets counted in
    /// [`rewritten_payload_type_rtp_packets`](Self::rewritten_payload_type_rtp_packets), the
    /// ones whose written payload type names a format other than the codec they were sent as:
    /// among the formats of the sender's kind that the media engine registered or that a
    /// description negotiated, the number names one or more and none has the MIME type of the
    /// codec the packet went out as (VP8 written with its offered number after the answer
    /// negotiated H.264 only, or a repair format's number the answer did not keep). Their bytes
    /// were sent labelled as a codec they are not in; a correct application keeps this at 0.
    /// The codecs are compared by MIME type only (an H.264 packet written with the number of
    /// another H.264 format is counted as the same codec renumbered), and a number that names
    /// no format at all is not counted here (nothing says what it carries). The sum over the
    /// connection's senders is [`RTCPeerConnection::rewritten_from_another_codec_rtp_packets`].
    /// Not a W3C attribute; a fork addition.
    pub fn rewritten_from_another_codec_rtp_packets(&self) -> u64 {
        self.sender().rewritten_from_another_codec_rtp_packets()
    }

    /// [`Self::write_rtp`] with the packet's absolute capture time (webrtc-extensions 8, the
    /// `abs-capture-time` header extension): `capture_ntp` is when its first frame was
    /// captured, an NTP timestamp (32.32 fixed point seconds since 1900) on the capture
    /// system's clock, and `clock_offset` the sender's estimate of that clock's offset from
    /// its own (signed 32.32), when it knows it. The element goes in only when the extension
    /// was negotiated for the sender; the packet is sent either way.
    ///
    /// libwebrtc stamps the first packet of a frame and then one about every second; the
    /// receiver interpolates the others from the RTP timestamps.
    pub fn write_rtp_with_capture_time(
        &mut self,
        now: Instant,
        mut packet: rtp::Packet,
        capture_ntp: u64,
        clock_offset: Option<i64>,
    ) -> Result<()> {
        use shared::marshal::Marshal;
        let id = self
            .get_parameters()
            .rtp_parameters
            .header_extensions
            .iter()
            .find(|e| e.uri == rtp::extension::ABS_CAPTURE_TIME_URI && !e.encrypted)
            .map(|e| e.id);
        if let Some(id) = id.and_then(|id| u8::try_from(id).ok()) {
            let element = rtp::extension::abs_capture_time_extension::AbsCaptureTimeExtension {
                timestamp: capture_ntp,
                estimated_capture_clock_offset: clock_offset,
            }
            .marshal()?;
            packet
                .header
                .set_extension_upgrading(id, element.freeze())?;
        }
        self.write_rtp(now, packet)
    }

    /// [`Self::write_rtp`] of an audio frame with the level of its source
    /// (webrtc-encoded-transform 4.4.1: a locally sourced frame's `audioLevel` "MUST be taken
    /// directly from the source and used as input to generate the \[RFC6464\] header extension
    /// if negotiated"). `audio_level` is linear, 0 (silence) to 1 (0 dBov), as
    /// `audioLevel`; it is written as the RFC 6464 level, `-20 log10(audio_level)` dBov
    /// rounded and clamped to 0..=127 (0 and below is 127), with the voice activity flag
    /// from `voice_activity` (0 when unknown). The element goes in only on an audio sender
    /// that negotiated the extension; the packet is sent either way.
    pub fn write_rtp_with_audio_level(
        &mut self,
        now: Instant,
        mut packet: rtp::Packet,
        audio_level: f64,
        voice_activity: Option<bool>,
    ) -> Result<()> {
        let id = (self.sender().kind() == RtpCodecKind::Audio)
            .then(|| {
                self.get_parameters()
                    .rtp_parameters
                    .header_extensions
                    .iter()
                    .find(|e| e.uri == ::sdp::extmap::AUDIO_LEVEL_URI)
                    .map(|e| e.id)
            })
            .flatten();
        if let Some(id) = id.and_then(|id| u8::try_from(id).ok()) {
            packet
                .header
                .set_extension_upgrading(id, rfc6464_element(audio_level, voice_activity))?;
        }
        self.write_rtp(now, packet)
    }

    /// [`Self::write_rtp`] of a video packet with the orientation of the frame it belongs to,
    /// as the Coordination of Video Orientation element (`urn:3gpp:video-orientation`, 3GPP
    /// TS 26.114 section 7.4.5): RFC 7742 section 4 has an endpoint that can produce video in
    /// other orientations generate the R0 and R1 bits "and MUST send them for all
    /// orientations when the peer indicates support for the mechanism". The element (camera,
    /// flip and rotation) goes in only on a video sender whose peer negotiated the extension
    /// (it is among the default header extensions); the packet is sent either way. TS 26.114
    /// puts it in the last packet of a frame (the one with the marker bit): call this for that
    /// packet, and [`Self::write_rtp`] for the others.
    pub fn write_rtp_with_video_orientation(
        &mut self,
        now: Instant,
        mut packet: rtp::Packet,
        orientation: rtp::extension::video_orientation_extension::VideoOrientationExtension,
    ) -> Result<()> {
        use shared::marshal::Marshal;
        let id = (self.sender().kind() == RtpCodecKind::Video)
            .then(|| {
                self.get_parameters()
                    .rtp_parameters
                    .header_extensions
                    .iter()
                    .find(|e| e.uri == ::sdp::extmap::VIDEO_ORIENTATION_URI)
                    .map(|e| e.id)
            })
            .flatten();
        if let Some(id) = id.and_then(|id| u8::try_from(id).ok()) {
            packet
                .header
                .set_extension_upgrading(id, orientation.marshal()?.freeze())?;
        }
        self.write_rtp(now, packet)
    }

    /// W3C `RTCRtpSender.dtmf`: the DTMF sender of an audio sender, `None` for a video one.
    pub fn dtmf(&mut self) -> Option<dtmf::RTCDTMFSender<'_>> {
        if self.sender().kind() != RtpCodecKind::Audio {
            return None;
        }
        Some(dtmf::RTCDTMFSender {
            id: self.id,
            peer_connection: &mut *self.peer_connection,
        })
    }

    /// `write_rtp`; `from_application` is false for the engine's own telephone-event packets,
    /// whose sequence numbers are already the stream's.
    pub(crate) fn write_rtp_inner(
        &mut self,
        now: Instant,
        mut packet: rtp::Packet,
        from_application: bool,
    ) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.

        // draft-ietf-avtcore-rtp-sframe-03 section 6: SFrame offered and not answered, the
        // offerer "MUST NOT send media for that m-section and MUST NOT fall back to sending
        // unencrypted RTP".
        if self.peer_connection.rtp_transceivers[self.id.0].sframe_refused() {
            return Err(Error::ErrSFrameRefused);
        }
        let mid = self.peer_connection.rtp_transceivers[self.id.0]
            .mid()
            .clone();
        let pass_unnegotiated_extensions = self
            .peer_connection
            .setting_engine
            .unnegotiated_header_extensions;
        let ssrc_per_clock_rate = self.peer_connection.setting_engine.ssrc_per_clock_rate;
        let negotiated_header_extensions = self.peer_connection.rtp_transceivers[self.id.0]
            .negotiated_header_extensions()
            .to_vec();
        let sender = self.peer_connection.rtp_transceivers[self.id.0]
            .sender_mut()
            .as_mut()
            .expect("every transceiver has a sender");

        if sender.track_removed() {
            return Err(Error::ErrRTPSenderTrackRemoved);
        }
        // An SSRC a collision replaced (RFC 3550 section 8.2) goes out as its replacement.
        packet.header.ssrc = sender.current_ssrc(packet.header.ssrc);

        // RFC 8853 section 5.3.3: no RTP for a simulcast stream the answer removed. Dropped
        // like an inactive encoding's packet, so an encoder that has not re-read the
        // parameters yet does not fail.
        if sender.is_removed_ssrc(packet.header.ssrc) {
            trace!(
                "rtp_sender {:?} drops RTP ssrc {}: the answer removed its simulcast stream",
                self.id, packet.header.ssrc
            );
            return Ok(());
        }

        if !sender
            .track()
            .ssrcs()
            .any(|ssrc| ssrc == packet.header.ssrc)
        {
            return Err(Error::ErrSenderWithNoSSRCs);
        }

        // RFC 7160 section 4.1: "An RTP Sender with RTCP turned on MUST use a different SSRC
        // for each different clock rate". A packet written with a negotiated codec of another
        // clock rate than its stream's moves the stream to a new SSRC (a BYE first for the
        // SSRC of a rate it returns to). Comfort noise and telephone events ride the stream
        // as they are (RFC 4733 section 2.5.1.2 puts the events in the stream's numbering); a
        // payload type that is not negotiated is sent as the encoding's codec, below.
        // Only with `with_ssrc_per_clock_rate(true)`: by default one SSRC.
        if from_application && ssrc_per_clock_rate {
            let stream_ssrc = packet.header.ssrc;
            let chosen = sender
                .get_send_codecs()
                .iter()
                .find(|codec| {
                    codec.payload_type == packet.header.payload_type
                        && !crate::peer_connection::handler::endpoint::is_auxiliary_mime_type(
                            &codec.rtp_codec.mime_type,
                        )
                })
                .cloned()
                .filter(|codec| {
                    sender.clock_rate_step(stream_ssrc, codec.rtp_codec.clock_rate)
                        == internal::ClockRateStep::Move
                });
            if let Some(codec) = chosen
                && let Some(new) = self.peer_connection.move_sender_to_clock_rate(
                    self.id.0,
                    stream_ssrc,
                    &codec,
                    now,
                )
            {
                packet.header.ssrc = new;
            }
        }
        let (sender, media_engine) = (
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender_mut()
                .as_mut()
                .expect("every transceiver has a sender"),
            &mut self.peer_connection.media_engine,
        );

        // W3C webrtc 5.2.5 maxFramerate (video): frames above the encoding's maximum rate are
        // dropped whole.
        if sender.kind() == RtpCodecKind::Video {
            // RFC 7741 section 6.1 (VP8: "a sender MUST NOT send frames at a higher rate or of
            // a larger size") and RFC 9628 section 6 (VP9: "SHOULD NOT"): the receiver's
            // `max-fr` and `max-fs` on the negotiated format.
            use crate::peer_connection::configuration::media_engine::{
                MIME_TYPE_VP8, MIME_TYPE_VP9,
            };
            let limits = sender
                .get_send_codecs()
                .iter()
                .find(|codec| codec.payload_type == packet.header.payload_type)
                .and_then(|codec| {
                    let mime = &codec.rtp_codec.mime_type;
                    let vp8 = mime.eq_ignore_ascii_case(MIME_TYPE_VP8);
                    (vp8 || mime.eq_ignore_ascii_case(MIME_TYPE_VP9)).then(|| {
                        let fmtp = &codec.rtp_codec.sdp_fmtp_line;
                        (
                            vp8,
                            internal::fmtp_number(fmtp, "max-fr").filter(|rate| *rate > 0),
                            internal::fmtp_number(fmtp, "max-fs").filter(|size| *size > 0),
                        )
                    })
                });
            let (max_fr, max_fs) = limits.map_or((None, None), |(_, fr, fs)| (fr, fs));
            let key_size = match limits {
                Some((true, _, Some(_))) => internal::vp8_key_frame_size(&packet.payload),
                Some((false, _, Some(_))) => internal::vp9_key_picture_size(&packet.payload),
                _ => None,
            };
            if !sender.admit_under_max_fs(packet.header.ssrc, key_size, max_fs) {
                trace!(
                    "rtp_sender {:?} drops RTP ssrc {} ts {}: the frame is larger than max-fs {:?}",
                    self.id, packet.header.ssrc, packet.header.timestamp, max_fs
                );
                return Ok(());
            }
            let max_framerate = sender
                .send_encodings()
                .iter()
                .find(|e| e.rtp_coding_parameters.ssrc == Some(packet.header.ssrc))
                .and_then(|e| e.max_framerate);
            let max_framerate = match (max_framerate, max_fr) {
                (Some(encoding), Some(codec)) => Some(encoding.min(f64::from(codec))),
                (encoding, codec) => encoding.or(codec.map(f64::from)),
            };
            if !sender.admit_under_max_framerate(
                packet.header.ssrc,
                packet.header.timestamp,
                max_framerate,
            ) {
                trace!(
                    "rtp_sender {:?} drops RTP ssrc {} ts {}: above maxFramerate {:?}",
                    self.id, packet.header.ssrc, packet.header.timestamp, max_framerate
                );
                return Ok(());
            }
        }

        // W3C webrtc 5.2.5 maxBitrate: the encoding's frames are dropped while they would
        // take it above its maximum (one frame always goes).
        let max_bitrate = sender
            .send_encodings()
            .iter()
            .find(|e| e.rtp_coding_parameters.ssrc == Some(packet.header.ssrc))
            .map_or(0, |e| e.max_bitrate);
        let bits = {
            use shared::marshal::MarshalSize;
            (packet.marshal_size() * 8) as f64
        };
        if !sender.admit_under_max_bitrate(
            now,
            packet.header.ssrc,
            packet.header.timestamp,
            bits,
            max_bitrate,
        ) {
            trace!(
                "rtp_sender {:?} drops RTP ssrc {} ts {}: the frame would exceed maxBitrate {}",
                self.id, packet.header.ssrc, packet.header.timestamp, max_bitrate
            );
            return Ok(());
        }
        // The payload types of comfort noise (13, and any the application registered) and of
        // telephone events: formats that ride an audio stream and are not media.
        let auxiliary_payload_types: Vec<u8> = std::iter::once(13)
            .chain(
                media_engine
                    .audio_codecs
                    .iter()
                    .filter(|codec| {
                        let mime_type = &codec.rtp_codec.mime_type;
                        mime_type.eq_ignore_ascii_case(
                            crate::peer_connection::configuration::media_engine::MIME_TYPE_CN,
                        ) || mime_type.eq_ignore_ascii_case(
                            crate::peer_connection::configuration::media_engine::MIME_TYPE_TELEPHONE_EVENT,
                        )
                    })
                    .map(|codec| codec.payload_type),
            )
            .collect();
        let mixed = sender.extmap_allow_mixed();
        let two_byte_stream = sender.is_two_byte_stream(packet.header.ssrc);
        let kind = sender.kind();
        let parameters = sender.get_parameters(media_engine, &negotiated_header_extensions);
        let (codecs, encodings) = (&parameters.rtp_parameters.codecs, &parameters.encodings);

        //From SSRC, find the encoding
        let encoding = encodings
            .iter()
            .find(|encoding| {
                encoding
                    .rtp_coding_parameters
                    .ssrc
                    .is_some_and(|s| s == packet.header.ssrc)
            })
            .ok_or(Error::ErrRTPSenderNoBaseEncoding)?;

        // W3C webrtc 5.2 RTCRtpEncodingParameters.active: an inactive encoding is not sent.
        if !encoding.active {
            trace!(
                "rtp_sender {:?} drops RTP ssrc {}: its encoding is inactive",
                self.id, packet.header.ssrc
            );
            return Ok(());
        }

        // Prefer the packet's negotiated payload type when it identifies a codec. Otherwise
        // fall back to the encoding's codec and rewrite the payload type to the one negotiated
        // for it, as before upstream's 8080cef3 removed the fallback (Brainwires fork keeps it;
        // the fork never narrows what an API accepts, see FORK.md). Only the number changes,
        // never the payload; each rewrite is counted (`rewritten_payload_type_rtp_packets`),
        // and apart, one whose written number names another format
        // (`rewritten_from_another_codec_rtp_packets`): its bytes go out labelled as a codec
        // they are not in.
        let mut rewritten: Option<bool> = None;
        if !codecs
            .iter()
            .any(|codec| codec.payload_type == packet.header.payload_type)
        {
            // A comfort noise or telephone event packet whose format this leg did not
            // negotiate is not media: rewritten to the media payload type, its noise
            // parameters or event would be decoded as audio (RFC 3389 section 5.1, RFC 4733
            // section 2.1: each is sent only when its format was negotiated). It is dropped.
            let pt = packet.header.payload_type;
            if auxiliary_payload_types.contains(&pt) {
                trace!(
                    "rtp_sender {:?} drops RTP ssrc {} pt {}: comfort noise or telephone events, not negotiated on this sender leg",
                    self.id, packet.header.ssrc, pt
                );
                return Ok(());
            }
            // An encoding that names no codec is sent with the one negotiation picked, as its
            // stream is bound (`encoding_send_codec`); one that names a codec, with that codec.
            let Some(codec) = encoding_send_codec(&encoding.codec, codecs) else {
                trace!(
                    "rtp_sender {:?} rejecting RTP ssrc {} pt {}: no negotiated codec matches the packet or its encoding; sender codecs [{}]",
                    self.id,
                    packet.header.ssrc,
                    packet.header.payload_type,
                    codecs
                        .iter()
                        .map(|codec| format!(
                            "{}:{}",
                            codec.rtp_codec.mime_type, codec.payload_type
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            };
            trace!(
                "rtp_sender {:?} rewriting RTP ssrc {} pt {} to the encoding's negotiated pt {}",
                self.id, packet.header.ssrc, packet.header.payload_type, codec.payload_type
            );
            rewritten = Some(names_another_format(
                media_engine,
                kind,
                packet.header.payload_type,
                &codec.rtp_codec.mime_type,
            ));
            packet.header.payload_type = codec.payload_type;
        }

        // RFC 8285 section 4.1.2: an element in a stream has a negotiated id. One that has
        // not is taken out (upstream's 1f1b0874 refuses the packet instead), or passed through
        // with `SettingEngineBuilder::with_unnegotiated_header_extensions`.
        let unnegotiated: Vec<u8> = packet
            .header
            .extensions
            .iter()
            .map(|ext| ext.id)
            .filter(|id| {
                !parameters
                    .rtp_parameters
                    .header_extensions
                    .iter()
                    .any(|negotiated| u8::try_from(negotiated.id).ok() == Some(*id))
            })
            .collect();
        for id in unnegotiated {
            trace!(
                "rtp_sender {:?} RTP ssrc {} carries header extension id {id} that is not negotiated on this sender leg; {}",
                self.id,
                packet.header.ssrc,
                if pass_unnegotiated_extensions {
                    "passing it through"
                } else {
                    "removed"
                },
            );
            if !pass_unnegotiated_extensions {
                packet.header.del_extension(id)?;
            }
        }

        // RFC 9143 sections 9.1 and 15: the offerer and answerer identify the m= section an
        // RTP stream belongs to with the MID header extension, and RFC 8852 section 3.3 / RFC
        // 8853 section 5.5 the encoding of a simulcast stream with RtpStreamId. Both go into
        // every packet the sender writes when the extension is negotiated: a receiver that
        // was not told the SSRC (the engine's descriptions name none for simulcast, and RFC
        // 9143 makes `a=ssrc` optional) needs one to associate the stream, at any time it
        // starts to listen or the SSRC changes. A value the application put there itself is
        // left alone. The NACK responder turns the RtpStreamId of a packet it retransmits
        // into RepairedRtpStreamId.
        let stamps = [
            (::sdp::extmap::SDES_MID_URI, mid.as_deref().unwrap_or("")),
            (
                ::sdp::extmap::SDES_RTP_STREAM_ID_URI,
                encoding.rtp_coding_parameters.rid.as_str(),
            ),
        ];
        for (uri, value) in stamps {
            if value.is_empty() {
                continue;
            }
            let Some(id) = parameters
                .rtp_parameters
                .header_extensions
                .iter()
                .find(|negotiated| negotiated.uri == uri)
                .and_then(|negotiated| u8::try_from(negotiated.id).ok())
            else {
                continue;
            };
            if packet.header.get_extension(id).is_none() {
                // The element may need the two-byte form (an id above 14, a value over 16
                // bytes): the packet takes it. It is on every packet of the stream, so the
                // stream stays in one form without mixing too (RFC 8285 section 4.1.2).
                packet
                    .header
                    .set_extension_upgrading(id, bytes::Bytes::copy_from_slice(value.as_bytes()))?;
            }
        }

        // RFC 8285 sections 4.1.2 and 6: without `a=extmap-allow-mixed` on both sides, a
        // stream is all one-byte or all two-byte. It is two-byte throughout when the session
        // negotiated an id above 14 for it (section 4.1.2: a transmitter that intends the
        // two-byte form "SHOULD negotiate the use of IDs above 14"), and from the first packet
        // that needed the two-byte form on. With mixing, each packet takes the smallest form
        // its elements fit.
        let in_dtmf_stream = encodings
            .first()
            .is_some_and(|first| first.rtp_coding_parameters.ssrc == Some(packet.header.ssrc));
        if !mixed && packet.header.extension {
            let two_byte_ids = parameters
                .rtp_parameters
                .header_extensions
                .iter()
                .any(|negotiated| negotiated.id > 14);
            if two_byte_ids || two_byte_stream {
                packet.header.upgrade_to_two_byte()?;
            }
            if packet.header.extension_form() == Some(rtp::header::ExtensionForm::TwoByte) {
                sender.set_two_byte_stream(packet.header.ssrc);
            }
        }

        // RFC 4733 section 2.5.1.2: DTMF events share the stream's sequence numbers. The
        // first encoding's stream carries them; the application's packets there move past
        // the event packets sent before them.
        if from_application && in_dtmf_stream {
            sender.dtmf.on_media_packet(now, &mut packet);
        }

        let track_id = sender.track().track_id().to_string();
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::RtpPacket(track_id, packet),
        })?;
        if let Some(another_codec) = rewritten {
            self.sender_mut()
                .count_rewritten_payload_type(another_codec);
        }
        Ok(())
    }

    /// Writes RTCP packets to the network.
    ///
    /// This method allows direct writing of sender-related RTCP reports such as
    /// Sender Reports (SR) or other feedback messages.
    ///
    /// # Parameters
    ///
    /// * `packets` - Vector of RTCP packets to send
    ///
    /// # Errors
    ///
    /// Returns an error if internal handle_write returns error
    pub fn write_rtcp(&mut self, now: Instant, packets: Vec<Box<dyn rtcp::Packet>>) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.

        // RFC 4585 section 4.2, RFC 5104 section 7.2: only the feedback the section negotiated.
        let codecs = self.sender().get_send_codecs();
        if !self
            .peer_connection
            .setting_engine
            .unnegotiated_rtcp_feedback
            && !codecs.is_empty()
            && let Some((typ, parameter)) =
                crate::rtp_transceiver::rtp_sender::rtp_codec::unnegotiated_feedback(
                    &packets, codecs,
                )
        {
            return Err(Error::ErrRTCPFeedbackNotNegotiated(
                typ.to_owned(),
                parameter.to_owned(),
            ));
        }

        let track_id = self.sender().track().track_id().to_string();
        self.peer_connection.handle_write(TaggedRTCMessage {
            now,
            message: RTCMessage::RtcpPacket(track_id, packets),
        })
    }
}

/// Whether `written`, a payload type `write_rtp` rewrites, names a format of `kind` other
/// than `sent_as` (the MIME type of the codec the packet is sent as): it numbers, among the
/// formats the engine registered or the negotiated ones (this endpoint's and the remote
/// descriptions' numbers), one or more formats and none of them has that MIME type. A number
/// that names no format of `kind` is not counted as another codec (nothing says what it
/// carries), and neither is one that names the same codec under another number (an
/// application that kept its own offer's number after the answer renumbered the codec).
fn names_another_format(
    media_engine: &crate::peer_connection::configuration::media_engine::MediaEngine,
    kind: RtpCodecKind,
    written: u8,
    sent_as: &str,
) -> bool {
    let negotiated = media_engine.get_codecs_by_kind(kind);
    let mut named = media_engine
        .registered_codecs_by_kind(kind)
        .iter()
        .chain(negotiated.iter())
        .filter(|codec| codec.payload_type == written)
        .peekable();
    named.peek().is_some()
        && !named.any(|codec| codec.rtp_codec.mime_type.eq_ignore_ascii_case(sent_as))
}

/// The RFC 6464 element of a linear level (0..1): `V` and the level in -dBov.
fn rfc6464_element(audio_level: f64, voice_activity: Option<bool>) -> bytes::Bytes {
    let dbov = if audio_level.is_nan() || audio_level <= 0.0 {
        127
    } else {
        (-20.0 * audio_level.min(1.0).log10())
            .round()
            .clamp(0.0, 127.0) as u8
    };
    let v = if voice_activity == Some(true) {
        0x80
    } else {
        0
    };
    bytes::Bytes::from(vec![v | dbov])
}
