use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MediaEngine, RTCPacketTime, has_symmetric_configuration,
};
use crate::peer_connection::sdp::codecs_from_media_description;
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::internal::RTCRtpSenderInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, codec_dictionary_match, codec_parameters_fuzzy_search, codec_parameters_search,
    find_rtx_payload_type, is_repair_codec, repair_family, rtcp_feedback_intersection,
};
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpHeaderExtensionToNegotiate, RtpCodecKind,
};
use crate::rtp_transceiver::{
    PayloadType, RTCFecGroupSemantics, RTCRemoteBandwidth, RTCRtpTransceiverDirection,
    RTCRtpTransceiverInit,
};
use interceptor::Interceptor;
use log::trace;
use sdp::MediaDescription;
use shared::error::{Error, Result};
use std::fmt;
use unicase::UniCase;

/// Internal representation of an RTP transceiver.
///
/// Represents a permanent pairing of an RTP sender and RTP receiver that share a common mid.
/// The transceiver manages the direction of media flow and codec preferences.
///
/// # Specification
///
/// See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.
#[derive(Default, Clone)]
pub(crate) struct RTCRtpTransceiverInternal {
    mid: Option<String>,
    kind: RtpCodecKind,
    sender: Option<RTCRtpSenderInternal>,
    receiver: Option<RTCRtpReceiverInternal>,
    direction: RTCRtpTransceiverDirection,
    current_direction: RTCRtpTransceiverDirection,
    preferred_codecs: Vec<RTCRtpCodecParameters>,
    /// The codec preferences set locally (`setCodecPreferences`, or the codec of the track
    /// a sender was created for), which a remote description does not replace: what limits a
    /// later offer's formats (RFC 9429 section 5.2.2, [`Self::get_offer_codecs`]). Empty: no
    /// limit.
    local_codec_preferences: Vec<RTCRtpCodecParameters>,
    /// Whether the sender's codecs are those of a remote description's section, with its
    /// payload types (`set_codec_preferences_from_remote_description`), rather than a copy of
    /// `preferred_codecs`.
    send_codecs_from_remote: bool,
    /// The application set codec preferences (`setCodecPreferences` with a non-empty list),
    /// as opposed to the list a remote description left in `preferred_codecs`.
    application_codec_preferences: bool,
    /// W3C `[[Stopping]]`: `stop()` was called, or the transceiver is stopped. Its direction
    /// reads "stopped" and offers reject its m= section.
    stopping: bool,
    /// W3C `[[Stopped]]`: a description rejected the m= section (or a rollback removed the
    /// transceiver). Its current direction reads "stopped".
    stopped: bool,
    /// W3C `[[Receptive]]`: whether the last description applied has this transceiver
    /// receive (a local offer or any answer with a receiving direction).
    receptive: bool,
    /// W3C `[[FiredDirection]]`: the direction of the last remote description processed for
    /// remote tracks, `None` before the first.
    fired_direction: Option<RTCRtpTransceiverDirection>,
    /// The `a=msid` values its section last carried: kept while the transceiver lives, so the
    /// lines stay the same when it stops having a track and a sending direction (RFC 9429
    /// sections 5.2.2, 5.3.2).
    described_msid: Vec<String>,
    /// Whether `[[CurrentDirection]]` ever was sendrecv or sendonly: such a transceiver's
    /// sender "has been used to send" and `addTrack` does not take it (W3C webrtc 5.1).
    used_to_send: bool,
    /// Whether this transceiver was implicitly created while applying a remote offer
    /// (as opposed to being created by the application via `add_track`/`add_transceiver_*`).
    /// Used by rollback (RFC 9429, Section 5.7): transceivers created by a remote offer that
    /// is subsequently rolled back must be stopped and removed, unless a track was later
    /// attached to them via `add_track`.
    created_by_remote_description: bool,
    /// Whether a remote offer's new media section may take this transceiver (RFC 9429,
    /// Section 5.10: only a transceiver "created by `addTrack`" is a candidate; one the
    /// application made with `addTransceiver` gets a media section of its own, in the next
    /// local offer). True by default, which is this crate's historical behaviour; a caller
    /// that tells the two kinds apart clears it with
    /// `RTCRtpTransceiver::set_associable_with_remote_offer`.
    associable_with_remote_offer: bool,
    /// Where the application wants this transceiver's m= section in the next offer's BUNDLE
    /// groups: `Some(false)` out of every group, with a transport of its own (RFC 9143 section
    /// 7.5.2), `Some(true)` in the first group (section 7.5.1), `None` where the most recent
    /// answer put it (RFC 9429 section 5.2.2).
    bundle_request: Option<bool>,
    /// webrtc-extensions `[[HeaderExtensionsToNegotiate]]`. `None` until the application or
    /// an answer sets it: the media engine's extensions for the kind, each in the direction
    /// it was registered for (`header_extension_control::default_to_negotiate`).
    header_extensions_to_negotiate: Option<Vec<RTCRtpHeaderExtensionToNegotiate>>,
    /// webrtc-encoded-transform 2.1 `[[useSFrame]]`: `None` (undefined) until a transform
    /// sets it or the transceiver is described; then whether its media section has
    /// `a=sframe` (draft-ietf-avtcore-rtp-sframe-03 section 6).
    use_sframe: Option<bool>,
    /// Whether the remote description's section for this transceiver has `a=sframe`.
    remote_sframe: bool,
    /// The answer left `a=sframe` out of a section this side offered it in: nothing is sent
    /// and what arrives is discarded (draft section 6).
    sframe_refused: bool,
    /// webrtc-extensions `[[NegotiatedHeaderExtensions]]`: empty until an answer is applied.
    negotiated_header_extensions: Vec<RTCRtpHeaderExtensionToNegotiate>,
    /// Reduced-size RTCP (RFC 5506) as the last answer negotiated it for this media section.
    rtcp_reduced_size: bool,
    /// The rids of the simulcast streams this transceiver's offers ask to receive
    /// (`RTCRtpTransceiver::set_receive_simulcast`, RFC 8853 section 5.3.1); empty for none.
    receive_simulcast: Vec<String>,
    /// The most this endpoint receives in this transceiver's section, in bits per second
    /// (`RTCRtpTransceiver::set_receive_bandwidth`): its descriptions' `b=TIAS` / `b=AS`.
    receive_bandwidth: Option<u64>,
    /// The `b=` lines of this transceiver's section of the remote description.
    remote_bandwidth: RTCRemoteBandwidth,
    /// The `xr-format`s of the remote description's `a=rtcp-xr` for this section (RFC 3611
    /// section 5.1); `None` when it has no such attribute.
    remote_rtcp_xr: Option<Vec<String>>,
    /// The `a=ptime` / `a=maxptime` of this transceiver's section of the remote description.
    remote_packet_time: RTCPacketTime,
    /// This transceiver's m= section is a FEC session (RFC 5109 section 14.1): it carries the
    /// `ulpfec` stream of another transceiver's media, in an RTP session of its own.
    fec_session: Option<FecSessionState>,
    /// The token of the FEC session ([`FecSessionState::token`]) that protects this
    /// transceiver's media.
    protected_by: Option<u64>,
}

/// The `ulpfec` format of a FEC session's m= section (RFC 5109 sections 13 and 14.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FecSessionFormat {
    /// The dynamic payload type (section 14.1).
    pub(crate) payload_type: PayloadType,
    /// The `rate` parameter (section 13: "larger than 1000 Hz" in a separate stream).
    pub(crate) clock_rate: u32,
    /// `onelevelonly=1` (section 13).
    pub(crate) one_level_only: bool,
    /// The section's per-packet congestion feedback: a FEC session is an RTP session on a
    /// transport and path of its own, with a congestion controller of its own (RFC 8836
    /// section 2, RFC 8834 section 7), which needs it.
    pub(crate) feedback: FecSessionFeedback,
}

/// The per-packet congestion control feedback a FEC session's section states: the
/// transport-wide sequence number extension (`a=extmap`, draft-holmer-rmcat-transport-wide-cc-
/// extensions-01 section 4) with `a=rtcp-fb:<pt> transport-cc`, and RFC 8888 `a=rtcp-fb:<pt>
/// ack ccfb` (section 6), as the media sections state them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FecSessionFeedback {
    /// The id of the transport-wide sequence number extension in the section, when it states
    /// both the extension and `transport-cc` feedback for its format.
    pub(crate) transport_cc_extension: Option<u8>,
    /// `a=rtcp-fb:<pt> ack ccfb`.
    pub(crate) ccfb: bool,
}

impl FecSessionFeedback {
    /// What both sides stated: the feedback in use. One mechanism, as RFC 8888 section 6 has
    /// an answer keep "only one of the offered congestion control feedback mechanisms": RFC
    /// 8888 when both state it, as the media sections negotiate it
    /// (`CongestionFeedback::Negotiated`), else transport-wide congestion control. The
    /// extension id is the remote description's, which an answer takes from the offer (RFC
    /// 8285 section 6).
    pub(crate) fn negotiated(local: Self, remote: Self) -> Self {
        let ccfb = local.ccfb && remote.ccfb;
        Self {
            transport_cc_extension: remote
                .transport_cc_extension
                .filter(|_| local.transport_cc_extension.is_some() && !ccfb),
            ccfb,
        }
    }

    /// The header extensions and RTCP feedback a stream of the FEC session is bound with, so
    /// the chain numbers its packets and reports their arrival on the session's transport.
    pub(crate) fn stream_info(
        self,
    ) -> (
        Vec<interceptor::RTPHeaderExtension>,
        Vec<interceptor::RTCPFeedback>,
    ) {
        let mut extensions = vec![];
        let mut feedback = vec![];
        if let Some(id) = self.transport_cc_extension {
            extensions.push(interceptor::RTPHeaderExtension {
                uri: ::sdp::extmap::TRANSPORT_CC_URI.to_owned(),
                id: u16::from(id),
            });
            feedback.push(interceptor::RTCPFeedback {
                typ: "transport-cc".to_owned(),
                parameter: String::new(),
            });
        }
        if self.ccfb {
            feedback.push(interceptor::RTCPFeedback {
                typ: "ack".to_owned(),
                parameter: "ccfb".to_owned(),
            });
        }
        (extensions, feedback)
    }
}

/// What a transceiver that is a FEC session knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FecSessionState {
    /// Pairs the session with the transceiver it protects
    /// ([`RTCRtpTransceiverInternal::protected_by`]): transceiver ids move when one is removed
    /// and a mid is not there before the first offer.
    pub(crate) token: u64,
    /// The semantics of the `a=group` line that groups the two sections.
    pub(crate) semantics: RTCFecGroupSemantics,
    /// The format this side's descriptions state: the payload type it receives FEC with.
    pub(crate) local: FecSessionFormat,
    /// The format of the remote description's section: the payload type to send FEC with.
    /// `None` until a remote description accepted the session with its group.
    pub(crate) remote: Option<FecSessionFormat>,
}

impl fmt::Debug for RTCRtpTransceiverInternal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RTCRtpTransceiver")
            .field("mid", &self.mid)
            .field("kind", &self.kind)
            //.field("sender", &self.sender)
            //.field("receiver", &self.receiver)
            .field("direction", &self.direction)
            .field("current_direction", &self.current_direction)
            .field("preferred_codecs", &self.preferred_codecs)
            .field("stopping", &self.stopping)
            .field("stopped", &self.stopped)
            .finish()
    }
}

impl RTCRtpTransceiverInternal {
    /// A transceiver with its sender and its receiver, which it has from the start and
    /// keeps (W3C webrtc 5.4 "create an RTCRtpTransceiver"): with `track`, a sender sending
    /// it; without, a sender whose track is null.
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: Option<MediaStreamTrack>,
        init: RTCRtpTransceiverInit,
    ) -> Self {
        Self {
            mid: None,
            kind,
            sender: Some(match track {
                Some(track) => {
                    RTCRtpSenderInternal::new(kind, track, init.streams, init.send_encodings)
                }
                None => {
                    RTCRtpSenderInternal::without_track(kind, init.streams, init.send_encodings)
                }
            }),
            receiver: Some(RTCRtpReceiverInternal::new(kind, vec![])),
            direction: init.direction,
            current_direction: RTCRtpTransceiverDirection::Unspecified,
            preferred_codecs: vec![],
            local_codec_preferences: vec![],
            send_codecs_from_remote: false,
            application_codec_preferences: false,
            stopping: false,
            stopped: false,
            receptive: false,
            fired_direction: None,
            described_msid: vec![],
            used_to_send: false,
            created_by_remote_description: false,
            associable_with_remote_offer: true,
            bundle_request: None,
            header_extensions_to_negotiate: None,
            use_sframe: None,
            remote_sframe: false,
            sframe_refused: false,
            negotiated_header_extensions: vec![],
            rtcp_reduced_size: false,
            receive_simulcast: vec![],
            receive_bandwidth: None,
            remote_bandwidth: RTCRemoteBandwidth::default(),
            remote_rtcp_xr: None,
            remote_packet_time: RTCPacketTime::default(),
            fec_session: None,
            protected_by: None,
        }
    }

    /// The FEC session this transceiver's m= section is (RFC 5109 section 14.1), if it is one.
    pub(crate) fn fec_session(&self) -> Option<&FecSessionState> {
        self.fec_session.as_ref()
    }

    pub(crate) fn fec_session_mut(&mut self) -> Option<&mut FecSessionState> {
        self.fec_session.as_mut()
    }

    pub(crate) fn set_fec_session(&mut self, session: Option<FecSessionState>) {
        self.fec_session = session;
    }

    /// The token of the FEC session that protects this transceiver's media.
    pub(crate) fn protected_by(&self) -> Option<u64> {
        self.protected_by
    }

    pub(crate) fn set_protected_by(&mut self, token: Option<u64>) {
        self.protected_by = token;
    }

    /// Whether the sender is described in this transceiver's m= section (its `a=msid` and
    /// SSRC lines) and counts as sending there: it has a track, or the transceiver's direction
    /// sends (RFC 9429 section 5.2.1), and it has encodings to describe.
    pub(crate) fn describes_sender(&self) -> bool {
        self.sender.as_ref().is_some_and(|sender| {
            sender.has_send_encodings() && (sender.has_track() || self.direction.has_send())
        })
    }

    pub(crate) fn receptive(&self) -> bool {
        self.receptive
    }

    pub(crate) fn set_receptive(&mut self, receptive: bool) {
        self.receptive = receptive;
    }

    /// The `a=msid` values its section last carried.
    pub(crate) fn described_msid(&self) -> &[String] {
        &self.described_msid
    }

    pub(crate) fn set_described_msid(&mut self, msid: Vec<String>) {
        self.described_msid = msid;
    }

    pub(crate) fn fired_direction(&self) -> Option<RTCRtpTransceiverDirection> {
        self.fired_direction
    }

    pub(crate) fn set_fired_direction(&mut self, direction: Option<RTCRtpTransceiverDirection>) {
        self.fired_direction = direction;
    }

    /// Whether the sender "has been used to send": `[[CurrentDirection]]` was once sendrecv
    /// or sendonly.
    pub(crate) fn used_to_send(&self) -> bool {
        self.used_to_send
    }

    pub(crate) fn associable_with_remote_offer(&self) -> bool {
        self.associable_with_remote_offer
    }

    pub(crate) fn set_associable_with_remote_offer(&mut self, associable: bool) {
        self.associable_with_remote_offer = associable;
    }

    pub(crate) fn bundle_request(&self) -> Option<bool> {
        self.bundle_request
    }

    pub(crate) fn set_bundle_request(&mut self, request: Option<bool>) {
        self.bundle_request = request;
    }

    /// The URIs of `[[HeaderExtensionsToNegotiate]]` that are not "stopped", what the media
    /// section may carry; `None` while the slot holds the media engine's defaults.
    pub(crate) fn header_extensions_to_negotiate(&self) -> Option<Vec<String>> {
        self.header_extensions_to_negotiate.as_ref().map(|list| {
            list.iter()
                .filter(|e| e.direction != RTCRtpTransceiverDirection::Stopped)
                .map(|e| e.uri.clone())
                .collect()
        })
    }

    /// The direction `[[HeaderExtensionsToNegotiate]]` gives `uri`, when the slot was set.
    pub(crate) fn header_extension_direction(
        &self,
        uri: &str,
    ) -> Option<RTCRtpTransceiverDirection> {
        self.header_extensions_to_negotiate
            .as_ref()?
            .iter()
            .find(|e| e.uri == uri)
            .map(|e| e.direction)
    }

    /// `[[HeaderExtensionsToNegotiate]]`, the media engine's defaults while it is unset.
    pub(crate) fn header_extensions_to_negotiate_list(
        &self,
        media_engine: &MediaEngine,
    ) -> Vec<RTCRtpHeaderExtensionToNegotiate> {
        self.header_extensions_to_negotiate
            .clone()
            .unwrap_or_else(|| {
                crate::rtp_transceiver::header_extension_control::default_to_negotiate(
                    media_engine,
                    self.kind(),
                )
            })
    }

    pub(crate) fn has_header_extensions_to_negotiate(&self) -> bool {
        self.header_extensions_to_negotiate.is_some()
    }

    pub(crate) fn set_header_extensions_to_negotiate(
        &mut self,
        list: Vec<RTCRtpHeaderExtensionToNegotiate>,
    ) {
        self.header_extensions_to_negotiate = Some(list);
    }

    pub(crate) fn negotiated_header_extensions(&self) -> &[RTCRtpHeaderExtensionToNegotiate] {
        &self.negotiated_header_extensions
    }

    /// An answer was applied: `negotiated` is `[[NegotiatedHeaderExtensions]]` and the new
    /// `[[HeaderExtensionsToNegotiate]]` (webrtc-extensions 4.1).
    pub(crate) fn set_negotiated_header_extensions(
        &mut self,
        negotiated: Vec<RTCRtpHeaderExtensionToNegotiate>,
    ) {
        self.header_extensions_to_negotiate = Some(negotiated.clone());
        if self.negotiated_header_extensions == negotiated {
            return;
        }
        self.negotiated_header_extensions = negotiated;
        // W3C 5.2 / 5.3 getParameters: the header extensions are those negotiated for each
        // way, so what an earlier call returned is stale.
        if let Some(sender) = self.sender.as_mut() {
            sender.invalidate_parameters();
        }
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.invalidate_parameters();
            receiver.set_negotiated_header_extensions(self.negotiated_header_extensions.clone());
        }
    }

    /// See [`Self::receive_simulcast`].
    pub(crate) fn set_receive_simulcast(&mut self, rids: Vec<String>) {
        self.receive_simulcast = rids;
    }

    /// The rids of the simulcast streams this transceiver's offers ask to receive.
    pub(crate) fn receive_simulcast(&self) -> &[String] {
        &self.receive_simulcast
    }

    /// The most this endpoint receives in this transceiver's section, in bits per second.
    pub(crate) fn receive_bandwidth(&self) -> Option<u64> {
        self.receive_bandwidth
    }

    /// See [`Self::receive_bandwidth`].
    pub(crate) fn set_receive_bandwidth(&mut self, bitrate: Option<u64>) {
        self.receive_bandwidth = bitrate;
    }

    /// Returns the media stream identification tag (mid) for this transceiver.
    ///
    /// The mid uniquely identifies the media description in the SDP. When not already set,
    /// this value will be assigned during `create_offer` or `create_answer`.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtptransceiver-mid).
    pub(crate) fn mid(&self) -> &Option<String> {
        &self.mid
    }

    /// Returns the media kind (audio or video) of this transceiver.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtptransceiver-mid).
    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub(crate) fn sender(&self) -> &Option<RTCRtpSenderInternal> {
        &self.sender
    }
    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub(crate) fn sender_mut(&mut self) -> &mut Option<RTCRtpSenderInternal> {
        &mut self.sender
    }

    /// receiver returns the RTPTransceiver's RTPReceiver if it has one
    pub(crate) fn receiver(&self) -> &Option<RTCRtpReceiverInternal> {
        &self.receiver
    }

    pub(crate) fn receiver_mut(&mut self) -> &mut Option<RTCRtpReceiverInternal> {
        &mut self.receiver
    }

    /// Returns the preferred direction of the transceiver.
    ///
    /// This indicates the direction that the application prefers for media flow.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub(crate) fn direction(&self) -> RTCRtpTransceiverDirection {
        self.direction
    }

    /// Sets the preferred direction of this transceiver.
    ///
    /// Changing the direction may trigger renegotiation to update the session description.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub(crate) fn set_direction(&mut self, direction: RTCRtpTransceiverDirection) {
        // The negotiation-needed flag is intentionally not updated here: this internal setter is
        // also invoked while applying a remote/local session description, where triggering
        // renegotiation would be incorrect. The public `RTCRtpTransceiver::set_direction` (which
        // maps to the spec's `direction` setter) performs that step.
        // See https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction
        self.direction = direction;
    }

    /// Returns the negotiated direction of the transceiver.
    ///
    /// This indicates the current direction as established by the most recent session description
    /// exchange. If this transceiver has never been negotiated or if it's stopped, this returns
    /// [`RTCRtpTransceiverDirection::Unspecified`].
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.currentDirection](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-currentdirection).
    pub(crate) fn current_direction(&self) -> RTCRtpTransceiverDirection {
        self.current_direction
    }

    /// W3C webrtc 5.4 "stop sending and receiving": the sender stops and says BYE for each
    /// stream it sent, the receiver stops and its track ends, `[[Direction]]` becomes
    /// inactive and `[[Stopping]]` true. What `RTCRtpTransceiver.stop()` does; the
    /// transceiver is stopped once a description rejects its m= section.
    ///
    /// # Returns
    ///
    /// Whether the receiver's track ended now (it was live), for the caller to announce.
    pub(crate) fn stop_sending_and_receiving(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<bool> {
        if self.stopping {
            return Ok(false);
        }
        self.stopping = true;

        if let Some(sender) = self.sender_mut() {
            sender.stop(media_engine, interceptor)?;
        }
        let mut ended = false;
        if let Some(receiver) = self.receiver_mut() {
            receiver.stop(media_engine, interceptor)?;
            ended = receiver.end_track();
        }

        self.direction = RTCRtpTransceiverDirection::Inactive;

        Ok(ended)
    }

    /// W3C webrtc 5.4 "stop the RTCRtpTransceiver": what a rejected m= section and a rollback
    /// do. Stops sending and receiving unless `stop()` already did, then `[[Stopped]]` is
    /// true, `[[Receptive]]` false and `[[CurrentDirection]]` null.
    ///
    /// # Returns
    ///
    /// Whether the receiver's track ended now, for the caller to announce.
    pub(crate) fn stop(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<bool> {
        let ended = self.stop_sending_and_receiving(media_engine, interceptor)?;
        self.stopped = true;
        self.receptive = false;
        self.current_direction = RTCRtpTransceiverDirection::Unspecified;
        Ok(ended)
    }

    /// Sets the preferred codec list for this transceiver.
    ///
    /// This overrides the default codec preferences from the media engine. If an empty list is
    /// provided, the transceiver resets to use the default codecs from the media engine.
    ///
    /// # Errors
    ///
    /// Returns an error if any codec in the list is not supported by the media engine.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.setCodecPreferences()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-setcodecpreferences).
    pub(crate) fn set_codec_preferences(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        for codec in &codecs {
            let media_engine_codecs = media_engine.registered_codecs_by_kind(self.kind());
            let (_, match_type) =
                codec_parameters_fuzzy_search(&codec.rtp_codec, media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }
        }

        if let Some(sender) = self.sender_mut() {
            sender.set_codec_preferences(codecs.clone());
        }

        if let Some(receiver) = self.receiver_mut() {
            receiver.set_codec_preferences(codecs.clone());
        }

        self.local_codec_preferences.clone_from(&codecs);
        self.preferred_codecs = codecs;
        self.send_codecs_from_remote = false;

        Ok(())
    }

    /// Whether the sender's codecs carry a remote description's payload types: they are then
    /// not to be replaced by the transceiver's preferences, which carry this endpoint's.
    pub(crate) fn send_codecs_from_remote(&self) -> bool {
        self.send_codecs_from_remote
    }

    /// W3C webrtc 5.4 `setCodecPreferences`, the steps before the codecs are stored:
    /// duplicates are removed, keeping the first; each codec has to match one the engine can
    /// send or receive for this kind (the codec dictionary match; the retransmission format
    /// matches by name, as `getCapabilities` lists it once, without an `apt`); and a list of
    /// nothing but RTX, RED, FEC and comfort noise formats is refused.
    pub(crate) fn validate_codec_preferences(
        &self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<Vec<RTCRtpCodecParameters>> {
        if codecs.is_empty() {
            return Ok(codecs);
        }
        let mut unique: Vec<RTCRtpCodecParameters> = Vec::with_capacity(codecs.len());
        for codec in codecs {
            // The same codec twice: the same name, clock rate, channels and parameters.
            if !unique.iter().any(|kept| {
                let (kept, codec) = (&kept.rtp_codec, &codec.rtp_codec);
                kept.mime_type.eq_ignore_ascii_case(&codec.mime_type)
                    && kept.clock_rate == codec.clock_rate
                    && kept.channels == codec.channels
                    && kept.sdp_fmtp_line.trim() == codec.sdp_fmtp_line.trim()
            }) {
                unique.push(codec);
            }
        }
        // The capabilities are what the engine can send or receive (`getCapabilities`), not
        // what a negotiation narrowed the kind to.
        let capabilities = media_engine.registered_codecs_by_kind(self.kind());
        for codec in &unique {
            let is_rtx =
                is_repair_codec(&codec.rtp_codec) && repair_family(&codec.rtp_codec) == "rtx";
            let supported = capabilities.iter().any(|capability| {
                if is_rtx {
                    capability
                        .rtp_codec
                        .mime_type
                        .eq_ignore_ascii_case(&codec.rtp_codec.mime_type)
                        && capability.rtp_codec.clock_rate == codec.rtp_codec.clock_rate
                } else {
                    codec_dictionary_match(&codec.rtp_codec, &capability.rtp_codec)
                }
            });
            if !supported {
                return Err(Error::InvalidModificationError);
            }
        }
        let is_auxiliary = |codec: &RTCRtpCodecParameters| {
            is_repair_codec(&codec.rtp_codec)
                || codec
                    .rtp_codec
                    .mime_type
                    .rsplit('/')
                    .next()
                    .is_some_and(|subtype| subtype.eq_ignore_ascii_case("CN"))
        };
        if unique.iter().all(is_auxiliary) {
            return Err(Error::InvalidModificationError);
        }
        Ok(unique)
    }

    /// W3C `setCodecPreferences`: the application's list (empty: none).
    pub(crate) fn set_application_codec_preferences(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        let set = !codecs.is_empty();
        let negotiated = self.current_direction() != RTCRtpTransceiverDirection::Unspecified;
        let sending = self
            .sender()
            .as_ref()
            .map(|sender| sender.get_send_codecs().to_vec());
        // The application's list names formats, not payload types (getCapabilities() has
        // none; the preferences carry 0). The preferences are not the codecs a sender sends
        // with (W3C 4.4.1.4: only negotiation sets [[SendCodecs]]): once negotiated the sender
        // keeps the negotiated codecs, and before that it reads the preferred formats with the
        // engine's payload types, the ones a local offer gives them. Without this, a sender's
        // `get_parameters()` named payload type 0 (PCMU) for every preferred format, and an
        // application that took Opus's number from it before the answer sent Opus as PCMU.
        let preferred_for_sending = RTCRtpReceiverInternal::get_codecs(
            &codecs,
            self.kind(),
            media_engine,
            self.use_sframe == Some(true),
        );
        let from_remote = self.send_codecs_from_remote;
        self.set_codec_preferences(codecs, media_engine)?;
        if let Some(sender) = self.sender_mut() {
            match sending {
                Some(sending) if negotiated => {
                    sender.set_codec_preferences(sending);
                    self.send_codecs_from_remote = from_remote;
                }
                _ if set => sender.set_codec_preferences(preferred_for_sending),
                _ => {}
            }
        }
        self.application_codec_preferences = set;
        Ok(())
    }

    /// Whether the application set codec preferences (RFC 9429 section 5.3.1: an answer then
    /// lists them, "regardless of what was offered", and no other format).
    pub(crate) fn has_application_codec_preferences(&self) -> bool {
        self.application_codec_preferences
    }

    pub(crate) fn get_codec_preferences(&self) -> &[RTCRtpCodecParameters] {
        &self.preferred_codecs
    }

    /// Codecs returns list of supported codecs
    pub(crate) fn get_codecs(&self, media_engine: &MediaEngine) -> Vec<RTCRtpCodecParameters> {
        self.codecs_in_numbering(media_engine, self.use_sframe == Some(true))
    }

    /// The formats a local offer lists for this transceiver's section (RFC 9429 section
    /// 5.2.2): once its kind is negotiated, "all currently available formats" the codec
    /// preferences do not exclude, the negotiated ones first in their order
    /// ([`MediaEngine::offer_codecs_for_section`]); before that, and for an SFrame section,
    /// [`Self::get_codecs`].
    pub(crate) fn get_offer_codecs(
        &self,
        media_engine: &MediaEngine,
    ) -> Vec<RTCRtpCodecParameters> {
        let sframe = self.use_sframe == Some(true)
            || self.preferred_codecs.iter().any(|codec| {
                media_engine
                    .sframe_payload_types
                    .contains(&codec.payload_type)
            });
        if sframe || !media_engine.is_kind_negotiated(self.kind()) {
            return self.get_codecs(media_engine);
        }
        // What the local preferences (the application's, or the track's codec) allow, in
        // their order.
        let available = RTCRtpReceiverInternal::preferred_among(
            &self.local_codec_preferences,
            media_engine.offer_codecs_for_section(self.kind()),
        );
        let codecs = if self.application_codec_preferences {
            available
        } else {
            // The list a remote description left (the most recent answer's formats, in its
            // order, with this endpoint's payload types) orders the formats and limits none:
            // the ones it lacks follow.
            let mut ordered: Vec<RTCRtpCodecParameters> = self
                .preferred_codecs
                .iter()
                .filter_map(|p| available.iter().find(|a| a.payload_type == p.payload_type))
                .cloned()
                .collect();
            for codec in available {
                if !ordered.iter().any(|o| o.payload_type == codec.payload_type) {
                    ordered.push(codec);
                }
            }
            ordered
        };
        // RFC 2198 section 5, as `codecs_in_numbering`.
        let all = codecs.clone();
        codecs
            .into_iter()
            .filter(|codec| {
                crate::peer_connection::configuration::media_engine::red_encodings_negotiated(
                    codec, &all,
                )
            })
            .collect()
    }

    /// [`Self::get_codecs`] in the SFrame numbering (`sframe`) or the plain one
    /// (draft-ietf-avtcore-rtp-sframe-03 section 6).
    fn codecs_in_numbering(
        &self,
        media_engine: &MediaEngine,
        sframe: bool,
    ) -> Vec<RTCRtpCodecParameters> {
        let codecs = RTCRtpReceiverInternal::get_codecs(
            &self.preferred_codecs,
            self.kind(),
            media_engine,
            sframe,
        );
        // RFC 2198 section 5: the encodings a RED format names "MUST" also be formats of the
        // m= line (and of RED's clock rate, section 3): a RED format whose fmtp names one the
        // section does not list is left out of what this section offers and matches.
        let all = codecs.clone();
        codecs
            .into_iter()
            .filter(|codec| {
                crate::peer_connection::configuration::media_engine::red_encodings_negotiated(
                    codec, &all,
                )
            })
            .collect()
    }

    /// set_mid sets the RTPTransceiver's mid. If it was already set, will return an error.
    pub(crate) fn set_mid(&mut self, mid: String) -> Result<()> {
        if self.mid.is_some() {
            return Err(Error::ErrRTPTransceiverCannotChangeMid);
        }

        self.mid = Some(mid);
        Ok(())
    }

    /// Whether the transceiver is stopping or stopped: an offer rejects its m= section, and
    /// it neither sends nor receives. What RFC 9429 calls a stopped RtpTransceiver. Stopping
    /// implies it (`stop()` sets both), so this reads `[[Stopping]]`, not `[[Stopped]]`.
    #[allow(clippy::misnamed_getters)]
    pub(crate) fn stopped(&self) -> bool {
        self.stopping || self.stopped
    }

    /// W3C `[[Stopped]]`.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// webrtc-encoded-transform 2.1 `[[useSFrame]]`.
    pub(crate) fn use_sframe(&self) -> Option<bool> {
        self.use_sframe
    }

    /// webrtc-encoded-transform 2.2, setting a transform whose `[[useSFrame]]` is
    /// `transform_uses_sframe` on the sender or receiver: refused (InvalidModificationError)
    /// when the transceiver's differs; an undefined one takes the transform's.
    pub(crate) fn set_transform_use_sframe(&mut self, transform_uses_sframe: bool) -> Result<()> {
        match self.use_sframe {
            Some(current) if current != transform_uses_sframe => {
                Err(Error::InvalidModificationError)
            }
            _ => {
                self.use_sframe = Some(transform_uses_sframe);
                Ok(())
            }
        }
    }

    /// Whether this side's next description of the transceiver carries `a=sframe`: in an
    /// offer when `[[useSFrame]]` is true (an undefined one becomes false now, when the
    /// transceiver is first described, webrtc-encoded-transform 2.1); in an answer when it is
    /// true and the offer had it (draft-ietf-avtcore-rtp-sframe-03 section 6).
    pub(crate) fn describe_sframe(&mut self, is_offer: bool) -> bool {
        let use_sframe = *self.use_sframe.get_or_insert(false);
        use_sframe && (is_offer || self.remote_sframe)
    }

    /// The remote description's section for this transceiver, with or without `a=sframe`:
    /// an undefined `[[useSFrame]]` is taken from it (webrtc-encoded-transform 2.1).
    pub(crate) fn note_remote_sframe(&mut self, has_sframe: bool) {
        self.remote_sframe = has_sframe;
        if self.use_sframe.is_none() {
            self.use_sframe = Some(has_sframe);
        }
    }

    /// An applied answer: `offered` / `answered` say whether the offer and the answer have
    /// `a=sframe` in the section. Offered by this side and left out of the answer, SFrame is
    /// refused: the transceiver sends nothing and discards what it receives (draft section 6).
    pub(crate) fn apply_sframe_answer(&mut self, we_offered: bool, offered: bool, answered: bool) {
        self.sframe_refused = we_offered && offered && !answered && self.use_sframe == Some(true);
    }

    /// See [`apply_sframe_answer`](Self::apply_sframe_answer).
    pub(crate) fn sframe_refused(&self) -> bool {
        self.sframe_refused
    }

    /// Returns whether this transceiver was implicitly created while applying a remote offer.
    /// See [`RTCRtpTransceiverInternal::created_by_remote_description`].
    pub(crate) fn created_by_remote_description(&self) -> bool {
        self.created_by_remote_description
    }

    /// Marks this transceiver as having been implicitly created while applying a remote offer.
    pub(crate) fn set_created_by_remote_description(&mut self, created: bool) {
        self.created_by_remote_description = created;
    }

    /// Disassociates this transceiver from its "m=" section, as required by rollback
    /// (RFC 9429, Section 5.7). The mid is cleared and the negotiated (current) direction is
    /// reset so the transceiver can be re-associated by a subsequent offer/answer exchange.
    pub(crate) fn disassociate(&mut self) {
        self.mid = None;
        self.current_direction = RTCRtpTransceiverDirection::Unspecified;
    }

    /// Brings back what the last completed exchange negotiated for this transceiver, from the
    /// copy `saved` taken when the offer now rolled back was applied (W3C webrtc-pc "set a
    /// session description", rollback: `[[ReceiveCodecs]]` and the send encodings return to
    /// their last stable values): the codecs of the transceiver, its sender and its receiver,
    /// and the repair (RTX / FEC) flows the offer took from the sender's encodings. What the
    /// application did since (direction, track, stop, the mid, which the caller handles) stays.
    pub(crate) fn restore_negotiated_state(&mut self, saved: &RTCRtpTransceiverInternal) {
        self.preferred_codecs.clone_from(&saved.preferred_codecs);
        self.send_codecs_from_remote = saved.send_codecs_from_remote;
        self.remote_bandwidth = saved.remote_bandwidth;
        self.remote_rtcp_xr.clone_from(&saved.remote_rtcp_xr);
        self.remote_packet_time = saved.remote_packet_time;
        if let (Some(sender), Some(saved)) = (self.sender.as_mut(), saved.sender.as_ref()) {
            sender.restore_negotiated_state(saved);
        }
        if let (Some(receiver), Some(saved)) = (self.receiver.as_mut(), saved.receiver.as_ref()) {
            receiver.restore_negotiated_state(saved);
        }
    }

    pub(crate) fn remote_rtcp_xr(&self) -> Option<&[String]> {
        self.remote_rtcp_xr.as_deref()
    }

    pub(crate) fn set_remote_rtcp_xr(&mut self, formats: Option<Vec<String>>) {
        self.remote_rtcp_xr = formats;
    }

    pub(crate) fn remote_packet_time(&self) -> RTCPacketTime {
        self.remote_packet_time
    }

    pub(crate) fn set_remote_packet_time(&mut self, packet_time: RTCPacketTime) {
        self.remote_packet_time = packet_time;
    }

    pub(crate) fn remote_bandwidth(&self) -> RTCRemoteBandwidth {
        self.remote_bandwidth
    }

    pub(crate) fn set_remote_bandwidth(&mut self, bandwidth: RTCRemoteBandwidth) {
        self.remote_bandwidth = bandwidth;
    }

    /// Whether the last answer negotiated reduced-size RTCP (RFC 5506) for this transceiver's
    /// media section.
    pub(crate) fn rtcp_reduced_size(&self) -> bool {
        self.rtcp_reduced_size
    }

    /// Records whether the last answer allows this transceiver's sender to mix one- and
    /// two-byte header extensions in a stream (RFC 8285 section 6).
    pub(crate) fn set_extmap_allow_mixed(&mut self, mixed: bool) {
        if let Some(sender) = self.sender.as_mut() {
            sender.set_extmap_allow_mixed(mixed);
        }
    }

    /// W3C webrtc-pc 5.2.9: a sender's codecs take their `sdpFmtpLine` from the remote
    /// description. `remote` is this transceiver's section of it: each send codec of the
    /// same payload type there takes that format's parameters.
    pub(crate) fn take_send_fmtp_from_remote(&mut self, remote: &MediaDescription) {
        let Ok(remote_codecs) = crate::peer_connection::sdp::codecs_from_media_description(remote)
        else {
            return;
        };
        if let Some(sender) = self.sender.as_mut() {
            sender.take_send_fmtp(&remote_codecs);
        }
    }

    /// W3C webrtc-pc 5.2.9: a receiver's codecs take their `sdpFmtpLine` from the local
    /// description; `local` is this transceiver's section of it.
    pub(crate) fn take_receive_fmtp_from_local(&mut self, local: &MediaDescription) {
        let Ok(local_codecs) = crate::peer_connection::sdp::codecs_from_media_description(local)
        else {
            return;
        };
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_local_fmtp(
                local_codecs
                    .into_iter()
                    .map(|c| (c.payload_type, c.rtp_codec.sdp_fmtp_line))
                    .collect(),
            );
        }
    }

    /// RFC 3264 sections 6.1 and 7, RFC 9429 section 5.3.1: the formats an answer of this
    /// endpoint listed beyond the offer's (`local` is this transceiver's section of the answer,
    /// `offer` the offer's) are formats it is willing to receive, which the offerer may send
    /// with; the receiver takes them (a repair format, never added, is left out). `None`, an
    /// answer of the peer's or a rejected section, leaves none.
    pub(crate) fn take_answered_formats(
        &mut self,
        sections: Option<(&MediaDescription, &MediaDescription)>,
    ) {
        let mut formats = vec![];
        if let Some((local, offer)) = sections
            && let Ok(codecs) = codecs_from_media_description(local)
        {
            let offered = |codec: &RTCRtpCodecParameters| {
                offer
                    .media_name
                    .formats
                    .iter()
                    .any(|format| format.parse::<u8>().ok() == Some(codec.payload_type))
            };
            formats = codecs
                .into_iter()
                .filter(|codec| !offered(codec) && !is_repair_codec(&codec.rtp_codec))
                .collect();
        }
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_answered_formats(formats);
        }
    }

    pub(crate) fn set_rtcp_reduced_size(&mut self, reduced_size: bool) {
        self.rtcp_reduced_size = reduced_size;
        if let Some(sender) = self.sender.as_mut() {
            sender.set_rtcp_reduced_size(reduced_size);
        }
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_rtcp_reduced_size(reduced_size);
        }
    }

    pub(crate) fn set_current_direction(&mut self, d: RTCRtpTransceiverDirection) {
        let previous: RTCRtpTransceiverDirection = self.current_direction;
        self.current_direction = d;
        self.used_to_send |= d.has_send();

        if d != previous {
            trace!("Changing current direction of transceiver from {previous} to {d}",);
        }
    }

    // match codecs from remote description, used when remote is offerer and creating a transceiver
    // from remote description with the aim of keeping order of codecs in remote description.
    pub(crate) fn set_codec_preferences_from_remote_description(
        &mut self,
        media: &MediaDescription,
        media_engine: &MediaEngine,
        answers: bool,
    ) -> Result<()> {
        let mut remote_codecs = codecs_from_media_description(media)?;
        // RFC 4585 section 4.1: the feedback of `a=rtcp-fb` is used only in a session whose
        // profile is AVPF (or one inheriting it); a section offered or answered as `RTP/AVP` or
        // `RTP/SAVP` negotiates none, whatever `a=rtcp-fb` lines it carries.
        if !crate::peer_connection::sdp::is_avpf_section(media) {
            for codec in &mut remote_codecs {
                codec.rtp_codec.rtcp_feedback.clear();
            }
        }

        // Codec preferences the application set (W3C `setCodecPreferences`) constrain what is
        // negotiated (JSEP RFC 8829 §5.3.1), so they are matched first; the remote codecs then
        // replace them in the remote's order and with the engine's payload types. When nothing
        // the application preferred was offered, the whole engine is matched instead, as with no
        // preferences, rather than leaving the section with no codec at all.
        // An SFrame section's formats are matched in the SFrame numbering, a plain one's in
        // the plain numbering (draft-ietf-avtcore-rtp-sframe-03 section 6).
        let sframe = media.has_attribute(crate::peer_connection::sdp::ATTR_KEY_SFRAME);
        // The local preferences only: the list an earlier remote description left does not
        // narrow what a later one negotiates (RFC 9429 section 5.2.2, a format a later offer
        // brings back).
        let (mut filtered_codecs, mut send_codecs) = if self.local_codec_preferences.is_empty() {
            (vec![], vec![])
        } else {
            Self::match_remote_codecs(
                remote_codecs.clone(),
                RTCRtpReceiverInternal::get_codecs(
                    &self.local_codec_preferences,
                    self.kind(),
                    media_engine,
                    sframe,
                ),
            )
        };
        if filtered_codecs.is_empty() {
            (filtered_codecs, send_codecs) = Self::match_remote_codecs(
                remote_codecs,
                media_engine.codecs_for_section(self.kind, sframe),
            );
        } else if answers {
            // A remote answer: what this endpoint sends is chosen among the answer's formats
            // it can send, not among the ones its codec preferences offered (RFC 9429 section
            // 5.11: "choose the media format to send as the most preferred media format from
            // the remote description that is also locally supported"; W3C webrtc-pc "set a
            // session description": [[SendCodecs]] are "the codecs that description
            // negotiates for sending and which the user agent is currently capable of
            // sending"; RFC 3264 section 7: the offerer "SHOULD use the first media format
            // listed in the answer"). A format the answer added beyond the offer (RFC 9429
            // section 5.3.1) is one of them. The receive side keeps the preferences: the
            // answerer sends only what the offer had (RFC 3264 section 6.1).
            send_codecs = Self::match_remote_codecs(
                remote_codecs,
                media_engine.codecs_for_section(self.kind, sframe),
            )
            .1;
        }

        // The remote description's list is not a local preference.
        let local = std::mem::take(&mut self.local_codec_preferences);
        let result = self.set_codec_preferences(filtered_codecs, media_engine);
        self.local_codec_preferences = local;
        result?;
        // RFC 9429 section 5.10: for each format of a remote description "the implementation
        // records the payload type to be used in outgoing RTP packets when sending each
        // specified media format", and section 5.11: "The payload type mapping from the remote
        // description is used to determine payload types for the outgoing RTP streams" (RFC
        // 3264 section 5.1: "the offerer MUST send with the payload type numbers from the
        // answer"; section 6.1: the answerer "MUST use the payload type numbers from the
        // offer, even if they differ from those in the answer"). The sender's codecs are the
        // remote section's, with its numbers; the transceiver's and the receiver's keep this
        // endpoint's (the local description's, RFC 9429 section 5.9).
        // RFC 3264 sections 5.1 and 6.1: the remote m= line lists its formats "in order of
        // preference"; `send_codecs` puts exact matches first, so the order is kept beside it.
        let remote_format_order: Vec<PayloadType> = media
            .media_name
            .formats
            .iter()
            .filter_map(|format| format.parse().ok())
            .collect();
        if let Some(sender) = self.sender_mut() {
            sender.set_codec_preferences(send_codecs);
            sender.set_remote_format_order(remote_format_order);
        }
        self.send_codecs_from_remote = true;
        Ok(())
    }

    /// The remote codecs that match one of `left_codecs`, exact matches first, and the RTX
    /// codecs that go with them, twice: with this endpoint's payload types (the matching local
    /// codecs'; an RTX format's `apt` and a RED format's encodings follow), and, entry for
    /// entry, with the remote description's own (what is sent to the remote side carries).
    fn match_remote_codecs(
        mut remote_codecs: Vec<RTCRtpCodecParameters>,
        mut left_codecs: Vec<RTCRtpCodecParameters>,
    ) -> (Vec<RTCRtpCodecParameters>, Vec<RTCRtpCodecParameters>) {
        use crate::peer_connection::configuration::media_engine::red_block_payload_types;
        use crate::rtp_transceiver::rtp_sender::rtp_codec::repair_family;
        // The remote section as it is, for the list in its own numbering.
        let given = remote_codecs.clone();
        // A RED format names its encodings by payload type (RFC 2198 section 5): it is
        // matched, and kept in the local list, with the local numbers of those encodings
        // (the receive path finds a RED packet's primary encoding by that list).
        let local_number = |remote: PayloadType| -> Option<PayloadType> {
            let named = given.iter().find(|codec| codec.payload_type == remote)?;
            match codec_parameters_search(&named.rtp_codec, Some(named.payload_type), &left_codecs)
            {
                (_, CodecMatch::None) => None,
                (local, _) => Some(local.payload_type),
            }
        };
        for codec in &mut remote_codecs {
            if repair_family(&codec.rtp_codec) == "red"
                && let Some(local) = red_block_payload_types(&codec.rtp_codec.sdp_fmtp_line)
                    .and_then(|blocks| {
                        blocks
                            .into_iter()
                            .map(local_number)
                            .collect::<Option<Vec<_>>>()
                    })
            {
                codec.rtp_codec.sdp_fmtp_line = local
                    .iter()
                    .map(|block| block.to_string())
                    .collect::<Vec<_>>()
                    .join("/");
            }
        }
        // find codec matches between what is in remote description and
        // the transceivers codecs and use payload type registered to
        // media engine.
        // For RTX re-mapping later. Ordered, not a map: the RTX pass below walks these in turn
        // and appends a codec per entry, so a `HashMap` would place the answer's rtx formats in
        // a different order on every run. Each pass fills its own list and hands it over, so the
        // whole stays in step with `filtered_codecs`: exact matches first, then partial, each in
        // the offer's order.
        let mut payload_mapping: Vec<(PayloadType, PayloadType)> = vec![];
        let mut filter_by_match = |match_filter: CodecMatch| -> Vec<RTCRtpCodecParameters> {
            let mut filtered_codecs = vec![];
            let mut pass_mapping = vec![];
            for remote_codec_idx in (0..remote_codecs.len()).rev() {
                let remote_codec = &mut remote_codecs[remote_codec_idx];
                if UniCase::new(remote_codec.rtp_codec.mime_type.as_str())
                    == UniCase::new(MIME_TYPE_RTX)
                {
                    continue;
                }

                // The local format that is this one (its parameters, its payload type), not the
                // first of its configuration: several H.264 levels of one profile are each
                // their own format (RFC 6184 section 8.2.2 lets the level differ, so any of
                // them matches).
                let (match_codec, match_type) = codec_parameters_search(
                    &remote_codec.rtp_codec,
                    Some(remote_codec.payload_type),
                    &left_codecs,
                );
                // A format whose parameters are its configuration (H.264, VP9, AV1) is not
                // matched by name alone: see `has_symmetric_configuration`.
                if match_type == CodecMatch::Partial
                    && has_symmetric_configuration(&remote_codec.rtp_codec)
                    && !match_codec.rtp_codec.sdp_fmtp_line.trim().is_empty()
                {
                    continue;
                }
                if match_type == match_filter {
                    pass_mapping.insert(0, (remote_codec.payload_type, match_codec.payload_type));

                    remote_codec.payload_type = match_codec.payload_type;
                    // Only the feedback both sides have is negotiated (RFC 4585 section 4.2):
                    // what a remote description lists beyond this endpoint's own, or an
                    // answer beyond the offer, is never enabled.
                    remote_codec.rtp_codec.rtcp_feedback = rtcp_feedback_intersection(
                        &match_codec.rtp_codec.rtcp_feedback,
                        &remote_codec.rtp_codec.rtcp_feedback,
                    );
                    // The scan runs backwards so that matched entries can be removed by index,
                    // so prepend to undo it: an answer must keep the offer's codec order (the
                    // offerer reads it back as our preference). Appending here would make the
                    // answer lead with the offer's *last* codec.
                    filtered_codecs.insert(0, remote_codec.clone());

                    // removed matched codec for next round
                    remote_codecs.remove(remote_codec_idx);

                    // The matched local format is taken: another remote format of the same
                    // configuration matches one of the others (before, the last local format
                    // of the configuration was removed instead, and every remote one took the
                    // first's payload type).
                    if let Some(taken) = left_codecs.iter().position(|left| left == &match_codec) {
                        left_codecs.remove(taken);
                    }
                }
            }

            payload_mapping.extend(pass_mapping);
            filtered_codecs
        };

        let mut filtered_codecs = filter_by_match(CodecMatch::Exact);
        filtered_codecs.append(&mut filter_by_match(CodecMatch::Partial));

        // The same formats as the remote section numbers them: `payload_mapping` runs in step
        // with `filtered_codecs`.
        let mut send_codecs: Vec<RTCRtpCodecParameters> = filtered_codecs
            .iter()
            .zip(&payload_mapping)
            .map(|(local, (remote_payload_type, _))| {
                let mut remote = local.clone();
                remote.payload_type = *remote_payload_type;
                if repair_family(&remote.rtp_codec) == "red"
                    && let Some(given) = given
                        .iter()
                        .find(|codec| codec.payload_type == *remote_payload_type)
                {
                    remote
                        .rtp_codec
                        .sdp_fmtp_line
                        .clone_from(&given.rtp_codec.sdp_fmtp_line);
                }
                remote
            })
            .collect();

        // find RTX associations and add those
        for (remote_payload_type, media_engine_payload_type) in payload_mapping {
            let Some(remote_rtx) = find_rtx_payload_type(remote_payload_type, &remote_codecs)
            else {
                continue;
            };
            // RFC 4588 section 4: "the retransmission payload type ... MUST use the same clock
            // rate as the original payload type": an `rtx` format of another rate than the one
            // it repairs is not negotiated.
            let rtx_rate = remote_codecs
                .iter()
                .find(|codec| codec.payload_type == remote_rtx)
                .map(|codec| codec.rtp_codec.clock_rate);
            let primary_rate = filtered_codecs
                .iter()
                .find(|codec| codec.payload_type == media_engine_payload_type)
                .map(|codec| codec.rtp_codec.clock_rate);
            if rtx_rate.is_some() && primary_rate.is_some() && rtx_rate != primary_rate {
                continue;
            }

            if let Some(media_engine_rtx) =
                find_rtx_payload_type(media_engine_payload_type, &left_codecs)
            {
                for rtx_codec in &left_codecs {
                    if rtx_codec.payload_type == media_engine_rtx {
                        filtered_codecs.push(rtx_codec.clone());
                        // The remote section's RTX format for the same primary, with its
                        // number and its `apt` (RFC 4588 section 8.6).
                        let mut remote = given
                            .iter()
                            .find(|codec| codec.payload_type == remote_rtx)
                            .cloned()
                            .unwrap_or_else(|| rtx_codec.clone());
                        remote
                            .rtp_codec
                            .rtcp_feedback
                            .clone_from(&rtx_codec.rtp_codec.rtcp_feedback);
                        send_codecs.push(remote);
                        break;
                    }
                }
            }
        }

        (filtered_codecs, send_codecs)
    }
}
