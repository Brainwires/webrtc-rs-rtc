use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::interceptor_registry::create_stream_info;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::PayloadType;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS;
use crate::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionToNegotiate;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    RTCRtpCodec, RtpCodecKind, codec_dictionary_match, encoding_send_codec, find_fec_format,
    find_rtx_payload_type, is_repair_codec, repair_family,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpRidRestrictions;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_send_parameters::RTCRtpSendParameters;
use crate::rtp_transceiver::rtp_sender::set_parameter_options::RTCSetParameterOptions;
use interceptor::{Interceptor, StreamInfo};
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;

/// Internal RTP sender implementation.
///
/// This structure manages the state and configuration of an RTP sender,
/// including track association, encoding parameters, codec selection, and negotiation status.
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcrtpsender-interface
#[derive(Default, Debug, Clone)]
pub(crate) struct RTCRtpSenderInternal {
    /// The codec kind (audio or video) for this sender
    kind: RtpCodecKind,
    /// What the sender is signalled and sent as: the ids of its `a=msid` lines, which
    /// `replaceTrack` leaves alone (W3C webrtc 5.2), and the codings (SSRCs) it sends now.
    /// It has the codings of `send_encodings`, and none once the track was removed
    /// (`track_removed`), so "has codings" is "sends": nothing is bound, routed or counted
    /// for a sender whose track was taken away.
    sender_track: MediaStreamTrack,
    /// The application set `[[SenderTrack]]` to null (`removeTrack`, `replaceTrack(null)`):
    /// the sender stopped sending and refuses RTP until it has a track again. A sender made
    /// without a track is not in this state: the engine makes no media of its own, so one
    /// created to send forwards what the application writes.
    track_removed: bool,
    /// W3C `[[SenderTrack]]`: the application's track, with the sender's codings; `None` is
    /// null (a transceiver made without a track, `removeTrack`, `replaceTrack(null)`).
    attached_track: Option<MediaStreamTrack>,
    /// W3C `[[AssociatedMediaStreamIds]]`: exactly what the application gave, without
    /// duplicates, possibly empty.
    associated_media_stream_ids: Vec<MediaStreamId>,
    /// The stream ids the `a=msid` lines carry: the associated ids, or `-` when there are
    /// none (RFC 9429 section 5.2.1).
    msid_stream_ids: Vec<MediaStreamId>,
    /// Encoding parameters for each simulcast/layered encoding
    send_encodings: Vec<RTCRtpEncodingParameters>,
    /// Negotiated codec parameters
    send_codecs: Vec<RTCRtpCodecParameters>,
    /// The payload types of the remote description's m= line, in its order (RFC 3264 sections
    /// 5.1 and 6.1: the order of preference); empty until a remote description set
    /// `send_codecs`. `send_codecs` lists exact matches before partial ones, so the streams
    /// bound to the interceptors list their section's formats in this order instead.
    remote_format_order: Vec<PayloadType>,

    /// Cached parameters returned by get_parameters()
    last_returned_parameters: Option<RTCRtpSendParameters>,

    /// Whether SDP negotiation has occurred for this sender
    negotiated: bool,
    sent: bool,
    /// The streams this sender bound to the interceptors, as they were bound: a renegotiation
    /// that changes one unbinds exactly these before binding the new ones, and `stop` unbinds
    /// them whatever the parameters are by then.
    bound_streams: Vec<StreamInfo>,
    /// Where this sender's ULPFEC goes when a FEC session of its own protects its media
    /// (RFC 5109 section 14.1), set by the peer connection from the negotiated session.
    fec_session: Option<FecSessionBinding>,
    /// The FEC streams of that session bound to the interceptors, one for each media stream.
    bound_fec_session_streams: Vec<StreamInfo>,
    /// Reduced-size RTCP as negotiated for the media section (`RTCRtcpParameters::reduced_size`).
    rtcp_reduced_size: bool,
    /// The transceiver's negotiated direction does not send (a recvonly or inactive
    /// exchange): W3C 4.4.1.4 sets `[[SendCodecs]]` to the codecs negotiated for sending,
    /// none, and `get_parameters` lists none.
    negotiated_not_sending: bool,
    /// The SSRCs of the simulcast encodings an answer removed (`apply_simulcast_answer`): the
    /// track still has them, but they are neither bound nor sent.
    removed_ssrcs: Vec<SSRC>,
    /// The rids of the encodings the first negotiation starts paused (RFC 8853 section 5.2:
    /// the remote description marks them `~`); bound with `StreamInfo::initially_paused`.
    initially_paused_rids: Vec<String>,
    /// W3C `[[LastStableRidlessSendEncodings]]`: the lone rid-less encoding a remote offer to
    /// receive simulcast replaced by its proposed encodings, which a rollback restores.
    last_stable_ridless_send_encodings: Option<Vec<RTCRtpEncodingParameters>>,
    /// The restrictions an offer gave each rid whose restrictions an applied answer then
    /// tightened (RFC 8851 section 6.4 step 3): the encoding sends under the answer's, and a
    /// later offer writes these, its `a=rid` line staying the same (RFC 9429 section 5.2.2).
    /// A rid leaves it when the answer removes its encoding or the application gives it new
    /// restrictions (`set_parameters`).
    offered_rid_restrictions: Vec<(String, RTCRtpRidRestrictions)>,
    /// `with_rejected_rids_kept_in_offers` (RFC 9429 section 5.2.2): the encodings of the
    /// simulcast streams remote answers rejected, which later offers still list and a later
    /// answer may accept again. Not sent, not in `get_parameters`.
    rejected_encodings: Vec<RTCRtpEncodingParameters>,
    /// The rids of the simulcast envelope in the order first offered, rejected ones included,
    /// kept with `rejected_encodings`: the order later offers list them in.
    envelope_rids: Vec<String>,
    /// The `RTCDTMFSender` of an audio sender: its slots and playout.
    pub(crate) dtmf: super::dtmf::DtmfState,
    /// Whether the last answer negotiated `a=extmap-allow-mixed` for the media section (RFC
    /// 8285 section 6): only then may a stream mix one- and two-byte header extensions.
    extmap_allow_mixed: bool,
    /// Without mixing, the SSRCs that have sent a two-byte header extension block: each keeps
    /// the two-byte form from then on (RFC 8285 section 4.1.2: "A stream MUST contain only
    /// one-byte headers or only two-byte headers").
    two_byte_ssrcs: Vec<SSRC>,
    /// Each encoding's share of the congestion controller's target (`allocate_bandwidth`):
    /// what its encoder is to aim for, by SSRC.
    allocated_bitrates: Vec<(SSRC, f64)>,
    /// The `maxBitrate` budget of each encoding that has one (`admit_under_max_bitrate`).
    max_bitrate_limiters: Vec<MaxBitrateLimiter>,
    /// The `maxFramerate` state of each video encoding that has one
    /// (`admit_under_max_framerate`): the RTP timestamp of the last frame admitted, and the
    /// frame being sent with whether it was admitted.
    max_framerate_limiters: Vec<MaxFramerateLimiter>,
    /// RFC 7741 section 6.1 `max-fs`: by SSRC, whether the VP8 key frame that started the
    /// stream's current run of frames fits the receiver's frame size (`admit_under_max_fs`).
    vp8_frame_size_fits: Vec<(SSRC, bool)>,
    /// The SSRCs moved after a collision (RFC 3550 section 8.2, RFC 5576 section 5): each new
    /// SSRC with the ones it replaced, oldest first. Descriptions say `a=ssrc:<new>
    /// previous-ssrc:<old> ...` (RFC 5576 section 6.2), and what the application still writes
    /// with an old SSRC goes out with the new one.
    previous_ssrcs: Vec<(SSRC, Vec<SSRC>)>,
    /// RFC 7160 section 4.1, by the SSRC each stream is sent with now: the clock rates the
    /// stream was sent with, the streams of the other rates (still in the session), and the
    /// codec the current SSRC is sent with when the application switched to one other than
    /// the negotiated choice.
    clock_rates: std::collections::HashMap<SSRC, ClockRateStreams>,
    /// The packets `write_rtp` accepted with a payload type it rewrote to the one negotiated
    /// for their encoding's codec (`RTCRtpSender::rewritten_payload_type_rtp_packets`).
    rewritten_payload_type_rtp_packets: u64,
    /// Of those, the ones whose written payload type names, in the media engine, a format
    /// other than the codec they were sent as
    /// (`RTCRtpSender::rewritten_from_another_codec_rtp_packets`).
    rewritten_from_another_codec_rtp_packets: u64,
}

/// What a sender keeps of one encoding's clock rates (RFC 7160 section 4.1: an SSRC per
/// clock rate, a BYE and a new SSRC on a return to a rate already used).
#[derive(Default, Debug, Clone)]
pub(crate) struct ClockRateStreams {
    history: rtp::clock_rate::ClockRateHistory,
    /// The streams of the other clock rates the encoding was sent with: they stay bound (their
    /// sender reports go on, RFC 7160 section 4.1) until the encoding returns to their rate.
    parked: Vec<StreamInfo>,
    /// The codec the current SSRC is sent with, when not the one negotiation picked.
    codec: Option<RTCRtpCodecParameters>,
}

/// What a packet of another clock rate asks of its stream (RFC 7160 section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClockRateStep {
    /// The packet's clock rate is the stream's: the SSRC stays.
    Keep,
    /// The stream moves to a new SSRC for the packet's clock rate.
    Move,
}

/// An encoding's `maxFramerate` state: its SSRC, the RTP timestamp of the last frame
/// admitted, and the frame being sent with whether it was admitted.
type MaxFramerateLimiter = (SSRC, u32, Option<(u32, bool)>);

/// W3C webrtc 5.2.5 `maxBitrate` on the wire: "a frame will always be sent as fast as
/// possible, but frames may be dropped until bitrate is low enough. Thus, even a bitrate of
/// zero will allow sending one frame." A budget that fills at `maxBitrate` (up to one second
/// of it) and is charged for every packet sent (RTP header and payload: TIAS, RFC 3890
/// 6.2.2); a frame (the packets of one RTP timestamp) that starts while the budget is spent
/// is dropped whole.
#[derive(Debug, Clone)]
struct MaxBitrateLimiter {
    ssrc: SSRC,
    budget_bits: f64,
    refilled: std::time::Instant,
    /// The frame being sent: its RTP timestamp and whether it was admitted.
    frame: Option<(u32, bool)>,
}

/// The streams `add_track` associates a sender with: the one its track names, or none when
/// the track names none (an empty stream id, or `-`, the msid-id RFC 8830 section 3 gives
/// "no MediaStream"; W3C `addTrack(track)` with no streams). A sender in no stream is
/// written `a=msid:- <id>` (RFC 9429 section 5.2.1).
pub(crate) fn track_streams(track: &MediaStreamTrack) -> Vec<MediaStreamId> {
    let stream = track.stream_id();
    if stream.is_empty() || stream == "-" {
        vec![]
    } else {
        vec![stream.to_string()]
    }
}

/// A sender's FEC session (RFC 5109 section 14.1), as its streams are bound with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FecSessionBinding {
    /// The key of the connection's `FecSessionSsrcMap`: inside the chain the FEC stream of the
    /// media stream `ssrc` is `ssrc ^ key`.
    pub(crate) key: u32,
    /// The payload type FEC is sent with: the remote description's `ulpfec` in the session's
    /// section.
    pub(crate) payload_type: PayloadType,
    /// The remote side signalled `onelevelonly=1` (RFC 5109 sections 13, 14.3: what the
    /// receiver accepts).
    pub(crate) one_level_only: bool,
    /// The per-packet congestion feedback negotiated for the session.
    pub(crate) feedback: crate::rtp_transceiver::internal::FecSessionFeedback,
}

impl RTCRtpSenderInternal {
    /// The share of the congestion controller's target allocated to the encoding sending on
    /// `ssrc`, once there is a target.
    pub(crate) fn allocated_bitrates(&self) -> &[(SSRC, f64)] {
        &self.allocated_bitrates
    }

    pub(crate) fn set_allocated_bitrates(&mut self, shares: Vec<(SSRC, f64)>) {
        self.allocated_bitrates = shares;
    }

    /// Whether a packet of `bits` on `ssrc` with RTP timestamp `timestamp`, written at `now`,
    /// fits the encoding's `max_bitrate` (bits per second; 0 is no limit): see
    /// [`MaxBitrateLimiter`].
    pub(crate) fn admit_under_max_bitrate(
        &mut self,
        now: std::time::Instant,
        ssrc: SSRC,
        timestamp: u32,
        bits: f64,
        max_bitrate: u32,
    ) -> bool {
        if max_bitrate == 0 {
            self.max_bitrate_limiters.retain(|l| l.ssrc != ssrc);
            return true;
        }
        let rate = f64::from(max_bitrate);
        let index = match self
            .max_bitrate_limiters
            .iter()
            .position(|l| l.ssrc == ssrc)
        {
            Some(index) => index,
            None => {
                self.max_bitrate_limiters.push(MaxBitrateLimiter {
                    ssrc,
                    budget_bits: 0.0,
                    refilled: now,
                    frame: None,
                });
                self.max_bitrate_limiters.len() - 1
            }
        };
        let limiter = &mut self.max_bitrate_limiters[index];
        let elapsed = now
            .saturating_duration_since(limiter.refilled)
            .as_secs_f64();
        limiter.budget_bits = (limiter.budget_bits + elapsed * rate).min(rate);
        limiter.refilled = limiter.refilled.max(now);
        let admitted = match limiter.frame {
            Some((frame_timestamp, admitted)) if frame_timestamp == timestamp => admitted,
            _ => {
                let admitted = limiter.budget_bits >= 0.0;
                limiter.frame = Some((timestamp, admitted));
                admitted
            }
        };
        if admitted {
            limiter.budget_bits -= bits;
        }
        admitted
    }

    /// W3C webrtc 5.2.5 `maxFramerate` on the wire: the engine has no encoder, so of the frames
    /// the application writes (the packets of one RTP timestamp) the sender drops those that
    /// would take the encoding above `max_framerate` frames per second. Frames are spaced by
    /// their RTP timestamps (video's 90 kHz clock, RFC 3551 section 5): a frame goes when at
    /// least `1 / max_framerate` (less 1 %, for timestamps rounded by the source) has passed
    /// since the last frame that went, so a source at that rate or below is untouched.
    pub(crate) fn admit_under_max_framerate(
        &mut self,
        ssrc: SSRC,
        timestamp: u32,
        max_framerate: Option<f64>,
    ) -> bool {
        const VIDEO_CLOCK_RATE: f64 = 90_000.0;
        let Some(max_framerate) = max_framerate.filter(|rate| *rate > 0.0) else {
            self.max_framerate_limiters.retain(|(s, _, _)| *s != ssrc);
            return true;
        };
        let interval = (VIDEO_CLOCK_RATE / max_framerate * 0.99) as u32;
        let Some(limiter) = self
            .max_framerate_limiters
            .iter_mut()
            .find(|(s, _, _)| *s == ssrc)
        else {
            self.max_framerate_limiters
                .push((ssrc, timestamp, Some((timestamp, true))));
            return true;
        };
        match limiter.2 {
            Some((frame, admitted)) if frame == timestamp => admitted,
            _ => {
                let admitted = timestamp.wrapping_sub(limiter.1) >= interval;
                if admitted {
                    limiter.1 = timestamp;
                }
                limiter.2 = Some((timestamp, admitted));
                admitted
            }
        }
    }

    /// RFC 7741 section 6.1 and RFC 9628 section 6: a sender does not send frames larger
    /// than the receiver's `max-fs`, "the maximum frame size in units of macroblocks" (16 by
    /// 16 pixels), which it decodes "as long as the width and height of the frame in
    /// macroblocks are less than int(sqrt(max-fs * 8))". The engine has no encoder: it reads
    /// the size each key picture states (`key_size`: a VP8 key frame's header, RFC 6386
    /// section 9.1; a VP9 key picture's scalability structure, RFC 9628 section 4.2.1) and
    /// drops, from one larger than `max_fs` up to the next that fits, every packet of the
    /// stream (a delta frame needs the key frame it follows). Without a limit everything
    /// passes.
    pub(crate) fn admit_under_max_fs(
        &mut self,
        ssrc: SSRC,
        key_size: Option<(u16, u16)>,
        max_fs: Option<u32>,
    ) -> bool {
        let Some(max_fs) = max_fs else {
            self.vp8_frame_size_fits.retain(|(s, _)| *s != ssrc);
            return true;
        };
        if let Some((width, height)) = key_size {
            let (columns, rows) = (
                u32::from(width).div_ceil(16),
                u32::from(height).div_ceil(16),
            );
            let side = f64::from(max_fs * 8).sqrt() as u32;
            let fits = columns * rows <= max_fs && columns < side && rows < side;
            match self
                .vp8_frame_size_fits
                .iter_mut()
                .find(|(s, _)| *s == ssrc)
            {
                Some(entry) => entry.1 = fits,
                None => self.vp8_frame_size_fits.push((ssrc, fits)),
            }
        }
        self.vp8_frame_size_fits
            .iter()
            .find(|(s, _)| *s == ssrc)
            .is_none_or(|(_, fits)| *fits)
    }

    /// Creates a new RTP sender internal state.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec kind (audio or video)
    /// * `track` - The media track to send
    /// * `streams` - Media stream IDs to associate with the track. This crate's `add_track`
    ///   has no streams argument: a track names the one stream it is in, so an empty list
    ///   stands for that stream.
    /// * `send_encodings` - Initial encoding parameters for the sender
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: MediaStreamTrack,
        streams: Vec<MediaStreamId>,
        send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Self {
        let streams = if streams.is_empty() {
            track_streams(&track)
        } else {
            streams
        };
        // Encodings left out are the track's own codings.
        let send_encodings = if send_encodings.is_empty() {
            track.codings().to_vec()
        } else {
            send_encodings
        };
        let mut sender = Self {
            kind,
            sender_track: track.clone(),
            attached_track: Some(track),
            send_encodings,
            ..Default::default()
        };
        sender.set_streams(streams);
        sender.sync_tracks();
        sender
    }

    /// A sender whose `[[SenderTrack]]` is null (W3C webrtc 5.2 "create an RTCRtpSender" with
    /// a kind): every transceiver has one, whether or not it ever sends.
    ///
    /// `send_encodings` may be empty: SSRCs are then allocated when the sender first needs
    /// them (a sending direction, a track).
    pub(crate) fn without_track(
        kind: RtpCodecKind,
        streams: Vec<MediaStreamId>,
        send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Self {
        let mut sender = Self {
            kind,
            // Signalled as `a=msid:<stream or -> <id>`: an id of its own, as a browser gives a
            // sender without a track.
            sender_track: MediaStreamTrack::new(
                "-".to_owned(),
                math_rand_alpha(16),
                String::new(),
                kind,
                vec![],
            ),
            attached_track: None,
            send_encodings,
            ..Default::default()
        };
        sender.set_streams(streams);
        sender.sync_tracks();
        sender
    }

    /// What the sender is signalled and sent as: the msid ids, and the codings it sends now
    /// (none while `[[SenderTrack]]` is null).
    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.sender_track
    }

    /// W3C `[[SenderTrack]]`: the track the application attached, `None` for null.
    pub(crate) fn attached_track(&self) -> Option<&MediaStreamTrack> {
        self.attached_track.as_ref()
    }

    pub(crate) fn attached_track_mut(&mut self) -> Option<&mut MediaStreamTrack> {
        self.attached_track.as_mut()
    }

    pub(crate) fn has_track(&self) -> bool {
        self.attached_track.is_some()
    }

    /// Whether the application removed the sender's track: it sends nothing until it gets one.
    pub(crate) fn track_removed(&self) -> bool {
        self.track_removed
    }

    /// Gives the signalled track and the attached one the sender's codings: all of
    /// `send_encodings`, and none for the signalled one once the track was removed.
    fn sync_tracks(&mut self) {
        if let Some(track) = self.attached_track.as_mut() {
            track.set_codings(self.send_encodings.clone());
        }
        self.sender_track.set_codings(if self.track_removed {
            vec![]
        } else {
            self.send_encodings.clone()
        });
    }

    /// Whether the sender has encodings with SSRCs to describe and send with.
    /// Each send codec whose payload type `remote` (the remote description's codecs of the
    /// section) has takes that codec's `sdp_fmtp_line` (W3C webrtc-pc 5.2.9).
    pub(crate) fn take_send_fmtp(&mut self, remote: &[RTCRtpCodecParameters]) {
        let mut changed = false;
        for codec in &mut self.send_codecs {
            if let Some(remote) = remote.iter().find(|r| {
                r.payload_type == codec.payload_type
                    && r.rtp_codec
                        .mime_type
                        .eq_ignore_ascii_case(&codec.rtp_codec.mime_type)
            }) && remote.rtp_codec.sdp_fmtp_line != codec.rtp_codec.sdp_fmtp_line
            {
                codec.rtp_codec.sdp_fmtp_line = remote.rtp_codec.sdp_fmtp_line.clone();
                changed = true;
            }
        }
        if changed {
            self.last_returned_parameters = None;
        }
    }

    /// Drops what [`Self::get_parameters`] returned last, so that the next call reads the
    /// negotiated state again.
    pub(crate) fn invalidate_parameters(&mut self) {
        self.last_returned_parameters = None;
    }

    pub(crate) fn has_send_encodings(&self) -> bool {
        !self.send_encodings.is_empty()
    }

    /// W3C "set the RTCSessionDescription", a remote offer to receive simulcast: the
    /// sender's lone rid-less encoding is replaced by `proposed` (the "proposed envelope"),
    /// and kept as `[[LastStableRidlessSendEncodings]]` for a rollback when none is kept yet.
    pub(crate) fn propose_send_encodings(&mut self, proposed: Vec<RTCRtpEncodingParameters>) {
        if self.last_stable_ridless_send_encodings.is_none() {
            self.last_stable_ridless_send_encodings = Some(self.send_encodings.clone());
        }
        self.set_send_encodings(proposed);
    }

    /// A rollback of the remote offer that proposed encodings: the rid-less encoding comes
    /// back. `true` when there was one to restore.
    pub(crate) fn restore_ridless_send_encodings(&mut self) -> bool {
        let Some(encodings) = self.last_stable_ridless_send_encodings.take() else {
            return false;
        };
        self.set_send_encodings(encodings);
        true
    }

    /// Whether the sender holds encodings a remote offer proposed, which a rollback replaces
    /// (`[[LastStableRidlessSendEncodings]]` is set).
    pub(crate) fn has_proposed_send_encodings(&self) -> bool {
        self.last_stable_ridless_send_encodings.is_some()
    }

    /// A track given to a sender that holds proposed encodings, which it keeps (W3C
    /// `addTrack` and `replaceTrack` change only `[[SenderTrack]]`). When the sender had no
    /// encodings before the offer (the engine's form of the W3C default encoding), what a
    /// rollback restores is `restore`: the track's own encodings, or `None` (the W3C slot
    /// stays null, so the proposed encodings stay).
    pub(crate) fn keep_proposed_send_encodings_for_track(
        &mut self,
        restore: Option<Vec<RTCRtpEncodingParameters>>,
    ) {
        if self
            .last_stable_ridless_send_encodings
            .as_ref()
            .is_some_and(|encodings| encodings.is_empty())
        {
            self.last_stable_ridless_send_encodings = restore;
        }
    }

    /// The negotiation completed: the proposed envelope is the sender's.
    pub(crate) fn forget_ridless_send_encodings(&mut self) {
        self.last_stable_ridless_send_encodings = None;
    }

    /// webrtc-svc 3.2.3: the scalability mode the encoder of encoding `index` is configured
    /// with, which may differ from the one requested; `getParameters` returns it.
    pub(crate) fn set_configured_scalability_mode(
        &mut self,
        index: usize,
        mode: Option<String>,
    ) -> Result<()> {
        let encoding = self.send_encodings.get_mut(index).ok_or_else(|| {
            Error::RangeError(format!("the sender has no encoding at index {index}"))
        })?;
        encoding.scalability_mode = mode;
        self.last_returned_parameters = None;
        Ok(())
    }

    /// Gives a sender that has none its encodings (SSRCs allocated by the caller).
    pub(crate) fn set_send_encodings(&mut self, send_encodings: Vec<RTCRtpEncodingParameters>) {
        self.send_encodings = send_encodings;
        // A new envelope: the streams answers rejected from the old one are not offered.
        self.rejected_encodings.clear();
        self.envelope_rids.clear();
        self.last_returned_parameters = None;
        self.sync_tracks();
    }

    /// Gives each encoding the codec the coding of a new track names for it (the coding with
    /// the same rid, or at the same place when there are no rids), when that codec is within
    /// what was negotiated: one of the send codecs, or any before negotiation. A coding that
    /// names no codec, or one that was not negotiated, leaves the encoding's codec alone (the
    /// envelope `replaceTrack` stays in). The SSRCs and rids are the sender's and stay.
    /// W3C `replaceTrack`: whether a track with `codings` "can be sent immediately by the
    /// sender without violating the sender's already-negotiated envelope". The engine encodes
    /// nothing, so what it can see of the envelope is the codec each coding says its source
    /// produces: every coding that names one must name a codec of [[SendCodecs]] by mime type,
    /// clock rate and channel count (webrtc-pc: "Sources that also encode ... might be unable
    /// to produce the negotiated codec", "An audio track having a different number of
    /// channels"). A coding without a codec, or a sender with nothing negotiated, is within it;
    /// a coding's clock rate or channel count of 0 is not compared.
    pub(crate) fn within_negotiated_envelope(&self, codings: &[RTCRtpEncodingParameters]) -> bool {
        if self.send_codecs.is_empty() {
            return true;
        }
        codings.iter().all(|coding| {
            let codec = &coding.codec;
            codec.mime_type.is_empty()
                || self.send_codecs.iter().any(|negotiated| {
                    let n = &negotiated.rtp_codec;
                    // A negotiated audio codec without a channel count has one (RFC 8866
                    // section 6.6: "the default value is one"); a coding that names none says
                    // nothing about its channels.
                    let negotiated_channels = match n.channels {
                        0 if n
                            .mime_type
                            .get(..6)
                            .is_some_and(|p| p.eq_ignore_ascii_case("audio/")) =>
                        {
                            1
                        }
                        channels => channels,
                    };
                    n.mime_type.eq_ignore_ascii_case(&codec.mime_type)
                        && (codec.clock_rate == 0 || codec.clock_rate == n.clock_rate)
                        && (codec.channels == 0 || codec.channels == negotiated_channels)
                })
        })
    }

    pub(crate) fn adopt_coding_codecs(&mut self, codings: &[RTCRtpEncodingParameters]) {
        for (i, encoding) in self.send_encodings.iter_mut().enumerate() {
            let rid = &encoding.rtp_coding_parameters.rid;
            let coding = if rid.is_empty() {
                codings.get(i)
            } else {
                codings
                    .iter()
                    .find(|coding| &coding.rtp_coding_parameters.rid == rid)
            };
            if let Some(coding) = coding
                && !coding.codec.mime_type.is_empty()
                && (self.send_codecs.is_empty()
                    || encoding_send_codec(&coding.codec, &self.send_codecs).is_some())
            {
                encoding.codec = coding.codec.clone();
            }
        }
        self.last_returned_parameters = None;
        self.sync_tracks();
    }

    /// W3C webrtc-pc 4.4.1.6, the signaling state is stable after an answer: "for each
    /// encoding ... in [[SendEncodings]], if encoding.codec does not match any entry in
    /// [[SendCodecs]], ... remove encoding.codec". Such an encoding is then sent with the codec
    /// negotiation picked. Returns whether an encoding lost its codec.
    pub(crate) fn drop_unnegotiated_encoding_codecs(&mut self) -> bool {
        if self.send_codecs.is_empty() {
            return false;
        }
        let mut dropped = false;
        for encoding in &mut self.send_encodings {
            if !encoding.codec.mime_type.is_empty()
                && encoding_send_codec(&encoding.codec, &self.send_codecs).is_none()
            {
                encoding.codec = RTCRtpCodec::default();
                dropped = true;
            }
        }
        if dropped {
            self.last_returned_parameters = None;
            self.sync_tracks();
        }
        dropped
    }

    /// W3C `addTrack` reusing this sender: the track becomes `[[SenderTrack]]` and what the
    /// sender is signalled as (its `a=msid`), `streams` its associated streams.
    pub(crate) fn attach_track(&mut self, track: MediaStreamTrack, streams: Vec<MediaStreamId>) {
        self.sender_track = track.clone();
        self.attached_track = Some(track);
        self.track_removed = false;
        self.set_streams(streams);
        self.sync_tracks();
    }

    /// W3C `removeTrack` / `replaceTrack(null)`: `[[SenderTrack]]` becomes null and the sender
    /// stops sending (an RTCP BYE goes out for each stream it sent, as the streams are
    /// unbound). The encodings, their SSRCs, the msid and the associated streams stay.
    pub(crate) fn detach_track(&mut self, interceptor: &mut dyn Interceptor) {
        self.attached_track = None;
        self.track_removed = true;
        self.unbind_local_streams(interceptor);
        self.sent = false;
        self.sync_tracks();
    }

    /// Returns the codec kind (audio or video) for this sender.
    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// Returns the negotiated codec parameters for this sender.
    ///
    /// These are the codecs that were negotiated during SDP exchange
    /// and are available for sending.
    pub(crate) fn get_send_codecs(&self) -> &[RTCRtpCodecParameters] {
        &self.send_codecs
    }

    /// Counts a packet `write_rtp` sent with a rewritten payload type; `another_codec` when
    /// the written number named a format other than the codec it was sent as.
    pub(crate) fn count_rewritten_payload_type(&mut self, another_codec: bool) {
        self.rewritten_payload_type_rtp_packets += 1;
        if another_codec {
            self.rewritten_from_another_codec_rtp_packets += 1;
        }
    }

    /// See `RTCRtpSender::rewritten_payload_type_rtp_packets`.
    pub(crate) fn rewritten_payload_type_rtp_packets(&self) -> u64 {
        self.rewritten_payload_type_rtp_packets
    }

    /// See `RTCRtpSender::rewritten_from_another_codec_rtp_packets`.
    pub(crate) fn rewritten_from_another_codec_rtp_packets(&self) -> u64 {
        self.rewritten_from_another_codec_rtp_packets
    }

    /// The RTP capabilities of the engine for sending `kind` (W3C webrtc 5.2
    /// `RTCRtpSender.getCapabilities`, a static method: no negotiation state is read).
    ///
    /// # Returns
    ///
    /// `None` for a kind that is neither audio nor video.
    pub(crate) fn get_capabilities(
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        rtp_capabilities(kind, RTCRtpTransceiverDirection::Sendonly, media_engine)
    }

    /// Updates the sender's RTP send parameters.
    ///
    /// Validates and applies new encoding parameters including bitrate limits,
    /// frame rates, and resolution scaling.
    ///
    /// # Parameters
    ///
    /// * `parameters` - The new send parameters to apply
    /// * `_set_parameter_options` - Reserved for future options (currently unused)
    ///
    /// # Errors
    ///
    /// The setParameters validation steps (W3C webrtc 5.2):
    /// - `InvalidStateError` when `get_parameters` has not been called since the last
    ///   `set_parameters` (or since the codecs changed)
    /// - `InvalidModificationError` when the transaction id is not the one `get_parameters`
    ///   returned, the number of encodings or an encoding's rid differs, or a read-only member
    ///   (`header_extensions`, `rtcp`, `codecs`) was changed
    /// - `InvalidModificationError` when an encoding's SSRCs were changed, or its `codec` was
    ///   set to one that is not choosable
    /// - `RangeError` for a `scale_resolution_down_by` below 1.0 or a negative `max_framerate`
    pub(crate) fn set_parameters(
        &mut self,
        mut parameters: RTCRtpSendParameters,
        _set_parameter_options: Option<RTCSetParameterOptions>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        // Validate parameters by running the following setParameters validation steps:
        {
            let Some(last) = self.last_returned_parameters.as_ref() else {
                return Err(Error::InvalidStateError);
            };
            // Read-only members: the transaction id, the header extensions, RTCP and codecs.
            if parameters.transaction_id != last.transaction_id {
                return Err(Error::InvalidModificationError);
            }
            if parameters.rtp_parameters.header_extensions != last.rtp_parameters.header_extensions
                || parameters.rtp_parameters.rtcp != last.rtp_parameters.rtcp
                || parameters.rtp_parameters.codecs != last.rtp_parameters.codecs
            {
                return Err(Error::InvalidModificationError);
            }
            // The number of encodings and their order: an encoding is its rid and, in this
            // crate, the SSRCs it was given, none of which `setParameters` may change.
            if parameters.encodings.len() != self.send_encodings.len() {
                return Err(Error::InvalidModificationError);
            }
            for (p, s) in parameters.encodings.iter().zip(self.send_encodings.iter()) {
                let (p, s) = (&p.rtp_coding_parameters, &s.rtp_coding_parameters);
                if p.rid != s.rid
                    || p.ssrc != s.ssrc
                    || p.rtx.as_ref().map(|rtx| rtx.ssrc) != s.rtx.as_ref().map(|rtx| rtx.ssrc)
                    || p.fec.as_ref().map(|fec| fec.ssrc) != s.fec.as_ref().map(|fec| fec.ssrc)
                {
                    return Err(Error::InvalidModificationError);
                }
            }
            // An encoding's codec is one of the choosable codecs: the negotiated send codecs,
            // or before negotiation the codecs the engine can send. An encoding whose codec
            // was not touched passes, whatever it names (`addTransceiver` checked it).
            let choosable: Vec<RTCRtpCodec> = if self.send_codecs.is_empty() {
                media_engine
                    .get_codecs_by_kind(self.kind())
                    .into_iter()
                    .map(|codec| codec.rtp_codec)
                    .collect()
            } else {
                self.send_codecs
                    .iter()
                    .map(|codec| codec.rtp_codec.clone())
                    .collect()
            };
            for (p, s) in parameters.encodings.iter().zip(self.send_encodings.iter()) {
                if p.codec.mime_type.is_empty() || p.codec == s.codec {
                    continue;
                }
                if is_repair_codec(&p.codec)
                    || !choosable
                        .iter()
                        .any(|codec| codec_dictionary_match(&p.codec, codec))
                {
                    return Err(Error::InvalidModificationError);
                }
            }

            if self.kind() == RtpCodecKind::Video {
                parameters.encodings.iter_mut().for_each(|encoding| {
                    encoding.scale_resolution_down_by.get_or_insert(1.0);
                });

                if parameters.encodings.iter().any(|e| {
                    e.scale_resolution_down_by
                        .is_some_and(|v| v.is_nan() || v < 1.0)
                }) {
                    return Err(Error::RangeError(
                        "scaleResolutionDownBy must be >= 1.0".to_string(),
                    ));
                }
            } else {
                // Audio has no resolution or frame rate: those members are removed, not the
                // encodings that carry them (whose count is read-only).
                for encoding in &mut parameters.encodings {
                    encoding.scale_resolution_down_by = None;
                    encoding.max_framerate = None;
                }
            }
            if parameters
                .encodings
                .iter()
                .any(|e| e.max_framerate.is_some_and(|v| v.is_nan() || v < 0.0))
            {
                return Err(Error::RangeError(
                    "maxFramerate must not be negative".to_string(),
                ));
            }
        }

        // webrtc-svc 3.2.2: against the negotiated send codecs, or the implemented ones while
        // there are none yet.
        let send_codecs: Vec<RTCRtpCodec> = if self.send_codecs.is_empty() {
            media_engine
                .get_codecs_by_kind(self.kind())
                .into_iter()
                .map(|codec| codec.rtp_codec)
                .collect()
        } else {
            self.send_codecs
                .iter()
                .map(|codec| codec.rtp_codec.clone())
                .collect()
        };
        validate_scalability_modes(self.kind(), &mut parameters.encodings, &send_codecs, |_| {
            Error::InvalidModificationError
        })?;
        validate_extension_members(self.kind(), &mut parameters.encodings, |_| {
            Error::InvalidModificationError
        })?;

        // Restrictions the application changes are its new ones, offered from now on.
        for (new, old) in parameters.encodings.iter().zip(self.send_encodings.iter()) {
            let (new, old) = (&new.rtp_coding_parameters, &old.rtp_coding_parameters);
            if new.rid_restrictions != old.rid_restrictions {
                self.offered_rid_restrictions
                    .retain(|(rid, _)| *rid != new.rid);
            }
        }
        self.send_encodings = parameters.encodings;
        self.last_returned_parameters = None;
        self.sync_tracks();

        Ok(())
    }

    /// Returns the sender's current RTP send parameters.
    ///
    /// Constructs and caches the send parameters including codecs, encodings,
    /// and header extensions. Subsequent calls return the cached version until
    /// `set_parameters` is called.
    ///
    /// # Parameters
    ///
    /// * `media_engine` - The media engine containing codec and extension information
    pub(crate) fn get_parameters(
        &mut self,
        media_engine: &MediaEngine,
        negotiated_header_extensions: &[RTCRtpHeaderExtensionToNegotiate],
    ) -> &RTCRtpSendParameters {
        if self.last_returned_parameters.is_none() {
            let mut rtp_parameters = media_engine
                .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Sendonly);
            // W3C 5.2 getParameters: "headerExtensions ... negotiated for sending" by this
            // transceiver's m= section (webrtc-extensions [[NegotiatedHeaderExtensions]]), not
            // every extension of the kind: none before an answer was applied.
            crate::rtp_transceiver::header_extension_control::retain_negotiated(
                &mut rtp_parameters.header_extensions,
                negotiated_header_extensions,
                true,
            );
            rtp_parameters.codecs = if self.negotiated_not_sending {
                vec![]
            } else {
                self.send_codecs.clone()
            };
            rtp_parameters.rtcp.reduced_size = self.rtcp_reduced_size;
            // RFC 7022 / RFC 8834 section 4.9: one CNAME for every stream of the connection.
            rtp_parameters.rtcp.cname = media_engine.rtcp_cname.clone();

            self.last_returned_parameters = Some(RTCRtpSendParameters {
                rtp_parameters,
                transaction_id: math_rand_alpha(16),
                encodings: self.send_encodings.clone(),
            });
        }

        self.last_returned_parameters.as_ref().unwrap()
    }

    /// Replaces the track the sender sends with another of the same kind, without
    /// negotiation: the encodings and their SSRCs, the `a=msid` the sender is signalled with
    /// and its associated streams all stay (W3C webrtc 5.2 `replaceTrack`).
    ///
    /// The caller checks the transceiver (stopping) and binds the streams when the sender
    /// had no track.
    ///
    /// # Errors
    ///
    /// Returns `Error::ErrRTPSenderNewTrackHasIncorrectKind` if the new track's kind
    /// doesn't match the sender's kind.
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack)
    pub(crate) fn replace_track(&mut self, track: MediaStreamTrack) -> Result<()> {
        if self.kind() != track.kind() {
            return Err(Error::ErrRTPSenderNewTrackHasIncorrectKind);
        }
        self.attached_track = Some(track);
        self.track_removed = false;
        self.sync_tracks();
        Ok(())
    }

    /// The stream ids of the sender's `a=msid` lines: its associated streams, or `-` when it
    /// has none (RFC 9429 section 5.2.1). What a description is compared with to tell whether
    /// `setStreams` needs negotiating.
    pub(crate) fn streams(&self) -> &[MediaStreamId] {
        &self.msid_stream_ids
    }

    /// W3C `[[AssociatedMediaStreamIds]]`.
    pub(crate) fn associated_streams(&self) -> &[MediaStreamId] {
        &self.associated_media_stream_ids
    }

    /// Sets the sender's associated stream ids to exactly `streams`, without duplicates; the
    /// list may be empty (W3C webrtc 5.2 `setStreams`).
    pub(crate) fn set_streams(&mut self, streams: Vec<MediaStreamId>) {
        let mut associated: Vec<MediaStreamId> = Vec::with_capacity(streams.len());
        for stream in streams {
            if !associated.contains(&stream) {
                associated.push(stream);
            }
        }
        self.msid_stream_ids = if associated.is_empty() {
            vec!["-".to_owned()]
        } else {
            associated.clone()
        };
        self.associated_media_stream_ids = associated;
        // The negotiation-needed flag is updated by `RTCRtpSender::set_streams`, which has the
        // peer connection.
    }

    /// Returns whether this sender has been negotiated via SDP.
    pub(crate) fn is_negotiated(&self) -> bool {
        self.negotiated
    }

    /// Marks this sender as having been negotiated.
    pub(crate) fn set_negotiated(&mut self) {
        self.negotiated = true;
    }

    pub(crate) fn has_sent(&self) -> bool {
        self.sent
    }
    pub(crate) fn set_sent(&mut self) {
        self.sent = true;
    }

    /// Stops the sender: its streams are unbound, which has the sender report interceptor
    /// say BYE for each (W3C webrtc 5.4 "stop sending and receiving").
    pub(crate) fn stop(
        &mut self,
        _media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<()> {
        self.unbind_local_streams(interceptor);

        self.negotiated = false;
        self.sent = false;

        Ok(())
    }

    /// Sets the preferred codecs for this sender.
    ///
    /// # Parameters
    ///
    /// * `codecs` - Vector of codec parameters in preference order
    pub(crate) fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) {
        self.send_codecs = codecs;
        self.remote_format_order.clear();
        self.last_returned_parameters = None;
    }

    /// Records the order of the remote description's m= line whose formats
    /// [`Self::set_codec_preferences`] just set, for the streams bound to the interceptors.
    pub(crate) fn set_remote_format_order(&mut self, order: Vec<PayloadType>) {
        self.remote_format_order = order;
    }

    /// The negotiated codecs in the remote description's order of preference, the ones it
    /// does not list (none, once negotiated) last.
    fn codecs_in_remote_order(&self) -> Vec<RTCRtpCodecParameters> {
        let mut codecs = self.send_codecs.clone();
        if !self.remote_format_order.is_empty() {
            codecs.sort_by_key(|codec| {
                self.remote_format_order
                    .iter()
                    .position(|pt| *pt == codec.payload_type)
                    .unwrap_or(usize::MAX)
            });
        }
        codecs
    }

    /// Configures RTX (retransmission) and FEC (forward error correction) for all encodings.
    ///
    /// # Parameters
    ///
    /// * `is_rtx_enabled` - Whether to enable RTX
    /// * `is_fec_enabled` - Whether to enable FEC
    pub(crate) fn configure_rtx_and_fec(&mut self, is_rtx_enabled: bool, is_fec_enabled: bool) {
        for encoding in self.send_encodings.iter_mut() {
            if !is_rtx_enabled {
                encoding.rtp_coding_parameters.rtx = None;
            }
            if !is_fec_enabled {
                encoding.rtp_coding_parameters.fec = None;
            }
        }
        // The streams are bound from the track's codings (`local_stream_infos`), which carry
        // the same repair SSRCs: dropped there too, or a stream would bind an RTX / FEC SSRC
        // with no payload type to send it with.
        self.sync_tracks();
        self.last_returned_parameters = None;
    }

    pub(crate) fn set_extmap_allow_mixed(&mut self, mixed: bool) {
        self.extmap_allow_mixed = mixed;
    }

    /// Whether a stream may mix one- and two-byte header extensions (RFC 8285 section 6).
    pub(crate) fn extmap_allow_mixed(&self) -> bool {
        self.extmap_allow_mixed
    }

    /// Whether the stream `ssrc` has sent the two-byte form (see `two_byte_ssrcs`).
    pub(crate) fn is_two_byte_stream(&self, ssrc: SSRC) -> bool {
        self.two_byte_ssrcs.contains(&ssrc)
    }

    /// Records that the stream `ssrc` sent the two-byte form.
    pub(crate) fn set_two_byte_stream(&mut self, ssrc: SSRC) {
        if !self.two_byte_ssrcs.contains(&ssrc) {
            self.two_byte_ssrcs.push(ssrc);
        }
    }

    /// Records whether the transceiver's negotiated direction does not send; the parameters
    /// `get_parameters` returned are dropped when that changes (W3C 4.4.1.4: an answer sets
    /// `[[SendCodecs]]` and `[[LastReturnedParameters]]` to null).
    pub(crate) fn set_negotiated_not_sending(&mut self, not_sending: bool) {
        if self.negotiated_not_sending != not_sending {
            self.negotiated_not_sending = not_sending;
            self.last_returned_parameters = None;
        }
    }

    pub(crate) fn set_rtcp_reduced_size(&mut self, reduced_size: bool) {
        if self.rtcp_reduced_size != reduced_size {
            self.rtcp_reduced_size = reduced_size;
            self.last_returned_parameters = None;
        }
    }

    /// The send codecs of the last stable state, and the repair (RTX / FEC) SSRCs a rolled-back
    /// offer took from the encodings (`configure_rtx_and_fec` drops them when the offer lacks
    /// the repair format), after a rollback. An encoding is found by its SSRC and rid, so one
    /// the application changed since is left alone.
    pub(crate) fn restore_negotiated_state(&mut self, saved: &RTCRtpSenderInternal) {
        self.send_codecs.clone_from(&saved.send_codecs);
        restore_repair_ssrcs(&mut self.send_encodings, &saved.send_encodings);
        self.sync_tracks();
        self.last_returned_parameters = None;
    }

    /// Keeps the simulcast encodings an applied answer accepted, `accepted` being their rids
    /// with the restrictions the answer gave them (see
    /// `RTCPeerConnection::apply_negotiated_simulcast`). Without any of them, the first
    /// encoding stays. A sender with one encoding is left as it is.
    ///
    /// `keep_rejected` (`with_rejected_rids_kept_in_offers`, a remote answer): the encodings
    /// the answer leaves out are kept aside instead of dropped, for later offers to list
    /// (RFC 9429 section 5.2.2), and those an earlier answer left out take part again: one
    /// this answer accepts is the sender's again, in its place in the envelope.
    pub(crate) fn apply_simulcast_answer(
        &mut self,
        accepted: &[(String, RTCRtpRidRestrictions)],
        keep_rejected: bool,
    ) {
        if keep_rejected {
            let order = if self.envelope_rids.is_empty() {
                self.send_encodings
                    .iter()
                    .map(|encoding| encoding.rtp_coding_parameters.rid.clone())
                    .collect()
            } else {
                std::mem::take(&mut self.envelope_rids)
            };
            self.send_encodings.append(&mut self.rejected_encodings);
            self.send_encodings.sort_by_key(|encoding| {
                order
                    .iter()
                    .position(|rid| *rid == encoding.rtp_coding_parameters.rid)
                    .unwrap_or(usize::MAX)
            });
            self.envelope_rids = order;
        }
        if self.send_encodings.len() < 2 {
            self.envelope_rids.clear();
            return;
        }
        let restrictions_of = |rid: &str| {
            accepted
                .iter()
                .find(|(id, _)| id == rid)
                .map(|(_, restrictions)| restrictions)
        };
        let keeps_any = self
            .send_encodings
            .iter()
            .any(|encoding| restrictions_of(&encoding.rtp_coding_parameters.rid).is_some());
        let mut kept = Vec::with_capacity(self.send_encodings.len());
        for (index, mut encoding) in std::mem::take(&mut self.send_encodings)
            .into_iter()
            .enumerate()
        {
            let coding = &mut encoding.rtp_coding_parameters;
            match restrictions_of(&coding.rid) {
                Some(restrictions) => {
                    if *restrictions != coding.rid_restrictions
                        && !self
                            .offered_rid_restrictions
                            .iter()
                            .any(|(rid, _)| *rid == coding.rid)
                    {
                        self.offered_rid_restrictions
                            .push((coding.rid.clone(), coding.rid_restrictions.clone()));
                    }
                    coding.rid_restrictions = restrictions.clone();
                    // A stream an earlier answer rejected, accepted again.
                    if let Some(ssrc) = coding.ssrc {
                        self.removed_ssrcs.retain(|removed| *removed != ssrc);
                    }
                    kept.push(encoding);
                }
                None if !keeps_any && index == 0 => kept.push(encoding),
                None => {
                    if let Some(ssrc) = coding.ssrc
                        && !self.removed_ssrcs.contains(&ssrc)
                    {
                        self.removed_ssrcs.push(ssrc);
                    }
                    if keep_rejected {
                        self.rejected_encodings.push(encoding);
                    }
                }
            }
        }
        self.send_encodings = kept;
        if self.rejected_encodings.is_empty() {
            self.envelope_rids.clear();
        }
        // The restrictions offered for a kept-aside stream stay what later offers write.
        let kept_rids: Vec<String> = self
            .send_encodings
            .iter()
            .chain(&self.rejected_encodings)
            .map(|encoding| encoding.rtp_coding_parameters.rid.clone())
            .collect();
        self.offered_rid_restrictions
            .retain(|(rid, _)| kept_rids.contains(rid));
        self.last_returned_parameters = None;
        self.sync_tracks();
    }

    /// The encodings an offer lists, in the envelope's order, each with whether a remote
    /// answer rejected it (`with_rejected_rids_kept_in_offers`): the sender's own, and those
    /// kept aside for later offers (RFC 9429 section 5.2.2). Without kept-aside ones, the
    /// sender's encodings.
    pub(crate) fn offered_encodings(&self) -> Vec<(&RTCRtpEncodingParameters, bool)> {
        let mut offered: Vec<(&RTCRtpEncodingParameters, bool)> = self
            .send_encodings
            .iter()
            .map(|encoding| (encoding, false))
            .chain(
                self.rejected_encodings
                    .iter()
                    .map(|encoding| (encoding, true)),
            )
            .collect();
        if !self.rejected_encodings.is_empty() {
            offered.sort_by_key(|(encoding, _)| {
                self.envelope_rids
                    .iter()
                    .position(|rid| *rid == encoding.rtp_coding_parameters.rid)
                    .unwrap_or(usize::MAX)
            });
        }
        offered
    }

    /// The restrictions the offer gave `rid` before an answer tightened them, which a later
    /// offer writes again (RFC 9429 section 5.2.2: the `a=rid` lines "MUST stay the same").
    /// `None` when no answer changed them.
    pub(crate) fn offered_rid_restrictions(&self, rid: &str) -> Option<&RTCRtpRidRestrictions> {
        self.offered_rid_restrictions
            .iter()
            .find(|(id, _)| id == rid)
            .map(|(_, restrictions)| restrictions)
    }

    /// Moves the encoding (media, RTX or FEC flow) that sends from `old` to `new`, after a
    /// collision (RFC 3550 section 8.2): `Some` with the encoding's media SSRC as it was before,
    /// `None` when no encoding has `old`. The streams are re-bound by the caller.
    pub(crate) fn replace_ssrc(&mut self, old: SSRC, new: SSRC) -> Option<SSRC> {
        let mut primary = None;
        for encoding in &mut self.send_encodings {
            let coding = &mut encoding.rtp_coding_parameters;
            let before = coding.ssrc;
            let slots = [
                coding.ssrc.as_mut(),
                coding.rtx.as_mut().map(|rtx| &mut rtx.ssrc),
                coding.fec.as_mut().map(|fec| &mut fec.ssrc),
            ];
            for slot in slots.into_iter().flatten() {
                if *slot == old {
                    *slot = new;
                    primary = before;
                }
            }
        }
        primary?;
        let mut replaced = self
            .previous_ssrcs
            .iter()
            .position(|(ssrc, _)| *ssrc == old)
            .map(|i| self.previous_ssrcs.remove(i).1)
            .unwrap_or_default();
        replaced.push(old);
        self.previous_ssrcs.push((new, replaced));
        if let Some(streams) = self.clock_rates.remove(&old) {
            self.clock_rates.insert(new, streams);
        }
        self.last_returned_parameters = None;
        self.sync_tracks();
        primary
    }

    /// The SSRCs `ssrc` replaced after collisions (`replace_ssrc`), oldest first.
    pub(crate) fn previous_ssrcs(&self, ssrc: SSRC) -> &[SSRC] {
        self.previous_ssrcs
            .iter()
            .find(|(new, _)| *new == ssrc)
            .map_or(&[], |(_, replaced)| replaced.as_slice())
    }

    /// The SSRCs collisions moved the sender to (`replace_ssrc`).
    pub(crate) fn replacement_ssrcs(&self) -> impl Iterator<Item = SSRC> + '_ {
        self.previous_ssrcs.iter().map(|(new, _)| *new)
    }

    /// The SSRC a packet the application wrote with `ssrc` is sent with: the one a collision
    /// moved it to, else `ssrc`.
    pub(crate) fn current_ssrc(&self, ssrc: SSRC) -> SSRC {
        self.previous_ssrcs
            .iter()
            .find(|(_, replaced)| replaced.contains(&ssrc))
            .map_or(ssrc, |(new, _)| *new)
    }

    /// Whether `ssrc` is the SSRC of an encoding an answer removed (`apply_simulcast_answer`).
    pub(crate) fn is_removed_ssrc(&self, ssrc: SSRC) -> bool {
        self.removed_ssrcs.contains(&ssrc)
    }

    /// The streams this sender sends, as the interceptors are to see them now: each coding's
    /// SSRCs with the codec it is sent with ([`encoding_send_codec`]), that codec's RTX
    /// payload type, the FEC payload type and the negotiated header extensions.
    ///
    /// Read from the negotiated state directly, not through `get_parameters`, so that neither
    /// its cache (header extensions do not invalidate it) nor its transaction id is touched.
    fn local_stream_infos(&self, media_engine: &MediaEngine) -> Vec<StreamInfo> {
        let codecs = &self.send_codecs;
        // The section's formats as the remote side ordered them: the RED interceptor sends
        // RED when the remote side lists it ahead of the stream's codec.
        let section_codecs = self.codecs_in_remote_order();
        let header_extensions = media_engine
            .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Sendonly)
            .header_extensions;

        let mut infos = vec![];
        for coding in self.track().codings() {
            // An encoding without a codec of its own is sent with the codec negotiation picked,
            // and its stream is bound like any other: without it the interceptors never see the
            // stream (no sender reports, no NACK responder, no TWCC).
            // A stream moved to another clock rate (RFC 7160 section 4.1) is sent with the
            // codec the application switched to, while that is still negotiated.
            let switched = |ssrc: SSRC| {
                self.clock_rates
                    .get(&ssrc)
                    .and_then(|streams| streams.codec.as_ref())
                    .and_then(|chosen| {
                        codecs.iter().find(|codec| {
                            codec.payload_type == chosen.payload_type
                                && codec
                                    .rtp_codec
                                    .mime_type
                                    .eq_ignore_ascii_case(&chosen.rtp_codec.mime_type)
                                && codec.rtp_codec.clock_rate == chosen.rtp_codec.clock_rate
                        })
                    })
            };
            if let Some(&ssrc) = coding.rtp_coding_parameters.ssrc.as_ref()
                && !self.is_removed_ssrc(ssrc)
                && let Some(codec) = switched(ssrc)
                    .cloned()
                    .or_else(|| encoding_send_codec(&coding.codec, codecs))
            {
                let payload_type_rtx = find_rtx_payload_type(codec.payload_type, codecs);
                let fec_format = find_fec_format(codecs);
                let mut info = create_stream_info(
                    ssrc,
                    // A repair SSRC goes with a repair payload type: without one negotiated it
                    // could not be sent, so the stream does not name it.
                    coding
                        .rtp_coding_parameters
                        .rtx
                        .as_ref()
                        .filter(|_| payload_type_rtx.is_some())
                        .map(|rtx| rtx.ssrc),
                    coding
                        .rtp_coding_parameters
                        .fec
                        .as_ref()
                        .filter(|_| fec_format.is_some())
                        .map(|fec| fec.ssrc),
                    codec.payload_type,
                    payload_type_rtx,
                    fec_format.as_ref(),
                    &codec.rtp_codec,
                    &header_extensions,
                    &section_codecs,
                );
                info.initially_paused = !coding.rtp_coding_parameters.rid.is_empty()
                    && self
                        .initially_paused_rids
                        .contains(&coding.rtp_coding_parameters.rid);
                // RFC 5109 section 14.1: the stream's FEC runs in an RTP session of its own.
                info.fec_session = self
                    .fec_session
                    .map(|session| interceptor::FecSessionStream {
                        ssrc: ssrc ^ session.key,
                        payload_type: session.payload_type,
                        one_level_only: session.one_level_only,
                    });
                infos.push(info);
            }
        }
        infos
    }

    /// RFC 8853 sections 5.2 and 5.3.3: the simulcast streams the remote description marks
    /// initially paused (`~`) start in an unsolicited local pause, with RFC 7728 pause and
    /// resume negotiated for them (the pause and resume interceptor does it). Only the
    /// negotiation that first binds the sender's streams sets them: afterwards RFC 7728
    /// signalling decides, not the marks of later descriptions (section 5.3.4, item 2).
    pub(crate) fn set_initially_paused_rids(&mut self, rids: Vec<String>) {
        if self.bound_streams.is_empty() {
            self.initially_paused_rids = rids;
        }
    }

    /// The sender's encodings as `set_parameters` last left them (their `active` flags are what
    /// the outbound streams' statistics report).
    pub(crate) fn send_encodings(&self) -> &[RTCRtpEncodingParameters] {
        &self.send_encodings
    }

    /// The streams this sender bound to the interceptors, as they were bound.
    pub(crate) fn bound_streams(&self) -> &[StreamInfo] {
        &self.bound_streams
    }

    /// Sets where this sender's ULPFEC goes when a FEC session of its own protects its media;
    /// the streams take it the next time they are bound or re-bound.
    pub(crate) fn set_fec_session(&mut self, session: Option<FecSessionBinding>) {
        self.fec_session = session;
    }

    /// The FEC streams of this sender's FEC session, each a stream of that session: the
    /// stream the chain knows by [`interceptor::FecSessionStream::ssrc`], with the session's
    /// `ulpfec` payload type and the media stream's clock (RFC 5109 section 7.2: "the
    /// timestamp MUST be set to the value of the media RTP clock").
    fn fec_session_stream_infos(&self, media: &[StreamInfo]) -> Vec<StreamInfo> {
        media
            .iter()
            .filter_map(|info| {
                let session = info.fec_session?;
                // Numbered and reported on the session's own transport, for its own
                // congestion controller.
                let (rtp_header_extensions, rtcp_feedback) = self
                    .fec_session
                    .map(|binding| binding.feedback.stream_info())
                    .unwrap_or_default();
                Some(StreamInfo {
                    ssrc: session.ssrc,
                    payload_type: session.payload_type,
                    mime_type: format!("{}/ulpfec", self.kind()),
                    clock_rate: info.clock_rate,
                    rtp_header_extensions,
                    rtcp_feedback,
                    ..Default::default()
                })
            })
            .collect()
    }

    /// Binds this sender's streams to the interceptors, as negotiation left them.
    pub(crate) fn bind_local_streams(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) {
        let infos = self.local_stream_infos(media_engine);
        for info in &infos {
            interceptor.bind_local_stream(info);
        }
        let fec = self.fec_session_stream_infos(&infos);
        for info in &fec {
            interceptor.bind_local_stream(info);
        }
        self.bound_streams = infos;
        self.bound_fec_session_streams = fec;
    }

    /// Re-binds this sender's streams when a renegotiation changed what they are bound with
    /// (the codec an encoding is sent with, so its payload type and clock rate, the RTX payload
    /// type or SSRC, the FEC flow, the header extensions). The SSRCs stay; each changed stream
    /// is unbound with the information it was bound with and bound again with the new.
    ///
    /// The sender report interceptor sees the unbind and bind back to back and keeps the
    /// stream (its packet and octet counts and timing carry on, no RTCP BYE is sent). Other
    /// interceptors reset what they keep for it: the NACK responder's buffer of sent packets is
    /// emptied (packets sent before the change are no longer resent), and the TWCC and
    /// congestion control send side forget the stream until its next packet.
    ///
    /// # Returns
    ///
    /// Whether anything was re-bound.
    pub(crate) fn rebind_local_streams(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> bool {
        let infos = self.local_stream_infos(media_engine);
        if infos == self.bound_streams {
            return false;
        }
        for info in &self.bound_streams {
            interceptor.unbind_local_stream(info);
        }
        for info in &infos {
            interceptor.bind_local_stream(info);
        }
        // The FEC session's streams follow: those that are no longer, or are bound with
        // something else now, leave; the new ones join.
        let fec = self.fec_session_stream_infos(&infos);
        for info in &self.bound_fec_session_streams {
            if !fec.contains(info) {
                interceptor.unbind_local_stream(info);
            }
        }
        for info in &fec {
            if !self.bound_fec_session_streams.contains(info) {
                interceptor.bind_local_stream(info);
            }
        }
        self.bound_streams = infos;
        self.bound_fec_session_streams = fec;
        true
    }

    /// The SSRCs a renegotiation must replace because the codec its stream is sent with now
    /// has another clock rate (RFC 9429 section 5.11: "If media is already being transmitted,
    /// the same SSRC SHOULD be used unless the clock rate of the new codec is different, in
    /// which case a new SSRC MUST be chosen, as specified in [RFC7160], Section 4.1"): each
    /// such bound stream's SSRC, and its RTX SSRC, whose clock rate is the primary's.
    pub(crate) fn clock_rate_changed_ssrcs(&self, media_engine: &MediaEngine) -> Vec<SSRC> {
        let mut changed = vec![];
        for info in self.local_stream_infos(media_engine) {
            if let Some(bound) = self.bound_streams.iter().find(|b| b.ssrc == info.ssrc)
                && bound.clock_rate != info.clock_rate
            {
                changed.push(info.ssrc);
                changed.extend(bound.ssrc_rtx);
            }
        }
        changed
    }

    /// Unbinds the streams this sender bound, with the information they were bound with.
    pub(crate) fn unbind_local_streams(&mut self, interceptor: &mut dyn Interceptor) {
        for info in std::mem::take(&mut self.bound_streams) {
            interceptor.unbind_local_stream(&info);
        }
        for info in std::mem::take(&mut self.bound_fec_session_streams) {
            interceptor.unbind_local_stream(&info);
        }
        // The streams of the other clock rates leave with it (RFC 3550 6.6: each says BYE).
        for streams in std::mem::take(&mut self.clock_rates).into_values() {
            for info in streams.parked {
                interceptor.unbind_local_stream(&info);
            }
        }
    }

    /// RFC 7160 section 4.1: what a packet of the stream `ssrc` sent with a codec of
    /// `clock_rate` asks of it. The stream's first clock rate is the one it was bound with;
    /// another one moves it to a new SSRC ([`move_to_clock_rate`](Self::move_to_clock_rate)),
    /// as does a return to one it used before (after a BYE for the SSRC that used it). A stream
    /// that is not bound is left alone.
    pub(crate) fn clock_rate_step(&mut self, ssrc: SSRC, clock_rate: u32) -> ClockRateStep {
        let Some(bound) = self
            .bound_streams
            .iter()
            .find(|info| info.ssrc == ssrc)
            .map(|info| info.clock_rate)
        else {
            return ClockRateStep::Keep;
        };
        let streams = self.clock_rates.entry(ssrc).or_insert_with(|| {
            let mut streams = ClockRateStreams::default();
            streams.history.switch_to(bound);
            streams
        });
        match streams.history.switch_to(clock_rate) {
            rtp::clock_rate::SsrcForClockRate::Keep => ClockRateStep::Keep,
            rtp::clock_rate::SsrcForClockRate::New
            | rtp::clock_rate::SsrcForClockRate::NewAfterBye => ClockRateStep::Move,
        }
    }

    /// RFC 7160 section 4.1: the stream `old` is sent with `codec`, of another clock rate,
    /// from now on, as SSRC `new` (its RTX stream as `new_rtx`). The stream it leaves stays in
    /// the session (its sender reports go on); the stream of `codec`'s clock rate it used
    /// before, if any, leaves it (BYE). Returns the new stream's information and the SSRCs of
    /// the other clock rates still in the session.
    pub(crate) fn move_to_clock_rate(
        &mut self,
        old: SSRC,
        new: SSRC,
        new_rtx: Option<SSRC>,
        codec: &RTCRtpCodecParameters,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> (Option<StreamInfo>, Vec<SSRC>) {
        let mut streams = self.clock_rates.remove(&old).unwrap_or_default();
        // A rate used before: the SSRC that used it says BYE, and a new one takes its place.
        if let Some(index) = streams
            .parked
            .iter()
            .position(|info| info.clock_rate == codec.rtp_codec.clock_rate)
        {
            let gone = streams.parked.remove(index);
            interceptor.unbind_local_stream(&gone);
        }
        let old_rtx = self
            .bound_streams
            .iter()
            .find(|info| info.ssrc == old)
            .and_then(|info| info.ssrc_rtx);
        if let Some(index) = self.bound_streams.iter().position(|info| info.ssrc == old) {
            streams.parked.push(self.bound_streams.remove(index));
        }
        self.replace_ssrc(old, new);
        if let (Some(old_rtx), Some(new_rtx)) = (old_rtx, new_rtx) {
            self.replace_ssrc(old_rtx, new_rtx);
        }
        streams.codec = Some(codec.clone());
        let parked: Vec<SSRC> = streams.parked.iter().map(|info| info.ssrc).collect();
        self.clock_rates.insert(new, streams);
        let info = self
            .local_stream_infos(media_engine)
            .into_iter()
            .find(|info| info.ssrc == new);
        if let Some(info) = &info {
            interceptor.bind_local_stream(info);
            self.bound_streams.push(info.clone());
        }
        (info, parked)
    }

    /// The SSRCs of the streams of other clock rates this sender keeps in the session.
    pub(crate) fn parked_ssrcs(&self) -> impl Iterator<Item = SSRC> + '_ {
        self.clock_rates.values().flat_map(|streams| {
            streams
                .parked
                .iter()
                .flat_map(|info| std::iter::once(info.ssrc).chain(info.ssrc_rtx))
        })
    }
}

/// The width and height of the VP8 key frame whose first packet `payload` is (RFC 7741
/// section 4.2 payload descriptor, then the key frame header of RFC 6386 section 9.1: frame
/// tag with P = 0, start code 9d 01 2a, 14-bit width and height), `None` for any other packet.
pub(crate) fn vp8_key_frame_size(payload: &[u8]) -> Option<(u16, u16)> {
    let first = *payload.first()?;
    // S (start of a partition) with partition index 0: the first packet of a frame.
    if first & 0x10 == 0 || first & 0x07 != 0 {
        return None;
    }
    let mut offset = 1;
    if first & 0x80 != 0 {
        let extension = *payload.get(1)?;
        offset = 2;
        if extension & 0x80 != 0 {
            // PictureID: one octet, two with M set.
            offset += if payload.get(offset)? & 0x80 != 0 {
                2
            } else {
                1
            };
        }
        if extension & 0x40 != 0 {
            offset += 1; // TL0PICIDX
        }
        if extension & 0x30 != 0 {
            offset += 1; // TID / Y / KEYIDX
        }
    }
    let header = payload.get(offset..offset + 10)?;
    if header[0] & 0x01 != 0 || header[3..6] != [0x9d, 0x01, 0x2a] {
        return None;
    }
    let width = u16::from_le_bytes([header[6], header[7]]) & 0x3fff;
    let height = u16::from_le_bytes([header[8], header[9]]) & 0x3fff;
    Some((width, height))
}

/// The largest frame size the scalability structure of a VP9 packet that starts a frame states
/// (RFC 9628 section 4.2.1, on a key picture's first packet), `None` for any other packet.
pub(crate) fn vp9_key_picture_size(payload: &bytes::Bytes) -> Option<(u16, u16)> {
    use rtp::packetizer::Depacketizer;
    let mut packet = rtp::codec::vp9::Vp9Packet::default();
    packet.depacketize(payload).ok()?;
    if !(packet.b && packet.v) {
        return None;
    }
    let width = packet.width.iter().copied().max()?;
    let height = packet.height.iter().copied().max()?;
    Some((width, height))
}

/// A numeric parameter of an `a=fmtp` line (`max-fs=3600;max-fr=30`), by its name in any
/// case.
pub(crate) fn fmtp_number(fmtp: &str, name: &str) -> Option<u32> {
    fmtp.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// webrtc-extensions 5: `scaleResolutionDownTo` is removed from audio encodings; when one
/// encoding has it, every active encoding must, each with both dimensions above 0 (`error`:
/// OperationError in addTransceiver, InvalidModificationError in setParameters);
/// `adaptivePtime` with `ptime` is an InvalidModificationError.
pub(crate) fn validate_extension_members(
    kind: RtpCodecKind,
    encodings: &mut [RTCRtpEncodingParameters],
    error: impl Fn(String) -> Error,
) -> Result<()> {
    if kind != RtpCodecKind::Video {
        for encoding in encodings.iter_mut() {
            encoding.scale_resolution_down_to = None;
        }
    }
    if encodings
        .iter()
        .any(|e| e.scale_resolution_down_to.is_some())
    {
        if encodings
            .iter()
            .any(|e| e.active && e.scale_resolution_down_to.is_none())
        {
            return Err(error(
                "scaleResolutionDownTo must be on every active encoding".to_owned(),
            ));
        }
        if encodings.iter().any(|e| {
            e.scale_resolution_down_to
                .is_some_and(|r| r.max_width == 0 || r.max_height == 0)
        }) {
            return Err(error(
                "scaleResolutionDownTo dimensions must be greater than 0".to_owned(),
            ));
        }
    }
    if encodings
        .iter()
        .any(|e| e.adaptive_ptime && e.ptime.is_some())
    {
        return Err(Error::InvalidModificationError);
    }
    Ok(())
}

/// W3C webrtc-svc 3.2: the `scalabilityMode` checks of `addTransceiver` (refused with
/// `OperationError`) and `setParameters` (`InvalidModificationError`): `error` is the one to
/// refuse with. A mode outside the webrtc-svc table, one the encoding's own codec cannot carry,
/// one no codec of `codecs` (the implemented, or the negotiated, send codecs) can carry, and an
/// active "S" mode with another active encoding are refused. An audio sender has no mode: it is
/// removed.
pub(crate) fn validate_scalability_modes(
    kind: RtpCodecKind,
    encodings: &mut [RTCRtpEncodingParameters],
    codecs: &[RTCRtpCodec],
    error: fn(String) -> Error,
) -> Result<()> {
    use rtp::codec::svc::ScalabilityMode;
    use std::str::FromStr;
    if kind != RtpCodecKind::Video {
        for encoding in encodings.iter_mut() {
            encoding.scalability_mode = None;
        }
        return Ok(());
    }
    let mut simulcast_mode_active = false;
    for encoding in encodings.iter() {
        let Some(name) = encoding.scalability_mode.as_deref() else {
            continue;
        };
        let mode = ScalabilityMode::from_str(name)
            .map_err(|_| error(format!("{name:?} is not a scalability mode")))?;
        if !encoding.codec.mime_type.is_empty() && !mode.supported_by(&encoding.codec.mime_type) {
            return Err(error(format!(
                "{} cannot carry scalability mode {name}",
                encoding.codec.mime_type
            )));
        }
        if !codecs
            .iter()
            .any(|codec| mode.supported_by(&codec.mime_type))
        {
            return Err(error(format!(
                "no send codec can carry scalability mode {name}"
            )));
        }
        if encoding.active && mode.is_simulcast() {
            simulcast_mode_active = true;
        }
    }
    if simulcast_mode_active && encodings.iter().filter(|e| e.active).count() > 1 {
        return Err(error(
            "an active \"S\" scalability mode with another active encoding".to_owned(),
        ));
    }
    Ok(())
}

/// W3C webrtc 5.1 `addTransceiver`, the steps that take `sendEncodings`:
///
/// - a rid that is not `1*255(alpha-numeric)` (RFC 8851 section 10 as corrected by erratum
///   7132) is a `TypeError`,
///   as are a rid on some encodings only and a repeated rid;
/// - for audio `scaleResolutionDownBy` and `maxFramerate` are removed;
/// - a `scaleResolutionDownBy` below 1.0 and a negative `maxFramerate` are `RangeError`s;
/// - encodings past [`MAX_SEND_ENCODINGS`] are dropped from the end;
/// - video encodings without `scaleResolutionDownBy` get 1.0 when another has one, and
///   otherwise `2^(count - index - 1)`: each layer half the next;
/// - a single encoding loses its rid.
///
/// The codec of an encoding is checked where the encodings are given their SSRCs
/// (`codec_preferences_from_encodings`: one the engine cannot send is refused).
pub(crate) fn validate_send_encodings(
    kind: RtpCodecKind,
    encodings: &mut Vec<RTCRtpEncodingParameters>,
) -> Result<()> {
    // An empty rid is no rid (the encoding has none).
    let is_rid = |rid: &str| rid.is_empty() || sdp::attribute::RidIdGrammar::Corrected.admits(rid);
    if let Some(encoding) = encodings
        .iter()
        .find(|encoding| !is_rid(&encoding.rtp_coding_parameters.rid))
    {
        return Err(Error::TypeError(format!(
            "rid {:?} is not RFC 8851 syntax",
            encoding.rtp_coding_parameters.rid
        )));
    }
    let with_rid = encodings
        .iter()
        .filter(|encoding| !encoding.rtp_coding_parameters.rid.is_empty())
        .count();
    if with_rid != 0 && with_rid != encodings.len() {
        return Err(Error::ErrRTPSenderRidNil);
    }
    if encodings.iter().enumerate().any(|(i, encoding)| {
        !encoding.rtp_coding_parameters.rid.is_empty()
            && encodings[..i].iter().any(|earlier| {
                earlier.rtp_coding_parameters.rid == encoding.rtp_coding_parameters.rid
            })
    }) {
        return Err(Error::ErrRTPSenderRIDCollision);
    }

    if kind != RtpCodecKind::Video {
        for encoding in encodings.iter_mut() {
            encoding.scale_resolution_down_by = None;
            encoding.max_framerate = None;
        }
    }
    if encodings.iter().any(|e| {
        e.scale_resolution_down_by
            .is_some_and(|v| v.is_nan() || v < 1.0)
    }) {
        return Err(Error::RangeError(
            "scaleResolutionDownBy must be >= 1.0".to_string(),
        ));
    }
    if encodings
        .iter()
        .any(|e| e.max_framerate.is_some_and(|v| v.is_nan() || v < 0.0))
    {
        return Err(Error::RangeError(
            "maxFramerate must not be negative".to_string(),
        ));
    }

    encodings.truncate(MAX_SEND_ENCODINGS);

    if kind == RtpCodecKind::Video {
        if encodings
            .iter()
            .any(|encoding| encoding.scale_resolution_down_by.is_some())
        {
            for encoding in encodings.iter_mut() {
                encoding.scale_resolution_down_by.get_or_insert(1.0);
            }
        } else {
            let count = encodings.len();
            for (i, encoding) in encodings.iter_mut().enumerate() {
                encoding.scale_resolution_down_by =
                    Some(f64::from(1u32 << (count - i - 1).min(31)));
            }
        }
    }

    if let [encoding] = encodings.as_mut_slice() {
        encoding.rtp_coding_parameters.rid = String::new();
    }
    Ok(())
}

/// The codecs and header extensions the engine implements for `kind` in `direction` (W3C
/// webrtc 5.2.10 `RTCRtpCapabilities`): every registered codec once, the retransmission
/// format as a single entry without an `sdpFmtpLine` (it stands for every primary), and the
/// header extensions registered for the kind and direction.
pub(crate) fn rtp_capabilities(
    kind: RtpCodecKind,
    direction: RTCRtpTransceiverDirection,
    media_engine: &MediaEngine,
) -> Option<RTCRtpCapabilities> {
    if kind == RtpCodecKind::Unspecified {
        return None;
    }
    let mut codecs: Vec<RTCRtpCodec> = vec![];
    // W3C webrtc-pc 5.2 / 5.3 getCapabilities: "the list of implemented send codecs" ("receive
    // codecs"), "the most optimistic view of the codecs the user agent supports": the
    // registered formats, never the list a negotiation narrowed them to.
    for codec in media_engine.registered_codecs_by_kind(kind).iter().cloned() {
        let mut codec = codec.rtp_codec;
        if is_repair_codec(&codec) && repair_family(&codec) == "rtx" {
            codec.sdp_fmtp_line = String::new();
            codec.rtcp_feedback = vec![];
        }
        if !codecs.contains(&codec) {
            codecs.push(codec);
        }
    }
    Some(RTCRtpCapabilities {
        codecs,
        // W3C webrtc-pc 5.2 / 5.3: "the list of implemented header extensions for sending"
        // ("for receiving"), "the most optimistic view": the registered extensions of the kind
        // that the direction allows, once per URI (a dictionary has the URI only), never the
        // set a negotiation narrowed them to.
        header_extensions: media_engine
            .registered_header_extension_uris(kind, direction)
            .into_iter()
            .map(|uri| RTCRtpHeaderExtensionCapability { uri })
            .collect(),
    })
}

/// Gives each encoding of `encodings` that lost its RTX or FEC SSRC the one the encoding with
/// the same SSRC and rid has in `saved`.
pub(crate) fn restore_repair_ssrcs(
    encodings: &mut [RTCRtpEncodingParameters],
    saved: &[RTCRtpEncodingParameters],
) {
    for encoding in encodings {
        let parameters = &mut encoding.rtp_coding_parameters;
        let Some(saved) = saved
            .iter()
            .map(|e| &e.rtp_coding_parameters)
            .find(|saved| saved.ssrc == parameters.ssrc && saved.rid == parameters.rid)
        else {
            continue;
        };
        if parameters.rtx.is_none() {
            parameters.rtx.clone_from(&saved.rtx);
        }
        if parameters.fec.is_none() {
            parameters.fec.clone_from(&saved.fec);
        }
    }
}

#[cfg(test)]
mod repair_ssrc_collision_test {
    use super::*;
    use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
    use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
        RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters,
    };

    /// RFC 3550 section 8.2 for a repair flow (draft-ietf-payload-flexible-fec-scheme-03 4.2,
    /// RFC 8627 4.2.1: "SSRC collisions ... resolved as in RFC 3550"; RFC 4588 section 4: only
    /// the colliding stream picks a new SSRC): a collision on the FEC or the RTX SSRC moves
    /// that SSRC alone, and names the primary stream whose streams are bound again.
    #[test]
    fn a_colliding_repair_ssrc_alone_moves_to_the_replacement() {
        let encoding = RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(1000),
                rtx: Some(RTCRtpRtxParameters { ssrc: 2000 }),
                fec: Some(RTCRtpFecParameters { ssrc: 3000 }),
                ..Default::default()
            },
            ..Default::default()
        };
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Video,
            vec![encoding.clone()],
        );
        let mut sender =
            RTCRtpSenderInternal::new(RtpCodecKind::Video, track, vec![], vec![encoding]);

        assert_eq!(
            Some(1000),
            sender.replace_ssrc(3000, 3333),
            "the primary is named"
        );
        let coding = &sender.send_encodings()[0].rtp_coding_parameters;
        assert_eq!(Some(1000), coding.ssrc);
        assert_eq!(Some(2000), coding.rtx.as_ref().map(|rtx| rtx.ssrc));
        assert_eq!(Some(3333), coding.fec.as_ref().map(|fec| fec.ssrc));

        assert_eq!(Some(1000), sender.replace_ssrc(2000, 2222));
        let coding = &sender.send_encodings()[0].rtp_coding_parameters;
        assert_eq!(Some(2222), coding.rtx.as_ref().map(|rtx| rtx.ssrc));
        assert_eq!(Some(1000), coding.ssrc, "the media SSRC stays");
        assert_eq!(
            None,
            sender.replace_ssrc(9999, 1),
            "an SSRC the sender does not have"
        );
    }
}

#[cfg(test)]
mod remote_format_order_test {
    use super::*;
    use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
    use crate::rtp_transceiver::rtp_sender::rtp_codec::RTCRtpCodec;
    use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;

    fn codec(payload_type: PayloadType, mime_type: &str, fmtp: &str) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 48_000,
                channels: 2,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    /// RFC 3264 sections 5.1 and 6.1: the remote m= line's order is the remote side's
    /// preference, and the RED interceptor reads it from the bound stream's section. The
    /// negotiated list puts exact matches before partial ones, so a list that leads with RED
    /// while the remote line leads with Opus is bound in the remote order; a list set without
    /// a remote order (before any remote description) is bound as it is.
    #[test]
    fn a_local_streams_section_is_bound_in_the_remote_order() {
        let encoding = RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                ssrc: Some(1000),
                ..Default::default()
            },
            ..Default::default()
        };
        let track = MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Audio,
            vec![encoding.clone()],
        );
        let mut sender =
            RTCRtpSenderInternal::new(RtpCodecKind::Audio, track, vec![], vec![encoding]);
        let matched = vec![
            codec(63, "audio/red", "111/111"),
            codec(111, "audio/opus", "minptime=20;useinbandfec=1"),
        ];
        let section = |sender: &RTCRtpSenderInternal| -> Vec<(u8, String)> {
            let infos = sender.local_stream_infos(&MediaEngine::default());
            assert_eq!(infos.len(), 1);
            assert_eq!(infos[0].payload_type, 111, "Opus is the stream's codec");
            infos[0].section_mime_types.clone()
        };

        sender.set_codec_preferences(matched.clone());
        sender.set_remote_format_order(vec![111, 63]);
        assert_eq!(
            section(&sender),
            vec![(111, "audio/opus".to_owned()), (63, "audio/red".to_owned())],
            "the remote m= line's order"
        );

        sender.set_codec_preferences(matched);
        assert_eq!(
            section(&sender),
            vec![(63, "audio/red".to_owned()), (111, "audio/opus".to_owned())],
            "no remote order: the list as set"
        );
    }
}
