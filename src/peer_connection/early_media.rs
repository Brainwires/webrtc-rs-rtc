//! Receiving as the local offer describes, before its answer arrives.
//!
//! RFC 3264 section 5.1: "Once the offerer has sent the offer, it MUST be prepared to receive
//! media for any recvonly streams described by that offer. It MUST be prepared to send and
//! receive media for any sendrecv streams in the offer". RFC 9429 section 4.1.11: "the
//! PeerConnection MUST be able to simultaneously support use of both the current and pending
//! local descriptions (e.g., support the codecs that exist in either description). This dual
//! processing begins when the PeerConnection enters the 'have-local-offer' state, and it
//! continues until setRemoteDescription is called with either (1) a final answer ... or (2) a
//! rollback". Section 5.9 lists what applying the local description prepares: the header
//! extension mappings, demultiplexing by MID and by payload type, the RTX mappings, and "If
//! the direction attribute is of type 'sendrecv' or 'recvonly', enable receipt and decoding of
//! media."
//!
//! # When media can arrive before the answer
//!
//! - A later offer on a transport that is up (the common case): the answerer sends as soon as
//!   it has applied its answer, and its media overtakes the answer whenever signalling is the
//!   slower path.
//! - An offer followed by a provisional answer (RFC 9429 section 4.1.10.1): the provisional
//!   answer brings the transport up and media flows while the offer is still pending; the
//!   final answer may choose other formats of the offer than the provisional one named.
//! - An initial offer without a provisional answer: none. The transports of this engine take
//!   their remote ICE credentials and DTLS fingerprint from the answer and run no handshake
//!   before it, so that nothing is accepted from an unverified source (RFC 8842 section 5.2;
//!   RFC 8830 section 3.1: "For initial negotiation, packets won't flow until the ... ICE
//!   candidates and fingerprints have been exchanged"). A section the offer stages on a new
//!   transport is in the same position until an answer starts that transport.
//!
//! # What the offer prepares
//!
//! For each m= section the offer lists with a receiving direction, the receiver takes the
//! section's formats ([`RTCRtpReceiverInternal::set_offered`]): a packet in any of them is
//! received, beside the formats negotiated before. The header extension ids of the offer are
//! read where no negotiated mapping exists (`MediaEngine::receive_header_extension_id`), so a
//! stream is placed by its MID (RFC 9143 section 9.2), by its rid for the layers an offer asks
//! to receive (RFC 8853 section 5.3.1), or by a payload type only one section lists. The
//! transport is the one the offer stages the section on (`TransportSet::transport_id_for`,
//! which the answer's BUNDLE grouping then settles), so the tables a packet is looked up in
//! follow the section.
//!
//! # Where the media goes
//!
//! To the receiver's track, at once. W3C webrtc-pc "set a session description" sets
//! `[[Receptive]]` to true when a *local* description, an offer included, lists the section
//! sendrecv or recvonly, and section 9.3 has a muted track of a receptive transceiver unmuted
//! by arriving data; the receiver and its track exist from `addTransceiver`. The `track` event
//! itself is tied to the remote description ("process remote tracks", section 5.1.1; RFC 8830
//! section 3.1: "If the connection is not in the RTCSignalingState 'stable', it will wait"
//! with the stream ids), and still fires when the answer is applied. Nothing is buffered:
//! a packet that matches nothing the offer lists is discarded and counted as before
//! (`RTCPeerConnection::discarded_rtp_packets`, RFC 8830 section 3.1).
//!
//! # What is sent before the answer
//!
//! Regular RTCP only where an RTP session already exists: RFC 3264 section 5.1, "even though
//! it may receive media before the answer arrives, it will not be able to send RTCP receiver
//! reports until the answer arrives", is about a session whose far end is not known yet, and
//! a transport that has only offered sections starts no RTCP session
//! (`RTCPeerConnection::sync_rtcp_sessions`). On a transport that carries negotiated sections
//! the session goes on, and its receiver reports cover a stream that arrived early (RFC 3550
//! section 6.4: every source heard is reported). RTCP feedback is another matter: RFC 4585
//! section 4.2, "The offerer and answerer MUST only use feedback mechanisms negotiated in this
//! way", and RFC 9429 section 5.11 enables them when an answer is applied. So an offered
//! format that was not negotiated before is bound without feedback until the answer.
//!
//! # The answer, and a rollback
//!
//! The final answer settles each receiver ([`RTCRtpReceiverInternal::settle_offered`]): the
//! formats it did not take stop being receivable, and a stream that arrived early keeps its
//! SSRC, its track and its statistics, and is bound again only if the answer changes what it
//! was bound with. A rollback (explicit, or the implicit one of a glare) takes all of it back
//! ([`RTCRtpReceiverInternal::roll_back_offered`]): the early streams are unbound and their
//! statistics retired, and the receivers are as the offer found them.

use super::RTCPeerConnection;
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use crate::peer_connection::sdp::simulcast::{SimulcastDirection, get_rids};
use crate::peer_connection::sdp::{
    MediaDescriptionExt, codecs_from_media_description, get_mid_value, get_peer_direction,
    is_rejected_media, rtp_extensions_from_media_description,
};
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::negotiates_ccfb;
use sdp::description::session::SessionDescription;

impl RTCPeerConnection {
    /// A local offer was applied: each receiver whose section it lists with a receiving
    /// direction is prepared for the section's formats, and the offer's header extension
    /// mappings are kept for reading what arrives before the answer.
    pub(super) fn prepare_offered_receive(&mut self, offer: &SessionDescription) {
        let negotiated_mids = self.current_description_mids();
        let mut extensions: Vec<(u16, String)> = vec![];
        for media in &offer.media_descriptions {
            let Some(mid) = get_mid_value(media) else {
                continue;
            };
            if media.is_webrtc_datachannel() || is_rejected_media(media) {
                continue;
            }
            let Some(transceiver) = self
                .rtp_transceivers
                .iter_mut()
                .find(|t| t.mid().as_deref() == Some(mid.as_str()))
            else {
                continue;
            };
            if transceiver.stopped() {
                continue;
            }
            if let Ok(mappings) = rtp_extensions_from_media_description(media) {
                for (uri, mapping) in mappings {
                    if !extensions.iter().any(|(id, _)| *id == mapping.id) {
                        extensions.push((mapping.id, uri));
                    }
                }
            }
            let receives = matches!(
                get_peer_direction(media),
                RTCRtpTransceiverDirection::Sendrecv | RTCRtpTransceiverDirection::Recvonly
            );
            let negotiated = negotiated_mids.contains(mid)
                && transceiver.current_direction() != RTCRtpTransceiverDirection::Unspecified;
            let Some(receiver) = transceiver.receiver_mut() else {
                continue;
            };
            if !receives {
                // A section a second offer no longer receives in: its formats are no longer
                // offered; what the first offer's early media established stays until the
                // answer or a rollback decides.
                if receiver.has_offered() {
                    receiver.set_offered(vec![], negotiated);
                }
                continue;
            }
            receiver.set_offered(
                codecs_from_media_description(media).unwrap_or_default(),
                negotiated,
            );
            // RFC 8853 section 5.3.1: "an offerer ... listing recv streams" is ready to
            // receive any of them.
            let rids: Vec<String> = get_rids(media, self.setting_engine.rid_id_grammar())
                .into_iter()
                .filter(|rid| rid.direction == SimulcastDirection::Recv && rid.simulcast)
                .map(|rid| rid.id)
                .collect();
            if !rids.is_empty() {
                receiver.set_offered_layers(&rids);
            }
        }
        extensions.sort_by_key(|(id, _)| *id);
        self.media_engine.offered_header_extensions = extensions;
        self.forget_ssrc_owners();
    }

    /// A provisional answer was applied: the sections it answers have negotiated receive
    /// codecs; every other format of the offer stays receivable until the final answer.
    pub(super) fn provisional_answer_received(&mut self, answer: &SessionDescription) {
        for media in &answer.media_descriptions {
            let Some(mid) = get_mid_value(media) else {
                continue;
            };
            if media.is_webrtc_datachannel() || is_rejected_media(media) {
                continue;
            }
            if let Some(receiver) = self
                .rtp_transceivers
                .iter_mut()
                .find(|t| t.mid().as_deref() == Some(mid.as_str()))
                .and_then(|transceiver| transceiver.receiver_mut().as_mut())
            {
                receiver.mark_offered_answered();
            }
        }
    }

    /// The final answer to the local offer was applied: every receiver is settled on what it
    /// negotiated, and the offer's header extension mappings are forgotten.
    pub(super) fn settle_offered_receive(&mut self) {
        for (id, transceiver) in self.rtp_transceivers.iter_mut().enumerate() {
            let kind = transceiver.kind();
            let mid = transceiver.mid().clone().unwrap_or_default();
            let Some(receiver) = transceiver.receiver_mut() else {
                continue;
            };
            if !receiver.settle_offered(&self.media_engine, self.interceptor.as_mut()) {
                continue;
            }
            // The statistics of the streams that arrived early take what the answer says of
            // them: the repair flows its `a=ssrc-group` lines name, and RFC 8888 feedback.
            let track_id = receiver.track().track_id().clone();
            for coding in receiver.track().codings() {
                let parameters = &coding.rtp_coding_parameters;
                let Some(ssrc) = parameters.ssrc else {
                    continue;
                };
                let stats = &mut self.pipeline_context.stats;
                if !stats.inbound_rtp_streams.contains_key(&ssrc) {
                    continue;
                }
                stats.get_or_create_inbound_rtp_streams(
                    ssrc,
                    kind,
                    &track_id,
                    &mid,
                    parameters.rtx.as_ref().map(|rtx| rtx.ssrc),
                    parameters.fec.as_ref().map(|fec| fec.ssrc),
                    id,
                );
                stats.set_inbound_ccfb(
                    ssrc,
                    negotiates_ccfb(
                        coding
                            .codec
                            .rtcp_feedback
                            .iter()
                            .map(|f| (f.typ.as_str(), f.parameter.as_str())),
                    ),
                );
            }
        }
        self.media_engine.offered_header_extensions.clear();
        self.forget_ssrc_owners();
    }

    /// The local offer is rolled back (RFC 9429 section 5.7, and the implicit rollback of a
    /// glare): what it prepared is taken back. The streams that arrived early are unbound and
    /// their statistics retired; a track their media unmuted is muted again. Their packets
    /// are unassociated media from here on (`discarded_rtp_packets`,
    /// `OnUnassociatedRtpDiscarded`).
    pub(super) fn roll_back_offered_receive(&mut self) {
        let mut muted = vec![];
        let mut gone = vec![];
        for transceiver in &mut self.rtp_transceivers {
            let Some(receiver) = transceiver.receiver_mut() else {
                continue;
            };
            let (ssrcs, muted_again) = receiver.roll_back_offered(self.interceptor.as_mut());
            if muted_again {
                muted.push(receiver.track().track_id().clone());
            }
            gone.extend(ssrcs);
        }
        for ssrc in gone {
            self.pipeline_context.stats.remove_inbound_rtp_stream(ssrc);
            let ctx = &mut self.pipeline_context.interceptor_handler_context;
            ctx.placed_ssrcs.remove(&ssrc);
            ctx.sdes_mids.remove(&ssrc);
            ctx.sdes_rids.remove(&ssrc);
            self.pipeline_context
                .endpoint_handler_context
                .delivered
                .remove(&ssrc);
        }
        for track_id in muted {
            self.pipeline_context
                .event_outs
                .push_back(RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnMute(
                    track_id,
                )));
        }
        self.media_engine.offered_header_extensions.clear();
        self.forget_ssrc_owners();
    }

    /// The cached owners of inbound SSRCs are hints the handlers re-check; after a change of
    /// what the receivers hold they are dropped.
    fn forget_ssrc_owners(&mut self) {
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
    }
}
