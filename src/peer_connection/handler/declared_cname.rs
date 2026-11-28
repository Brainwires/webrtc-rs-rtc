//! RFC 5576 section 6.1: the `cname` source attribute "MUST be the CNAME value that the media
//! sender will place in its RTCP SDES packets ... If a session participant receives an RTCP
//! SDES packet associating this SSRC with a different CNAME, it SHOULD assume there has been an
//! SSRC collision and that the description of the source that was carried in the SDP
//! description is not applicable to the actual source being received."
//!
//! The collision meant is one between remote sources (the declared source moved, or another
//! one took its SSRC), not one with a local SSRC: an SDES chunk for one of this endpoint's own
//! SSRCs is the RTCP session's RFC 3550 8.2 collision, which moves the local sender
//! (`RtcpSessionEvent::SsrcCollision`); the session reports no remote CNAME for it. Nothing
//! here moves a local SSRC or asks for negotiation.
//!
//! What the engine does with a declaration found not applicable:
//!
//! - The application is told, once per SSRC and declared CNAME
//!   ([`RTCPeerConnectionEvent::OnRemoteCnameMismatch`](crate::peer_connection::event::RTCPeerConnectionEvent::OnRemoteCnameMismatch)).
//! - A declared stream no packet has established yet, the only stream of its receiver, is
//!   taken off the receiver: its packets are then received as those of an SSRC no description
//!   mentions (RFC 5576 section 5: "they SHOULD be handled in the same manner as packets from
//!   additional sources would be handled had the endpoint not received any a=ssrc: attributes
//!   at all"), placed by the single section, their MID or their payload type (RFC 9143 section
//!   9.2) on the track the section's description made, and the `a=ssrc-group` repair flows
//!   the description paired with it are not used (an RTX stream is associated by its `apt`,
//!   RFC 4588 section 5.3). This is done only where the packets can be placed without the
//!   declaration: one media section, or the MID header extension negotiated.
//! - Otherwise the stream keeps the place the declaration gave it: one that packets have
//!   established keeps flowing as it is (it is not unbound, re-routed or ended), and one
//!   declared beside others (an `a=ssrc-group:SIM` layer, an SSRC declared beside `a=rid`
//!   lines) stays, since the engine has no place for it without the declaration and its media
//!   would be dropped. A repair flow the contradicted SSRC is, of a stream not established
//!   yet, is taken off that stream.
//! - A later remote description is held to the same rule: while it declares the SSRC with
//!   the CNAME its SDES contradicted, the declaration is not applied again; one that declares
//!   it with the CNAME the SDES carries (RFC 5576 section 5's updated description) applies.

use super::interceptor::InterceptorHandlerContext;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::internal::RTCRtpTransceiverInternal;
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
use std::collections::HashMap;

impl InterceptorHandlerContext {
    /// The CNAMEs a new remote description declares (`sdp::declared_cnames`). An SSRC found
    /// contradicted stays so only while the description still declares it with the same
    /// CNAME.
    pub(crate) fn set_declared_cnames(&mut self, declared: HashMap<SSRC, String>) {
        self.contradicted_declarations
            .retain(|ssrc, cname| declared.get(ssrc) == Some(cname));
        self.declared_cnames = declared;
    }

    /// Whether the remote description declares `ssrc` with another CNAME than the one its
    /// RTCP SDES named.
    pub(crate) fn declaration_contradicted(&self, ssrc: SSRC) -> bool {
        matches!(
            (self.declared_cnames.get(&ssrc), self.remote_cnames.get(&ssrc)),
            (Some(declared), Some(heard)) if declared != heard
        )
    }

    /// Applies RFC 5576 section 6.1 to every declared SSRC whose SDES CNAME contradicts the
    /// description (module documentation): after a remote description is applied and when an
    /// SDES names a CNAME. `mid_negotiated`: the MID header extension is negotiated, so a
    /// packet carries the m= section it belongs to. Returns the SSRCs found contradicted
    /// that were not before, in order.
    pub(crate) fn withdraw_contradicted_declarations(
        &mut self,
        transceivers: &mut [RTCRtpTransceiverInternal],
        mid_negotiated: bool,
    ) -> Vec<SSRC> {
        let mut contradicted: Vec<(SSRC, String)> = self
            .declared_cnames
            .iter()
            .filter(|(ssrc, _)| self.declaration_contradicted(**ssrc))
            .map(|(ssrc, cname)| (*ssrc, cname.clone()))
            .collect();
        contradicted.sort_unstable();
        let placeable = transceivers.len() == 1 || mid_negotiated;
        let mut new = vec![];
        for (ssrc, declared) in contradicted {
            for transceiver in transceivers.iter_mut() {
                if let Some(receiver) = transceiver.receiver_mut() {
                    withdraw(receiver, ssrc, placeable);
                }
            }
            self.ssrc_owners.remove(ssrc);
            if self.contradicted_declarations.get(&ssrc) != Some(&declared) {
                log::warn!(
                    "ssrc {ssrc}: its RTCP SDES names the CNAME {:?}, the remote description \
                     {declared:?}; the description is not the source's (RFC 5576 section 6.1)",
                    self.remote_cnames.get(&ssrc)
                );
                self.contradicted_declarations.insert(ssrc, declared);
                new.push(ssrc);
            }
        }
        new
    }
}

/// Whether `receiver` declares `ssrc` and no packet has established its stream yet (the
/// track's coding has no codec).
fn unestablished(receiver: &RTCRtpReceiverInternal, ssrc: SSRC) -> bool {
    receiver
        .track()
        .get_codec_by_ssrc(ssrc)
        .is_some_and(|codec| codec.mime_type.is_empty())
}

/// Takes the declaration of `ssrc` off `receiver` where that is safe (module documentation):
/// the receiver's only stream, not established, when `placeable`; a repair flow of a stream
/// not established.
fn withdraw(receiver: &mut RTCRtpReceiverInternal, ssrc: SSRC, placeable: bool) {
    let codings = receiver.get_coding_parameters();
    if let [only] = codings
        && only.ssrc == Some(ssrc)
    {
        if placeable && only.rid.is_empty() && unestablished(receiver, ssrc) {
            receiver.set_coding_parameters(vec![]);
            receiver.track_mut().set_codings(vec![]);
        }
        return;
    }
    let primaries: Vec<SSRC> = codings
        .iter()
        .filter(|coding| {
            coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == ssrc)
                || coding.fec.as_ref().is_some_and(|fec| fec.ssrc == ssrc)
        })
        .filter_map(|coding| coding.ssrc)
        .filter(|primary| unestablished(receiver, *primary))
        .collect();
    if primaries.is_empty() {
        return;
    }
    let drop_repair = |coding: &mut RTCRtpCodingParameters| {
        if !coding
            .ssrc
            .is_some_and(|primary| primaries.contains(&primary))
        {
            return;
        }
        if coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == ssrc) {
            coding.rtx = None;
        }
        if coding.fec.as_ref().is_some_and(|fec| fec.ssrc == ssrc) {
            coding.fec = None;
        }
    };
    let mut parameters = receiver.get_coding_parameters().to_vec();
    parameters.iter_mut().for_each(&drop_repair);
    receiver.set_coding_parameters(parameters);
    let mut track_codings = receiver.track().codings().to_vec();
    track_codings
        .iter_mut()
        .for_each(|coding| drop_repair(&mut coding.rtp_coding_parameters));
    receiver.track_mut().set_codings(track_codings);
}
