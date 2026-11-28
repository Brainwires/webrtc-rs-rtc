//! Where a key-frame request came from (a fork addition: webrtc-encoded-transform's
//! `keyframerequest` has no origin).

use crate::rtp_transceiver::RTCRtpSenderId;

/// A key-frame request for one encoding of a sender, with where it came from: the payload of
/// [`RTCPeerConnectionEvent::OnKeyFrameRequestOrigin`](super::RTCPeerConnectionEvent::OnKeyFrameRequestOrigin).
///
/// Not a W3C type. Fields may be added (the struct is `#[non_exhaustive]`): read them by name
/// and match it with `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RTCKeyFrameRequestEvent {
    /// The sender whose stream the request names.
    pub sender: RTCRtpSenderId,
    /// The RID of the requested layer, `None` when the sender's encoding has none.
    pub rid: Option<String>,
    /// Who asked, and how.
    pub origin: RTCKeyFrameRequestOrigin,
}

/// Who asked for a key frame: the remote peer (and with which message), or this endpoint's
/// own interceptor chain.
///
/// The origin is carried from where the request is made: the engine's own requests are
/// Picture Loss Indications that carry an
/// [`interceptor::LocalKeyFrameRequest`] attribute from the interceptor that made them, and
/// every request without one came from the network. A remote peer's PLI with sender SSRC 0
/// (an SSRC is any 32-bit number, RFC 3550 section 8.1) is still `RemotePictureLossIndication`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RTCKeyFrameRequestOrigin {
    /// The remote peer sent a Picture Loss Indication (RFC 4585 section 6.3.1) naming the
    /// stream.
    RemotePictureLossIndication,
    /// The remote peer sent a Full Intra Request (RFC 5104 section 4.3.1) with an entry for
    /// the stream (a repetition of a command already seen is not delivered,
    /// `KeyFrameRequestInterceptor`).
    RemoteFullIntraRequest,
    /// The engine asked, not the remote peer: the pacer discarded a frame or gave its queue
    /// up, or the NACK responder gave the stream's repair up (see
    /// [`interceptor::LocalKeyFrameRequest`]). The receiver has not asked; it will miss
    /// what was dropped, and the next picture it can decode after it is a key frame.
    Local(interceptor::LocalKeyFrameRequest),
}

impl RTCKeyFrameRequestOrigin {
    /// Whether the remote peer sent the request (a PLI or a FIR from the network).
    pub fn is_remote(&self) -> bool {
        !matches!(self, Self::Local(_))
    }
}
