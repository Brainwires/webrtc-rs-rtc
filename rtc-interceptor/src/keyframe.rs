//! Lets inbound key-frame requests reach the application.

use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, Packet, TaggedPacket};
use rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// Marks inbound RTCP that asks for a key frame — a Picture Loss Indication (RFC 4585 §6.3.1) or
/// a Full Intra Request (RFC 5104 §4.3.1) — [`Attribute::DeliverToApplication`], so it passes the
/// chain's terminus ([`NoopInterceptor`](crate::NoopInterceptor)) instead of ending there.
///
/// # Why
///
/// The terminus ends every inbound RTCP packet no interceptor vouches for, which is right for
/// reports and feedback the chain itself acts on. A key-frame request is the exception: no
/// interceptor can act on it, because only the encoder can produce a key frame, and the encoder
/// is the application (or sits behind it). Swallowed, a receiver that lost its reference picture
/// asks again and again while the sender never hears it, and the picture stays broken until the
/// next scheduled key frame. So the requests are delivered: the application reads them as
/// `RTCMessage::RtcpPacket` (the whole compound packet the request arrived in).
///
/// # Where it goes
///
/// [`Slot::KeyFrameRequests`](crate::Slot::KeyFrameRequests), application-ward of every default
/// interceptor, so each of them has seen the packet first. It only marks packets; it never holds,
/// drops or generates one, so its position constrains nothing else. Marking an already marked
/// packet does nothing, so an application interceptor that marks the same packets can stay.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{KeyFrameRequestInterceptor, Registry, Slot};
///
/// let chain = Registry::new()
///     .with(Slot::KeyFrameRequests, KeyFrameRequestInterceptor::new())
///     .build();
/// # let _ = chain;
/// ```
#[derive(Default)]
pub struct KeyFrameRequestInterceptor {
    reads: VecDeque<TaggedPacket>,
    writes: VecDeque<TaggedPacket>,
}

impl KeyFrameRequestInterceptor {
    /// An interceptor that delivers inbound PLI and FIR.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Whether a compound RTCP packet carries a PLI or a FIR.
fn asks_for_key_frame(packets: &[Box<dyn rtcp::Packet>]) -> bool {
    packets.iter().any(|p| {
        let p = p.as_any();
        p.downcast_ref::<PictureLossIndication>().is_some()
            || p.downcast_ref::<FullIntraRequest>().is_some()
    })
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for KeyFrameRequestInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(packets) = &msg.message.packet
            && asks_for_key_frame(packets)
            && !msg.message.has(&Attribute::DeliverToApplication)
        {
            msg.message.attributes.push(Attribute::DeliverToApplication);
        }
        self.reads.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.reads.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.writes.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.writes.pop_front()
    }
}

impl Interceptor for KeyFrameRequestInterceptor {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttributedPacket, Registry, Slot};
    use rtcp::receiver_report::ReceiverReport;
    use shared::TransportContext;

    fn rtcp(packets: Vec<Box<dyn rtcp::Packet>>) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(packets)),
        }
    }

    fn pli() -> Box<dyn rtcp::Packet> {
        Box::new(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        })
    }

    fn fir() -> Box<dyn rtcp::Packet> {
        Box::new(FullIntraRequest {
            sender_ssrc: 1,
            media_ssrc: 2,
            fir: vec![],
        })
    }

    fn rr() -> Box<dyn rtcp::Packet> {
        Box::new(ReceiverReport {
            ssrc: 1,
            ..Default::default()
        })
    }

    /// What the application gets from a whole chain: the terminus is appended by `build`.
    fn delivered(with_interceptor: bool, packets: Vec<Box<dyn rtcp::Packet>>) -> usize {
        let registry = if with_interceptor {
            Registry::new().with(Slot::KeyFrameRequests, KeyFrameRequestInterceptor::new())
        } else {
            Registry::new()
        };
        let mut chain = registry.build();
        chain.handle_read(rtcp(packets)).unwrap();
        std::iter::from_fn(|| chain.poll_read())
            .filter(|p| match &p.message.packet {
                Packet::Rtcp(packets) => !packets.is_empty(),
                Packet::Rtp(_) => true,
            })
            .count()
    }

    #[test]
    fn pli_and_fir_reach_the_application() {
        assert_eq!(delivered(true, vec![pli()]), 1);
        assert_eq!(delivered(true, vec![fir()]), 1);
        // In a compound packet beside a report.
        assert_eq!(delivered(true, vec![rr(), pli()]), 1);
    }

    #[test]
    fn other_rtcp_still_ends_at_the_terminus() {
        assert_eq!(delivered(true, vec![rr()]), 0);
    }

    #[test]
    fn without_it_the_terminus_swallows_them() {
        assert_eq!(delivered(false, vec![pli()]), 0);
    }

    #[test]
    fn marking_is_idempotent() {
        let mut i = KeyFrameRequestInterceptor::new();
        let mut msg = rtcp(vec![pli()]);
        msg.message.attributes.push(Attribute::DeliverToApplication);
        i.handle_read(msg).unwrap();
        let out = i.poll_read().unwrap();
        assert_eq!(
            out.message
                .attributes
                .iter()
                .filter(|a| matches!(a, Attribute::DeliverToApplication))
                .count(),
            1
        );
    }
}
