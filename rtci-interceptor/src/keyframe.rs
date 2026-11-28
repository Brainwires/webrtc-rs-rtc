//! Lets inbound key-frame requests reach the application.

use crate::Interceptor;
use crate::stream_info::StreamInfo;
use crate::{Attribute, Packet, TaggedPacket};
use rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use sansio::Protocol;
use shared::error::Error;
use std::collections::{HashMap, VecDeque};
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
/// # Repeated full intra requests
///
/// A FIR is a command with a sequence number (RFC 5104 section 4.3.1): the requester repeats
/// it, with the same number, until it sees the key frame, and "the encoder ... does not need
/// to act on a repetition". An FCI entry whose command sequence number is the one last seen
/// from that requester for that stream is a repetition and is not delivered again; a FIR left
/// with no entry is taken out of the compound packet. A PLI has no sequence number and is
/// always delivered.
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
/// use rtci_interceptor::{KeyFrameRequestInterceptor, Registry, Slot};
///
/// let chain = Registry::new()
///     .with(Slot::KeyFrameRequests, KeyFrameRequestInterceptor::new())
///     .build();
/// # let _ = chain;
/// ```
#[derive(Default)]
pub struct KeyFrameRequestInterceptor {
    /// The last FIR command sequence number seen, by (requester SSRC, target SSRC).
    fir_commands: HashMap<(u32, u32), u8>,
    reads: VecDeque<TaggedPacket>,
    writes: VecDeque<TaggedPacket>,
}

/// The most (requester, target) pairs whose last FIR command is remembered.
const MAX_FIR_COMMANDS: usize = 1024;

impl KeyFrameRequestInterceptor {
    /// An interceptor that delivers inbound PLI and FIR.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Why an interceptor of this crate asked the application for a key frame itself: the
/// Picture Loss Indication it puts on the read leg (sender SSRC 0, marked
/// [`Attribute::DeliverToApplication`]) carries this as [`Attribute::Custom`], so whoever
/// reads it can tell it from a request the remote peer sent. Read it with
/// [`AttributedPacket::custom`](crate::AttributedPacket::custom); a PLI or FIR without it came
/// from the network.
///
/// The origin rides with the packet from where it is made, rather than being guessed from the
/// sender SSRC: an SSRC is a random 32-bit number (RFC 3550 section 8.1), 0 included, so a
/// remote peer may send a PLI with sender SSRC 0, and that one is still the peer's. The peer connection reads it into
/// `RTCPeerConnectionEvent::OnKeyFrameRequestOrigin`.
///
/// ```
/// use rtci_interceptor::{Attribute, AttributedPacket, LocalKeyFrameRequest, Packet};
/// use std::sync::Arc;
///
/// let notice = AttributedPacket::new(Packet::Rtcp(vec![]))
///     .with(Attribute::Custom(Arc::new(LocalKeyFrameRequest::PacerDiscard)));
/// assert_eq!(
///     Some(&LocalKeyFrameRequest::PacerDiscard),
///     notice.custom::<LocalKeyFrameRequest>()
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LocalKeyFrameRequest {
    /// The pacer discarded a frame of the stream (`PacerDiscard`, outside a flush): the
    /// receiver will miss it, and the next picture it can decode is a key frame.
    PacerDiscard,
    /// The pacer gave its queue up at a collapse of the target (`PacerFlush`): for every
    /// video stream, whether it had media queued (then a `PacerDiscard` came first) or not
    /// (its repairs were dropped all the same).
    PacerFlush,
    /// The NACK responder gave the repair of the stream up (a request for a packet too old
    /// to be useful, or a repair backlog after a fall of the target): what was sent before is
    /// no longer repaired.
    RepairGivenUp,
}

/// Whether a compound RTCP packet carries a request only the encoder can answer: a PLI or a
/// FIR, and also an SLI or an RPSI (RFC 4585 sections 6.3.2, 6.3.3; RFC 8834 sections 5.1.3,
/// 5.1.4: a sender "SHOULD" try to repair the slice, and act on a reference picture
/// selection), which the encoder needs as much as a key-frame request.
///
/// The other codec control messages that only the encoder can act on go with them: a TSTR
/// (RFC 5104 section 4.3.2.2: "the encoder SHOULD take [it] into account" when it chooses its
/// trade-off; the TSTN that acknowledges it is the engine's), a VBCM (section 4.3.4, a
/// payload for the codec) and an LRR (RFC 9627, a layer refresh).
fn asks_for_key_frame(packets: &[Box<dyn rtcp::Packet>]) -> bool {
    use rtcp::payload_feedbacks::layer_refresh_request::LayerRefreshRequest;
    use rtcp::payload_feedbacks::reference_picture_selection_indication::ReferencePictureSelectionIndication;
    use rtcp::payload_feedbacks::slice_loss_indication::SliceLossIndication;
    use rtcp::payload_feedbacks::temporal_spatial_tradeoff::TemporalSpatialTradeoffRequest;
    use rtcp::payload_feedbacks::video_back_channel_message::VideoBackChannelMessage;
    packets.iter().any(|p| {
        let p = p.as_any();
        p.is::<PictureLossIndication>()
            || p.is::<FullIntraRequest>()
            || p.is::<SliceLossIndication>()
            || p.is::<ReferencePictureSelectionIndication>()
            || p.is::<TemporalSpatialTradeoffRequest>()
            || p.is::<VideoBackChannelMessage>()
            || p.is::<LayerRefreshRequest>()
    })
}

impl KeyFrameRequestInterceptor {
    /// Takes the repetitions out of the FIRs of a compound packet (RFC 5104 4.3.1.2): an
    /// entry is new when its command sequence number differs from the last one this
    /// requester sent for that stream.
    fn drop_repeated_firs(&mut self, packets: &mut Vec<Box<dyn rtcp::Packet>>) {
        if !packets
            .iter()
            .any(|packet| packet.as_any().is::<FullIntraRequest>())
        {
            return;
        }
        let mut kept: Vec<Box<dyn rtcp::Packet>> = Vec::with_capacity(packets.len());
        for packet in packets.drain(..) {
            let Some(fir) = packet.as_any().downcast_ref::<FullIntraRequest>() else {
                kept.push(packet);
                continue;
            };
            if fir.fir.is_empty() {
                // Nothing to tell a repetition by; the application gets it as it is.
                kept.push(packet);
                continue;
            }
            let new_commands: Vec<FirEntry> = fir
                .fir
                .iter()
                .filter(|entry| {
                    let key = (fir.sender_ssrc, entry.ssrc);
                    if self.fir_commands.get(&key) == Some(&entry.sequence_number) {
                        return false;
                    }
                    if self.fir_commands.len() >= MAX_FIR_COMMANDS
                        && !self.fir_commands.contains_key(&key)
                    {
                        self.fir_commands.clear();
                    }
                    self.fir_commands.insert(key, entry.sequence_number);
                    true
                })
                .cloned()
                .collect();
            if new_commands.len() == fir.fir.len() {
                kept.push(packet);
            } else if !new_commands.is_empty() {
                kept.push(Box::new(FullIntraRequest {
                    sender_ssrc: fir.sender_ssrc,
                    media_ssrc: fir.media_ssrc,
                    fir: new_commands,
                }));
            }
        }
        *packets = kept;
    }
}

/// The FIR commands an endpoint sends (RFC 5104 section 4.3.1): each new command for a media
/// sender takes the next command sequence number (modulo 256), a repetition keeps it, and
/// the "SSRC of media source" field of the packet is zero, the target being in the FCI.
///
/// The application decides when a request is new (it needs another key frame) and when it is
/// repeating one that has not been answered; this keeps the numbers.
///
/// ```
/// use rtci_interceptor::FirCommands;
///
/// let mut commands = FirCommands::new();
/// let first = commands.request(0x1111, 0x2222);
/// let again = commands.repeat(0x1111, 0x2222).unwrap();
/// let next = commands.request(0x1111, 0x2222);
///
/// assert_eq!(first.fir[0].sequence_number, again.fir[0].sequence_number);
/// assert_eq!(
///     first.fir[0].sequence_number.wrapping_add(1),
///     next.fir[0].sequence_number
/// );
/// assert_eq!(0, first.media_ssrc);
/// ```
#[derive(Debug, Default, Clone)]
pub struct FirCommands {
    /// The sequence number of the last command sent to each media sender.
    last: HashMap<u32, u8>,
}

impl FirCommands {
    /// No command sent yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// A new command for the media sender `media_ssrc`, from `sender_ssrc`.
    pub fn request(&mut self, sender_ssrc: u32, media_ssrc: u32) -> FullIntraRequest {
        let sequence_number = match self.last.get(&media_ssrc) {
            Some(last) => last.wrapping_add(1),
            None => 0,
        };
        self.last.insert(media_ssrc, sequence_number);
        Self::packet(sender_ssrc, media_ssrc, sequence_number)
    }

    /// The last command for `media_ssrc` again, or `None` when none was sent.
    pub fn repeat(&self, sender_ssrc: u32, media_ssrc: u32) -> Option<FullIntraRequest> {
        self.last
            .get(&media_ssrc)
            .map(|&sequence_number| Self::packet(sender_ssrc, media_ssrc, sequence_number))
    }

    fn packet(sender_ssrc: u32, media_ssrc: u32, sequence_number: u8) -> FullIntraRequest {
        FullIntraRequest {
            sender_ssrc,
            // RFC 5104 4.3.1.2: "SSRC of media source ... SHALL be set to 0".
            media_ssrc: 0,
            fir: vec![FirEntry {
                ssrc: media_ssrc,
                sequence_number,
            }],
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for KeyFrameRequestInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtcp(packets) = &mut msg.message.packet
            && !packets.is_empty()
        {
            self.drop_repeated_firs(packets);
            if packets.is_empty() && msg.message.attributes.is_empty() {
                // The compound packet was a repeated FIR and nothing else.
                return Ok(());
            }
        }
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

    /// RFC 4585 sections 6.3.2 and 6.3.3, RFC 8834 sections 5.1.3 and 5.1.4: SLI and RPSI
    /// reach the application, whose encoder repairs the slice or switches reference.
    #[test]
    fn sli_and_rpsi_reach_the_application() {
        use rtcp::payload_feedbacks::reference_picture_selection_indication::ReferencePictureSelectionIndication;
        use rtcp::payload_feedbacks::slice_loss_indication::SliceLossIndication;
        let sli: Box<dyn rtcp::Packet> = Box::new(SliceLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
            ..Default::default()
        });
        let rpsi: Box<dyn rtcp::Packet> = Box::new(ReferencePictureSelectionIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
            ..Default::default()
        });
        assert_eq!(delivered(true, vec![rr(), sli]), 1);
        assert_eq!(delivered(true, vec![rpsi]), 1);
    }

    /// RFC 5104 section 4.3.2.2 (the encoder "SHOULD take [a TSTR] into account"), section
    /// 4.3.4 (a VBCM is a message for the codec) and RFC 9627 (a layer refresh): the requests
    /// only the encoder can act on reach the application, which owns it; without the
    /// interceptor the terminus would end them.
    #[test]
    fn tstr_vbcm_and_lrr_reach_the_application() {
        use rtcp::payload_feedbacks::layer_refresh_request::{LayerRefreshRequest, LrrEntry};
        use rtcp::payload_feedbacks::temporal_spatial_tradeoff::{
            TemporalSpatialTradeoffRequest, TstEntry,
        };
        use rtcp::payload_feedbacks::video_back_channel_message::{
            VbcmEntry, VideoBackChannelMessage,
        };
        let tstr = || -> Box<dyn rtcp::Packet> {
            Box::new(TemporalSpatialTradeoffRequest {
                sender_ssrc: 1,
                entries: vec![TstEntry {
                    ssrc: 2,
                    sequence_number: 0,
                    index: 31,
                }],
            })
        };
        let vbcm = || -> Box<dyn rtcp::Packet> {
            Box::new(VideoBackChannelMessage {
                sender_ssrc: 1,
                entries: vec![VbcmEntry {
                    ssrc: 2,
                    sequence_number: 0,
                    payload_type: 96,
                    octet_string: bytes::Bytes::from_static(&[1, 2]),
                }],
            })
        };
        let lrr = || -> Box<dyn rtcp::Packet> {
            Box::new(LayerRefreshRequest {
                sender_ssrc: 1,
                entries: vec![LrrEntry {
                    ssrc: 2,
                    sequence_number: 0,
                    payload_type: 96,
                    target_temporal_layer_id: 0,
                    target_layer_id: 1,
                    ..Default::default()
                }],
            })
        };
        for packet in [tstr, vbcm, lrr] {
            assert_eq!(delivered(true, vec![rr(), packet()]), 1);
            assert_eq!(delivered(false, vec![rr(), packet()]), 0);
        }
    }

    #[test]
    fn other_rtcp_still_ends_at_the_terminus() {
        assert_eq!(delivered(true, vec![rr()]), 0);
    }

    #[test]
    fn without_it_the_terminus_swallows_them() {
        assert_eq!(delivered(false, vec![pli()]), 0);
    }

    fn fir_command(requester: u32, target: u32, sequence_number: u8) -> Box<dyn rtcp::Packet> {
        Box::new(FullIntraRequest {
            sender_ssrc: requester,
            media_ssrc: 0,
            fir: vec![FirEntry {
                ssrc: target,
                sequence_number,
            }],
        })
    }

    /// What the application gets from one chain as `compounds` arrive in turn.
    fn delivered_in_turn(
        compounds: Vec<Vec<Box<dyn rtcp::Packet>>>,
    ) -> Vec<Vec<Box<dyn rtcp::Packet>>> {
        let mut chain = Registry::new()
            .with(Slot::KeyFrameRequests, KeyFrameRequestInterceptor::new())
            .build();
        let mut out = vec![];
        for compound in compounds {
            chain.handle_read(rtcp(compound)).unwrap();
            let mut got = vec![];
            while let Some(tagged) = chain.poll_read() {
                if let Packet::Rtcp(packets) = tagged.message.packet {
                    got.extend(packets);
                }
            }
            out.push(got);
        }
        out
    }

    /// RFC 5104 4.3.1: a FIR repeated with the same command sequence number is one command.
    #[test]
    fn a_repeated_fir_is_delivered_once() {
        let out = delivered_in_turn(vec![
            vec![fir_command(1, 2, 7)],
            vec![fir_command(1, 2, 7)],
            vec![fir_command(1, 2, 7)],
            // The next command.
            vec![fir_command(1, 2, 8)],
        ]);
        assert_eq!(
            vec![1, 0, 0, 1],
            out.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    /// The sequence numbers are per requester and per target.
    #[test]
    fn fir_commands_are_told_apart_by_requester_and_target() {
        let out = delivered_in_turn(vec![
            vec![fir_command(1, 2, 7)],
            vec![fir_command(9, 2, 7)],
            vec![fir_command(1, 3, 7)],
            vec![fir_command(1, 2, 7)],
        ]);
        assert_eq!(
            vec![1, 1, 1, 0],
            out.iter().map(Vec::len).collect::<Vec<_>>()
        );
    }

    /// A repetition is taken out of the compound packet; what stands beside it stays, and a
    /// FIR that repeats one command and gives another keeps the new one.
    #[test]
    fn only_the_repeated_entries_are_dropped() {
        let both: Box<dyn rtcp::Packet> = Box::new(FullIntraRequest {
            sender_ssrc: 1,
            media_ssrc: 0,
            fir: vec![
                FirEntry {
                    ssrc: 2,
                    sequence_number: 7,
                },
                FirEntry {
                    ssrc: 3,
                    sequence_number: 1,
                },
            ],
        });
        let out = delivered_in_turn(vec![
            vec![fir_command(1, 2, 7)],
            vec![rr(), fir_command(1, 2, 7), pli()],
            vec![both],
        ]);
        // The PLI keeps the second compound packet deliverable, without the FIR.
        assert_eq!(2, out[1].len());
        assert!(out[1].iter().all(|p| !p.as_any().is::<FullIntraRequest>()));
        let fir = out[2][0]
            .as_any()
            .downcast_ref::<FullIntraRequest>()
            .unwrap();
        assert_eq!(
            vec![FirEntry {
                ssrc: 3,
                sequence_number: 1
            }],
            fir.fir
        );
    }

    /// RFC 5104 4.3.1.1: the command sequence number goes up by one, modulo 256, per new
    /// command, and stays for a repetition.
    #[test]
    fn fir_command_numbers_count_new_commands_modulo_256() {
        let mut commands = FirCommands::new();
        assert!(commands.repeat(1, 2).is_none());
        let mut last = commands.request(1, 2).fir[0].sequence_number;
        for _ in 0..300 {
            assert_eq!(last, commands.repeat(1, 2).unwrap().fir[0].sequence_number);
            let next = commands.request(1, 2);
            assert_eq!(last.wrapping_add(1), next.fir[0].sequence_number);
            assert_eq!(0, next.media_ssrc);
            assert_eq!(1, next.sender_ssrc);
            assert_eq!(2, next.fir[0].ssrc);
            last = next.fir[0].sequence_number;
        }
        // Another stream has its own count.
        assert_eq!(0, commands.request(1, 3).fir[0].sequence_number);
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
