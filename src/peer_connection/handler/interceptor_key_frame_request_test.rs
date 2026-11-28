//! Where a key-frame request came from, at the peer connection: `OnKeyFrameRequest` is
//! followed by `OnKeyFrameRequestOrigin`, which tells a Picture Loss Indication or Full Intra
//! Request the remote peer sent from the engine's own requests (the pacer's discard and flush,
//! the NACK responder's give-up). The origin is the `LocalKeyFrameRequest` attribute the
//! request carries from the interceptor that made it, never its sender SSRC: a remote peer's
//! PLI with sender SSRC 0 is still the peer's (RFC 3550 section 8.1, an SSRC is any 32-bit
//! number).

use super::*;
use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::event::{RTCKeyFrameRequestEvent, RTCKeyFrameRequestOrigin};
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodingParameters, RTCRtpEncodingParameters, RtpCodecKind,
};
use crate::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use bytes::Bytes;
use interceptor::{AttributedPacket, LocalKeyFrameRequest, PacerBacklog, PacerBuilder, StreamInfo};
use rtcp::payload_feedbacks::full_intra_request::{FirEntry, FullIntraRequest};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use sansio::Protocol;
use shared::TransportContext;
use std::sync::Arc;
use std::time::Duration;

/// Hands out on `poll_read` what was queued: the chain application-ward of the interceptors
/// that made the packets.
#[derive(Default)]
struct ReadChain {
    reads: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for ReadChain {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, _: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_read(&mut self) -> Option<TaggedPacket> {
        self.reads.pop_front()
    }
    fn handle_write(&mut self, _: TaggedPacket) -> Result<()> {
        Ok(())
    }
    fn poll_write(&mut self) -> Option<TaggedPacket> {
        None
    }
    fn handle_event(&mut self, _: ()) -> Result<()> {
        Ok(())
    }
    fn poll_event(&mut self) -> Option<()> {
        None
    }
    fn handle_timeout(&mut self, _: Instant) -> Result<()> {
        Ok(())
    }
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }
    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Interceptor for ReadChain {
    fn bind_local_stream(&mut self, _: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _: &StreamInfo) {}
}

/// What the application was told, in order: an `OnKeyFrameRequest` (its sender and RID) or an
/// `OnKeyFrameRequestOrigin`.
#[derive(Debug, Clone, PartialEq)]
enum Told {
    Request(RTCRtpSenderId, Option<String>),
    Origin(RTCKeyFrameRequestEvent),
}

/// Hands `messages` to the connection's interceptor handler as its chain would on the read
/// leg, and returns the key-frame events the application is given for them.
fn hand(
    pc: &mut crate::peer_connection::RTCPeerConnection,
    messages: Vec<AttributedPacket>,
) -> Vec<Told> {
    let mut chain = ReadChain::default();
    for message in messages {
        chain.reads.push_back(TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message,
        });
    }
    let media_engine = MediaEngine::default();
    let context = &mut pc.pipeline_context;
    context
        .interceptor_handler_context
        .is_dtls_handshake_complete = true;
    {
        let mut handler = InterceptorHandler::new(
            &mut context.interceptor_handler_context,
            &mut pc.rtp_transceivers,
            &media_engine,
            &mut chain,
            &mut context.stats,
            None,
        );
        while handler.poll_read().is_some() {}
    }
    context
        .interceptor_handler_context
        .event_outs
        .drain(..)
        .filter_map(|tagged| match tagged.event {
            RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnKeyFrameRequest { sender, rid },
            ) => Some(Told::Request(sender, rid)),
            RTCEventInternal::RTCPeerConnectionEvent(
                RTCPeerConnectionEvent::OnKeyFrameRequestOrigin(event),
            ) => Some(Told::Origin(event)),
            _ => None,
        })
        .collect()
}

const HIGH: u32 = 0x1001;
const LOW: u32 = 0x1002;
/// The remote peer's SSRC, as its receiver reports and requests carry it.
const VIEWER: u32 = 0x7777;

fn encoding(rid: &str, ssrc: u32) -> RTCRtpEncodingParameters {
    RTCRtpEncodingParameters {
        active: true,
        rtp_coding_parameters: RTCRtpCodingParameters {
            rid: rid.to_owned(),
            ssrc: Some(ssrc),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// A connection that sends a simulcast video, rids `h` (`HIGH`) and `l` (`LOW`).
fn connection() -> (crate::peer_connection::RTCPeerConnection, RTCRtpSenderId) {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().unwrap();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_media_engine(media_engine)
        .build(Instant::now())
        .unwrap();
    let video = RTCRtpSenderId::from(
        pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                streams: vec![],
                send_encodings: vec![encoding("h", HIGH), encoding("l", LOW)],
            }),
        )
        .unwrap(),
    );
    (pc, video)
}

fn pli(sender_ssrc: u32, media_ssrc: u32) -> AttributedPacket {
    AttributedPacket::new(Packet::Rtcp(vec![Box::new(PictureLossIndication {
        sender_ssrc,
        media_ssrc,
    })]))
    .with(Attribute::DeliverToApplication)
}

/// The packet an interceptor of the chain puts on the read leg to ask for a key frame.
fn local_pli(media_ssrc: u32, why: LocalKeyFrameRequest) -> AttributedPacket {
    pli(0, media_ssrc).with(Attribute::Custom(Arc::new(why)))
}

/// Both events for one request: `OnKeyFrameRequest`, then the same request with its origin.
fn told(sender: RTCRtpSenderId, rid: &str, origin: RTCKeyFrameRequestOrigin) -> [Told; 2] {
    [
        Told::Request(sender, Some(rid.to_owned())),
        Told::Origin(RTCKeyFrameRequestEvent {
            sender,
            rid: Some(rid.to_owned()),
            origin,
        }),
    ]
}

/// A PLI the remote peer sent is a remote PLI, whatever its sender SSRC: 0 is an SSRC a peer
/// may hold, so a PLI from SSRC 0 without the engine's attribute is still the peer's.
#[test]
fn a_remote_picture_loss_indication_is_told_as_remote() {
    let (mut pc, video) = connection();
    assert_eq!(
        told(
            video,
            "h",
            RTCKeyFrameRequestOrigin::RemotePictureLossIndication
        )
        .to_vec(),
        hand(&mut pc, vec![pli(VIEWER, HIGH)])
    );
    assert_eq!(
        told(
            video,
            "l",
            RTCKeyFrameRequestOrigin::RemotePictureLossIndication
        )
        .to_vec(),
        hand(&mut pc, vec![pli(0, LOW)]),
        "a remote PLI from sender SSRC 0 is the peer's"
    );
}

/// A FIR the remote peer sent is a remote FIR, one pair of events per entry naming a stream
/// of the sender.
#[test]
fn a_remote_full_intra_request_is_told_as_remote() {
    let (mut pc, video) = connection();
    let fir = AttributedPacket::new(Packet::Rtcp(vec![Box::new(FullIntraRequest {
        sender_ssrc: VIEWER,
        media_ssrc: 0,
        fir: vec![
            FirEntry {
                ssrc: LOW,
                sequence_number: 1,
            },
            FirEntry {
                ssrc: HIGH,
                sequence_number: 1,
            },
        ],
    })]))
    .with(Attribute::DeliverToApplication);
    let mut expected = told(video, "l", RTCKeyFrameRequestOrigin::RemoteFullIntraRequest).to_vec();
    expected.extend(told(
        video,
        "h",
        RTCKeyFrameRequestOrigin::RemoteFullIntraRequest,
    ));
    assert_eq!(expected, hand(&mut pc, vec![fir]));
}

/// The pacer's request after a discard, and the NACK responder's after a give-up (both a PLI
/// with sender SSRC 0, as `pacing/sender.rs` and `nack/responder.rs` make them), are told as
/// the engine's, with the reason they carry.
#[test]
fn the_engines_own_requests_are_told_as_local_with_their_reason() {
    let (mut pc, video) = connection();
    let mut expected = told(
        video,
        "h",
        RTCKeyFrameRequestOrigin::Local(LocalKeyFrameRequest::PacerDiscard),
    )
    .to_vec();
    expected.extend(told(
        video,
        "l",
        RTCKeyFrameRequestOrigin::Local(LocalKeyFrameRequest::RepairGivenUp),
    ));
    expected.extend(told(
        video,
        "h",
        RTCKeyFrameRequestOrigin::Local(LocalKeyFrameRequest::PacerFlush),
    ));
    assert_eq!(
        expected,
        hand(
            &mut pc,
            vec![
                local_pli(HIGH, LocalKeyFrameRequest::PacerDiscard),
                local_pli(LOW, LocalKeyFrameRequest::RepairGivenUp),
                local_pli(HIGH, LocalKeyFrameRequest::PacerFlush),
            ]
        )
    );
}

/// The real pacer at a collapse of the target (the default `PacerBacklog::Flush`): `HIGH` had
/// media queued (its request follows the `PacerDiscard`), `LOW` had none (no `PacerDiscard`
/// before its request, the case an application cannot recognise from the discard events).
/// Both requests are the pacer's flush, not the remote peer's.
#[test]
fn the_pacers_flush_requests_are_told_as_local() {
    let (mut pc, video) = connection();
    let epoch = Instant::now();
    let mut pacer = PacerBuilder::new()
        .with_target_bitrate(1_200_000.0)
        .with_backlog(PacerBacklog::Flush)
        .build();
    for ssrc in [HIGH, LOW] {
        pacer.bind_local_stream(&StreamInfo {
            ssrc,
            clock_rate: 90_000,
            mime_type: "video/VP8".to_owned(),
            payload_type: 96,
            ..Default::default()
        });
    }
    let target = |now: Instant, bits_per_second: f64| TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![]))
            .with(Attribute::TargetBitrateChanged { bits_per_second }),
    };
    pacer.handle_read(target(epoch, 1_200_000.0)).unwrap();
    for sequence_number in 0..40u16 {
        pacer
            .handle_write(TaggedPacket {
                now: epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        timestamp: u32::from(sequence_number / 4) * 3000,
                        ssrc: HIGH,
                        ..Default::default()
                    },
                    payload: Bytes::from(vec![0u8; 1488]),
                })),
            })
            .unwrap();
    }
    while pacer.poll_write().is_some() {}
    while pacer.poll_read().is_some() {}
    let fall = epoch + Duration::from_millis(10);
    pacer.handle_read(target(fall, 100_000.0)).unwrap();
    pacer.handle_timeout(fall).unwrap();
    let mut reads = Vec::new();
    while let Some(read) = pacer.poll_read() {
        reads.push(read.message);
    }
    assert!(
        reads
            .iter()
            .any(|read| read.custom::<interceptor::PacerFlush>().is_some()),
        "the pacer flushed: {reads:?}"
    );

    let mut expected = told(
        video,
        "h",
        RTCKeyFrameRequestOrigin::Local(LocalKeyFrameRequest::PacerFlush),
    )
    .to_vec();
    expected.extend(told(
        video,
        "l",
        RTCKeyFrameRequestOrigin::Local(LocalKeyFrameRequest::PacerFlush),
    ));
    assert_eq!(expected, hand(&mut pc, reads));
}

/// The origin is what the request is, not who it names: `is_remote` answers for the
/// application that only needs to know whether the peer asked.
#[test]
fn is_remote_holds_for_the_peers_requests_only() {
    assert!(RTCKeyFrameRequestOrigin::RemotePictureLossIndication.is_remote());
    assert!(RTCKeyFrameRequestOrigin::RemoteFullIntraRequest.is_remote());
    for why in [
        LocalKeyFrameRequest::PacerDiscard,
        LocalKeyFrameRequest::PacerFlush,
        LocalKeyFrameRequest::RepairGivenUp,
    ] {
        assert!(!RTCKeyFrameRequestOrigin::Local(why).is_remote());
    }
}
