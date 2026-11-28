//! `CongestionControlInterceptor` in a chain (P7-02).
//!
//! The interceptor's job is entirely about *what it records and when*, so these tests drive it
//! behind a real pacer and a real TWCC sender rather than in isolation. A recording estimator
//! stands in for an algorithm, so what is asserted is the interceptor's behaviour and not GCC's.

use rtci_interceptor::{
    Attribute, AttributedPacket, BandwidthEstimator, CongestionControlBuilder, Interceptor,
    PacerBuilder, Packet, PacketReport, RTCPFeedback, RTPHeaderExtension, Registry, Slot,
    StreamInfo, TaggedPacket, TwccSenderBuilder,
};
use sansio::Protocol;
use shared::TransportContext;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod rtcp_to_application;
use rtcp_to_application::DeliverRtcp;

const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

const SSRC: u32 = 0x0A0B_0C0D;
/// 1.2 Mb/s: one full-sized packet every 10 ms, so the release schedule is easy to read.
const BITRATE: f64 = 1_200_000.0;
const PAYLOAD_BYTES: usize = 1188;

/// An estimator that records what it was told and reports whatever it is set to.
#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Vec<PacketReport>>>,
    target: Arc<Mutex<f64>>,
}

impl Recorder {
    fn new(target: f64) -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            target: Arc::new(Mutex::new(target)),
        }
    }
    fn reports(&self) -> Vec<PacketReport> {
        self.seen.lock().unwrap().clone()
    }
    fn set_target(&self, target: f64) {
        *self.target.lock().unwrap() = target;
    }
}

impl BandwidthEstimator for Recorder {
    fn on_reports(&mut self, _now: Instant, reports: &[PacketReport]) {
        self.seen.lock().unwrap().extend_from_slice(reports);
    }
    fn target_bitrate(&self) -> f64 {
        *self.target.lock().unwrap()
    }
}

/// The shipped ordering, wire-to-application: congestion control, TWCC sender, pacer.
///
/// So on the write leg a packet is paced first, numbered second, and recorded third — which is what
/// makes `packet.now` the release instant by the time the history sees it.
fn chain(estimator: Recorder) -> impl Interceptor {
    Registry::new()
        // So a test can see the feedback packet the estimate rides out on. The real consumer is
        // the pacer, which reads the attribute mid-chain and needs no such thing.
        .with(Slot::from(14_000), DeliverRtcp::new())
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(estimator).build(),
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(
            Slot::Pacer,
            PacerBuilder::new()
                .with_target_bitrate(BITRATE)
                .with_burst_bits(12_000.0)
                .build(),
        )
        .build()
}

fn stream() -> StreamInfo {
    StreamInfo {
        ssrc: SSRC,
        clock_rate: 90_000,
        mime_type: "video/VP8".to_owned(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        }],
        rtp_header_extensions: vec![RTPHeaderExtension {
            uri: TRANSPORT_CC_URI.to_owned(),
            id: 5,
        }],
        ..Default::default()
    }
}

fn rtp(now: Instant, sequence_number: u16) -> TaggedPacket {
    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: 96,
                sequence_number,
                timestamp: u32::from(sequence_number) * 3_000,
                ssrc: SSRC,
                ..Default::default()
            },
            payload: vec![0xAB; PAYLOAD_BYTES].into(),
        })),
    }
}

/// TWCC feedback saying every packet from `base` arrived, one 64 ms reference tick apart.
fn twcc_feedback(now: Instant, base: u16, count: u16) -> TaggedPacket {
    twcc_feedback_at(now, base, count, 1, 0)
}

/// [`twcc_feedback`] with its reference time (64 ms ticks) and feedback packet count.
fn twcc_feedback_at(
    now: Instant,
    base: u16,
    count: u16,
    reference_time: u32,
    fb_pkt_count: u8,
) -> TaggedPacket {
    use rtcp::transport_feedbacks::transport_layer_cc::{
        PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
        TransportLayerCc,
    };

    let feedback = TransportLayerCc {
        sender_ssrc: 0,
        media_ssrc: SSRC,
        base_sequence_number: base,
        packet_status_count: count,
        reference_time,
        fb_pkt_count,
        packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
            type_tcc: StatusChunkTypeTcc::RunLengthChunk,
            packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
            run_length: count,
        })],
        recv_deltas: (0..count)
            .map(|_| RecvDelta {
                type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                delta: 250,
            })
            .collect(),
    };

    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(feedback)])),
    }
}

/// Send `count` packets and drive the pacer until everything has been released.
fn send_and_drain(chain: &mut impl Interceptor, epoch: Instant, count: u16) -> Vec<Instant> {
    for sequence_number in 0..count {
        chain
            .handle_write(rtp(epoch, sequence_number))
            .expect("write");
    }

    let mut released = Vec::new();
    for step in 0..200u32 {
        let now = epoch + Duration::from_millis(u64::from(step));
        chain.handle_timeout(now).expect("timeout");
        while let Some(packet) = chain.poll_write() {
            if matches!(packet.message.packet, Packet::Rtp(_)) {
                released.push(packet.now);
            }
        }
        if released.len() == usize::from(count) {
            break;
        }
    }
    released
}

/// The core of the task: every departing packet is recorded, with the instant the **pacer**
/// released it rather than the instant the application enqueued it.
#[test]
fn every_departing_packet_is_recorded_at_its_release_instant() {
    let epoch = Instant::now();
    let estimator = Recorder::new(BITRATE);
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&stream());

    let released = send_and_drain(&mut chain, epoch, 5);
    assert_eq!(5, released.len(), "the pacer eventually releases all five");

    // A burst of one packet at 1.2 Mb/s is one packet per 10 ms, so the pacer must have spread
    // them: if it had not, every release instant would be the epoch.
    assert!(
        released.last().unwrap() > &epoch,
        "the pacer released everything at once, so this test cannot tell enqueue from release: \
         {released:?}"
    );

    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(200), 0, 5))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert_eq!(5, reports.len(), "one report per packet sent");

    let departures: Vec<Instant> = reports.iter().map(|report| report.departure).collect();
    assert_eq!(
        released, departures,
        "the history must record the release instant — the pacer's queueing delay counted as \
         network delay is exactly what makes a delay-based estimate collapse"
    );
}

/// The reports carry the transport-wide sequence numbers the TWCC sender assigned, which is how
/// the remote's feedback is matched back to what was sent.
#[test]
fn reports_carry_the_transport_wide_sequence_numbers() {
    let epoch = Instant::now();
    let estimator = Recorder::new(BITRATE);
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&stream());

    send_and_drain(&mut chain, epoch, 4);
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(200), 0, 4))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert!(
        reports.iter().all(|report| report.is_twcc),
        "a stream that negotiated transport-cc must be tracked by its transport-wide number"
    );
    assert_eq!(
        vec![0, 1, 2, 3],
        reports
            .iter()
            .map(|report| report.twcc_sequence_number)
            .collect::<Vec<_>>()
    );
    assert!(
        reports.iter().all(|report| report.arrived),
        "the feedback said every one arrived"
    );
}

/// A changed estimate leaves on the feedback packet that produced it, so the pacer — which sits
/// application-ward — reads it on its way past.
#[test]
fn a_changed_estimate_rides_out_on_the_feedback_packet() {
    let epoch = Instant::now();
    let estimator = Recorder::new(BITRATE);
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&stream());
    send_and_drain(&mut chain, epoch, 3);

    // The first inbound packet announces the estimator's starting rate: the pacer has to learn
    // it too, not only its changes.
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(200), 0, 3))
        .expect("read");
    let first = chain.poll_read().expect("the feedback packet carries on");
    assert!(matches!(
        first.message.get(&Attribute::TargetBitrateChanged {
            bits_per_second: 0.0
        }),
        Some(Attribute::TargetBitrateChanged { bits_per_second }) if *bits_per_second == BITRATE
    ));
    while chain.poll_read().is_some() {}

    // Unchanged: nothing to announce.
    send_and_drain(&mut chain, epoch + Duration::from_millis(210), 3);
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(280), 3, 3))
        .expect("read");
    let unchanged = chain.poll_read().expect("the feedback packet carries on");
    assert!(
        !unchanged.message.has(&Attribute::TargetBitrateChanged {
            bits_per_second: 0.0
        }),
        "an estimate that did not move must not re-announce itself"
    );
    while chain.poll_read().is_some() {}

    // Moved: it rides out.
    estimator.set_target(BITRATE / 2.0);
    send_and_drain(&mut chain, epoch + Duration::from_millis(300), 3);
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(500), 6, 3))
        .expect("read");

    let mut announced = None;
    while let Some(packet) = chain.poll_read() {
        if let Some(Attribute::TargetBitrateChanged { bits_per_second }) =
            packet.message.get(&Attribute::TargetBitrateChanged {
                bits_per_second: 0.0,
            })
        {
            announced = Some(*bits_per_second);
        }
    }
    assert_eq!(
        Some(BITRATE / 2.0),
        announced,
        "a moved estimate must leave on the feedback packet that produced it — that is the only \
         leg on which it can reach the pacer"
    );
}

/// An idle interceptor asks for no wake-up. Its estimator has no timer, and pruning is bounded work
/// that can ride any wake-up the chain already has (delivery rule 3, #862).
#[test]
fn an_idle_interceptor_asks_for_no_wakeup() {
    let mut chain = Registry::new()
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(Recorder::new(BITRATE)).build(),
        )
        .build();

    assert_eq!(None, chain.poll_timeout());
    chain.handle_timeout(Instant::now()).expect("timeout");
    assert_eq!(
        None,
        chain.poll_timeout(),
        "a congestion controller with a timerless estimator must not wake the chain"
    );
}

/// The history is bounded on a path that has stopped reporting: packets older than the prune
/// horizon are written off rather than accumulating forever.
#[test]
fn unacknowledged_packets_are_written_off_after_the_prune_horizon() {
    let epoch = Instant::now();
    let horizon = Duration::from_millis(500);

    let interceptor = CongestionControlBuilder::new(Recorder::new(BITRATE))
        .with_prune_horizon(horizon)
        .build();
    let mut chain = Registry::new()
        .with(Slot::CongestionControl, interceptor)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream());

    for sequence_number in 0..4 {
        chain
            .handle_write(rtp(epoch, sequence_number))
            .expect("write");
    }
    while chain.poll_write().is_some() {}

    // Well past the horizon, with no feedback ever arriving.
    chain.handle_timeout(epoch + horizon * 4).expect("timeout");

    // Feedback for packets that have been written off names nothing the history knows, so it
    // resolves to no reports rather than to wrong ones.
    chain
        .handle_read(twcc_feedback(epoch + horizon * 4, 0, 4))
        .expect("read");
    while chain.poll_read().is_some() {}
}

/// A retransmission is a **separate transmission** consuming separate bandwidth, and the history
/// has to count it as one.
///
/// This is what the plan expected `Attribute::Retransmission` to be needed for. It is not: the NACK
/// responder is application-ward of this interceptor, so its retransmission travels the write leg
/// and passes here like any other departing packet. Two departures, two history entries — by
/// ordering, not by inspection.
///
/// Without RTX the retransmission is the original packet sent again, and the TWCC sender gives it
/// the transport-wide number it gave the original: a new number would change its bytes, and the
/// SRTP sender below the chain refuses a second, different packet under one index (RFC 3711
/// section 3.3.1). Both entries therefore carry the same number.
///
/// The attribute still earns its place by letting an estimator *tell them apart* if it wants to;
/// it is not needed for the byte total to be right.
#[test]
fn a_retransmission_is_recorded_as_a_separate_departure() {
    use rtci_interceptor::NackResponderBuilder;

    let epoch = Instant::now();
    let estimator = Recorder::new(BITRATE);

    let mut chain = Registry::new()
        .with(Slot::from(14_000), DeliverRtcp::new())
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(estimator.clone()).build(),
        )
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .build();

    let mut info = stream();
    info.rtcp_feedback.push(RTCPFeedback {
        typ: "nack".to_owned(),
        parameter: String::new(),
    });
    chain.bind_local_stream(&info);

    // One packet out.
    chain.handle_write(rtp(epoch, 0)).expect("write");
    while chain.poll_write().is_some() {}

    // The remote asks for it back.
    let nack = rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
        sender_ssrc: 0,
        media_ssrc: SSRC,
        nacks: vec![rtcp::transport_feedbacks::transport_layer_nack::NackPair {
            packet_id: 0,
            lost_packets: 0,
        }],
    };
    chain
        .handle_read(TaggedPacket {
            now: epoch + Duration::from_millis(50),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(nack)])),
        })
        .expect("read");
    while chain.poll_read().is_some() {}

    let mut retransmitted = 0;
    while let Some(packet) = chain.poll_write() {
        if let Packet::Rtp(_) = packet.message.packet {
            assert!(
                packet.message.has(&Attribute::Retransmission),
                "CC-PRE-02: the responder must tag what it retransmits"
            );
            retransmitted += 1;
        }
    }
    assert_eq!(1, retransmitted, "the responder retransmitted the packet");

    // Both departures are on the books, under the one transport-wide number they share.
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(100), 0, 1))
        .expect("read");
    while chain.poll_read().is_some() {}

    let reports = estimator.reports();
    assert_eq!(
        2,
        reports.len(),
        "the original and the retransmission are two departures, two entries — an estimator that \
         saw only one would under-count the bytes on the wire exactly when the path is lossy"
    );
    assert_eq!(
        vec![0, 0],
        reports
            .iter()
            .map(|report| report.twcc_sequence_number)
            .collect::<Vec<_>>(),
        "a retransmission without RTX keeps the original's transport-wide number"
    );
}

/// P7-03: the estimate actually reaches the pacer and changes what it does.
///
/// This is the point at which #840's second requirement is met — an application can supply its own
/// `BandwidthEstimator` and watch the pacer follow it, with no GCC anywhere.
///
/// Asserted as a *schedule*, not an eventuality: the budget is a pure function of the instants
/// handed in, so halving the target must halve the release rate, exactly.
#[test]
fn the_pacer_follows_the_estimate() {
    let epoch = Instant::now();
    let estimator = Recorder::new(BITRATE);
    let mut chain = chain(estimator.clone());
    chain.bind_local_stream(&stream());

    // At 1.2 Mb/s with a one-packet burst, a 12 000-bit packet leaves every 10 ms.
    let before = send_and_drain(&mut chain, epoch, 4);
    let spacing_before = before[3].duration_since(before[0]) / 3;

    // Halve the estimate and let it ride out on a feedback packet.
    estimator.set_target(BITRATE / 2.0);
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(200), 0, 4))
        .expect("read");
    while chain.poll_read().is_some() {}

    let after = send_and_drain(&mut chain, epoch + Duration::from_millis(300), 4);
    let spacing_after = after[3].duration_since(after[0]) / 3;

    assert!(
        spacing_after > spacing_before,
        "halving the target must slow the pacer: {spacing_before:?} → {spacing_after:?}"
    );
    // Half the rate is twice the spacing. Allow a millisecond of slack for the 1 ms test clock.
    let expected = spacing_before * 2;
    assert!(
        spacing_after.abs_diff(expected) <= Duration::from_millis(1),
        "half the rate should be twice the spacing: expected about {expected:?}, got \
         {spacing_after:?}"
    );
}

/// `CongestionControlHandle::has_feedback` tells whether the target comes from the path yet:
/// `false` while `target_bitrate()` is the start value (and `stats()` already carries both
/// halves of the estimate, so they cannot tell), `true` from the first feedback batch the
/// estimator was given. A feedback packet that reports none of this controller's packets is
/// no batch. With the default `Gcc`, `packet_loss` and `round_trip_time` are `None` before
/// feedback, as the handle's documentation says.
#[test]
fn the_handle_says_whether_the_target_comes_from_feedback() {
    use rtci_interceptor::{GCC_INITIAL_BITRATE, Gcc};

    let epoch = Instant::now();
    let (controller, handle) = CongestionControlBuilder::new(Gcc::default())
        .with_bandwidth_probing(false)
        .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::from(14_000), DeliverRtcp::new())
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream());

    assert!(!handle.has_feedback());
    assert_eq!(0, handle.feedback_reports());
    assert_eq!(
        GCC_INITIAL_BITRATE,
        handle.target_bitrate(),
        "the start value"
    );
    let before = handle.stats();
    assert!(before.delay_based_bitrate.is_some() && before.loss_based_bitrate.is_some());
    assert_eq!(None, before.packet_loss);
    assert_eq!(None, before.round_trip_time);

    send_and_drain(&mut chain, epoch, 3);
    assert!(!handle.has_feedback(), "sending is not feedback");

    // Feedback about packets this controller never sent is not a batch.
    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(100), 500, 3))
        .expect("read");
    while chain.poll_read().is_some() {}
    assert!(
        !handle.has_feedback(),
        "feedback reporting none of its packets"
    );

    chain
        .handle_read(twcc_feedback(epoch + Duration::from_millis(200), 0, 3))
        .expect("read");
    while chain.poll_read().is_some() {}
    assert!(handle.has_feedback());
    assert_eq!(1, handle.feedback_reports());
    assert!(
        handle.stats().packet_loss.is_some(),
        "the batch was folded in"
    );

    // A second batch: three new packets (RTP 3 to 5, transport-wide 3 to 5), reported by the
    // receiver's next feedback (count 1, a later reference time). (The first version of this
    // test re-sent RTP 0 to 2 and repeated the first feedback's count and reference time, and
    // that batch reported nothing, CI 45883163416.)
    let second = epoch + Duration::from_millis(210);
    for sequence_number in 3..6 {
        chain
            .handle_write(rtp(second, sequence_number))
            .expect("write");
    }
    chain.handle_timeout(second).expect("timeout");
    while chain.poll_write().is_some() {}
    chain
        .handle_read(twcc_feedback_at(
            epoch + Duration::from_millis(300),
            3,
            3,
            3,
            1,
        ))
        .expect("read");
    while chain.poll_read().is_some() {}
    assert_eq!(2, handle.feedback_reports());
}

/// Without per-packet feedback the estimator runs on the loss of receiver reports
/// (draft-ietf-rmcat-gcc-02 section 7): a receiver report block for a stream this controller
/// sends is feedback too.
#[test]
fn a_receiver_reports_loss_counts_as_feedback_without_per_packet_feedback() {
    use rtci_interceptor::Gcc;
    use rtcp::receiver_report::ReceiverReport;
    use rtcp::reception_report::ReceptionReport;

    let epoch = Instant::now();
    let (controller, handle) = CongestionControlBuilder::new(Gcc::default())
        .with_bandwidth_probing(false)
        .build_with_handle();
    let mut chain = Registry::new()
        .with(Slot::from(14_000), DeliverRtcp::new())
        .with(Slot::CongestionControl, controller)
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .build();
    chain.bind_local_stream(&stream());
    send_and_drain(&mut chain, epoch, 3);
    assert!(!handle.has_feedback());

    let report = ReceiverReport {
        ssrc: 0x1111,
        reports: vec![ReceptionReport {
            ssrc: SSRC,
            fraction_lost: 0,
            last_sequence_number: 2,
            ..Default::default()
        }],
        ..Default::default()
    };
    chain
        .handle_read(TaggedPacket {
            now: epoch + Duration::from_millis(500),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(report)])),
        })
        .expect("read");
    while chain.poll_read().is_some() {}
    assert!(handle.has_feedback());
    assert_eq!(1, handle.feedback_reports());
}
