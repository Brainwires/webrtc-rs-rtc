//! Pacing, asserted as a release *schedule*.
//!
//! The budget is a pure function of the instants handed in, so the schedule is reproducible: a
//! test can say exactly when each packet should leave, not merely that everything eventually
//! does. Upstream cannot do this without a fake clock, which is why its own tests check only that
//! packets come out.
//!
//! A marker below the pacer records what the rest of the chain saw and when — that placement is
//! the point, since everything below the pacer must observe the release instant rather than the
//! instant the application enqueued.

use rtci_interceptor::{
    Attribute, AttributedPacket, CircuitBreakerNotice, CircuitBreakerReason, Interceptor,
    LocalKeyFrameRequest, MinimumTarget, PacerBuilder, PacerDiscard, PacerPause,
    PacerQueueOverflow as QueueOverflow, Packet, Registry, RetransmissionsLeft, Slot, StreamInfo,
    TaggedPacket,
};
use rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::MarshalSize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One released packet: which it was, and when the layer below saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Released {
    sequence_number: u16,
    at: Duration,
}

struct Marker {
    released: Arc<Mutex<Vec<Released>>>,
    epoch: Instant,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Marker {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message.packet {
            self.released.lock().unwrap().push(Released {
                sequence_number: rtp.header.sequence_number,
                at: msg.now.saturating_duration_since(self.epoch),
            });
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for Marker {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

/// A maximum-sized packet: 12-byte RTP header plus payload makes 1500 bytes on the wire.
///
/// Full-sized because the smallest burst a pacer allows is one such packet — a burst below that
/// would make every packet take the larger-than-burst path and stop enforcing the rate at all.
const PAYLOAD_BYTES: usize = 1488;
const PACKET_BITS: f64 = 12_000.0;

/// 1.2 Mb/s: one 12 000-bit packet every 10 ms, which makes the schedule easy to read.
const BITRATE: f64 = 1_200_000.0;

struct Harness {
    chain: Box<dyn Interceptor>,
    released: Arc<Mutex<Vec<Released>>>,
    epoch: Instant,
}

impl Harness {
    /// A pacer with a burst of exactly one packet, so releases are one at a time and the schedule
    /// is the rate rather than the burst.
    fn new() -> Self {
        Self::with_burst(PACKET_BITS)
    }

    fn with_burst(burst_bits: f64) -> Self {
        Self::with(burst_bits, QueueOverflow::default())
    }

    /// The pacer of [`Harness::with_burst`] with `overflow` for media the target has no room
    /// for.
    fn with(burst_bits: f64, overflow: QueueOverflow) -> Self {
        Self::with_queue(
            burst_bits,
            overflow,
            rtci_interceptor::PACER_DEFAULT_QUEUE_LIMIT,
        )
    }

    /// [`Harness::with`] with a queue of `queue_limit` packets.
    fn with_queue(burst_bits: f64, overflow: QueueOverflow, queue_limit: usize) -> Self {
        let epoch = Instant::now();
        let released = Arc::new(Mutex::new(Vec::new()));
        let marker_released = Arc::clone(&released);

        let chain = Registry::new()
            .with(
                // Wire-ward of the pacer at 3_000, so it sees what the pacer released.
                Slot::from(2_500),
                Marker {
                    released: marker_released,
                    epoch,
                    read_queue: VecDeque::new(),
                    write_queue: VecDeque::new(),
                },
            )
            .with(
                Slot::Pacer,
                PacerBuilder::new()
                    .with_target_bitrate(BITRATE)
                    .with_burst_bits(burst_bits)
                    .with_queue_overflow(overflow)
                    .with_queue_limit(queue_limit)
                    .build(),
            )
            .build();

        Self {
            chain: Box::new(chain),
            released,
            epoch,
        }
    }

    fn send(&mut self, at: Duration, sequence_number: u16) {
        self.send_sized(at, sequence_number, PAYLOAD_BYTES);
    }

    /// A video packet of stream 1 that is a frame of its own (the RTP timestamp follows the
    /// sequence number), so a discard takes the packets it is meant to and no more.
    fn send_sized(&mut self, at: Duration, sequence_number: u16, payload_bytes: usize) {
        self.send_frame_packet(
            at,
            1,
            sequence_number,
            u32::from(sequence_number) * 3000,
            payload_bytes,
        );
    }

    /// A full-sized packet of the frame with RTP timestamp `timestamp` of the stream `ssrc`.
    fn send_of(&mut self, at: Duration, ssrc: u32, sequence_number: u16, timestamp: u32) {
        self.send_frame_packet(at, ssrc, sequence_number, timestamp, PAYLOAD_BYTES);
    }

    fn send_frame_packet(
        &mut self,
        at: Duration,
        ssrc: u32,
        sequence_number: u16,
        timestamp: u32,
        payload_bytes: usize,
    ) {
        self.chain
            .handle_write(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        timestamp,
                        ssrc,
                        ..Default::default()
                    },
                    payload: vec![0u8; payload_bytes].into(),
                })),
            })
            .expect("handle_write");
    }

    /// What the chain hands application-ward: the pacer's discard notices and key-frame
    /// requests.
    fn reads(&mut self) -> Vec<TaggedPacket> {
        std::iter::from_fn(|| self.chain.poll_read()).collect()
    }

    /// A padding-only packet (RFC 3550 section 5.1), as the NACK responder fills a probe
    /// cluster with: no payload and 255 octets of padding, 2136 bits on the wire.
    /// A retransmission (`Attribute::Retransmission`, as the NACK responder tags it) on the
    /// RTX stream.
    fn send_retransmission(&mut self, at: Duration, sequence_number: u16) {
        self.send_retransmission_of(at, 3, sequence_number);
    }

    /// A retransmission under the SSRC `ssrc`, not bound as a repair flow, so the packet it
    /// repairs is its own sequence number.
    fn send_retransmission_of(&mut self, at: Duration, ssrc: u32, sequence_number: u16) {
        self.chain
            .handle_write(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: 97,
                        sequence_number,
                        ssrc,
                        ..Default::default()
                    },
                    payload: vec![0u8; PAYLOAD_BYTES].into(),
                }))
                .with(rtci_interceptor::Attribute::Retransmission),
            })
            .expect("handle_write");
        self.drain();
    }

    fn send_padding(&mut self, at: Duration, sequence_number: u16) {
        self.chain
            .handle_write(TaggedPacket {
                now: self.epoch + at,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        padding: true,
                        payload_type: 97,
                        sequence_number,
                        ssrc: 2,
                        padding_size: 255,
                        ..Default::default()
                    },
                    payload: bytes::Bytes::new(),
                })),
            })
            .expect("handle_write");
    }

    /// Fire a timeout and then drain, which is what a driver does.
    ///
    /// The draining is load-bearing on the belt and was not under nesting: a released packet is
    /// handed on by the pacer's `poll_write`, so it only reaches the stages between the pacer and
    /// the wire when the chain's `poll_write` walk runs. `handle_timeout` alone moves a packet out
    /// of the pacer's queue and no further.
    /// Tell the pacer a new target rate.
    ///
    /// With no event channel the estimate travels as an attribute on an outgoing packet, which is
    /// how a congestion controller application-ward of the pacer would deliver it.
    /// Tell the pacer a new target rate.
    ///
    /// On the **read** leg, because that is the only one the estimate can cross on: the congestion
    /// controller is wire-*ward* of the pacer, so on the write leg it never sees a packet before the
    /// pacer does. It attaches the attribute to the inbound feedback packet that produced the
    /// estimate, and the pacer reads it on the way past.
    fn retarget(&mut self, bits_per_second: f64) {
        let mut msg = TaggedPacket {
            now: self.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        };
        msg.message
            .add(Attribute::TargetBitrateChanged { bits_per_second });
        self.chain.handle_read(msg).expect("handle_read");
        while self.chain.poll_read().is_some() {}
    }

    fn tick(&mut self, at: Duration) {
        self.chain
            .handle_timeout(self.epoch + at)
            .expect("handle_timeout");
        self.drain();
    }

    /// Pull everything the chain is ready to send.
    fn drain(&mut self) {
        while self.chain.poll_write().is_some() {}
    }

    /// Advance the clock the way the driver does: fire every deadline the chain asks for, in
    /// order, up to `at`. This is what turns "eventually" into a schedule.
    fn advance_to(&mut self, at: Duration) {
        let deadline = self.epoch + at;
        let mut fired_deadline = false;
        // Bounded so a pacer that reports a non-advancing deadline fails the test rather than
        // hanging it — the webrtc#862 failure mode.
        for _ in 0..10_000 {
            let Some(next) = self.chain.poll_timeout() else {
                break;
            };
            if next > deadline {
                break;
            }
            fired_deadline |= next == deadline;
            self.chain.handle_timeout(next).expect("handle_timeout");
            self.drain();
        }
        // Only if the loop did not already reach it: a driver fires each deadline once, and a
        // harness that fires twice would hide an interceptor that treats timeouts as edge
        // triggered. `repeated_timeouts_at_one_instant_release_nothing_extra` asserts that
        // property directly rather than leaning on this having covered it by accident.
        if !fired_deadline {
            self.tick(at);
        }
    }

    fn released(&self) -> Vec<Released> {
        self.released.lock().unwrap().clone()
    }

    fn schedule(&self) -> Vec<(u16, Duration)> {
        self.released()
            .iter()
            .map(|packet| (packet.sequence_number, packet.at))
            .collect()
    }

    fn next_timeout(&mut self) -> Option<Duration> {
        self.chain
            .poll_timeout()
            .map(|instant| instant.saturating_duration_since(self.epoch))
    }
}

fn ms(milliseconds: u64) -> Duration {
    Duration::from_millis(milliseconds)
}

// ---------------------------------------------------------------------------------------
// The schedule
// ---------------------------------------------------------------------------------------

/// A packet's size in bits over the rate is its spacing: 1000 bits at 100 kb/s is 10 ms.
#[test]
fn a_burst_is_released_at_the_configured_rate() {
    let mut harness = Harness::new();

    // Five packets handed over at once.
    for sequence_number in 0..5 {
        harness.send(ms(0), sequence_number);
    }
    harness.drain();
    assert_eq!(
        vec![(0, ms(0))],
        harness.schedule(),
        "the packet the budget covers leaves as it is written; the rest wait for the clock"
    );

    harness.advance_to(ms(100));

    assert_eq!(
        vec![
            (0, ms(0)),
            (1, ms(10)),
            (2, ms(20)),
            (3, ms(30)),
            (4, ms(40))
        ],
        harness.schedule(),
        "one packet per 10 ms, in order"
    );
}

/// Changing the rate changes the spacing of everything after it — this is the knob a bandwidth
/// estimator turns, and it has to take effect on the next release rather than the next block.
#[test]
fn changing_the_rate_changes_the_subsequent_schedule() {
    let mut harness = Harness::new();
    for sequence_number in 0..4 {
        harness.send(ms(0), sequence_number);
    }

    harness.advance_to(ms(20));
    assert_eq!(
        vec![(0, ms(0)), (1, ms(10)), (2, ms(20))],
        harness.schedule(),
        "three released at the original rate"
    );

    // Twice the rate: the next packet is due half as long after the last one.
    harness.retarget(BITRATE * 2.0);
    harness.advance_to(ms(40));

    let schedule = harness.schedule();
    assert_eq!(4, schedule.len());
    assert_eq!(
        ms(25),
        schedule[3].1,
        "5 ms after the previous release, not 10: {schedule:?}"
    );
}

#[test]
fn a_larger_burst_releases_more_at_once() {
    let mut harness = Harness::with_burst(PACKET_BITS * 3.0);
    for sequence_number in 0..5 {
        harness.send(ms(0), sequence_number);
    }

    harness.tick(ms(0));

    assert_eq!(
        vec![(0, ms(0)), (1, ms(0)), (2, ms(0))],
        harness.schedule(),
        "a three-packet burst goes at once; the rest waits"
    );
}

/// Packets arriving while the queue drains join the back of it and keep their order.
#[test]
fn packets_arriving_mid_drain_keep_their_order() {
    let mut harness = Harness::new();
    harness.send(ms(0), 0);
    harness.send(ms(0), 1);

    harness.advance_to(ms(10));
    harness.send(ms(12), 2);
    harness.advance_to(ms(40));

    assert_eq!(
        vec![0, 1, 2],
        harness
            .schedule()
            .iter()
            .map(|(sequence_number, _)| *sequence_number)
            .collect::<Vec<_>>()
    );
}

/// A probe cluster is written as a burst of padding the moment it is asked for. Media written
/// while that padding waits goes ahead of it, as soon as the budget allows, instead of waiting
/// out the whole cluster; the padding keeps its order and leaves once nothing else waits.
#[test]
fn media_leaves_ahead_of_queued_padding() {
    let mut harness = Harness::new();
    // 20 padding packets of 2136 bits: the 12 000-bit burst lets 5 out at once, and the other
    // 15 would take about 27 ms at 1.2 Mb/s.
    for sequence_number in 100..120 {
        harness.send_padding(ms(0), sequence_number);
    }
    harness.send(ms(1), 1);
    harness.advance_to(ms(100));

    let schedule = harness.schedule();
    let order: Vec<u16> = schedule.iter().map(|(seq, _)| *seq).collect();
    let mut expected: Vec<u16> = (100..105).collect();
    expected.push(1);
    expected.extend(105..120);
    assert_eq!(expected, order, "{schedule:?}");
    // The media packet waits only for the budget its own 12 000 bits need: 1320 bits were
    // left after the padding that went at once, and 10 680 more take 8.9 ms.
    let (_, media_at) = schedule[5];
    assert!(
        media_at < ms(10),
        "the media packet left at {media_at:?}, behind the padding"
    );
}

/// Retransmissions leave ahead of the new media already waiting, in the order they were
/// written, as in libwebrtc's pacer ("Send retransmissions before new media"): ten video
/// packets queue at 0 ms (one leaves at once, one every 10 ms after), two retransmissions are
/// written at 15 ms and leave next, at 20 and 30 ms, before the video still waiting.
#[test]
fn retransmissions_leave_ahead_of_queued_new_media() {
    let mut harness = Harness::new();
    for sequence_number in 1..=10 {
        harness.send(ms(0), sequence_number);
    }
    harness.advance_to(ms(15));
    harness.send_retransmission(ms(15), 500);
    harness.send_retransmission(ms(15), 501);
    harness.advance_to(ms(200));
    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![1, 2, 500, 501, 3, 4, 5, 6, 7, 8, 9, 10], order);
}

/// Among the retransmissions waiting, a stream's oldest packet leaves first, whenever its
/// retransmission was written (a receiver that plays in order waits for its oldest gap); the
/// other streams' retransmissions keep their places, and the sequence number wraps. At 0 ms
/// video 1 leaves at once and spends the one-packet budget, video 2 waits, and then, all at
/// 0 ms: stream 4's 500, stream 3's 30, stream 4's 501, stream 3's 10 and 20, stream 5's 0 and
/// 65535. Each retransmission goes ahead of the new media, in front of the first waiting
/// retransmission of its stream that repairs a newer packet: 10 in front of 30, 20 between 10
/// and 30, 65535 in front of 0 (0 is the newer, one past it); stream 4's 501 behind its 500.
/// The queue is 500, 10, 20, 30, 501, 65535, 0 and then video 2, one leaving every 10 ms.
#[test]
fn retransmissions_of_a_stream_leave_oldest_packet_first() {
    let mut harness = Harness::new();
    harness.send(ms(0), 1);
    harness.send(ms(0), 2);
    harness.drain();
    for (ssrc, sequence_number) in [
        (4, 500),
        (3, 30),
        (4, 501),
        (3, 10),
        (3, 20),
        (5, 0),
        (5, 65_535),
    ] {
        harness.send_retransmission_of(ms(0), ssrc, sequence_number);
    }
    harness.advance_to(ms(200));
    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![1, 500, 10, 20, 30, 501, 65_535, 0, 2], order);
}

// ---------------------------------------------------------------------------------------
// The chain contract
// ---------------------------------------------------------------------------------------

/// Rule 3. Everything below the pacer must see the release instant; recording the enqueue instant
/// would charge this queueing delay to the network, which is what makes a bandwidth estimate
/// collapse.
#[test]
fn a_released_packet_carries_the_release_instant_not_the_enqueue_instant() {
    let mut harness = Harness::new();
    harness.send(ms(0), 0);
    harness.send(ms(0), 1);

    harness.advance_to(ms(50));

    let schedule = harness.schedule();
    assert_eq!(ms(0), schedule[0].1);
    assert_eq!(
        ms(10),
        schedule[1].1,
        "the second packet departed 10 ms later and says so"
    );
}

/// Rule 2. Released packets travel through `inner`, so a downstream layer sees each exactly once.
#[test]
fn each_packet_reaches_the_layer_below_exactly_once() {
    let mut harness = Harness::new();
    for sequence_number in 0..5 {
        harness.send(ms(0), sequence_number);
    }

    harness.advance_to(ms(200));

    let mut sequence_numbers: Vec<u16> = harness
        .schedule()
        .iter()
        .map(|(sequence_number, _)| *sequence_number)
        .collect();
    sequence_numbers.sort_unstable();
    assert_eq!(
        vec![0, 1, 2, 3, 4],
        sequence_numbers,
        "no duplicates, none lost"
    );
}

// ---------------------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------------------

/// Delivery rule 3: an idle pacer must not wake the chain, and an armed deadline must advance.
#[test]
fn poll_timeout_is_none_when_the_queue_is_empty() {
    let mut harness = Harness::new();

    assert_eq!(None, harness.next_timeout(), "nothing queued");

    harness.send(ms(0), 0);
    assert_eq!(
        None,
        harness.next_timeout(),
        "a packet inside the budget left as it was written: nothing to wake for"
    );
    harness.send(ms(0), 1);
    assert_eq!(
        Some(ms(10)),
        harness.next_timeout(),
        "the next is due a packet-time later"
    );

    harness.tick(ms(0));
    assert_eq!(
        Some(ms(10)),
        harness.next_timeout(),
        "and a timeout before then changes nothing"
    );

    harness.advance_to(ms(100));
    assert_eq!(
        None,
        harness.next_timeout(),
        "drained, so idle again rather than waking at the pacing interval"
    );
}

/// The deadline is derived from when the head can afford to go, so it is always in the future —
/// a repeated past instant is the webrtc#862 busy-loop, and `advance_to` would spin on it.
#[test]
fn the_reported_deadline_advances() {
    let mut harness = Harness::new();
    for sequence_number in 0..3 {
        harness.send(ms(0), sequence_number);
    }

    harness.tick(ms(0));
    let first = harness.next_timeout().expect("armed");
    harness.tick(first);
    let second = harness.next_timeout().expect("armed");

    assert!(second > first, "{second:?} follows {first:?}");
}

// ---------------------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------------------

/// RTCP is not paced: feedback is only useful while it is fresh, and holding it back would delay
/// the very reports congestion control depends on.
#[test]
fn rtcp_is_not_paced() {
    let mut harness = Harness::new();

    harness
        .chain
        .handle_write(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        })
        .expect("handle_write");

    assert!(
        harness.chain.poll_write().is_some(),
        "RTCP leaves immediately rather than waiting for a release deadline"
    );
}

/// A driver may hand the same instant over more than once — two protocols' deadlines can coincide.
/// Releasing again on the second call would put a packet on the wire that the budget never paid
/// for.
#[test]
fn repeated_timeouts_at_one_instant_release_nothing_extra() {
    let mut harness = Harness::new();
    for sequence_number in 0..4 {
        harness.send(ms(0), sequence_number);
    }

    harness.tick(ms(0));
    let once = harness.schedule();
    harness.tick(ms(0));
    harness.tick(ms(0));

    assert_eq!(
        vec![(0, ms(0))],
        once,
        "one packet fits the one-packet burst"
    );
    assert_eq!(
        once,
        harness.schedule(),
        "and repeating the instant adds none"
    );
}

/// A burst the caller configured is not a function of the rate, so an estimator raising the rate
/// must not widen it. Otherwise the first rate update silently turns a one-at-a-time sender into a
/// bursty one, which is exactly what a pacer exists to prevent.
///
/// The pacer has to be left *idle* across the rate change for this to bite: a widened burst only
/// shows up once the budget has had time to accumulate into it. Draining continuously hides it.
#[test]
fn a_configured_burst_survives_a_rate_change() {
    let mut harness = Harness::new();
    harness.tick(ms(0));

    // Twenty times the rate. A burst derived from this would be 240 000 bits — twenty packets.
    harness.retarget(BITRATE * 20.0);

    // Idle long enough for the budget to fill whatever the burst now is.
    harness.advance_to(ms(100));
    for sequence_number in 0..6 {
        harness.send(ms(100), sequence_number);
    }
    harness.tick(ms(100));

    assert_eq!(
        vec![(0, ms(100))],
        harness.schedule(),
        "one packet, not a burst at the widened rate"
    );
}

/// Packets larger than the burst are paced too. Releasing them unconditionally — the only way to
/// keep them from stalling the queue — would let a run of them leave all at once, defeating the
/// pacer for exactly the traffic that stresses the path most.
#[test]
fn oversized_packets_are_paced_not_dumped() {
    let mut harness = Harness::with_burst(PACKET_BITS);
    for sequence_number in 0..4 {
        harness.send_sized(ms(0), sequence_number, 4000);
    }

    harness.advance_to(ms(0));
    assert_eq!(
        1,
        harness.schedule().len(),
        "one oversized packet per release: {:?}",
        harness.schedule()
    );

    // 4012 bytes is 32 096 bits; at 1.2 Mb/s that is 26.7 ms of debt before the next may go.
    harness.advance_to(ms(26));
    assert_eq!(1, harness.schedule().len(), "the next still owes");
    harness.advance_to(ms(27));
    assert_eq!(2, harness.schedule().len(), "and then goes");

    harness.advance_to(ms(500));
    assert_eq!(4, harness.schedule().len(), "all of them get out");
}

/// A packet larger than a full burst can never become affordable, since the budget caps at the
/// burst. It must still get out, or it stalls the whole queue behind it forever.
#[test]
fn a_packet_larger_than_the_burst_is_still_released() {
    let mut harness = Harness::with_burst(PACKET_BITS);

    harness
        .chain
        .handle_write(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    sequence_number: 99,
                    ssrc: 1,
                    ..Default::default()
                },
                // Far bigger than the one-packet burst.
                payload: vec![0u8; 4000].into(),
            })),
        })
        .expect("handle_write");
    harness.send(ms(0), 100);

    harness.advance_to(ms(500));

    let sequence_numbers: Vec<u16> = harness
        .schedule()
        .iter()
        .map(|(sequence_number, _)| *sequence_number)
        .collect();
    assert!(
        sequence_numbers.contains(&99),
        "the oversized packet was released: {sequence_numbers:?}"
    );
    assert!(
        sequence_numbers.contains(&100),
        "and did not stall the packet behind it"
    );
}

/// With [`QueueOverflow::Drain`] (libwebrtc's pacer) nothing in a full queue is thrown away:
/// a packet arriving at a full queue makes the oldest leave at once, over the budget. Ten
/// packets into a queue of three: all ten leave, in order, with no gap.
#[test]
fn with_drain_a_full_queue_releases_its_oldest_and_refuses_nothing() {
    let epoch = Instant::now();
    let released = Arc::new(Mutex::new(Vec::new()));
    let mut chain = Registry::new()
        .with(
            Slot::from(2_500),
            Marker {
                released: Arc::clone(&released),
                epoch,
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            },
        )
        .with(
            Slot::Pacer,
            PacerBuilder::new()
                .with_target_bitrate(BITRATE)
                .with_queue_limit(3)
                .with_queue_overflow(QueueOverflow::Drain)
                .build(),
        )
        .build();

    for sequence_number in 0..10u16 {
        chain
            .handle_write(TaggedPacket {
                now: epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        sequence_number,
                        ssrc: 1,
                        ..Default::default()
                    },
                    payload: vec![0u8; PAYLOAD_BYTES].into(),
                })),
            })
            .expect("handle_write");
        while chain.poll_write().is_some() {}
    }
    // Seven left at the write: the first inside the budget, six to make room.
    assert_eq!(7, released.lock().unwrap().len());

    let mut now = epoch;
    for _ in 0..100 {
        chain.handle_timeout(now).expect("handle_timeout");
        while chain.poll_write().is_some() {}
        now += Duration::from_millis(10);
    }
    let order: Vec<u16> = released
        .lock()
        .unwrap()
        .iter()
        .map(|packet| packet.sequence_number)
        .collect();
    assert_eq!(
        (0..10).collect::<Vec<u16>>(),
        order,
        "every packet, in order"
    );
}

/// By default ([`QueueOverflow::Drop`]) nothing leaves above the target: a source writing
/// 2.4 Mb/s for ten seconds against a 1.2 Mb/s target has what waited the 2 s bound dropped,
/// what leaves leaves at the target's spacing (one 12 000-bit packet each 10 ms), and no packet
/// that leaves has waited longer than the bound. With `Drain` the same source puts all 2.4 Mb/s
/// on the path (the test below), which on a link that carries the target is the loss that
/// drives the estimate to its floor (`tests/gcc_rate_limited_link_rtc2rtc.rs`).
#[test]
fn by_default_nothing_leaves_above_the_target_and_what_waited_the_bound_is_dropped() {
    let mut harness = Harness::new();
    for n in 0..2000u16 {
        let at = ms(5 * u64::from(n));
        harness.advance_to(at);
        harness.send(at, n);
        harness.drain();
    }
    harness.advance_to(ms(20_000));
    let released = harness.released();
    // At the target, one packet each 10 ms, from the first write until the queue is empty: the
    // ten seconds of writes and the last two seconds' packets after them, 1200 in all.
    assert!(
        (1190..=1210).contains(&released.len()),
        "12 s at the target, the rest dropped: {} left",
        released.len()
    );
    for pair in released.windows(2) {
        assert!(
            pair[1].at - pair[0].at >= ms(10) - Duration::from_micros(10),
            "two packets closer than the target allows: {pair:?}"
        );
    }
    let longest = released
        .iter()
        .map(|packet| packet.at - ms(5 * u64::from(packet.sequence_number)))
        .max()
        .unwrap_or_default();
    assert!(longest <= ms(2_010), "a packet waited {longest:?}");
}

/// By default a packet arriving at a full queue drops the oldest (the newest is the one still
/// worth sending), and nothing leaves over the budget: ten packets into a queue of three leave
/// the first (inside the budget) and the last three.
#[test]
fn by_default_a_full_queue_drops_its_oldest() {
    let mut harness = Harness::with_queue(PACKET_BITS, QueueOverflow::default(), 3);
    for n in 0..10u16 {
        harness.send(ms(0), n);
        harness.drain();
    }
    harness.advance_to(ms(1_000));
    let order: Vec<u16> = harness
        .schedule()
        .iter()
        .map(|(sequence_number, _)| *sequence_number)
        .collect();
    assert_eq!(vec![0, 7, 8, 9], order);
}

/// The discard notices ([`PacerDiscard`]) among `reads`: (stream, sequence numbers, frames).
fn discards(reads: &[TaggedPacket]) -> Vec<(u32, Vec<u16>, u32)> {
    reads
        .iter()
        .filter_map(|read| read.message.custom::<PacerDiscard>())
        .map(|discard| {
            (
                discard.ssrc,
                discard.sequence_numbers.clone(),
                discard.frames,
            )
        })
        .collect()
}

/// The streams `reads` ask a key frame for: a Picture Loss Indication delivered to the
/// application, as a receiver's would be.
fn key_frame_requests(reads: &[TaggedPacket]) -> Vec<u32> {
    reads
        .iter()
        .filter(|read| read.message.has(&Attribute::DeliverToApplication))
        .filter_map(|read| match &read.message.packet {
            Packet::Rtcp(packets) => Some(packets),
            _ => None,
        })
        .flatten()
        .filter_map(|packet| {
            packet
                .as_any()
                .downcast_ref::<PictureLossIndication>()
                .map(|pli| pli.media_ssrc)
        })
        .collect()
}

/// The reason each key-frame request among `reads` carries ([`LocalKeyFrameRequest`], `None`
/// for a request without one), by stream.
fn key_frame_request_origins(reads: &[TaggedPacket]) -> Vec<(u32, Option<LocalKeyFrameRequest>)> {
    reads
        .iter()
        .filter(|read| read.message.has(&Attribute::DeliverToApplication))
        .filter_map(|read| match &read.message.packet {
            Packet::Rtcp(packets) => Some((packets, read.message.custom::<LocalKeyFrameRequest>())),
            _ => None,
        })
        .flat_map(|(packets, why)| {
            packets.iter().filter_map(move |packet| {
                packet
                    .as_any()
                    .downcast_ref::<PictureLossIndication>()
                    .map(|pli| (pli.media_ssrc, why.copied()))
            })
        })
        .collect()
}

/// 12 kbit/s: one full-sized packet a second, so waits of seconds are easy to read.
const SLOW: f64 = 12_000.0;

/// What waited the 2 s bound is discarded whole frames at a time, with every other frame of
/// its stream that waits, when it was written into a pause (a source that does not follow it).
/// At one packet a second (12 000 bits of budget a second, one packet of budget at most):
/// stream 1's packet 0 leaves at once at 0 s, and its packet 1 (same frame), queued at 0 s,
/// holds a second's worth, half the bound: the pause begins at 0 s, so 1 is a following
/// source's and is never discarded for its age. Into the pause, at 0.3 s, stream 1 writes two
/// frames (2 and 3, timestamp 3000; 4 and 5, timestamp 6000). A retransmission written at 0.5 s
/// goes ahead of the new media and leaves at 1 s (a full budget); audio written at 1.5 s leaves
/// when written (896 bits of the 6000 refilled since 1 s); 1 leaves when the budget is full
/// again, at 1.5 + (12 000 - 5104) / 12 000 = 2.075 s. Then 2 heads the queue and, written at
/// 0.3 s, has waited the bound at 2.3 s (its budget would come at 3.075 s): 2 to 5 go, oldest
/// first, two frames. Stream 9's frame written at 1.2 s is another stream's: it stays, and
/// leaves at 3.075 s, before it would have waited the bound itself (3.2 s). The pause holds
/// throughout (a full packet stays queued until 3.075 s), so it began at 0 s for all of them.
#[test]
fn an_overdue_frame_is_discarded_whole_with_every_frame_of_its_stream_that_waits() {
    let mut harness = Harness::new();
    harness.retarget(SLOW);
    harness
        .chain
        .bind_local_stream(&rtci_interceptor::StreamInfo {
            ssrc: 7,
            mime_type: "audio/opus".to_owned(),
            clock_rate: 48_000,
            ..Default::default()
        });
    harness.send_of(ms(0), 1, 0, 0);
    harness.send_of(ms(0), 1, 1, 0);
    harness.drain();
    harness.advance_to(ms(300));
    for (sequence_number, timestamp) in [(2, 3000), (3, 3000), (4, 6000), (5, 6000)] {
        harness.send_of(ms(300), 1, sequence_number, timestamp);
    }
    harness.drain();
    harness.advance_to(ms(500));
    harness.send_retransmission(ms(500), 900);
    harness.advance_to(ms(1_200));
    harness.send_of(ms(1_200), 9, 100, 0);
    harness.drain();
    harness.advance_to(ms(1_500));
    harness.send_frame_packet(ms(1_500), 7, 5000, 0, 100);
    harness.drain();
    harness.advance_to(ms(5_000));

    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 900, 5000, 1, 100], order);
    let reads = harness.reads();
    assert_eq!(vec![(1, vec![2, 3, 4, 5], 2)], discards(&reads));
    let target = reads
        .iter()
        .find_map(|read| read.message.custom::<PacerDiscard>())
        .map(|discard| discard.target_bitrate);
    assert_eq!(Some(SLOW), target, "the target at the discard");
}

/// The stream that lost a frame needs a key frame, and the application is asked for it the
/// way a receiver asks: a Picture Loss Indication for the stream, delivered to the
/// application, once per discard that lost a frame. A repair flow (here the stream's FEC
/// SSRC) has no key frame to ask for: its discard is announced, no key frame is asked for.
///
/// At one packet a second: 0 leaves at once at 0 s; 1 and 2, queued at 0 s, start the pause
/// (a second's worth or more queued, half the bound) and leave at 1 s and 2 s. Written into
/// the pause at 0.3 s, stream 1's 3 and its FEC flow's 50 wait behind them; at 2.3 s 3 heads
/// the queue having waited the bound (its budget would come at 3 s) and is discarded, and
/// then 50, written at the same instant, has too.
#[test]
fn a_discard_asks_the_application_for_a_key_frame_of_a_media_stream_only() {
    let mut harness = Harness::new();
    harness.retarget(SLOW);
    harness
        .chain
        .bind_local_stream(&rtci_interceptor::StreamInfo {
            ssrc: 1,
            ssrc_fec: Some(11),
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90_000,
            ..Default::default()
        });
    harness.send_of(ms(0), 1, 0, 0);
    harness.send_of(ms(0), 1, 1, 3000);
    harness.send_of(ms(0), 1, 2, 6000);
    harness.drain();
    harness.advance_to(ms(300));
    harness.send_of(ms(300), 1, 3, 9000);
    harness.send_of(ms(300), 11, 50, 9000);
    harness.drain();
    harness.advance_to(ms(5_000));

    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 1, 2], order);
    let reads = harness.reads();
    assert_eq!(vec![(1, vec![3], 1), (11, vec![50], 1)], discards(&reads));
    assert_eq!(vec![1], key_frame_requests(&reads));
    assert_eq!(
        vec![(1, Some(LocalKeyFrameRequest::PacerDiscard))],
        key_frame_request_origins(&reads),
        "the request says it is the pacer's, after a discard"
    );
}

/// The packets of a discarded frame that the application writes after the discard are
/// discarded too (a frame with a packet missing is worth nothing), announced without a frame
/// or a key-frame request of their own; the next frame of the stream is sent. At one packet a
/// second: 0 leaves at once at 0 s; 1 and 2, queued at 0 s, start the pause and leave at 1 s
/// and 2 s. Written into the pause at 0.3 s, the first two packets (3, 4) of the frame of
/// timestamp 3000 head the queue at 2 s and have waited the bound at 2.3 s (their budget would
/// come at 3 s): discarded, one frame. Its third packet (5), written at 2.4 s, goes the same
/// way; the next frame (6), written at 3.1 s with a full budget (refilled since 2 s, capped at
/// one packet) and nothing queued, leaves when it is written.
#[test]
fn the_rest_of_a_discarded_frame_is_discarded_when_it_is_written() {
    let mut harness = Harness::new();
    harness.retarget(SLOW);
    harness.send_of(ms(0), 1, 0, 0);
    harness.send_of(ms(0), 1, 1, 0);
    harness.send_of(ms(0), 1, 2, 0);
    harness.drain();
    harness.advance_to(ms(300));
    harness.send_of(ms(300), 1, 3, 3000);
    harness.send_of(ms(300), 1, 4, 3000);
    harness.drain();
    harness.advance_to(ms(2_400));
    harness.send_of(ms(2_400), 1, 5, 3000);
    harness.drain();
    harness.advance_to(ms(3_100));
    harness.send_of(ms(3_100), 1, 6, 6000);
    harness.drain();
    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 1, 2, 6], order, "6 left when it was written");
    harness.advance_to(ms(5_000));

    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 1, 2, 6], order);
    let reads = harness.reads();
    assert_eq!(vec![(1, vec![3, 4], 1), (1, vec![5], 0)], discards(&reads));
    assert_eq!(vec![1], key_frame_requests(&reads));
}

/// What a source that follows the pause wrote is never discarded for its age (see "Pausing the
/// source" on `PacerInterceptor`): six packets written at 0 s against one packet a second, the
/// second of them starting the pause, and nothing written after. Each leaves when the budget
/// has a packet's worth again, 0 at once and then one a second, 5 at 5 s, long past the 2 s
/// bound; no discard, no key-frame request. Driven deadline by deadline to 10 s: every
/// deadline the pacer asks for after a timeout is later than the instant just handled (no
/// spin on a bound that does not apply), and none is asked for once the queue is empty.
#[test]
fn media_written_before_the_pause_is_never_discarded_for_its_age() {
    let mut harness = Harness::new();
    harness.retarget(SLOW);
    for sequence_number in 0..6u16 {
        harness.send(ms(0), sequence_number);
    }
    harness.drain();
    let mut handled = ms(0);
    let mut wakes = 0;
    while let Some(due) = harness.next_timeout() {
        assert!(
            due > handled,
            "a deadline at {due:?} after the timeout at {handled:?}: a spin"
        );
        assert!(due <= ms(10_000), "a deadline at {due:?}");
        wakes += 1;
        assert!(wakes <= 20, "{wakes} wake-ups for six packets");
        harness.tick(due);
        handled = due;
    }
    harness.tick(ms(10_000));

    let schedule = harness.schedule();
    let order: Vec<u16> = schedule.iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 1, 2, 3, 4, 5], order, "every packet left, in order");
    for (sequence_number, at) in schedule {
        let expected = ms(1_000 * u64::from(sequence_number));
        assert!(
            at.abs_diff(expected) <= ms(1),
            "{sequence_number} left at {at:?}, not at {expected:?}"
        );
    }
    let reads = harness.reads();
    assert!(discards(&reads).is_empty(), "nothing discarded");
    assert!(
        key_frame_requests(&reads).is_empty(),
        "no key frame asked for"
    );
}

/// A full queue discards its oldest packet's frame with every frame of that stream that waits,
/// and keeps the other streams' packets: stream 1's frames 1 and 3 go when packet 4 arrives at
/// a queue of three (at 0.5 s), stream 9's packets 2 and 4 leave, one a second.
#[test]
fn a_full_queue_discards_the_oldest_frame_with_its_stream() {
    let mut harness = Harness::with_queue(PACKET_BITS, QueueOverflow::default(), 3);
    harness.retarget(SLOW);
    harness.send_of(ms(0), 1, 0, 0);
    harness.send_of(ms(0), 1, 1, 3000);
    harness.send_of(ms(0), 9, 2, 0);
    harness.send_of(ms(0), 1, 3, 6000);
    harness.drain();
    harness.advance_to(ms(500));
    harness.send_of(ms(500), 9, 4, 3000);
    harness.drain();
    harness.advance_to(ms(1_900));

    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 2], order, "one packet a second");
    harness.advance_to(ms(3_500));
    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 2, 4], order);
    let reads = harness.reads();
    assert_eq!(vec![(1, vec![1, 3], 2)], discards(&reads));
    assert_eq!(vec![1], key_frame_requests(&reads));
}

/// The targets among `reads`, with the congestion controller's target riding a pause.
fn targets(reads: &[TaggedPacket]) -> Vec<(f64, Option<f64>)> {
    reads
        .iter()
        .filter_map(|read| {
            read.message
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    Attribute::TargetBitrateChanged { bits_per_second } => Some((
                        *bits_per_second,
                        read.message
                            .custom::<PacerPause>()
                            .map(|pause| pause.target_bits_per_second),
                    )),
                    _ => None,
                })
        })
        .collect()
}

/// A source above the target is told to pause before anything waits the 2 s bound (libwebrtc
/// gives its encoder a target of zero while the pacer's expected queue time exceeds the
/// bound): at 2.4 Mb/s against 1.2 Mb/s the queue holds a second's worth (half the bound) after
/// about a second, and the target handed application-ward is zero, with the controller's riding
/// along ([`PacerPause`]). A target that passes meanwhile also reaches the application as
/// zero. The source stops; the queue drains at the target, and once 100 ms is left the real
/// target is announced again. Nothing is discarded, every packet leaves.
#[test]
fn a_source_above_the_target_is_paused_before_anything_waits_the_bound() {
    let mut harness = Harness::new();
    let mut reads = Vec::new();
    let mut paused_at = None;
    let mut written = 0u16;
    for n in 0..2000u16 {
        let at = ms(5 * u64::from(n));
        harness.advance_to(at);
        harness.send(at, n);
        harness.drain();
        written += 1;
        reads.extend(harness.reads());
        if targets(&reads).iter().any(|(bps, _)| *bps == 0.0) {
            paused_at = Some(at);
            break;
        }
    }
    let paused_at = paused_at.expect("the source was paused");
    assert!(
        (ms(900)..=ms(1_100)).contains(&paused_at),
        "paused at {paused_at:?}"
    );
    assert_eq!(vec![(0.0, Some(BITRATE))], targets(&reads));

    // A target from the congestion controller while paused reaches the application as zero.
    let mut msg = TaggedPacket {
        now: harness.epoch + paused_at,
        transport: TransportContext::default(),
        message: AttributedPacket::new(Packet::Rtcp(vec![])),
    };
    msg.message.add(Attribute::TargetBitrateChanged {
        bits_per_second: BITRATE,
    });
    harness.chain.handle_read(msg).expect("handle_read");
    let while_paused = harness.reads();
    assert_eq!(vec![(0.0, Some(BITRATE))], targets(&while_paused));

    let mut resumed_at = None;
    let mut at = paused_at;
    while at < ms(5_000) {
        at += ms(5);
        harness.advance_to(at);
        let reads = harness.reads();
        assert!(discards(&reads).is_empty(), "nothing is discarded");
        if !targets(&reads).is_empty() {
            assert_eq!(vec![(BITRATE, None)], targets(&reads));
            resumed_at = Some(at);
            break;
        }
    }
    let resumed_at = resumed_at.expect("the pause ended");
    // About 90 packets of the hundred queued leave at 10 ms each first.
    assert!(
        (ms(800)..=ms(1_000)).contains(&(resumed_at - paused_at)),
        "paused for {:?}",
        resumed_at - paused_at
    );
    harness.advance_to(ms(5_000));
    assert_eq!(
        usize::from(written),
        harness.released().len(),
        "every packet left"
    );
}

/// The target the pacer announces itself, when a pause begins and when it ends, is the
/// congestion controller's said again: it carries the minimum that rode with the controller's
/// last target ([`MinimumTarget`]). The NACK responder takes the minimum from every target it
/// reads and never tells the original media less; without it on the pacer's announcement the
/// end of a pause read as "no minimum", and a target at the controller's floor went
/// application-ward lowered by the whole retransmission reserve (`availableOutgoingBitrate`
/// 46 850 bit/s against a floor of 100 000). A controller's target without a minimum takes
/// the minimum off the next announcement.
#[test]
fn the_target_the_pacer_announces_carries_the_controllers_minimum() {
    let minimum_of = |reads: &[TaggedPacket]| -> Vec<(f64, Option<f64>)> {
        reads
            .iter()
            .filter_map(|read| {
                read.message
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        Attribute::TargetBitrateChanged { bits_per_second } => Some((
                            *bits_per_second,
                            read.message
                                .custom::<MinimumTarget>()
                                .map(|minimum| minimum.bits_per_second),
                        )),
                        _ => None,
                    })
            })
            .collect()
    };
    let target = |harness: &mut Harness, at: Duration, minimum: Option<f64>| {
        let mut msg = TaggedPacket {
            now: harness.epoch + at,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        };
        msg.message.add(Attribute::TargetBitrateChanged {
            bits_per_second: BITRATE,
        });
        if let Some(bits_per_second) = minimum {
            msg.message.add(Attribute::Custom(Arc::new(MinimumTarget {
                bits_per_second,
            })));
        }
        harness.chain.handle_read(msg).expect("handle_read");
    };
    // Writes at twice the target from `from` until the pause begins, then waits for its end:
    // the targets the pacer announced, and when the last came.
    let pause_and_resume = |harness: &mut Harness, from: Duration, first: u16| {
        let mut announced = Vec::new();
        let mut paused_at = None;
        for n in 0..2000u16 {
            let at = from + ms(5 * u64::from(n));
            harness.advance_to(at);
            harness.send(at, first + n);
            harness.drain();
            announced.extend(minimum_of(&harness.reads()));
            if !announced.is_empty() {
                paused_at = Some(at);
                break;
            }
        }
        let mut at = paused_at.expect("the source was paused");
        let end = at + ms(5_000);
        while at < end && announced.len() < 2 {
            at += ms(5);
            harness.advance_to(at);
            announced.extend(minimum_of(&harness.reads()));
        }
        (announced, at)
    };

    let mut harness = Harness::new();
    target(&mut harness, ms(0), Some(100_000.0));
    assert_eq!(
        vec![(BITRATE, Some(100_000.0))],
        minimum_of(&harness.reads()),
        "the controller's target passes as it came"
    );
    let (announced, resumed_at) = pause_and_resume(&mut harness, ms(0), 0);
    assert_eq!(
        vec![(0.0, Some(100_000.0)), (BITRATE, Some(100_000.0))],
        announced,
        "the pause and its end, each with the controller's minimum"
    );

    // The controller's next target has no minimum: neither has what the pacer says after it.
    let again = resumed_at + ms(1_000);
    harness.advance_to(again);
    target(&mut harness, again, None);
    assert_eq!(vec![(BITRATE, None)], minimum_of(&harness.reads()));
    let (announced, _) = pause_and_resume(&mut harness, again, 3000);
    assert_eq!(vec![(0.0, None), (BITRATE, None)], announced);
}

/// A retransmission of a packet whose retransmission already waits in the queue is not queued
/// again (libwebrtc's packet history ignores a request for a packet "already in pacer queue"):
/// two RTX packets repairing the same original (sequence number 0 ahead of the payload, RFC 4588
/// section 4) written while video waits, and only the first leaves. Its departure is reported
/// application-ward ([`RetransmissionsLeft`]) as (RTX SSRC, the sequence number it repairs).
#[test]
fn a_retransmission_already_waiting_is_not_queued_again() {
    let mut harness = Harness::new();
    harness.chain.bind_local_stream(&StreamInfo {
        ssrc: 1,
        ssrc_rtx: Some(3),
        mime_type: "video/VP8".to_owned(),
        clock_rate: 90_000,
        ..Default::default()
    });
    for sequence_number in 1..=10 {
        harness.send(ms(0), sequence_number);
    }
    harness.advance_to(ms(15));
    harness.send_retransmission(ms(15), 500);
    harness.send_retransmission(ms(15), 501);
    harness.advance_to(ms(200));
    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![1, 2, 500, 3, 4, 5, 6, 7, 8, 9, 10], order);
    let departed: Vec<(u32, u16)> = harness
        .reads()
        .iter()
        .filter_map(|read| read.message.custom::<RetransmissionsLeft>())
        .flat_map(|notice| notice.departed.clone())
        .collect();
    assert_eq!(vec![(3, 0)], departed);
}

/// The queue time is bounded (libwebrtc's pacer: an expected queue length of 2 s). A source
/// writing 2.4 Mb/s for ten seconds against a 1.2 Mb/s target fills the queue at 1.2 Mb/s;
/// the pacing rate rises above the target as far as it takes to drain what is queued before
/// the oldest packet has waited 2 s, so no packet waits longer than that (and a packet more),
/// and every packet leaves. Without the bound the last packet waits 10 s.
#[test]
fn with_drain_no_packet_waits_longer_than_the_queue_time_limit() {
    let mut harness = Harness::with(PACKET_BITS, QueueOverflow::Drain);
    let waits = |harness: &Harness| -> Vec<Duration> {
        harness
            .released()
            .iter()
            .map(|packet| packet.at - ms(5 * u64::from(packet.sequence_number)))
            .collect()
    };
    for n in 0..2000u16 {
        let at = ms(5 * u64::from(n));
        harness.advance_to(at);
        harness.send(at, n);
        harness.drain();
    }
    harness.advance_to(ms(20_000));
    let released = harness.released();
    assert_eq!(2000, released.len(), "every packet left");
    let longest = waits(&harness).into_iter().max().unwrap_or_default();
    assert!(
        longest <= ms(2_010),
        "the longest wait was {longest:?}, over the 2 s limit"
    );
    assert!(longest >= ms(1_500), "the queue did grow: {longest:?}");
}

/// The queue time bound is the media's: padding never counts toward raising the pacing rate.
/// 2000 padding packets (4.27 Mbit) at a 1.2 Mb/s target take 3.55 s; were they counted, the
/// rate would rise to send them all within 2 s, on top of a target that has no room for them.
#[test]
fn padding_never_raises_the_pacing_rate() {
    let mut harness = Harness::new();
    for n in 0..2000u16 {
        harness.send_padding(ms(0), 60_000 + n);
    }
    harness.drain();
    harness.advance_to(ms(2_500));
    // 12 000 bits of burst and 2.5 s at 1.2 Mb/s: 1410 packets of 2136 bits.
    let by_then = harness.released().len();
    assert!(
        (1_400..=1_410).contains(&by_then),
        "{by_then} padding packets left in 2.5 s: not at the target rate"
    );
    harness.advance_to(ms(4_000));
    assert_eq!(
        2000,
        harness.released().len(),
        "and then all of it, none dropped"
    );
}

/// Padding that has waited longer than the queue time bound is sent late, not dropped and not
/// forced out ahead of media: with a source above the target behind it for four seconds, the
/// queued padding leaves only once the media queue is empty (here when the frames that waited
/// the bound are discarded, or after the last media), every packet of it: no media packet that
/// was waiting when a padding packet left leaves after it. And the media still waits no longer
/// than the bound.
#[test]
fn padding_older_than_the_queue_time_limit_waits_for_spare_budget() {
    let mut harness = Harness::new();
    for n in 0..10u16 {
        harness.send_padding(ms(0), 60_000 + n);
    }
    harness.drain();
    // 2.4 Mb/s of media against the 1.2 Mb/s target for 4 s.
    for n in 0..800u16 {
        let at = ms(5 * u64::from(n));
        harness.advance_to(at);
        harness.send(at, n);
        harness.drain();
    }
    harness.advance_to(ms(20_000));
    let released = harness.released();
    let padding: Vec<&Released> = released
        .iter()
        .filter(|packet| packet.sequence_number >= 60_000)
        .collect();
    assert_eq!(10, padding.len(), "no padding is dropped");
    let media: Vec<&Released> = released
        .iter()
        .filter(|packet| packet.sequence_number < 60_000)
        .collect();
    assert!(!media.is_empty(), "media left");
    // The burst let the first five go at once; the other five waited out the media.
    assert_eq!(
        5,
        padding.iter().filter(|packet| packet.at == ms(0)).count()
    );
    for late in padding.iter().filter(|packet| packet.at > ms(0)) {
        // Media packet `n` was written at 5n ms: one written before the padding left was
        // waiting then, unless it had left already.
        let overtaken: Vec<&&Released> = media
            .iter()
            .filter(|packet| ms(5 * u64::from(packet.sequence_number)) < late.at)
            .filter(|packet| packet.at > late.at)
            .collect();
        assert!(
            overtaken.is_empty(),
            "padding {late:?} went ahead of waiting media {overtaken:?}"
        );
    }
    let longest = released
        .iter()
        .filter(|packet| packet.sequence_number < 60_000)
        .map(|packet| packet.at - ms(5 * u64::from(packet.sequence_number)))
        .max()
        .unwrap_or_default();
    assert!(longest <= ms(2_010), "media waited {longest:?}");
}

/// Audio is not queued behind video (libwebrtc paces audio first): with a second of video
/// queued, an audio packet leaves when it is written.
#[test]
fn audio_is_not_queued_behind_video() {
    let mut harness = Harness::new();
    harness
        .chain
        .bind_local_stream(&rtci_interceptor::StreamInfo {
            ssrc: 7,
            mime_type: "audio/opus".to_owned(),
            clock_rate: 48_000,
            ..Default::default()
        });
    for n in 0..100u16 {
        harness.send(ms(0), n);
    }
    harness.drain();
    harness
        .chain
        .handle_write(TaggedPacket {
            now: harness.epoch + ms(1),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    payload_type: 111,
                    sequence_number: 5000,
                    ssrc: 7,
                    ..Default::default()
                },
                payload: vec![0u8; 100].into(),
            })),
        })
        .expect("handle_write");
    harness.drain();
    let audio = harness
        .released()
        .into_iter()
        .find(|packet| packet.sequence_number == 5000)
        .expect("the audio packet left");
    assert_eq!(ms(1), audio.at, "at the instant it was written");
}

/// RFC 8836 section 2, requirement 1 (self-induced delay as low as possible) with
/// draft-ietf-rmcat-gcc-02 section 4 (no more than the target rate times the burst time at
/// once): a packet the budget covers leaves when it is written, at the instant it was written,
/// and the budget it used still spaces what follows.
#[test]
fn a_packet_inside_the_budget_leaves_when_it_is_written() {
    let mut harness = Harness::new();

    harness.send(ms(3), 0);
    harness.drain();
    assert_eq!(vec![(0, ms(3))], harness.schedule(), "no timer was needed");

    // The budget is spent: the next packet waits its 10 ms, wherever the clock is asked.
    harness.send(ms(4), 1);
    harness.drain();
    assert_eq!(1, harness.schedule().len(), "the second is over budget");
    harness.advance_to(ms(50));
    let schedule = harness.schedule();
    assert_eq!((0, ms(3)), schedule[0]);
    assert_eq!(1, schedule[1].0);
    assert!(
        schedule[1].1.abs_diff(ms(13)) < Duration::from_micros(1),
        "one packet-time after the first, not after the write: {:?}",
        schedule[1].1
    );

    // And one written behind a queued packet does not overtake it.
    harness.send(ms(60), 2);
    harness.send(ms(60), 3);
    harness.send(ms(70), 4);
    harness.advance_to(ms(100));
    let order: Vec<u16> = harness.schedule().iter().map(|(seq, _)| *seq).collect();
    assert_eq!(vec![0, 1, 2, 3, 4], order);
}

/// The setting for a driver that wants every departure on its own clock: nothing leaves from
/// a write, only from a timeout.
#[test]
fn without_immediate_release_only_the_clock_releases() {
    let epoch = Instant::now();
    let mut chain = Registry::new()
        .with(
            Slot::Pacer,
            PacerBuilder::new()
                .with_target_bitrate(BITRATE)
                .with_immediate_release(false)
                .build(),
        )
        .build();

    chain
        .handle_write(TaggedPacket {
            now: epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    ssrc: 1,
                    ..Default::default()
                },
                payload: vec![0u8; PAYLOAD_BYTES].into(),
            })),
        })
        .expect("handle_write");
    assert!(chain.poll_write().is_none(), "held for the clock");
    assert_eq!(Some(epoch), chain.poll_timeout());

    chain.handle_timeout(epoch).expect("handle_timeout");
    assert!(chain.poll_write().is_some(), "released by the timeout");
}

/// A packet's size is its size on the wire, since that is what occupies the path.
#[test]
fn pacing_meters_the_wire_size() {
    let packet = rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            payload_type: 96,
            sequence_number: 0,
            ssrc: 1,
            ..Default::default()
        },
        payload: vec![0u8; PAYLOAD_BYTES].into(),
    };
    assert_eq!(
        PACKET_BITS as usize,
        packet.marshal_size() * 8,
        "the fixture is the size the schedule assumes"
    );
}

/// A flow the circuit breaker ceased (RFC 8083 section 4.5) is dropped below the pacer: its
/// packets are not charged to the budget, so what the application keeps writing into it
/// takes nothing from the other streams. (Charged, a ceased voice at 76 kbit/s left the
/// video 24 of a 100 kbit/s target on the path of `tests/capacity_cap_video_rtc2rtc.rs`.)
/// After the restart the flow is metered again.
#[test]
fn a_flow_the_circuit_breaker_ceased_is_not_charged_to_the_budget() {
    let notice = |harness: &mut Harness, ceased: Option<CircuitBreakerReason>| {
        let msg = TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])).with(Attribute::Custom(Arc::new(
                CircuitBreakerNotice {
                    ssrc: 7,
                    ceased,
                    restart_after: Duration::ZERO,
                },
            ))),
        };
        harness.chain.handle_read(msg).expect("handle_read");
        while harness.chain.poll_read().is_some() {}
    };
    let media_left_at = |ceased: bool| {
        let mut harness = Harness::new();
        if ceased {
            notice(&mut harness, Some(CircuitBreakerReason::MediaTimeout));
        }
        // Ten full packets of the flow, 120 000 bits: 100 ms of the 1.2 Mb/s budget.
        for sequence_number in 100..110 {
            harness.send_of(ms(0), 7, sequence_number, 0);
        }
        harness.send(ms(0), 1);
        harness.advance_to(ms(300));
        harness
            .schedule()
            .into_iter()
            .find(|(sequence_number, _)| *sequence_number == 1)
            .map(|(_, at)| at)
            .expect("the media packet left")
    };
    assert!(
        media_left_at(false) >= ms(80),
        "behind ten packets of a flow that sends: {:?}",
        media_left_at(false)
    );
    assert_eq!(ms(0), media_left_at(true), "the ceased flow costs nothing");

    // Restarted: metered again.
    let mut harness = Harness::new();
    notice(&mut harness, Some(CircuitBreakerReason::MediaTimeout));
    notice(&mut harness, None);
    for sequence_number in 100..110 {
        harness.send_of(ms(0), 7, sequence_number, 0);
    }
    harness.send(ms(0), 1);
    harness.advance_to(ms(300));
    let (_, at) = harness
        .schedule()
        .into_iter()
        .find(|(sequence_number, _)| *sequence_number == 1)
        .expect("the media packet left");
    assert!(at >= ms(80), "{at:?}");
}
