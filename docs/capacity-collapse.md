# What happens to the backlog when the path's capacity collapses

A call sends 2.5 Mbit/s of video and the path drops to 300 kbit/s. The congestion controller
brings the target down within about 0.6 s, but what the application wrote meanwhile, and the
retransmissions of what the path dropped, were sized for the old rate: 0.4 s of 2.5 Mbit/s
video and its repairs take 8 s to leave at 100 to 250 kbit/s. Delivered in order, the picture
on the receiver's screen is 8 s old. This page says what the engine does instead, which texts
permit it, what an application has to do, what was measured, and what is still not met.

## The rule

The pacer (`rtci-interceptor/src/pacing/sender.rs`, "A capacity collapse") keeps the targets
the congestion controller set, back to the one in force when the oldest queued new media was
written or two seconds ago (the queue time bound), whichever reaches further back.

A **collapse** is: what waits in the pacer (new media, retransmissions or both) would take one
second or more to leave at the target (half the queue time bound: the mark at which a pause
would begin), and the target is at most **half** of the highest in that history.

At a collapse, with `PacerBacklog::Flush` (the default):

- every queued packet is discarded: new media and FEC whole frames at a time
  (`PacerDiscard`, `RTCPeerConnectionEvent::OnPacerDiscard`), queued retransmissions
  (`RetransmissionsLeft`). Padding stays. Audio is never queued and is not touched; SCTP does
  not pass the pacer.
- the NACK responder forgets everything sent before on the video streams (`PacerFlush`): a
  later NACK for any of it is answered by nothing. What is written afterwards is buffered and
  repaired as ever.
- the application is asked for a key frame of every video stream, once per stream (one per
  simulcast layer: each is its own SSRC).
- the source is **not** paused. A pause in force ends. The next frame it writes, at the target
  it now reads, is the key frame.
- the history is cleared: no target from before the flush counts again.

`PacerBacklog::Keep` (`DefaultInterceptorOptions::pacer_backlog`,
`PacerBuilder::with_backlog`) is the behaviour before this change: the source is paused, the
queue and every retransmission asked for are delivered in order. It is for a receiver that
plays strictly in order and cannot resume at a key frame. `QueueOverflow::Drain` (libwebrtc's
form, the `Chrome` profile) never discards and is unchanged: see "The Chrome profile keeps its
backlog" below for what that costs.

### Why half, and why a flush does not repeat

A pause that begins at a steady target (a key frame larger than a second of the floor rate, a
source above the target) is not a collapse. Flushing there would discard the very key frame the
flush asked for, ask again, and loop. Two things prevent it. A single decrease of the
delay-based controller is 0.85 and a loss report cuts by at most half, so a target that halved
within the life of the queue separates a path that lost its capacity from a controller
adapting. And because the history is cleared at a flush, the key frame written in answer is
judged only against targets set since: however long it takes to leave, it is a pause and it
is delivered. The target has to halve again from what it was at the flush for another flush:
at most log2(highest / lowest target) in a row, four from 2.5 Mbit/s to a 100 kbit/s floor.
No RFC gives the factor; it is a constant (`COLLAPSE_AT`), not a setting.

### Why the repairs alone count, and why two seconds

Behind a deep queue on the path the receiver sees the gap a second after the drop, when the
packets behind it arrive, and its NACKs reach a sender whose pacer no longer holds any media
written for the old rate. Those repairs are of media written for the old rate all the same.
Two seconds is the pacer's own bound on how long anything may wait before it is stale.

### Why the mark is one second and not lower

Flushing as soon as the target has halved, with 0.5 s or 0.25 s of queue, was measured (200
seeds per cell): the standard cell gains little (oldest picture 1.33 to 1.27 s in the median,
2.08 to 1.64 s at worst) and the deep-queue cell loses: the key frame asked for early goes into
a path queue that is still full, runs with more than 2 s without any frame rise from 6 to 46
(0.5 s) and 69 (0.25 s) of 200, and runs with more than a second without audio from 69 to 96
(0.25 s). One second, the pause mark, is kept.

### The sequence-number gap

The application numbered the discarded packets, so the receiver sees a gap before the key frame
and its NACKs for it go unanswered. Renumbering in the engine was rejected: the packets the
path lost at the drop are gaps anyway, and a renumbering pacer would have to translate every
NACK and RTX original sequence number. The receiver counts the discarded packets as lost in its
RTCP reports (RFC 3550 A.3). The RTP circuit breaker sits wire-ward of the pacer
(`Slot::CircuitBreaker` 2 500, `Slot::Pacer` 3 000, the NACK responder and the FEC encoder
above), so it never saw them leave and does not count them as sent or lost.

## The NACK responder: repairs that cannot be useful

The pacer's flush covers a chain with a pacer whose queue is long. Two cases it does not
reach are the responder's own (`rtci-interceptor/src/nack/responder.rs`,
`NackResponderBuilder`), in any chain:

- **Age** (`with_max_repair_age`, `DefaultInterceptorOptions::nack_max_repair_age`, 2 s): a
  NACK for a packet written more than two seconds ago is declined. Two seconds is the pacer's
  queue time bound, past which the pacer itself drops what waits as stale. This is the outage:
  nothing queues at the sender while the path is dead, so nothing is flushed, and when the
  path returns a receiver without a bound in time asks for everything sent into it.
- **Backlog** (`with_repair_backlog_bound`, `nack_repair_backlog_bound`, 2 s): the requests
  waiting would take two seconds or more to leave at the whole target, and the target is at
  most half of the highest in force within two seconds (the pacer's definition of a collapse,
  with the same constant). This is the chain without a pacer that stands at the path's rate
  when the capacity goes: a fifth of a megabyte is lost at the path's queue before the
  estimate reacts, nothing pauses or flushes, and the responder would repair it in order,
  within the target, for up to twelve seconds, most of the repairs dropped at the queue
  again, while the original media is held at the floor by the retransmission reserve.

Either way the **video stream is given up**: everything sent on it so far is forgotten (a
later NACK for any of it is answered by nothing), the retransmission reserve those repairs
held is released at once, and the application is asked for one key frame of the stream, the
same request as at a flush (below). What is written afterwards is buffered and repaired as
ever. The target history is cleared at a give-up as at a flush: the key frame that answers
is written for the target now, and a backlog of its own losses gives the stream up again
only if the target halves again. (A fixed hold of two seconds after a give-up was built and
measured: 200 calls in each of 14 cells without a pacer came out row for row the same with
and without it, since no run gave a stream up twice within it. It is not there.) **Audio** is declined by age and nothing
else: no key frame is asked of it, its waiting requests survive a give-up of the video.

A backlog at a target that did not just halve is ordinary loss and is repaired, however
large: "retransmission of an important lost packet to repair decoder state can have lower
cost than sending a full intra frame" (RFC 8834 section 6.1). With 3 % of the packets lost
for 20 s at 2.5 Mbit/s the engine sends 149 retransmissions and 3 key frames a call (the two
of the start and one more), with the rules as without them, row for row (the instrument's
`fl3` cells; a tripwire holds the key frames on every pull request).

`PacerBacklog::Keep` switches both rules off in the default chain: it means "keep and repair
everything". A chain built by hand passes `None` to both builder methods. The `Chrome`
profile has both off: libwebrtc's sender serves every NACK its packet history can answer and
never asks itself for a key frame (its receiver does). The age bound is the sender's own
judgement and is not announced as `rtx-time` (RFC 4588 section 8.1): it would change every
offer, and a receiver learns of a give-up by the key frame.

**Where an `rtx-time` is set, it is the age bound.** RFC 4588 section 8.1 defines `rtx-time`
as "the maximum time a sender will keep an original RTP packet in its buffers available for
retransmission", and section 8.8 has the receiver "take into account the signalled sender
retransmission buffer length". A time in force for a stream (announced in the session
description or set by the application for the stream's retransmission format,
`NackControl::LocalRtxTime`; or `NackResponderBuilder::with_max_packet_age`) is what the
other side counts on: a packet of that stream is repaired for that long, whether that is
shorter or longer than two seconds, and the two seconds do nothing for the stream. Past the
`rtx-time` a packet is not retransmitted and nothing else happens: the stream is not given
up and no key frame is asked for, since the receiver was told the time and gives the gap up
by its own rule. The backlog rule is not changed by an `rtx-time` (the time is the most a
packet is kept; a collapse ends the repairs of what was sent before it, as the flush does).

**The `rtx-time` is the packet's, not the stream's.** RFC 4588 section 8.6 maps each
retransmission payload type to one original payload type with `apt`, and `rtx-time` is a
parameter of that retransmission format (section 8.1), so one stream can carry formats with
different times: video sent as RED (the `Chrome` profile's `fec.video-red-ulpfec`) goes under
the RTX of `red`, plain media under the RTX of its codec. The responder takes, for each packet,
the time of the format the packet is sent again in (`LocalStream::repair_form`; the stream's
own for a packet sent again as it was), and that one value decides everything for the packet:
the cut at the time, the two seconds where there is none, and whether its age gives the stream
up. A RED packet whose RTX of `red` announces no time is declined at two seconds and gives the
stream up, whatever the codec's RTX announces; a RED packet whose RTX of `red` announces five
seconds is repaired at three, while a plain packet of the same stream with no time of its own
is declined.

**Only a packet that would be answered can give the stream up.** A NACK can name a packet the
responder never sends again: a FEC packet in RED on a stream without RTX, or a packet whose
payload type has no RTX format on a stream that has RTX. Such an entry is skipped silently, by
the give-up's age test as by the repair itself: the receiver is not waiting for a picture
because a FEC packet was lost. On a stream without RTX every other packet is answered (the
packet again as it was), so the give-up there is as above.

What the responder remembers of a repair (`DELIVERED_MEMORY`, four seconds from the report
that a retransmission arrived; four seconds for a retransmission a pacer never reports on)
is longer than the default age bound and stays so: under the default a packet's memory can
no longer be reached once the packet is two seconds old (the request is declined by age
first), and the four seconds are the bound for the configurations in which a packet is
repaired longer, an `rtx-time` over two seconds or the age rule off.

### Why two seconds of backlog and not one

One second was measured first (200 calls a cell, ParolNet's chain). It gives up while the
target is still falling or while the path's queue still holds a second of old media, and the
key frame asked for goes into that queue: behind a 100 ms queue 8 calls showed no frame for
2.5 s (none at two seconds, none without the rule), behind a 1000 ms queue 24 calls for over
2 s (none at two seconds, 1 without the rule). A hold after a give-up does not help: there
is one give-up a call. With two seconds no cell has a worse tail than without the rule. An
age bound of one second (libwebrtc's shortest packet history) breaks the default chain behind
a 1000 ms queue, where a NACK for a packet still wanted is older than that (pictures over
2 s old in 109 -> 200 of 200 calls).

### A probe after a give-up

A probe cluster is padded under the header of the newest packet in the responder's buffer.
A give-up (and the pacer's flush) empties the buffer; the header of the newest packet it
held is kept for the padding until the next packet is written. Without it a cluster asked
for in that gap is not sent, and a chain without a pacer, which stops asking after an
unanswered cluster, does not probe again (measured with a give-up at every path change:
1000 kbit/s reached 14.9 s after the path's return instead of 0.5 s).

### Repairs already in the pacer at a give-up (known small effect)

A give-up does not tell the pacer: a retransmission of a forgotten packet that the responder
handed to the pacer before the give-up still leaves when its turn comes. It is rare and small,
so the pacer is not told. Counted in the instrument's paced cells, 100 calls each (the
standard cap, the 100 ms and 1000 ms queues, both directions capped, 5 % reverse loss, the two
outages: 700 calls, 247 give-ups): 3 such retransmissions in all, at one give-up in one call
with both directions capped; none in every other cell. In a paced chain the flush comes first
at a collapse (it empties the pacer's queue itself), and the age rule fires after an outage,
when nothing waits in the pacer.

## The texts

No text obliges a sender to deliver what it queued, or to answer a NACK.

- RFC 8834 section 6.1: "Retransmission needs to be used with care in interactive real-time
  applications to ensure that the retransmitted packet arrives in time to be useful [...] It
  is not appropriate to blindly retransmit RTP packets in response to a NACK. The importance of
  lost packets and the likelihood of them arriving in time to be useful need to be considered
  before RTP retransmission is used."
- RFC 4588 section 7: "In a best-effort environment, the sender SHOULD NOT send retransmission
  packets without reducing the packet rate and bitrate of the original stream [...] In
  addition, the sender MAY selectively retransmit only the packets that it deems important and
  ignore NACK messages for other packets in order to limit the bitrate." There is no "gone"
  message: silence is the answer. And: "These congestion control mechanisms should keep the
  packet loss rate within acceptable parameters. [...] If congestion is not kept under
  control, then retransmission SHOULD NOT be used": a backlog repaired for seconds at a rate
  the path drops again is that case.
- RFC 8836 section 2: interactive media is useful "within a very limited time window (no more
  delay than hundreds of milliseconds end-to-end)", and the controller "reacts quickly [...] to
  avoid delay buildup" (requirement 1).
- RFC 5104 section 4.3.1.2: "Upon reception of FIR, the encoder MUST send a decoder refresh
  point [...] as soon as possible"; section 2.2: a decoder refresh point "completely resets the
  decoder to a known state". Nothing sent before it is needed after it. RFC 4585 section
  6.3.1: "The sender MAY react to a PLI by transmitting an intra-picture".
- Precedent for discarding at the sender, RFC 8298 (SCReAM) section 3: "The reaction to reduced
  throughput MUST be prompt in order to avoid getting too much data queued in the RTP packet
  queue(s) in the sender. [...] In cases where the sender's frame queues increase rapidly, such
  as in the case of a Radio Access Type (RAT) handover, the SCReAM sender MAY implement
  additional actions, such as discarding of encoded media frames or frame skipping in order to
  ensure that the RTP queues are drained quickly."

libwebrtc, for comparison, drops frames before they are encoded and numbered and drains its
pacer above the target once the queue passes 2 s; its receiver gives a NACK list up and asks
for a key frame. Its sender-side form is `QueueOverflow::Drain` here.

## What an application must do

**Produce a key frame when asked.** At a flush, and when the NACK responder gives a stream's
repairs up, the application of the sending peer gets, for each video stream concerned, at
that instant:

- on `RTCPeerConnection::poll_read`, an `RTCMessage::RtcpPacket` holding a Picture Loss
  Indication for the stream's SSRC with sender SSRC 0, the same message a receiver's request
  arrives as; and
- on `poll_event`, `RTCPeerConnectionEvent::OnKeyFrameRequest { sender, rid }`, followed by
  `OnKeyFrameRequestOrigin`, the same request with its origin:
  `RTCKeyFrameRequestOrigin::Local(LocalKeyFrameRequest::PacerFlush)` (or `PacerDiscard`,
  `RepairGivenUp`), where a receiver's request is `RemotePictureLossIndication` or
  `RemoteFullIntraRequest`. The origin rides on the PLI as an attribute from the interceptor
  that made it, not inferred from sender SSRC 0, which a remote peer may hold too.

An application that answers either with a key frame, as it must for a remote request anyway,
needs no new code. One that treats the engine's own requests differently reads the origin. `OnPacerDiscard` names the media that was queued. The key frame should be
sized for the target read then (`RTCRtpSender::target_bitrates`).

**On the receiving side**, bound the wait for a missing packet in time, or resume at a key
frame. `rtci-media`'s `SampleBuilder` does both by default for video
(`docs/receiver-gap-policy.md`); browsers decode from a key frame whatever is missing before it.
A receiver that waits for a gap by packet count only and cannot skip to a key frame needs the
sender on `PacerBacklog::Keep`.

Tests: `rtci-interceptor/tests/pacer_flush.rs` (the pacer's rule),
`rtci-interceptor/tests/nack_declines_useless_repairs.rs` (the responder's two rules),
`tests/capacity_cap_video_rtc2rtc.rs::a_capacity_collapse_asks_the_application_for_a_key_frame_of_its_video_stream`
(through the peer connection), `tests/capacity_instrument.rs` (two-peer calls of each
problem: `an_unpaced_call_collapsing_from_the_paths_rate_gives_its_repairs_up_for_a_key_frame`,
`a_paced_call_resumes_within_two_seconds_of_an_outage_with_a_receiver_without_a_bound`,
`ordinary_loss_is_repaired_and_asks_for_no_key_frames`; and the ensembles below).

## What was measured

`tests/capacity_instrument.rs`, 200 seeds per cell, 2.5 Mbit/s each way, the caller's uplink
capped at 300 kbit/s for 20 s (or dead for 4 s, the outage). "Missed" is a picture older than
2 s on the screen for more than 0.5 s. Before = the pause (the circuit breaker's corrected
rules, the estimator's collapse changes and the receiver's gap bound already in); after = the
flush. Oldest picture is the median.

| cell | missed before | missed after | oldest picture before | after (median / 90th / worst) |
|---|---|---|---|---|
| standard (300 ms path queue, bounded receiver) | 200 | 0 | 7.9 s | 1.33 / 1.55 / 2.08 s |
| receiver without a bound in time | 200 | 0 | 7.2 s | 1.33 / 1.57 / 1.82 s |
| 5 % loss on the reverse path | 200 | 1 | 7.6 s | 1.34 / 1.61 / 2.77 s |
| 1000 ms path queue | 200 | 109 | 7.0 s | 2.52 / 2.89 / 3.13 s |
| both directions capped | 200 | 119 | 12.9 s | 2.60 / 3.42 / 10.87 s |
| outage, bounded receiver: resume later than 2 s | 134 | 0 | | |
| outage, receiver without a bound: resume later than 2 s | 200 | 66 | | |

Key frames the caller sends per run: 5 in the median (4 before), 8 at most. Key-frame
requests the callee sends: 2 (8 before). Audio, the target under the cap (about 245 kbit/s),
the target 15 to 25 s after the cap is lifted and the time to recover are not moved. The
chains without a pacer are not touched by the flush.

### With the responder's rules

Same instrument, 200 seeds per cell; before = the flush alone (and, without a pacer, start-up
probing: the call stands at 2.5 Mbit/s when the cap comes).

| cell | figure | before | after |
|---|---|---|---|
| ParolNet's chain (no pacer), bounded receiver | retransmissions a call / dropped again | 142 / 38 | 18 / 16 |
| | median target under the cap | 229 kbit/s | 257 kbit/s |
| | key frames the caller sends / requests the callee sends | 9 / 7 | 5 / 2 |
| ParolNet's chain, receiver without a bound | oldest picture (median / 90th / worst) | 7.48 / 8.89 / 9.27 s | 1.13 / 1.61 / 1.69 s |
| | missed | 200 | 0 |
| ParolNet's chain, 100 ms path queue | retransmissions / dropped again | 263 / 155 | 39 / 37 |
| | median target under the cap; oldest picture (median) | 142 kbit/s; 1.72 s | 252 kbit/s; 0.79 s |
| ParolNet's chain, both directions capped | missed; no frame for over 2 s | 25; 28 | 0; 0 |
| default chain without the pacer, 1000 ms path queue | no frame for over 2 s; over 1 s without audio | 10; 20 | 0; 7 |
| default chain, outage, receiver without a bound | resume later than 2 s | 66 | 0 |
| default chain, the capacity cells above | every figure | | unchanged or within noise (the flush fires first) |
| 3 % loss at the full rate, no collapse (either chain) | retransmissions / key frames / requests | 149 / 3 / 1 | 149 / 3 / 1, row for row |

## The Chrome profile keeps its backlog

The flush applies with `QueueOverflow::Drop` only. The `Chrome` behaviour profile sets
`pacer_queue_overflow` to `Drain`, libwebrtc's form (`drain_large_queues`): its pacer never
discards. At a collapse the source is paused (a target of zero) and what is queued, the
retransmissions of what the path dropped at the drop, is delivered in order; the key frame
the receiver asks for is written only when the pause ends. The profile does what it says, and
after a sharp capacity drop its picture is about 5 s old where the default's is about 1 s.
This is not a defect of the profile; it is what libwebrtc's sender-side form costs with a
receiver that plays in order.

One call (seed 1, the cap at 20.0 s; run 45608112012): both chains cut the estimate first at
20.3 s. Under `Chrome` the target is zero from 20.8 to 24.3 s, 73 retransmissions leave
meanwhile at 110 to 240 kbit/s, and the next usable frame arrives at 25.4 s. The default
flushes once, is never paused, and has frames again at 21.3 s.

`tests/capacity_instrument.rs`, cell `cap/<chain>/gap300/up/q300/rl0`, seeds 1 to 200, means
(run 45615240747; tree: train 32 at ff4d06af with `conf/rtcpbudget-4`, `conf/red-1`, `-3`, `-2`
and two chain tokens made for this measurement and not kept: the `Chrome` profile with
`pacer_queue_overflow = Drop`, and the default with `Drain`). In brackets the difference per
seed from the chain the row varies, with its 95 % half-width.

| | `Chrome` | `Chrome` with `Drop` | default | default with `Drain` |
|---|---|---|---|---|
| oldest picture, s | 5.50 | 1.46 (-4.04 +-0.09) | 1.32 | 6.60 (+5.28 +-0.13) |
| freeze, s | 5.18 | 1.14 (-4.04 +-0.09) | 1.01 | 6.29 (+5.28 +-0.13) |
| picture older than 2 s for over 0.5 s (runs of 200) | 200 | 0 | 0 | 200 |
| time the source was paused, s | 4.87 | 0.02 | 0.00 | 5.12 |
| pacer flushes | 0 | 1.0 | 1.2 | 0 |
| retransmissions | 176 | 35 | 1.9 | 102 |
| key frames sent; requests received | 8.7; 7.2 | 5.4; 2.4 | 5.1; 2.1 | 5.2; 3.3 |
| target under the cap, kbit/s | 196 | 274 (+78 +-4) | 246 | 231 (-15 +-1) |
| time to detect, s | 0.588 | 0.588 | 0.590 | 0.590 |
| time to recover, s | 14.5 | 14.2 (-0.3 +-0.3) | 17.2 | 17.7 (+0.4 +-0.3) |
| audio packets lost | 27.8 | 26.8 (-1.0 +-0.7) | 27.2 | 32.0 (+4.8 +-1.1) |
| flows ceased by the circuit breaker | 0 | 0 | 0 | 0 |

Both directions capped (`cap/<chain>/gap300/both/q300/rl0`, 200 seeds): `Chrome` oldest picture
11.52 s, paused 9.6 s, target under the cap 117 kbit/s; with `Drop` 2.66 s (-8.86 +-0.53),
0.3 s and 201 kbit/s (the default: 2.64 s and 271 kbit/s).

The whole difference follows the one setting, in both directions: the `Chrome` profile with
`Drop` is within 0.14 +-0.05 s of the default, and the default with `Drain` is as stale as
`Chrome`. What it is not: the estimator reacts at the same instant in every column (0.59 s);
the circuit breaker, off under `Chrome`, ceases no flow in any; the FEC of the profile's RED
video takes 42 to 100 kbit/s of the stream under the cap in the traced calls (run 45615247297) (so the media target is 196 against
246 kbit/s) without overloading the path, and is the same in the `Drop` column; and answering
a NACK for a lost FEC packet (`conf/red-2`) halved the gaps the receiver gave up on (353 to
156 a call) and did not move the freeze.

**An application that wants the `Chrome` profile's other rows and a fresh picture after a
collapse** sets `DefaultInterceptorOptions::pacer_queue_overflow` to
`PacerQueueOverflow::Drop` on the options `DefaultInterceptorOptions::for_profile` returns
(`pacer_backlog` is `Flush` already). It then also takes `Drop`'s rule for a source that
writes above the target: the excess is discarded at the pacer, not put on the path.

## Known limits

- **Both directions capped.** Each sender's feedback crosses the other's overloaded uplink and
  most of it is dropped, so the estimate falls only by the rule for missing feedback, once per
  half second: four halvings from 2.5 Mbit/s take 2.0 to 2.5 s. Until then the pacer has no
  backlog (it sends at a target far above the path): the backlog is in the network and there is
  nothing to flush. Honest target today: reaction 2.0 to 2.5 s + the path queue 0.3 s + a key
  frame 0.3 s, about 3 s of oldest picture; measured 2.6 s in the median. The remedy is the
  estimator's reaction to missing feedback, not the flush.
- **A deep queue on the path (1000 ms).** The second of media already in the path's queue
  cannot be recalled. Honest target: reaction 0.6 s + 1.0 s in the queue + a key frame 0.2 s,
  oldest picture about 2.0 s in the median; measured 2.52 s. The rest is a pacer queue of about
  0.45 s that stands for a second while the estimate holds at the path's rate (a source that
  writes at the target does not drain it), until the target falls again and the flush fires.
  With such a queue the voice is still held by the circuit breaker for some seconds in about a
  third of runs (`docs/circuit-breaker.md`).

Two limits recorded here before are gone with the NACK responder's rules (above): **an outage
with a receiver that has no bound in time** (in a third of the runs no flush fired and 294
packets sent into the dead path were repaired in order, 8.7 s without a fresh picture: now
declined by age, resumed within 0.3 s in 200 of 200 runs), and **the repair tail of a chain
without a pacer** that meets a collapse from the path's rate (up to 12 s of repairs, most
dropped again, the target at its floor: now given up as a backlog).
