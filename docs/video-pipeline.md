# The video pipeline: design

The engine (`rtci`) carries video; it never captures, encodes, decodes or renders it. This
document designs the crates that do that beside the engine, as `docs/media-pipeline.md` did
for audio, and fixes the phases in which they are built. It is measured against libwebrtc
(Chrome's stack): every behaviour that libwebrtc has is either built, or listed here with the
reason it is not.

Rules carried over from the audio pipeline and the engine:

- **Sans-I/O.** No pipeline type reads a clock, opens a device or starts a thread. The caller
  passes `now` in. Capture and hardware backends are opt-in features that open what the
  application asks for and nothing else.
- **Pure Rust by default.** Default features need no system library and no C or assembly
  toolchain (the workspace's CI installs none). Anything else is opt-in, named after what it
  links.
- **Licences**: permissive only (`deny.toml`: MIT, Apache-2.0, BSD-2/3, ISC, Zlib, ...; no
  GPL, LGPL, AGPL, MPL). MSRV 1.89.
- **Spec first, libwebrtc as a profile.** Where an RFC or a W3C document defines the
  behaviour, the default follows it; where libwebrtc chooses differently, its choice is a
  `BehaviourProfile::Chrome` setting (`docs/behaviour-profiles.md`).
- **Measured.** Each phase states acceptance figures, asserts them in tests that run in
  virtual time with fixed seeds, and mutation-checks the assertions.

References: libwebrtc sources at `a222406d49ecffb8e045d113e45f89f62b3819e8` (2026-11-23),
cited as `file:line @ a222406d`; RFC and W3C texts as in the conformance work
(`specs/`). Engine references are to this repository at `2cdbe502` (phase 1; on master from
`conf/vp-3-on-master`, engine master 4431dda0).

---

## 1. Inventory

### 1.1 What the engine already provides for video

| Area | Where | What it gives the pipeline |
|---|---|---|
| Payload formats | `rtci-rtp/src/codec/{vp8,vp9,av1,h264,h265}` | packetizers and depacketizers; `Vp8Packet` (PictureID with its width, TL0PICIDX, TID, Y, KEYIDX, N, S, PID), `Vp9Packet` (I, P, L, F, B, E, V, Z, PictureID, TID, U, SID, D, P_DIFF, the scalability structure with its GOF), `Av1Depacketizer` (OBU aggregation, Z / Y / N bits), `H264Packet` (RFC 6184 single NAL, STAP-A, FU-A, packetization modes, interleaved), `H265Packet` (RFC 7798) |
| Dependency Descriptor | `rtci-rtp/src/codec/dependency_descriptor/` | `DependencyDescriptor` (frame number, template, DTIs, fdiffs, chains, attached structure, active decode targets), `DependencyDescriptorReader` (keeps the structure across packets), `DependencyDescriptorWriter`, `DecodeTargetSelector` with chain integrity |
| SVC / simulcast signalling | `rtci-rtp/src/codec/svc/`, `RTCRtpSender::set_configured_scalability_mode` | the webrtc-svc mode table, `ScalabilityPattern` (per-picture layer frames with their dependencies, VP8 / VP9 info, the DD structure and the VP9 scalability structure for a mode); RID simulcast in SDP (RFC 8853), `send_restrictions` (rid restrictions, `max-fr` / `max-fs` / `max-mbps` / `max-br`, `b=TIAS`), `send_resolution` (`a=imageattr`) |
| Containers | `rtci-media/src/io/{ivf_reader,ivf_writer,h26x_reader,h26x_writer,sample_builder}` | IVF and Annex B readers and writers; `SampleBuilder` (the upstream frame assembler the capacity test uses) |
| Retransmission | `rtci-interceptor/src/nack/` (generator and responder), `src/peer_connection/handler/endpoint.rs` | NACK generation (RFC 4585) with reordering allowance, round-trip spacing, optional age and count limits; RTX (RFC 4588) answered by the responder, and an RTX packet reaches the application as the original packet it carries (`interceptor_rtx_test.rs::the_chain_sees_the_original_packet_an_rtx_packet_carries`) |
| FEC | `rtci-interceptor/src/{flexfec,ulpfec}` | FlexFEC (draft-03 and RFC 8627) and ULPFEC (RFC 5109) encoders and decoders; not in the default interceptors (`tests/default_codecs_omit_ulpfec.rs`) |
| Key-frame requests | `rtci-interceptor/src/keyframe.rs`, `src/peer_connection/event/mod.rs` (`OnKeyFrameRequest`), `RTCRtpReceiver::send_key_frame_request` (FIR), `RTCRtpReceiver::write_rtcp` | inbound PLI / FIR reach the application, and a sender gets `OnKeyFrameRequest { sender, rid }`; a receiver can send FIR (webrtc-encoded-transform) and any RTCP (PLI) |
| Congestion control | `rtci-interceptor/src/{gcc,twcc,rfc8888,cc,pacing}` | GCC on transport-cc or RFC 8888, probing, the pacer, TMMBR, REMB; `RTCRtpSender::target_bitrates()` is the share of the target per encoding (W3C webrtc-priority split, capped at `maxBitrate`) |
| Header extensions | `rtci-rtp/src/extension/` | `playout_delay_extension`, `abs_capture_time_extension`, `video_orientation_extension`, `transport_cc_extension`, `abs_send_time_extension`, `corruption_detection_extension`, `sdes` (MID, RID, repaired RID) |
| Frame metadata | `src/rtp_transceiver/rtp_receiver/frame_metadata.rs` | `RTCRtpReceiver::encoded_frame_metadata(packets)`: receive time, capture time (abs-capture-time, or from the sender reports), the DD frame id and dependencies, frame type, size, layer indices |
| Receiver track | `RTCRtpReceiver::report_received_frame(now, w, h)`, `jitter_buffer_target()` | track settings (size, aspect, frame rate) and the W3C `jitterBufferTarget` |
| SFrame | `rtci-sframe`, `encoded_transform_sframe_rtc2rtc.rs` | per-frame end-to-end encryption |
| Statistics | `src/statistics/feed.rs`, `accumulator/media/app_provided.rs` | `update_decoder_stats(ssrc, DecoderStatsUpdate)` (framesReceived, framesDecoded, keyFramesDecoded, framesRendered, framesDropped, frameWidth / Height, framesPerSecond, qpSum, totalDecodeTime, totalInterFrameDelay, totalSquaredInterFrameDelay, totalProcessingDelay, pauseCount, totalPausesDuration, freezeCount, totalFreezesDuration, packetsDiscarded, totalAssemblyTime, framesAssembledFromMultiplePackets, decoderImplementation, corruption measurements); `update_encoder_stats`; `update_video_source_stats`. The engine itself counts packets, bytes, NACK, PLI and FIR counts, RTX and FEC packets |

What none of this does: assemble frames that survive loss and reordering correctly per codec,
track decodability, time playout, decide when a picture is lost, decode, render, capture,
scale, encode, allocate bitrate across layers, or adapt quality.

### 1.2 What a complete receiver needs beyond the engine

1. **Packet buffer and frame assembly** per codec: sequence-ordered storage with wrap-safe
   unwrapping, duplicate removal, growth to a cap, frame boundaries from the marker bit and
   the codec's partition head (VP8 S=1 and PID=0, VP9 B / E, AV1 Z / Y and the DD
   start / end of frame, H.264 / H.265 first NAL of an access unit), key-frame detection per
   codec, padding-only packets (bandwidth probes) closing sequence gaps.
2. **Frame reference finder**: frame ids and references from the codec descriptors: VP8
   (PictureID, TL0PICIDX, TID, Y), VP9 (flexible P_DIFF, non-flexible GOF, inter-layer), the
   Dependency Descriptor (AV1 and any codec that carries it), and sequence-number continuity
   for streams with none of these (H.264, H.265, VP8 without PictureID).
3. **Frame buffer**: continuity and decodability, the next decodable temporal unit, drop of
   stale or undecodable frames, a bound on what is held.
4. **Playout timing**: inter-frame delay variation and a jitter estimate, the mapping from
   RTP time to local time, render time, `playout-delay`, `jitterBufferTarget`, a minimum
   delay from A/V synchronisation, decode-time estimate, render delay.
5. **Key-frame request policy**: PLI when the chain is broken (first frame not a key frame,
   packet buffer overflow, NACK list overflow, no decodable frame within the wait, decoder
   error), repeated at a bounded rate until a key frame arrives.
6. **The boundary with the NACK generator**: the generator asks for packets that the
   pipeline no longer needs unless it is told (section 2.6).
7. **Decoder abstraction**, a decode queue, frame dropping under decode overload.
8. **Render statistics**: freezes, pauses, inter-frame delay, frames rendered.
9. **A/V synchronisation** with `rtc-audio`'s jitter buffer.

### 1.3 What a complete sender needs beyond the engine

1. **Capture abstraction**: camera, screen, synthetic sources; a timestamped frame type
   (I420 / NV12 / RGB), rotation, colour space.
2. **Frame cadence**: zero-hertz screen content (repeat the last frame at a low rate so the
   receiver converges), frame rate limits from `maxFramerate` and `max-fr`.
3. **Scaling, cropping, pixel-format conversion** to the encoder's input, per simulcast
   layer, with the aspect ratio of the source.
4. **Encoder abstraction**: rate control (`set_rates` per layer), key-frame requests per
   layer, temporal and spatial layers, simulcast, screen-content mode, QP reporting, encoder
   information (QP thresholds for the quality scaler, resolution alignment).
5. **Bitrate allocation** from the congestion target: across simulcast streams and across
   temporal / spatial layers; encoder bitrate adjustment for over- and under-shoot.
6. **Quality scaler and degradation preference**: resolution vs frame rate under bandwidth
   and CPU limits; `qualityLimitationReason` and its durations.
7. **FEC / RTX budget**: the share of the target spent on protection.
8. **RTP timestamping and packetization hand-off**: the 90 kHz clock from the capture time,
   the Dependency Descriptor and codec descriptors, `abs-capture-time`, video orientation.
9. **CPU overuse adaptation**: encode time against the frame interval.
10. **Encoder statistics**: `framesEncoded`, `keyFramesEncoded`, `qpSum`, `totalEncodeTime`,
    `qualityLimitation*`, `encoderImplementation`, `scalabilityMode`, PSNR.

---

## 2. Receive side: element by element

Each element: what libwebrtc does, what the specifications require, what this project does.

### 2.1 Packet buffer and frame assembly

**libwebrtc.** `modules/video_coding/packet_buffer.cc @ a222406d` keeps packets in a ring
indexed by sequence number. It starts at 512 entries and grows to 2048
(`video/rtp_video_stream_receiver2.cc:110-111`, `kPacketBufferStartSize = 512`,
`kPacketBufferMaxSize = 2048`). A duplicate is dropped (`packet_buffer.cc:92-96`); when the
slot is taken by another packet and the buffer cannot grow, it clears itself and returns
`buffer_cleared` (`:105-113`), on which the receiver requests a key frame
(`rtp_video_stream_receiver2.cc:1054-1058`). A backward jump of half the buffer clears it
(`packet_buffer.cc:82-89`). `FindFrames` (`:237`) walks forward from a packet that may
complete a frame back to a `is_first_packet_in_frame` packet with no gap. For H.264 an
access unit is a key frame when it has an IDR (or SPS + PPS + IDR when
`sps_pps_idr_is_h264_keyframe_` is set, `:311-313`, false by default `:54`). Padding older
than 1000 sequence numbers is forgotten (`:415`).

**Specifications.** RFC 3550 A.1 (sequence-number extension), the payload formats: RFC 7741
4.2 (VP8 S and PID: "the first packet of a frame"), RFC 9628 (VP9 B and E bits), the AV1 RTP
specification 4.4 (Z, Y, N) and appendix A (`start_of_frame`, `end_of_frame`), RFC 6184 5.1
(the marker bit "set for the very last packet of the access unit") and RFC 7798. They define
the boundaries; buffering policy is left to the receiver.

**This project.** `rtci_video::assembly::PacketBuffer`, one per SSRC (RTX already folded back
by the engine): unwrapped sequence numbers (`i64`), a `BTreeMap` window instead of a ring
(same complexity for the sizes involved, no aliasing), capacity 2048 packets by default
(libwebrtc's maximum; configurable), duplicate drop counted, overflow and large backward
jumps clear the buffer and raise `KeyFrameNeeded::BufferCleared`. Boundaries and key frames
come from a per-codec `PayloadReader` built on the engine's depacketizers, so the bitstream
handed to the decoder is the depacketizer's output (VP8 / VP9 / AV1 payload without the
descriptor, H.264 / H.265 as Annex B). Each frame records first and last arrival (W3C
`totalAssemblyTime`), packet count, whether any packet was a retransmission (the engine marks
RTX-repaired packets; section 2.6), and padding fills sequence gaps.

### 2.2 Frame reference finder

**libwebrtc.** `modules/video_coding/rtp_frame_reference_finder.cc:62-115 @ a222406d`
dispatches on what the packets carry: a generic descriptor (the Dependency Descriptor) wins
(`:66-69`, `RtpGenericFrameRefFinder`, references = frame id minus each fdiff); VP8 with TID
and TL0PICIDX uses `RtpVp8RefFinder`, VP8 with a PictureID only `RtpFrameIdOnlyRefFinder`,
without one `RtpSeqNumOnlyRefFinder` (`:72-86`); VP9 likewise with `RtpVp9RefFinder`
(`:88-101`); every other codec (H.264, H.265) uses sequence numbers only (`:111-114`). The VP8
and VP9 finders stash frames whose references are not known yet (100 frames,
`rtp_vp8_ref_finder.h:42`, `rtp_vp9_ref_finder.h:43`), keep 50 GOF structures for VP9
(`rtp_vp9_ref_finder.h:40`) and use 15-bit unwrapped picture ids (`kFrameIdLength = 1 << 15`).

**Specifications.** RFC 7741 4.2 (PictureID; TL0PICIDX "a running index for the temporal base
layer frames"; TID; Y "layer sync": the frame depends only on the base layer), RFC 9628 4.2
(flexible mode P_DIFF; non-flexible mode with the scalability structure's GOF), AV1 RTP
specification appendix A (frame_number, fdiffs: "the frame dependencies"). The payload
formats make the references explicit; nothing is left to policy except what to do with a
frame whose references are unknown.

**This project.** `rtci_video::reference::ReferenceFinder`, an enum over the same five
finders with libwebrtc's dispatch, written from the RFCs; frame ids unwrapped to `i64`
(picture ids per their width, which RFC 7741 4.2 lets change mid-session: the engine's
`picture_id_15_bits`), the DD frame number to `i64`. Stash limits as libwebrtc's. A finder
that sees a key frame starts afresh. For sequence-number-only streams a delta frame refers to
the last frame of an unbroken sequence; a gap that padding does not explain leaves it waiting
(and ends in a key-frame request, section 2.5).

### 2.3 Frame buffer

**libwebrtc.** `api/video/frame_buffer.cc @ a222406d`. `InsertFrame` (`:76-126`) refuses
frames with invalid references and frames at or before the last decoded id (a newer key
frame clears instead, `:84-96`), clears on a key frame into a full buffer (`:98-107`); the
buffer holds 800 frames and remembers 8192 decoded ids
(`video/video_stream_buffer_controller.cc:46-48`). `FindNextAndLastDecodableTemporalUnit`
(`frame_buffer.cc:225-...`) finds the first temporal unit (frames of one RTP timestamp)
whose references were all decoded or lie inside the unit. Frames passed over are dropped
and counted (`DropNextDecodableTemporalUnit`, `:145`).

**Specifications.** W3C webrtc-stats: `framesDropped` "dropped prior to decode or dropped
because the frame missed its display deadline"; `framesReceived` "complete frames received";
`packetsDiscarded` "discarded by the jitter buffer due to late or early-arrival".

**This project.** `rtci_video::buffer::FrameBuffer` with the same rules and limits; a temporal
unit is what is handed out (all spatial layers of one picture); every frame that leaves the
buffer undecoded is counted in `framesDropped`, its packets in `packetsDiscarded`.

### 2.4 Playout timing

**libwebrtc.**

- *Jitter estimate*: `video/timing/jitter_estimator.cc @ a222406d`, a Kalman filter on frame
  delay variation against frame size (`frame_delay_variation_kalman_filter.cc`), a noise
  variance with outlier rejection (15 standard deviations for delay, 3 for size,
  `:52-55`), the estimate `size slope * (max size - avg size) + max(2.33 * sigma - 30 ms, 1 ms)`
  (`:390-430`), plus 10 ms of "operating system jitter" (`:73`), plus `min(0.9 * RTT, 200 ms)`
  after 3 NACKed frames in 60 s (`:76-81`), scaled to zero below 5 fps and linearly up to
  10 fps (`:452-466`). The inter-frame delay variation is
  `inter_frame_delay_variation_calculator.cc`; RTP time maps to local time through
  `timestamp_extrapolator.cc` (a recursive least squares fit). Retransmitted frames do not
  update it (`video/timing/default_video_jitter_timing.cc:54-58`).
- *Delays*: `modules/video_coding/timing/timing.cc @ a222406d`. Target delay =
  `max(min_playout_delay, minimum_delay + estimated_max_decode_time + render_delay)` (`:66-69`,
  render delay 10 ms, `timing.h`), the decode time the 95th percentile of recent decode times
  (`decode_time_percentile_filter.cc`). The current delay rises towards the target as frames
  are late (`UpdateCurrentDelay`, `:163-178`). Render time = local time of the RTP timestamp +
  `clamp(current_delay, min_playout_delay, max_playout_delay)` (`RenderTime`, `:197-...`);
  with `min_playout_delay` 0 and `max_playout_delay` at most 500 ms the frame is rendered at
  once (low-latency rendering, `:37-38`, `:76-79`).
- *Scheduling*: `video/frame_decode_timing.cc @ a222406d`: a frame whose render time is more
  than 5 ms past (`frame_decode_timing.h:34`, `kMaxAllowedFrameDelay`) is skipped when a
  later one is decodable; low-latency frames are paced 8 ms apart (`:35`) unless more than 8
  are queued (`video_stream_buffer_controller.cc:54`). A render time more than 10 s off resets
  the timing (`modules/video_coding/frame_helpers.cc:32-60`).
- *jitterBufferDelay*: first packet received to the decodable frame released
  (`video_stream_buffer_controller.cc:338-350`).

**Specifications.** W3C webrtc-stats `jitterBufferDelay`: "from the time the first packet is
received by the jitter buffer (ingest timestamp) to the time it exits the jitter buffer
(emit timestamp) ... the ingest timestamp is the earliest packet of the frame that entered
the jitter buffer and the emit timestamp is when the whole frame exits the jitter buffer";
`jitterBufferTargetDelay`, `jitterBufferMinimumDelay` ("not affected by external mechanisms
... such as jitterBufferTarget ... AV sync"), `jitterBufferEmittedCount`. W3C
webrtc-extensions `jitterBufferTarget` (the engine's `RTCRtpReceiver::jitter_buffer_target`).
The playout-delay extension is a webrtc.org experiment
(`http://www.webrtc.org/experiments/rtp-hdrext/playout-delay`, engine
`rtci-rtp/src/extension/playout_delay_extension`), no RFC.

**This project.** `rtci_video::timing` ports the model: jitter estimator (Kalman filter,
noise, outliers, NACK term, frame-rate scaling), timestamp extrapolator, decode-time
percentile, target / current / render time, scheduling with the 5 ms skip rule, the
low-latency path, the 10 s reset. `jitterBufferTarget` raises the minimum (as libwebrtc's
`base_minimum_playout_delay`); the A/V sync input raises it too; the stats report target and
minimum per W3C. One deliberate change: the 8-frame low-latency queue bound is kept, but its
dropping is counted in `framesDropped` (W3C), which libwebrtc also does.

### 2.5 Key-frame request policy

**libwebrtc.** Requests (PLI by default, FIR when configured,
`rtp_video_stream_receiver2.cc:946-950`) are made when: the first assembled frame is not a
key frame (`:1067-1072`); the packet buffer cleared itself (`:1054-1058`); the NACK list
would pass 1000 entries (`nack_requester.cc:35`, `:206-219`); a Dependency Descriptor
arrives before any structure (at most once a second, `:808-814`); a large sequence-number
discontinuity is waiting for a key frame (`:649-682`); no decodable frame came within the
wait, 200 ms when a key frame is needed and 3 s otherwise
(`video/video_receive_stream2.h:74-75`; with `rtx-time` the wait is the RTX time for a key
frame and three times it otherwise, `video_receive_stream2.cc:218-229`), and only if a packet
arrived in the last 5 s (`:1033-1037`) and no key frame is being received
(`IsReceivingKeyFrame`, `:1216-1226`); a decode error (`:1098-1102`). Once a key frame is
asked for, the request is repeated every wait (200 ms) until a key frame decodes
(`HandleKeyFrameGeneration`, `:1187-1213`).

**Specifications.** RFC 5104 4.3.1.2: "FIR SHALL NOT be sent as a reaction to picture losses
-- it is RECOMMENDED to use PLI [RFC4585] instead." RFC 4585 6.3.1.1: with PLI "a decoder
informs the encoder about the loss of an undefined amount of coded video data belonging to
one or more pictures". RFC 8834 5.1.2: "Receivers MAY send PLI messages." PLI needs `nack
pli` negotiated (RFC 4585 4.2; the engine registers it for video by default).

**This project.** PLI, written through `RTCRtpReceiver::write_rtcp` when `nack pli` was
negotiated; FIR only when the application asks (`send_key_frame_request`, webrtc-encoded-
transform). The triggers and the waits are libwebrtc's (they are policy, no RFC fixes a
number); the repetition interval is the key-frame wait. The pipeline exposes the reason of
each request (`KeyFrameReason`), so tests assert why a request was made.

### 2.6 The NACK boundary

**libwebrtc.** NACK lives in the receive stream: `NackRequester` (`nack_requester.cc`) is
told when a frame was decoded (`ClearUpTo`, `:189-198`, via `RtpVideoStreamReceiver2::
FrameDecoded` and `packet_buffer_.ClearTo` / `reference_finder_->ClearTo`,
`rtp_video_stream_receiver2.cc:1730-1734`), so packets older than the last decoded frame are
never asked for again; packets recovered by FEC or RTX are not asked for (`:163-172`); 100
retries at most (`:39`).

**Specifications.** RFC 4588 6.3: "The receiver should generally assess whether the
retransmitted packet would still be useful at the time it is received."

**Engine today.** `rtci-interceptor/src/nack/generator.rs` asks for a missing packet for as long
as its receive log holds it, unless an age (`with_max_packet_age`, or the sender's
`rtx-time`) or a count limit is set; its documentation states the gap: "How long a packet
stays useful is the receiving application's playout (RFC 4588 6.3), which this interceptor
does not know".

**This project.** The boundary is: the generator decides *how* to ask (timing, RTT spacing,
reordering allowance, RTX); the pipeline decides *until when* a packet is useful. The
pipeline computes, after each decoded or dropped frame, the oldest sequence number still
useful (the first packet of the oldest frame still in the frame buffer or packet buffer),
and hands it to the generator. That needs one engine addition (phase 1b):
`RTCRtpReceiver::set_nack_horizon(ssrc, seq)` carried to the generator like the existing
`NackControl` (an `Attribute::Custom` on an empty RTCP packet), so the generator drops older
entries. Until it exists, phase 1 runs with the generator's own limits and measures what the
missing horizon costs (retransmissions of dropped frames).

### 2.7 Decoder abstraction, decode queue, overload

**libwebrtc.** `api/video_codecs/video_decoder.h @ a222406d`: `Configure(Settings)` (`:98`),
`Decode(EncodedImage, render_time_ms)` (`:102-109`), a `DecodedImageCallback` (`:30-35`),
`DecoderInfo` (`:46`). The receive stream decodes on its own task queue; decode results set
`keyframe_required` (`video_receive_stream2.cc:1064-1110`). Under overload the buffer
controller skips late frames (2.4) and the low-latency path releases at most what the queue
bound allows.

**This project.** `rtci_video::decoder::VideoDecoder` trait: `decode(&mut self, frame:
&EncodedFrame) -> Result<Option<DecodedPicture>, DecodeError>` with `DecodeError::
NeedKeyFrame` / `Corrupt`, `implementation_name()`, `is_hardware()`, the QP of the last frame
when the decoder knows it. Synchronous and `Send`, so the application runs it where it likes:
the pipeline itself is sans-I/O and hands out `DecodeRequest`s (`poll_frame(now)`) and takes
results back (`on_decoded(now, outcome)`), so a decode thread is the application's (section
4.4). Overload: the frame buffer skips frames whose render time passed (2.4); the number of
frames handed out and not yet returned is bounded (default 2, libwebrtc's
`kMaxPendingPostDecodeFrames`, `video_receive_stream2.cc:780`), beyond which the pipeline
holds frames back and, if they go stale, drops them as libwebrtc does.

### 2.8 Render statistics: freezes and pauses

**libwebrtc.** `video/video_quality_observer2.cc @ a222406d`: a freeze when the interval
between two rendered frames is at least `max(3 * avg, avg + 150 ms)` over the last 30
intervals (`:29-31`, `:155-176`), only once 5 intervals are known (`kMinFrameSamplesToDetect
Freeze = 5`), measured on decode timestamps; a pause after 5 s without packets
(`video_receive_stream2.cc:1033`, `OnStreamInactive`).

**Specifications.** W3C webrtc-stats `freezeCount`: "It is a freeze if frame duration, which
is time interval between two consecutively rendered frames, is equal or exceeds Max(3 *
avg_frame_duration_ms, avg_frame_duration_ms + 150), where avg_frame_duration_ms is linear
average of durations of last 30 rendered frames." `pauseCount`: "paused if time passed since
last rendered frame exceeds 5 seconds"; `totalFreezesDuration`, `totalPausesDuration`,
`totalInterFrameDelay`, `totalSquaredInterFrameDelay`, `framesRendered` are recorded "just
after a frame has been rendered".

**This project.** `rtci_video::render::RenderStats`, fed by the application's renderer
(`on_rendered(now, width, height)`), or by the pipeline at the frame's render time when the
application has no renderer of its own. Default: the W3C definition, on render times, from
the first interval. `BehaviourProfile::Chrome`: libwebrtc's five-interval warm-up. A pause is
the W3C definition (5 s since the last rendered frame); its interval is not a freeze.

### 2.9 Statistics: which exist, which the pipeline supplies

| W3C member (inbound-rtp, video) | Engine | Pipeline supplies |
|---|---|---|
| packetsReceived, bytesReceived, headerBytesReceived, packetsLost, jitter, nackCount, firCount, pliCount, retransmittedPackets/BytesReceived, rtxSsrc, fecPacketsReceived, fecBytesReceived, fecSsrc, lastPacketReceivedTimestamp | counted | - |
| framesReceived, framesAssembledFromMultiplePackets, totalAssemblyTime | field exists, `DecoderStatsUpdate` | assembly (2.1) |
| framesDropped, packetsDiscarded | field exists | frame buffer (2.3) |
| framesDecoded, keyFramesDecoded, totalDecodeTime, qpSum, frameWidth, frameHeight, framesPerSecond, totalProcessingDelay, decoderImplementation, powerEfficientDecoder | field exists | decode results (2.7) |
| framesRendered, totalInterFrameDelay, totalSquaredInterFrameDelay, freezeCount, totalFreezesDuration, pauseCount, totalPausesDuration | field exists | render statistics (2.8) |
| jitterBufferDelay, jitterBufferTargetDelay, jitterBufferMinimumDelay, jitterBufferEmittedCount | inbound fields exist, fed only through `AudioReceiverStatsUpdate` | timing (2.4); phase 1b adds them to `DecoderStatsUpdate` (an engine addition: a video stream has no audio update) |
| estimatedPlayoutTimestamp | inbound field exists | A/V sync phase |
| totalCorruptionProbability, ... | field exists | not planned (needs the corruption-detection extension's decoder-side computation) |

---

## 3. Send side: element by element

Summarised here; each is specified in full when its phase starts.

| Element | libwebrtc @ a222406d | Specification | This project |
|---|---|---|---|
| Encoder interface | `api/video_codecs/video_encoder.h`: `Encode` (`:446`), `SetRates(RateControlParameters)` (`:452`, a per-layer allocation), `GetEncoderInfo` (`:495`, QP thresholds `:87`, resolution alignment, `is_qp_trusted` `:277`) | webrtc-svc (modes), RFC 7741 / 9628 / AV1 RTP (layer signalling) | `VideoEncoder` trait: `encode(frame, keyframe: LayerMask) -> Vec<EncodedLayerFrame>`, `set_rates(&LayerAllocation)`, `info()`; one call can yield every spatial layer |
| Frame cadence | `video/frame_cadence_adapter.cc`: zero-hertz mode for screen content repeats frames; `kMaxAllowedDelay` 34 ms (`:790`) | none | `CadenceAdapter`: pass-through for cameras, zero-hertz for screen content (profile-independent) |
| Simulcast layers | `video/config/simulcast.cc`: the resolution / bitrate table for VP8 (`:82`) and VP9 (`:132`), 3 temporal layers by default (`:58`), 2 layers for screen share (`:59-60`) | RFC 8853, W3C `scaleResolutionDownBy` / `maxBitrate` / `maxFramerate` | the application's `encodings` first; libwebrtc's table for defaults it leaves out (Chrome profile and default alike: no RFC number) |
| Rate allocation | `modules/video_coding/utility/simulcast_rate_allocator.cc` (temporal split `kLayerRateAllocation` `:36`, hysteresis 1.2 / 1.35 `:50-51`); `svc/svc_rate_allocator.cc` (0.55 scaling `:37-38`) | W3C webrtc-priority (between senders; the engine does it) | port both; input `RTCRtpSender::target_bitrates()` per SSRC |
| Encoder bitrate adjuster | `video/encoder_bitrate_adjuster.cc`, `encoder_overshoot_detector.cc` | none | port |
| Quality scaler, degradation | `modules/video_coding/utility/quality_scaler.cc` (2 s window `:34`, 60 % frame drop `:36`); `api/rtp_parameters.h:182-196` (`DegradationPreference`: MAINTAIN_FRAMERATE, MAINTAIN_RESOLUTION, BALANCED); `call/adaptation/video_stream_adapter.cc` (min 2 fps, `:40`) | W3C mediacapture / webrtc-pc `degradationPreference` (in webrtc-extensions) | port; `qualityLimitationReason` / durations / resolution changes through `update_encoder_stats` |
| CPU overuse | `video/adaptation/overuse_frame_detector.cc` (ramp-up delays 10 / 40 / 240 s `:51-54`, 7..30 fps `:74-75`) | none | port; the application reports encode time |
| FEC / RTX budget | `modules/video_coding/fec_controller_default.*`, `media_opt_util.cc` (protection tables by loss and RTT) | RFC 8854 (FEC for WebRTC), RFC 4588 | port the protection-overhead split; the engine already holds retransmissions under the target |
| Packetization hand-off | `call/rtp_video_sender.cc` | the payload formats, AV1 RTP appendix A | engine payloaders plus `DependencyDescriptorWriter`; `write_rtp_with_capture_time` |

---

## 4. Codecs under the constraints

All figures read on 2026-11-23 from `https://crates.io/api/v1/crates/<name>` (licence of the
newest version, `rust_version`, recent downloads) and the repository through `gh api`.
"Evidence" says where a speed or conformance claim comes from: the project's own README
unless stated; none of these was run here yet (no test binary runs on this machine). Phase 2
measures each one used on hosted runners.

### 4.1 Software codecs

| Codec | Crate (version) | Licence | Pure Rust | MSRV | Platforms | Real-time evidence | Feature |
|---|---|---|---|---|---|---|---|
| VP8 decode | `vp8-decoder` 0.1.3 (repo `AlakazamLabs/vp8`, crate first published 2026-11-06) | (MIT OR Apache-2.0) AND BSD-3-Clause (a port of the RFC 6386 section 20 reference decoder) | yes (small NEON / SSE2 loop-filter kernels via `std::arch`; `--cfg vp8_portable` removes them) | 1.80 | any | README: 560 fps at 1280x720 1.2 Mbit/s on an Apple M4, 270 fps on a Xeon E-2288G, one core; "matches the WebM project's 59 VP8 test vectors bit for bit" | `vp8` (opt-in until the owner decides; pinned `=0.1.3`; 4.6, 4.7) |
| VP8 encode | `vp8-encoder` 0.1.3 (same repo) | same | yes, `#![forbid(unsafe_code)]` | 1.80 | any | README: 720p camera clip at 2 Mbit/s, 47 fps on one Ryzen 7 3800X core, 124 fps on an Apple M4; rate control within 12 % of target; key frames on request; L1T2 / L1T3; streams decoded by libvpx and Chrome's WebCodecs "byte-identical" | `vp8` (opt-in until the owner decides; pinned `=0.1.3`; 4.6, 4.7) |
| VP8 / VP9 encode + decode | libvpx (BSD-3-Clause, C and assembly) through a binding written here, as `parolnet-media` has one (MIT OR Apache-2.0, same owner) | BSD-3-Clause | no: system library | - | Linux, macOS, Windows (vcpkg) | the reference implementation | `libvpx` (opt-in) |
| AV1 encode | `rav1e` 0.8.1 | BSD-2-Clause | yes with `default-features = false` (the default `asm` feature needs NASM on x86_64) | 1.83 | any | README: "11 speed settings (0-10, exhaustive to near real-time)"; no figure without assembly; to be measured at speed 10, low-latency mode | `av1` (**opt-in**: not real time without assembly; 4.6) |
| AV1 decode | `rav1d` 1.1.0 (Rust port of dav1d) | BSD-2-Clause | yes without its default `asm` feature (which needs NASM on x86) | 1.79 (crates.io) | stable for x86, x86_64, aarch64; "requires a nightly compiler for `arm` and `riscv64`" (README) | none for the Rust fallback; the API is dav1d's C API in Rust ("A Rust API is planned") | `av1` (**opt-in**: a hostile frame aborts the process; 4.6, 4.8) |
| AV1 decode | `dav1d` 0.12.0 / `dav1d-sys` 0.9.0 (bindings) to libdav1d | bindings MIT; libdav1d BSD-2-Clause | no: C and assembly, system or built library | 1.85 | any | dav1d is the decoder browsers ship | `dav1d` (opt-in) |
| H.264 encode + decode | `openh264` 0.9.10 / `openh264-sys2` | BSD-2-Clause (wrapper and OpenH264) | no: C++ (feature `source` builds the bundled source with `cc`; `libloading` loads a Cisco binary) | 1.85 | any | the codec Firefox ships (as Cisco's binary) | `openh264` (opt-in) |
| H.264 decode | `rust_h264` 0.6.1 (repo `roticv/rust_h264`, created 2026-02) | MIT OR Apache-2.0 (repository LICENSE: Apache-2.0) | yes (SIMD) | 1.89 | any | README: "199 of 204" JVT conformance vectors, byte-identical to FFmpeg on its streams; speed in its BENCHMARK.md | candidate for a later `h264-rust` (opt-in) |
| H.264 encode + decode | `rusty_h264-encoder` / `-decoder` 0.17.4 (repo `Remade-With-Rust/rusty_h264`) | BSD-2-Clause | yes | 1.85 | any | README: decoder byte-identical on 35 openh264 conformance streams | **not used**: the repository describes itself as "x264 remade with rust"; x264 is GPL-2.0-or-later, and a remake of it may be a derived work. Not usable until its provenance is shown to be clean |
| H.265 decode | `rust_h265` 0.4.1 (repo `roticv/rust_h265`) | MIT OR Apache-2.0 | yes | 1.88 | any | README: passes the 147 JCT-VC HEVC_v1 vectors | candidate for `h265-rust` (opt-in), decode only |
| H.265 encode | none in pure Rust found | - | - | - | - | - | hardware backends only |

Searched and rejected: `vpx-sys` 0.1.1 (MIT, last release 2021), `env-libvpx-sys` and
`libvpx-native-sys` (MPL-2.0: not in `deny.toml`), `oxideav-vp8` / `oxideav-h264` /
`oxideav-av1` (descriptions: "scaffold pending clean-room re-implementation", MSRV 1.95),
`gamut-av1` (intra frames only, MSRV 1.92), `less-avc` (lossless intra-only H.264).

**VP8 pure Rust: say it plainly.** Until November 2026 there was no real pure-Rust VP8 encoder
or decoder on crates.io. `vp8-decoder` and `vp8-encoder` were first published on 2026-11-06
(0.1.0; 0.1.3 on 2026-11-23); their repository `AlakazamLabs/vp8` was created on 2026-11-23
with one import commit. (The first version of this section said the crates were published the
day the repository was created; the crates are 17 days older.) Phase 2 checked their claims
(section 4.6); section 4.7 sets out who publishes them and what is in them, and recommends.

**H.264 and H.265 licensing, plainly.** The code licences are permissive (OpenH264 BSD-2,
`rust_h264` / `rust_h265` MIT or Apache-2.0). The patents are a separate matter, and no crate
licence covers them. Cisco's arrangement covers only Cisco's own binary, under conditions
(`specs/openh264-BINARY_LICENSE.txt`, from `http://www.openh264.org/BINARY_LICENSE.txt`, v1.0):
"this binary is licensed under Cisco's AVC/H.264 Patent Portfolio License from MPEG LA, at no
cost to you, provided that the requirements and conditions shown below ... are met", among
them "1. The Cisco-provided binary is separately downloaded to an end user's device, and not
integrated into or combined with third party software prior to being downloaded", "2. The end
user must have the ability to control (e.g., to enable, disable, or re-enable) the use of the
Cisco-provided binary", and the text "OpenH264 Video Codec provided by Cisco Systems, Inc."
shown where the user controls it. Built from source (the `openh264` crate's default `source`
feature) or written in Rust, an H.264 codec carries no patent licence; Cisco's FAQ, quoted in
`ralfbiedert/openh264-rs` issue 43: "a team can choose to use the source code, in which case
the team is responsible for paying all applicable license fees". So: H.264 is opt-in; the
`openh264` feature defaults to loading Cisco's binary at run time (`libloading`), which only
the application can obtain from Cisco and present to the user under those conditions; building
from source is a second, explicitly named feature. H.265 is in the same position, with several
patent pools and no free binary arrangement.

### 4.6 Phase 2: the pure-Rust codecs checked (evidence and decision)

All on GitHub-hosted runners (ubuntu-latest, 4 vCPUs AMD EPYC), release builds, one thread
per codec, `conf/vp-5-codecs`; `scripts/video-codec-check.sh` (runs 45314695095, 45315317423,
45316349668) fetches the test data, nothing is committed. ffmpeg (`-c:v libvpx`,
`-c:v libdav1d`) is the outside reference there, never a dependency.

**vp8-decoder 0.1.3**

| Check | Result |
|---|---|
| Source | 8.7k lines for both crates, no runtime dependency; `unsafe` only in the decoder's SSE2 (x86_64) and NEON (aarch64) loop filters, each kernel asserting its slice lengths first (`#![deny(unsafe_code)]` elsewhere; the encoder `#![forbid(unsafe_code)]`); licence `(MIT OR Apache-2.0) AND BSD-3-Clause` with the RFC 6386 section 20 notice in NOTICE; PROVENANCE.md: written from RFC 6386 and its section 20 reference decoder, libvpx not opened |
| Publisher | crates.io user / GitHub account `z3thon` (account from 2016, 113 public repositories); organisation `AlakazamLabs` created 2026-11-20 |
| WebM VP8 test vectors (59 streams, the WebM project's published `.md5`) | **59 of 59 bit-exact, 1896 pictures** |
| Against libvpx, byte for byte | 58 of 60 streams identical (the 59 vectors and `examples/test-data/output_vp8.ivf`); the two others (`vp80-03-segmentation-1425`, `-1436`) change resolution mid-stream, which ffmpeg's raw output rescales; both match the published MD5s |
| Speed, decode | 720p camera (WebM `niklas_1280_720_30`, 2 Mbit/s): 257 to 422 fps; 360p: 1018 to 1654 fps (spread between runs: shared runners) |
| Fuzzing | libFuzzer with AddressSanitizer, 15 min, seeded with the fixture: 82,382 runs, no crash, no leak (run 45317175240); in-tree, `hostile_vp8_frames_never_panic_the_decoder`: 1500 seeded mutations, 113 refused, 0 panics, the decoder recovers at the next key frame |
| In the pipeline | the libvpx fixture through 5 % loss and reordering decodes bit-exactly to the in-order decode (`vp8_ivf_through_loss_decodes_bit_exactly_with_the_vp8_decoder`); MD5 of the whole fixture equal to libvpx's (`the_vp8_decoder_decodes_the_libvpx_fixture_as_libvpx_does`) |

**vp8-encoder 0.1.3**

| Check | Result |
|---|---|
| Speed, encode | 720p camera at 2 Mbit/s: 53 to 83 fps (slowest picture 26 to 42 ms); 360p at 600 kbit/s: 194 to 300 fps |
| Rate and quality | 720p: 2034 kbit/s for 2000, PSNR 37.6 dB; 360p camera: 610 for 600, 34.9 dB; synthetic 640x360: 600 for 600, 39.5 dB (acceptance >= 32 dB: `vp8_at_640x360_and_600_kbits_reaches_32_db`) |
| Streams decodable by libvpx | every stream it made decoded identically by libvpx and by vp8-decoder (4 of 4) |
| In a call | two peers, 2 % loss, 320x240, 500 kbit/s, 20 s: 596 pictures decoded, PSNR 40.1 dB mean, 39.5 dB worst, no decoder error (`a_call_with_the_real_vp8_codecs_decodes_every_released_picture`, run 45317355088) |

**Technically, `vp8` qualifies as a default.** Every claim checked held: conformance on the
published vectors, identity with libvpx both ways, real-time speed on one core with margin
(the acceptance was 720p decode at 30 fps: measured 257 or more), and robustness under
fuzzing. Phase 2 made it a default feature on that evidence. **It is opt-in again since
`conf/vp-6-codec-safety`**: a default dependency of a security-sensitive library is also a
supply-chain decision, which is the owner's (section 4.7 has the facts and the recommendation;
section 7, decision 2). Until the owner decides, the default build decodes and encodes no video
at all: it receives, assembles, times and requests key frames for every payload format, and
hands frames to whatever decoder the application registers.

### 4.7 Supply chain of the VP8 crates

Checked 2026-11-24 from crates.io (`/api/v1/crates/<name>`, `/owners`, `/users`, the published
`.crate` files from `static.crates.io`) and GitHub (`gh api`, a clone of the repository).

**Who publishes them.**

| | Fact |
|---|---|
| crates.io owner | one user, `z3thon` (name on the account: Rosson Long), the only owner of both crates and the publisher of all eight versions; crates.io account created **2026-11-03**, three days before the first version; versions published with an API token (no crates.io trusted publishing) |
| GitHub account `z3thon` | created 2016-04-01, 113 public repositories, 2 followers |
| Repository | `AlakazamLabs/vp8`, created **2026-11-23**, one commit (`28844d61`, "vp8: import vp8-decoder and vp8-encoder 0.1.3", unsigned), tags `vp8-decoder-v0.1.3` and `vp8-encoder-v0.1.3` on it; no history before 0.1.3 is public; 0 stars, 0 forks; organisation `AlakazamLabs` created 2026-11-20, one repository, not verified |
| Other work of the publisher | 13 other crates on crates.io, all first published 2026-11-05 to 2026-11-17, from the GitHub organisation `Alakazam-211` ("Alakazam Labs", created 2025-10-14, 26 public repositories): `sew-*` (a voice/call client: LiveKit-protocol signalling, MLS, Noise), `kessel-*` (capture and codecs; `kessel-video` depends on both VP8 crates), and `sew-str0m` / `sew-str0m-is`, published from `Alakazam-211/str0m`, a fork of `algesten/str0m` (the Rust WebRTC library). That fork is the only link to a known project; no sign that str0m's maintainers know of or review these crates |
| Use | reverse dependencies: `vp8-encoder` (on the decoder), `kessel-video`, `nestor-satellite`. Downloads: 40,231 (decoder) and 36,079 (encoder) by 2026-11-24, almost all from 2026-11-18 on (2,971 to 10,705 a day), against 100 to 700 in total for each of the publisher's other crates. Where these downloads come from cannot be seen; they are not evidence of review |

**Is the published code the repository's code?** Yes, exactly. The two `.crate` files'
SHA-256 sums equal the index's (`7011d3a4...` for the decoder, `f3a93dc2...` for the encoder;
cargo checks every download against them). Each crate's `.cargo_vcs_info.json` names commit
`28844d61`; every file in each crate is byte-identical to the same file of the repository at
that commit, except cargo's own additions (`.cargo_vcs_info.json`, `Cargo.lock`, the normalised
`Cargo.toml`, whose `Cargo.toml.orig` is identical to the repository's manifest). The
repository has more files than the crates: tests, benches, scripts (left out by the manifests'
`include` lists). No mismatch.

**What runs at build time.** Nothing: `build = false` in both manifests, no build script, no
proc-macro, no `links`. No dependency: `vp8-decoder` has none; `vp8-encoder` depends only on
`vp8-decoder = "=0.1.3"` (for its tables and reconstruction); `serde_json` is a dev-dependency
of both and never built for a user. Nothing in the source reads files, the environment, the
network or a process (`std::fs`, `std::env`, `std::net`, `std::process`, `include_bytes!`,
`extern "C"`, `asm!`: none; one `include_str!` of the README for documentation).

**`unsafe`.** 8,767 lines of Rust in both crates. The encoder is `#![forbid(unsafe_code)]`. The
decoder is `#![deny(unsafe_code)]` except two modules compiled only for their target:
`src/sse2.rs` (409 lines, x86_64 with SSE2) and `src/neon.rs` (314 lines, aarch64 with NEON),
46 `unsafe` occurrences in all: SIMD loop filters made of `core::arch` intrinsics inside private
`unsafe fn`s that `assert!` the length of every slice they load from or store to before the
first access; the safe callers cut those slices with bounds-checked indexing. `--cfg
vp8_portable` (a `RUSTFLAGS` setting) removes both modules, leaving no `unsafe` at all, at the
cost of speed. They were read for this review; 82,382 fuzz runs under AddressSanitizer
exercised them on x86_64 (4.6).

**Licence `(MIT OR Apache-2.0) AND BSD-3-Clause`: what is BSD-3 and why.** The BSD-3-Clause part
is **not libvpx**. It is the reference decoder published inside RFC 6386 itself (section 20,
"dixie", copyright 2010, 2011 Google Inc., licensed in section 20.26). Per each crate's
PROVENANCE.md, the decoder is a port of that reference decoder (its files `dixie.c`,
`modemv.c`, `predict.c`, `tokens.c`, `idct_add.c`, `dixie_loopfilter.c` decided the edge cases)
and its probability, quantizer and mode tables were extracted from section 20's headers by
script; the encoder uses those tables and routines. "libvpx source was not opened". Everything
else is the publisher's own, MIT OR Apache-2.0. Each crate ships the section 20.26 licence
verbatim in `NOTICE`.

What that requires downstream: the BSD-3 conditions ("Redistributions in binary form must
reproduce the above copyright notice, this list of conditions and the following disclaimer in
the documentation and/or other materials provided with the distribution"; no use of Google's
name to endorse). For source, the crates satisfy it themselves (NOTICE travels in the
`.crate`). For **binaries**, the obligation falls on whoever ships an application built with
`vp8`: it must carry Google's notice from the crates' `NOTICE` with its other licence notices.
`rtci-video` is not published and contains no code derived from section 20, so it carries no
notice of its own; its README says what an application must include.

The patent text is a different matter and is **not** a condition to ship. RFC 6386 section
20.27 ("Additional IP Rights Grant (Patents)", the same text as libvpx's `PATENTS`) grants
Google's VP8 patent licence for "the copyrightable works distributed by Google as part of the
WebM Project", and "does not include claims that would be infringed only as a consequence of
further modification of this implementation". A Rust port is not a work Google distributes, so
the grant does not plainly extend to these crates, and the crates do not claim it (PROVENANCE.md:
"Nothing here grants any patent licence beyond what Apache-2.0 grants for our own
contributions"; libvpx's PATENTS file is deliberately not included). Whether other patent
arrangements for VP8 cover an independent implementation is a legal question this review does
not answer; the owner should treat it as such. Nothing has to be added to `rtci-video` for the
patent text: there is no obligation to ship it, and shipping it would claim a grant that may not
apply.

**Prior art: is there an older pure-Rust VP8 decoder?** No, not one that decodes video. Every
pure-Rust VP8 decoder that handles inter frames on crates.io is from 2026: `zvidlib-vp8`
(2026-10-07, MIT, one owner; PROVENANCE.md of `vp8-decoder` says it passes the same vectors;
private decoder API, RGBA output, about 100 `unsafe` blocks, edition 2024), `filmcraft-vp8`
(2026-11-04, one version, MSRV 1.95, no repository), `oxideav-vp8` (2026-04, "scaffold pending
clean-room re-implementation", MSRV 1.95). The one VP8 decoder with years of history and real
use is in `image-webp` (image-rs, since 2024-02, 117 million downloads, MIT OR Apache-2.0); it
decodes WebP's lossy images, which are VP8 **key frames only**: no inter prediction, motion
vectors, golden / alt-ref buffers or probability persistence, so it cannot decode a WebRTC
stream. The other route with history is libvpx through the opt-in `libvpx` backend (C).

**The pin and how it is enforced.**

- `vp8-decoder = "=0.1.3"` and `vp8-encoder = "=0.1.3"` in `rtci-video/Cargo.toml`: cargo
  cannot select another version, not even a patch release.
- crates.io never changes the contents of a published version (a version can be yanked, not
  replaced), and cargo checks each download against the SHA-256 in the index.
- `Cargo.lock` is git-ignored at the root of this repository, so the checksum is recorded
  nowhere in the tree. `scripts/check-video-codec-pins.py` closes that: it fails when the
  manifest asks for anything but `=0.1.3`, or when a `Cargo.lock` (any build generates one; it
  lists optional dependencies whether or not their feature is on) holds either crate at another
  version, from another source, or with another checksum than the reviewed one. Wiring it into
  `cargo.yml` after the build step is proposed to the train (not done here: that workflow is
  the train's).
- `deny.toml` already has `[sources] unknown-registry = "deny"` and `unknown-git = "deny"`: no
  other registry or git source can stand in for them.

**Recommendation.** Keep the crates as dependencies pinned by exact version and checksum (the
first option), and make `vp8` a default again when the owner accepts the facts above, on two
conditions: the pin check runs in CI, and a VP8 decoder fuzz target is registered in the
train's fuzz job (it ran only on a throwaway branch: 82,382 runs in 15 minutes is a smoke test,
not a campaign). Reasons: (1) what made a weeks-old crate from a new publisher risky is the
next release, and the exact pin plus the checksum check already keeps every release out until
someone reviews it, which is the whole benefit of vendoring; (2) vendoring the 8,767 lines would
add no review the pinned bytes have not had and would make this repository the maintainer of a
VP8 fork, with upstream fixes arriving only by hand; (3) waiting until the crates "have a
history" has no end date and buys less than the evidence already gathered (59/59 conformance
vectors, identity with libvpx both ways, fuzzing) — history is a proxy for exactly that kind of
evidence. The residual risk, stated plainly: the code is a single author's, unreviewed by anyone
else in public, parsing what any peer sends; a logic bug is caught at worst as a decoder error
(the wrapper also catches a panic, `codec::vp8`), and memory safety rests on 723 lines of
asserted SIMD, which `--cfg vp8_portable` removes for an application that wants none.

### 4.8 AV1 on hostile input: the abort, the leak, containment

**The abort is rav1d's, known upstream, fixed but not released.** `rav1d` 1.1.0 panics at
`src/decode.rs:4997:33` (`called Option::unwrap() on a None value`). The line is in `on_error`
of `rav1d_submit_frame`: with one frame context (`n_fc = min(max_frame_delay, n_threads) = 1`,
which a real-time decoder has: each picture out of the call that took its data), when
`rav1d_decode_frame` fails, `rav1d_decode_frame_exit` has already taken `f.frame_hdr`
(`decode.rs:4873`), and `on_error` (called at `:5343`) unwraps it. The panic happens inside
`dav1d_send_data`, an `extern "C"` function, which cannot unwind: the process aborts
(`panic in a function that cannot unwind`), whatever the caller does. Upstream: issue
memorysafety/rav1d#1497 (closed) and #1492 report exactly this; pull request #1503 fixed it on
`main` on 2026-10-12 (`6c6f463`, a one-line change in `on_error`); 1.1.0 (2025-05-06) is still
the latest release, and #1521 (open) asks for a release and for the `dav1d_*` functions to be
`extern "C-unwind"`. No new report was filed; a comment for #1521 with the figures below is
prepared for the owner (not posted).

How easy it is to reach (hosted run 45322103402, a throwaway program decoding each candidate in
a child process; rav1e 96x64 stream, 12 temporal units):

| Input | Aborts rav1d 1.1.0 (`n_threads` 1, `max_frame_delay` 1) |
|---|---|
| every single-bit flip of the 2419-byte key frame, alone | **711 of 19,352** |
| phase 2's seeded mutations of the stream (flips, truncation, appended or overwritten bytes) | 193 of 750 |

The reproducer (`rtci-video/tests/data/rav1d-abort.ivf`, 2463 bytes): the key frame with bit 6
of byte 4 flipped (the first payload byte of the sequence header: `seq_profile` 0 becomes 2).
With rav1d 1.1.0 it aborts at `n_threads` 1 or 4 with `max_frame_delay` 1; at `n_threads` 2,
`max_frame_delay` 2 it does not (the delayed-output path, unusable for a decoder that must
return the picture of the frame it was given); rav1d `main` at `6c6f463` returns `EINVAL` (-22)
and carries on.

**Containment.** In process there is none with rav1d 1.1.0: its Rust functions
(`rav1d_open`, `rav1d_send_data`, `rav1d_get_picture`) are `pub(crate)`; only the `extern
"C"` functions are reachable, and `catch_unwind` never sees a panic inside them. rav1d's `main`
branch has a public Rust API (`rav1d::Decoder`, `src/rust_api.rs`, since 2026-04) through which a
panic would unwind normally and could be caught, but it is unreleased; taking it as a git
dependency would need a `deny.toml` exception for one git source and would track an unreleased
branch (not done; the owner's call when a release does not come). What is sound today is a
**separate process**: `codec::isolated` (feature `isolation`) runs any `VideoDecoder` in a child
process; when the child aborts, crashes or hangs past a timeout (2 s by default), that frame
returns `DecodeError::Corrupt`, the next frame starts a new child, which asks for a key frame
like any fresh decoder. It costs two copies through a pipe per frame. Tested in
`rtci-video/tests/isolated.rs` (the reproducer kills an in-process decoder; through the child it
costs one frame and the next key frame decodes to the same picture; a hung child is killed). It
contains the C backends' crashes too (libvpx, dav1d, OpenH264), which no in-process mechanism
can.

**The 96-byte leak** (found by phase 2's fuzz run) is rav1d's, and it is not specific to
hostile input. Replayed under LeakSanitizer with symbols (run 45326503227), the two 48-byte
blocks are allocated inside `dav1d_picture_unref` (`src/lib.rs:830`, the `mem::take` of the
picture, whose derived `Default` allocates a fresh `Arc` for the ITU-T T.35 metadata,
`include/dav1d/picture.rs:425`), called from this crate's `take_picture`. The function writes
that new `Arc` back into the caller's C struct, where no public function can free it; a
`dav1d_get_picture` that returns no picture (every "try again") does the same. Upstream:
memorysafety/rav1d#1522 (open since 2026-11-21, by reading; the same code is on `main`). This
decoder unrefs a picture and polls once more on every frame, so it leaks about 50 to 100 bytes
a frame, some 5 to 10 MB an hour at 30 fps; libFuzzer reported it only a few times because it
checks for leaks only on inputs that add coverage. Nothing in the wrapper can avoid it through
the C API; a decoder in a child process (`codec::isolated`) can be restarted to give it back.
A first attribution in this branch blamed the wrapper and was wrong: the same input leaks the
same 96 bytes with the wrapper changed (run 45324307021). The change made then stays because it
closes a real path by reading: when taking a waiting picture out failed, `decode_bytes`
returned through `?` before releasing the temporal unit's `Dav1dData`; a guard (`OwnedData`) now
releases it on every path.

### 4.9 The system-library backends: `libvpx`, `dav1d`, `openh264`

**All three load their library at run time** (`dlopen` through `libloading` 0.9, ISC; the
`openh264` crate 0.9.10, BSD-2-Clause, without its `source` feature). Building any of them
needs no library, no header and no C toolchain, so `cargo check --workspace --all-features`
(cargo.yml) stays pure Rust and passes on a runner with nothing installed (checked: `cargo
tree` of the three features has no `cc`, `nasm` or `pkg-config`). Running needs the library
installed; a missing or different library is an error from the constructor, never a crash:

| Feature | Library (checked against) | How a wrong library is refused |
|---|---|---|
| `libvpx` | libvpx 1.16.0 (`libvpx.so.12`; also tries `.so.11` to `.so.9`) | contexts are made through `vpx_codec_dec_init_ver` / `vpx_codec_enc_init_ver` with the headers' ABI versions (decoder 12, encoder 39): libvpx answers `VPX_CODEC_ABI_MISMATCH`; the structures libvpx writes before that check (encoder configuration, image, context) have 1 KiB of room after them |
| `dav1d` | libdav1d 1.5.3 (`libdav1d.so.7`) | `dav1d_version_api()` must have major version 7 before any structure is exchanged |
| `openh264` | Cisco's OpenH264 2.6.0 binary (`libopenh264-2.6.0-linux64.8.so`) | `OpenH264API::from_blob_path` loads a file only if its SHA-256 is in Cisco's published lists for 2.6.0 and 2.7.0 (a foreign file: "Invalid hash: ...") |

The bindings for libvpx and libdav1d are written here from their public headers (those of the runner's packages, printed by run 45327646972), not generated and not taken
from `parolnet-media`, whose libvpx binding is a C shim built with `cc` at build time (the
opposite of what `--all-features` needs). OpenH264 is used as Cisco's binary only, never built
from source here; the licensing of 4.1 applies, and `codec::openh264::ATTRIBUTION` is the text
Cisco's conditions require.

Measured on GitHub-hosted runners (ubuntu-26.04 image, 4 vCPUs), libraries from the
distribution (`apt-get install libdav1d7 libvpx12`), Cisco's binary downloaded from
`ciscobinary.openh264.org` (SHA-256 `2f0cde7c...` matched); runs 45328698491 (release build)
and 45329271661 (every feature, all tests of the crate: 9 binaries, 81 passed, 0 failed):

| Check | Result |
|---|---|
| libvpx, the repository's VP8 fixture | I420 MD5 `4b669885...`, equal to libvpx through ffmpeg (the reference `tests/codecs.rs` holds the pure-Rust decoder to) |
| libvpx, the VP9 fixture | 300 of 300 frames, 176x144 (I420 MD5 `4c2587ad...`, recorded) |
| libvpx encode, 640x360, 600 kbit/s, synthetic | VP8 39.2 dB at 575 kbit/s, VP9 40.2 dB at 583 kbit/s; every VP8 frame decoded by `vp8-decoder` to the same bytes as by libvpx (90 of 90) |
| libvpx rate change in place (`vpx_codec_enc_config_set`) | 1015 kbit/s at a 1000 target, then 330 at 300, no key frame |
| libvpx speed, 1280x720, 2 Mbit/s, one thread | VP8 encode 173 fps, decode 578 fps; VP9 encode 96 fps, decode 488 fps |
| libdav1d against rav1d | the rav1e stream decoded to the same pictures, byte for byte |
| libdav1d on rav1d's reproducer | `dav1d_send_data` returns -22 (EINVAL); the next key frame decodes |
| libdav1d on hostile input, in process | every single-bit flip of the key frame (19,352): 768 refused, 0 crashes; phase 2's 1500 seeded mutations: 759 refused, 0 crashes, the key frame decodes after every one (against rav1d 1.1.0: 711 and 193 aborts, 4.8) |
| libdav1d speed, 640x360, one thread | 1785 fps (rav1d without assembly: 462 fps, release builds) |
| OpenH264 (Cisco 2.6.0), the H.264 fixture | 300 of 300 access units decoded, 176x144 |
| OpenH264 encode, 640x360, 600 kbit/s, synthetic | 40.2 dB at 605 kbit/s, a frame for every picture, key frames exactly where asked (2 of 90); encode and decode together 463 fps |

libFuzzer on libdav1d through this backend, the harness used on rav1d (4.8), 15 minutes, fork
mode, AddressSanitizer and LeakSanitizer on the Rust side (the distribution's libdav1d is not
instrumented, so a memory error inside it shows only if it crashes; run 45328745696): **no
crash, no leak, no timeout, no out-of-memory** (rav1d, same harness and time: 1 crash, 3 and 4
leak, 1 timeout artifacts). For AV1 from a peer that is not trusted, `dav1d` is the decoder to
use; `isolation` still contains a C crash nobody has found yet.

The first of those runs found a bug in this crate's AV1 wrappers (both): dav1d reports a
frame's decode error when the next picture is taken out, and the wrappers took that error, met
while sending the following unit, as the following unit's own, so a key frame after an accepted
hostile delta frame was refused (`hostile_av1_frames_do_not_crash_dav1d` failed). An error from
a waiting picture is now logged as the earlier unit's and the current unit is still sent (run
45329271661: 0 key frames refused after a hostile frame).

**CI job** (`video_codecs` in `cargo.yml`, added by `conf/video-1-send-tests-run-and-pass`
as proposed here, with `libvpx-dev` / `libdav1d-dev` for the libraries; until then no job ran
any of the crate's feature-gated tests). The proposal was: a job `video-codecs` on ubuntu-latest: `sudo apt-get install -y libdav1d7
libvpx12`, download Cisco's `libopenh264-2.6.0-linux64.8.so.bz2` from
`http://ciscobinary.openh264.org/` into the runner's temporary directory (a CI machine fetching
the binary for a test is the "separately downloaded" case; it is never committed or cached in
the repository) and set `OPENH264_LIBRARY`, then `cargo test -p rtci-video --all-features`. About
3 minutes with a warm cache. No other job changes: `cargo check --workspace --all-features`
needs no library. macOS (Homebrew `libvpx`, `dav1d`) and Windows (vcpkg) variants are possible
but not proposed until an application needs them.

**rav1d 1.1.0 (decode) and rav1e 0.8.1 (encode), without assembly**

| Check | Result |
|---|---|
| rav1d against dav1d (libaom's AV1 vectors: sizes, intra, CDF update, motion vectors, SVC L1T2 / L2T1 / L2T2) | 10 of 10 byte-identical (with `all_layers = 0`: the highest spatial layer, as a WebRTC receiver renders) |
| rav1d speed | 360p: 136 to 182 fps; 720p: 37 to 43 fps (one thread) |
| rav1d on hostile input | **aborts the process**: a seeded mutation of a rav1e stream panicked in `rav1d/src/decode.rs:4997`; the panic crosses rav1d's `extern "C"` API, which cannot unwind, so the process aborts whatever catches it (run 45316346260; 711 of 19,352 single-bit flips of a key frame do it, rav1d issue 1497, section 4.8). The fuzz run found a 96-byte leak within minutes: rav1d's, about 50 to 100 bytes on every frame (rav1d issue 1522, 4.8) |
| rav1e speed, speed preset 10 | 360p camera: 4.8 to 6.3 fps; 360p synthetic: 7.8 to 10.2 fps; 720p camera: 1.4 to 1.8 fps; presets 8 and 6 slower (2.0 to 2.6, 1.2 to 1.6 fps at 360p) |
| rav1e latency | holds 4 pictures back even in low-latency mode (`keyframe_lookahead_distance` = reordering latency + 1, plus one picture of RDO look-ahead): 133 ms at 30 fps before the first output |
| rav1e rate and quality | synthetic 640x360: 612 to 655 kbit/s for 600, 39.6 to 40.2 dB; the camera clip overshoots in 60 pictures (1572 kbit/s at 360p) |
| Streams decodable by dav1d | every rav1e stream decoded identically by libdav1d and by rav1d (5 of 5) |
| In the pipeline | rav1e stream through 5 % loss and reordering: every picture bit-exact to the in-order decode (`av1_from_rav1e_through_loss_decodes_bit_exactly_with_rav1d`) |

**Decision: `av1` stays opt-in.** In plain words, the default build cannot encode AV1 in real
time: 5 to 8 pictures a second at 360p, against 30. It can decode AV1 in real time up to
720p30 on one core, but rav1d aborts the process on a malformed frame, and a peer chooses
what it sends: that cannot be a default of a library that takes media from the network. The
`av1` feature is for an application that accepts both limits (a trusted sender, or decode in a
separate process: `codec::isolated`, 4.8). The real-time AV1 path is the opt-in `dav1d` (decode) and the libaom or SVT
encoders, which need C and assembly.

The opt-in backends that use system libraries (`libvpx`, `dav1d`, `openh264`) are in 4.9.

### 4.2 Hardware encoders and decoders (later, opt-in)

| Backend | Crate | Licence | Notes |
|---|---|---|---|
| VideoToolbox (macOS, iOS) | `objc2-video-toolbox` 0.3.2 | Zlib OR Apache-2.0 OR MIT | H.264, H.265 (and VP9 / AV1 decode on recent hardware); system framework, no extra install |
| Media Foundation (Windows) | `windows` (Microsoft) | MIT OR Apache-2.0 | H.264, H.265, AV1 / VP9 decode where the drivers have them |
| VA-API (Linux) | `cros-codecs` 0.0.6 / `cros-libva` 0.0.13 | BSD-3-Clause | needs libva at run time; H.264, H.265, VP8, VP9, AV1 per driver |
| NVENC / NVDEC | `shiguredo_nvcodec` 2026.2.0 | Apache-2.0 | MSRV 1.93: cannot be a dependency at MSRV 1.89 (as `sonora` for audio) |

Platform encoders ship with the platform's own H.264 / H.265 patent arrangements; that is the
practical route to H.264 encoding for an application that cannot take the Cisco conditions.

### 4.3 Scaling and colour conversion

| Crate | Licence | Pure Rust | MSRV | Use |
|---|---|---|---|---|
| `yuv` 0.8.21 (repo `awxkee/yuvutils-rs`) | BSD-3-Clause OR Apache-2.0 | yes (SIMD through `std::arch`) | 1.82 | RGB / NV12 / YUY2 to I420 and back (`parolnet-media` uses it) |
| `pic-scale` 0.7.14 | BSD-3-Clause OR Apache-2.0 | yes | 1.89 | high-quality resampling of planes |
| `fast_image_resize` 6.2.0 | MIT OR Apache-2.0 | yes | 1.87 | alternative resampler |
| `dcv-color-primitives` 1.0.0 | MIT-0 | yes | 1.87 | not in `deny.toml`'s list: not used |

A box / bilinear I420 down-scaler written here covers simulcast and the quality scaler in
the default build; `yuv` and `pic-scale` are the opt-in `convert` feature for capture formats
and better filters.

### 4.4 Capture (later, opt-in)

Camera: `nokhwa` 0.10.11 (Apache-2.0; AVFoundation, Media Foundation, V4L2), as
`parolnet-media` uses. Screen: `xcap` 0.9.10 (Apache-2.0) or per-platform APIs
(ScreenCaptureKit, Windows Graphics Capture, PipeWire). Every one opens a system privacy
prompt; none runs in CI.

### 4.5 What the default build can and cannot do

| | Receive (decode) | Send (encode) |
|---|---|---|
| Default (pure Rust) | nothing (the pipeline receives, assembles and times every payload format; no decoder) | nothing |
| `vp8` (pure Rust, opt-in until the owner decides, 4.7) | VP8 (`vp8-decoder`, real time to 720p and beyond) | VP8 (`vp8-encoder`, real time to 720p on one core) |
| `av1` (pure Rust, opt-in) | AV1 (`rav1d`, real time to 720p30 on one core; a hostile frame aborts the process, and it leaks about 50 to 100 bytes a frame, 4.8) | AV1 (`rav1e`, not real time: 5 to 8 fps at 360p) |
| `isolation` (opt-in) | any of these in a child process: a crash costs a frame (4.8) | - |
| `libvpx` (C, loaded at run time, 4.9) | VP8, VP9 | VP8, VP9 (SVC later, phase 3) |
| `dav1d` (C, loaded at run time, 4.9) | AV1 at browser speed, robust on hostile input | - |
| `openh264` (Cisco's binary, loaded at run time, 4.9) | H.264 | H.264 Constrained Baseline |
| hardware | H.264, H.265, others per platform | H.264, H.265 per platform |

The default build decodes no video at all until the application enables a codec feature or
registers its own decoder; it cannot do VP9 or H.264 at all. The receive pipeline of phase 1 is
codec-agnostic: it assembles, orders, times and requests key frames for every payload format
the engine depacketizes, and hands frames to whichever decoder the application registers.

---

## 5. Crate layout, attachment, threading

### 5.1 Crates

- **`rtci-video`**: the receive pipeline (assembly, reference finder, frame buffer,
  timing, key-frame policy, render statistics), the decoder and encoder traits, the send
  pipeline (cadence, scaling, allocation, adaptation), the codec backends behind features,
  and `engine` (feature, default) for the glue to `RTCRtpReceiver` / `RTCRtpSender`, as
  `rtc-audio` does. Default features: `engine` only; `vp8` (4.7), `av1` (4.8) and `isolation`
  are opt-in. The engine does not depend on `rtci-video` in any way (not even as a
  dev-dependency): the interop peer's video scenario is built by the `rtci-video-interop`
  package (`rtci-video/interop`, not published) from `examples/interop-peer`, and the
  workspace's ordinary builds compile no codec (6.4).
- **Capture**: not in `rtc-devices`, which is audio-only and another agent's; a crate
  `rtci-video-devices` (or features of `rtci-video`) for cameras and screens is an owner decision
  (section 7). Synthetic sources (test patterns, moving shapes, noise) are in `rtci-video` itself
  and are what every test uses.

### 5.2 Attachment to the engine

Receive: `rtci_video::engine::VideoReceiver::new(&mut pc, receiver_id, config)`; for every
`RTCMessage::RtpPacket(track, packet)` of its track `handle_rtp(now, &packet)`; `poll(&mut pc,
now)` writes due PLI, returns `DecodeRequest`s; `on_decoded(&mut pc, now, outcome)` reports
the decoded size (`report_received_frame`) and statistics; `poll_timeout()` for the next
deadline; `update_stats(&mut pc)` for `update_decoder_stats`. The receiver's RTT comes from the
engine's statistics (remote-inbound / candidate pair RTT) for the jitter estimator's NACK term.

Send (phase 3): `VideoSender` takes frames, follows `target_bitrates()` and
`OnKeyFrameRequest`, packetizes with the negotiated codec's payloader and the DD writer, and
reports encoder statistics.

### 5.3 A/V synchronisation

Both pipelines know each frame's capture time on the sender's clock
(`encoded_frame_metadata().capture_time`, from `abs-capture-time` or the RTCP sender reports'
NTP / RTP mapping, RFC 3550 6.4.1; RFC 6051 rapid synchronisation where negotiated). The sync
module computes, as libwebrtc's `video/stream_synchronization.cc @ a222406d`, the relative
delay (`:35-63`), filters it (`kFilterLength = 4`, `:24`), ignores differences under 30 ms
(`kMinDeltaMs`, `:26`), moves at most 80 ms per step (`kMaxChangeMs`, `:22`) once a second
(`rtp_streams_synchronizer2.cc:35`), adding delay to the earlier stream: to video through
the timing's minimum delay, to audio through `rtc_audio::jitter::JitterBuffer::
set_target_delay` (an existing API; no change to `rtc-audio`). One clock: both pipelines are
given the same `now`.

**On master without the audio crates.** Engine `master` (4431dda0) does not contain
`rtc-audio`, `rtc-devices` or `rtc-ffi`: they were reverted and return on
`conf/ffi-mp-5`. `rtci-video` does not depend on them, and phase 4 keeps it that way: the sync
module takes each stream's measurements as plain values (capture time on the sender's clock,
render or playout time on the receiver's, the current extra delay) and returns the extra delay
for each side. The video side applies its own through `ReceivePipeline::set_sync_delay` (it
exists since phase 1); the audio side's is handed to the application, which sets it on
`rtc_audio::jitter::JitterBuffer::set_target_delay`. A convenience glue that does that last
step (an `audio-sync` feature depending on `rtc-audio`) is added only once `rtc-audio` is on
master again; nothing in phases 1 to 3 needs it.

### 5.4 Threading, back-pressure, allocation

The engine is single-threaded; so is the pipeline's control part (cheap: bookkeeping per
packet and per frame). Decoding and encoding are the only heavy work and are synchronous calls
on trait objects that are `Send`: an application runs them on the engine's thread (tests,
small resolutions) or on a worker and returns the results. Back-pressure: on receive, at most
`max_pending_decodes` frames are out (2.7); on send, the encoder input is a single-slot
mailbox (the newest captured frame replaces an unencoded one, counted as a frame dropped by
the source; libwebrtc's `kMaxFramesInPreparation = 10`, `video/video_stream_encoder.cc:125`,
bounds the same queue). Allocation: encoded frame payloads are `Bytes` slices of the
depacketized packets (one copy to join packets); decoded pictures come from a `FramePool`
(reference-counted planes returned on drop), so steady state allocates nothing per frame.

---

## 6. Phases

Every phase: a branch `conf/vp-<n>-<name>` stacked on the previous one, `cargo check`,
clippy, fmt, the `scripts/check-*.py` gates and `cargo deny --all-features` locally; the new
crate's tests and `cargo test --workspace` on GitHub-hosted runners (ubuntu; macOS and
Windows at phase milestones); CHANGELOG under `[Unreleased]`. Browser cells are added to the
test environment's matrix (`scripts/test-env/interop/webrtc.spec.mjs`) and run only on the
integration train.

### Phase 1: the receive pipeline, codec-agnostic (`conf/vp-2-receive`)

Scope: `rtci-video` with `assembly`, `reference`, `buffer`, `timing`, `keyframe`, `render`,
`stats`, `decoder` (trait only, plus a test decoder that models reference validity),
`engine::VideoReceiver`. No codec dependency.

Tests (no camera, no browser):

- Unit: each finder with descriptor sequences from the RFCs' examples (VP8 L1T3 with Y bits,
  VP9 flexible and non-flexible GOF, DD L1T3 / L3T3 structures from the engine's own
  `ScalabilityPattern`), sequence-number wrap, duplicates, padding, overflow, the jitter
  estimator against constructed delay series.
- Golden streams: `examples/test-data/output_vp8.ivf` and `output_vp9.ivf` (libvpx, 176x144,
  300 frames at 29.97 fps), `output.264` and `output.265` (Annex B), packetized with the
  engine's payloaders, shuffled and lost by a seeded network model; every frame the pipeline
  releases must be byte-identical to the IVF frame and released in order with its references
  released before it. Test-environment GStreamer fixtures (`vp8.ivf`, `h264` 640x480) where
  the env stage runs.
- Virtual-time networks: two `rtci` peer connections (a world like `rtc-audio/tests/common`'s:
  seeded loss, uniform jitter that reorders) with default interceptors (NACK, RTX, PLI),
  a synthetic VP8 sender (frames sized by a bitrate, PictureID / TL0PICIDX, key frame on PLI)
  and the pipeline on the receiver; and the capacity scenario of
  `tests/capacity_cap_video_rtc2rtc.rs` (300 kbit/s for 20 s) with the sender following GCC.

Acceptance (asserted, seeded, each assertion mutation-checked). The first version of this
table, written before anything ran, set `freezeCount` = 0 at 2 % loss in the two-peer call,
"under 500 ms" at 10 % and a jitter buffer "within p95 - 10 .. p95 + 50 ms" of the network
jitter. Measurement showed the first two depend on how fast the engine repairs a loss, not on
the pipeline (section 6.1), and the third on libwebrtc's estimator, which this port follows;
the figures below replace them, each with its reason.

| Scenario | Figure | Source of the threshold |
|---|---|---|
| golden streams (VP8, VP9, H.264, H.265 fixtures), 5 % loss, 25 ms + 0..40 ms, a retransmission one 60 ms round trip after each loss | every released picture byte-identical to the source; no delta picture before the one it predicts from (the fixtures' own I-P-P order, independent of the reference finder); at least 99 % decoded; `freezeCount` = 0 | correctness; W3C `freezeCount` |
| two-peer call, 2 % and 10 % loss, 25 ms + 0..40 ms, 500 kbit/s, 30 s, the engine's NACK and RTX | no corrupt picture, no decode out of order, no delta picture without its predecessor (the source's frame numbers); longest interval between rendered pictures at most the slowest repair + 100 ms (the pipeline waits for nothing but repairs) | `ReceiveStats::max_repair_delay`, measured on the same run |
| capacity 300 kbit/s for 20 s, then open, the sender following GCC | longest interval between rendered pictures under 1 s over the whole run (the last release froze 7 s) | regression bound for the engine's known failure |
| key frame lost at start | first PLI at the first delta frame; at most one request per 200 ms; decoding resumes at the next key frame | `rtp_video_stream_receiver2.cc:1067-1072`, `video_receive_stream2.cc:1187-1213` |
| pictures stuck behind a gap retransmission never fills | a key frame asked for (`RepairWindow`) between 5 RTT (at least 1 s) and that + 50 ms after the last release; with `ReceiveConfig::chrome()` only the 3 s decode timeout | RFC 4588 6.3 ("would still be useful"); libwebrtc `video_receive_stream2.h:75` |
| `jitterBufferTarget` 100 ms, steady stream | a picture is not released before render time - decode time - render delay, and its render time is arrival + 100 ms (+-5 ms) | `frame_decode_timing.cc` `MaxWaitingTime`; W3C webrtc-extensions `jitterBufferTarget` |
| clean link, 0..40 ms jitter | no freeze, no frame dropped, mean `jitterBufferDelay` per picture 10..60 ms (measured 25.9 ms: libwebrtc's estimate for this jitter is about 20 ms, `2.33 sigma - 30 ms + 10 ms` with `sigma = 40 / sqrt(6)` ms) | `jitter_estimator.cc:62-73` |

Browser cells: none yet (no decoder); phase 2 adds them.

#### 6.1 Phase 1: what was measured

GitHub-hosted runs of `cargo test -p rtci-video -- --nocapture` on `conf/vp-2-receive`
(ubuntu-latest; the `MEASURE` lines), virtual time, fixed seeds:

| Scenario | Decoded | Freezes (W3C) | Longest interval | Mean jitter buffer delay | Repairs: count, mean, max |
|---|---|---|---|---|---|
| VP8 fixture, clean / 5 % loss | 300 / 298 of 300 | 0 / 0 | 54 / 131 ms | | |
| VP9 fixture, clean / 5 % loss | 300 / 299 | 0 / 0 | 54 / 113 ms | | |
| H.264 fixture, clean / 5 % loss | 300 / 298 | 0 / 0 | 54 / 164 ms | | |
| H.265 fixture, clean / 5 % loss | 300 / 300 | 0 / 0 | 54 / 164 ms | | |
| call, clean, 0..40 ms jitter, 20 s | 599 of 599 | 0 | 45 ms | 25.9 ms | 0 |
| call, 2 % loss, 30 s | 897 of 899 | 13 (2.98 s) | 319 ms | 98.3 ms | 24, 227 ms, 375 ms |
| call, 10 % loss, 30 s | 887 of 896 | 51 (13.2 s) | 654 ms | 249 ms | 175, 321 ms, 877 ms |
| call, 300 kbit/s for 20 s then open, 50 s | 1498 of 1500 | 5 (2.23 s) | 620 ms | 86.6 ms | 28, 605 ms, 1089 ms |

No run released a picture that differed from what was sent or that its references did not
allow, on any codec.

**Engine finding: repair latency.** In the calls a lost packet comes back 227 ms (mean, 2 %
loss) to 605 ms (capacity drop) after the first packet past its gap, against a round trip of
about 70 ms on that link. libwebrtc asks as soon as a gap shows (`nack_requester.cc`
`OnReceivedPacket` sends `GetNackBatch(kSeqNumOnly)` on the packet that reveals it) and again
every round trip; the engine's generator waits for its learned reordering allowance (up to
500 ms) and runs on a 100 ms cycle. Shortening the cycle to 20 ms made it worse (2 % loss:
repairs 554 ms mean, 28 freezes; run 45308589888), so the cause is not the cycle alone; it is
reported to the congestion / retransmission work and not changed here (outside this crate).
The W3C freezes in the loss rows are those repairs: the pipeline waits for nothing else (the
asserted bound), and with repairs one round trip late (the golden streams) there is none.

**Mutation check.** Each mutation on a throwaway branch, `cargo test -p rtci-video` on a hosted
runner; all killed:

| Mutation | Killed by |
|---|---|
| frame buffer ignores references (`decodable` never cleared) | buffer unit tests, golden H.264 / H.265, the 10 % loss and capacity calls, the repair-window test (11 failures) |
| picture-id finder gives no references | golden VP8 / VP9, all three loss calls, the jitter call, the repair-window test (7) |
| release ignores render time | `a_picture_is_held_until_its_render_time_less_decode_and_render_delay` (added after the first round, where this mutation survived) |
| repair window never asks | `frames_stuck_behind_an_unrepaired_gap_ask_for_a_key_frame_after_the_repair_window` |
| freeze margin 300 ms instead of 150 | `a_long_interval_after_steady_frames_is_a_freeze` |
| retransmissions never detected | `a_packet_late_against_the_packet_after_its_gap_counts_as_a_retransmission` (added after the first round) |

### Phase 1b: the engine boundary (`conf/vp-4-engine-boundary`)

`RTCRtpReceiver::set_nack_horizon` (2.6) and the four jitter-buffer members in
`DecoderStatsUpdate` (2.9), each with a failing-first test. Acceptance: in the capacity
scenario, retransmissions of packets older than the horizon = 0.

#### 6.2 Phase 1b: what was built and measured

- `NackControl::Horizon { media_ssrc, oldest_useful }` (rtci-interceptor) and
  `RTCRtpReceiver::set_nack_horizon(now, ssrc, Option<u16>)` (rtc): the generator drops
  missing sequence numbers older than the horizon, wrap-aware, and forgets their requests;
  the RTCP session drops them from a NACK it still holds for its next packet (RFC 4585 3.5.2:
  early feedback is rate-limited, and what waits is sent only if still useful), so no NACK
  that leaves after the horizon names a packet behind it
  (`rtci-interceptor/tests/nack_control_horizon.rs`,
  `rtcp_session_feedback.rs::a_nack_held_for_the_regular_packet_drops_what_the_nack_horizon_passed`;
  two peers:
  `tests/rtcp_session_rtc2rtc.rs::a_receiver_stops_asking_for_packets_behind_its_nack_horizon`).
  `VideoReceiver::poll` moves it on after every released picture (`ReceiveConfig::
  nack_horizon`, on by default and in `chrome()`: libwebrtc's `NackRequester::ClearUpTo`).
- `DecoderStatsUpdate::{jitter_buffer_delay, jitter_buffer_target_delay,
  jitter_buffer_minimum_delay, jitter_buffer_emitted_count}`, which win over the audio
  update's (`statistics::feed_test::the_decoder_update_carries_the_jitter_buffer_members_of_a_video_stream`);
  `rtci-video` no longer calls `update_audio_receiver_stats`.
- Tap interceptors in `rtci-video/tests/receive_rtc2rtc.rs` record every NACK as generated, as
  it leaves and as it arrives, and every RTX as it leaves (by its original sequence number):
  the per-packet repair trace is `docs/video-repair-latency.md` (the first NACK is made
  157 ms after a gap on average; the rest of a repair is the link).

Measured (hosted run 45314248391 at `134ce3a7`; NACKs for packets behind the horizon the
pipeline had computed before the NACK was made):

| Scenario | Sequence numbers asked for | Behind the horizon | Without the horizon (mutation, run 45314253623) |
|---|---|---|---|
| call, 2 % loss, 30 s | 26 | 0 | 26, 0 |
| capacity 300 kbit/s, then open, 50 s | 157 | 0 | 157, 0 |
| one packet lost for good (original and every RTX), 13 s | 11 | 0 | 84, **73** |

In the loss and capacity scenarios every lost packet is repaired before playout reaches it,
so the generator never had a reason to ask behind playout; the third scenario is where the
horizon matters: the pipeline asks for a key frame after its repair window (one PLI, 1.1 s
freeze, 31 frames dropped), plays on, and from the moment playout passed the lost packet
(5.07 s into the call) the generator stops asking for it. Without the horizon it asked 73 more
times. Phase 1's frame figures (6.1) are unchanged by the horizon (same runs, same numbers).

### Phase 2: codecs (`conf/vp-5-codecs`)

`VideoDecoder` / `VideoEncoder` backends: `vp8` (vp8-decoder / vp8-encoder), `av1` (rav1e,
rav1d), `libvpx` (VP8, VP9), `dav1d`, `openh264`. Tests: conformance vectors where licensable
(fetched in CI, not committed), golden fixtures decoded with frame checksums, encode-decode
PSNR at stated bitrates, decode and encode speed at 360p and 720p (reported, and asserted
against real time on the runner for the defaults), fuzzing of the decoders' entry.
Acceptance: VP8 decode 720p at 30 fps or more on one GitHub-hosted core; PSNR of
encode-decode at 640x360, 600 kbit/s at least 32 dB on the synthetic source; AV1 figures
reported, no real-time claim unless measured. Browser cells: Rust sends VP8 (and AV1) through
the pipeline, the browser decodes (framesDecoded > 0, no freeze at 0 % loss); the browser
sends, `rtci-video` decodes (frames decoded, sizes right) — Chromium, Firefox, WebKit.

#### 6.3 Phase 2: status

Built: the `vp8` (default) and `av1` (opt-in) backends (`codec::vp8`, `codec::av1`), `picture`
(I420, PSNR, the synthetic source), the `VideoEncoder` trait (each output names its input,
`source_index`), `VideoDecoder::picture`; the evidence of 4.6; the decoders in the pipeline
(golden streams, the two-peer call); the browser cells. Not built: the `libvpx`, `dav1d` and
`openh264` backends.

Browser cells (`scripts/test-env/interop/webrtc.spec.mjs`, `pipeline receive VP8` and
`pipeline receive AV1`; interop-peer scenario `{"media":"pipeline","video":...}`, which only
the peer built by `cargo build -p rtci-video-interop --features pipeline` (binary
`interop-peer-video`, what `scripts/test-env/interop/run.sh` now starts) has): the
browser sends its canvas track, the peer runs it through `rtci-video` and its pure-Rust
decoder and reports what it decoded. Not run here (browsers run on the integration train). The
train must confirm, for Chromium, Firefox and WebKit: at least 15 pictures decoded within
25 s, no decoder error, no codec without a decoder, the decoder named (`vp8-decoder`,
`rav1d`), a size at most the canvas's 320x240 with its 4:3 aspect; and record the
`video-pipeline` annotation (freezes, longest interval, PLIs). A browser without the AV1
encoder is skipped by its own capabilities. Rust sending to the browser waits for phase 3
(the send pipeline).

#### 6.4 Codec safety (`conf/vp-6-codec-safety`)

What changed: `vp8` opt-in (4.7, with `scripts/check-video-codec-pins.py`); the AV1 wrapper's
leak fixed and the abort documented where the feature is (4.8); `codec::vp8` catches a decoder
panic (pure Rust: it unwinds) and replaces the decoder; `codec::isolated` (feature
`isolation`); the `rtci` crate no longer dev-depends on `rtci-video`: the interop peer's
`pipeline` scenario is behind the `pipeline` feature of the new `rtci-video-interop` package,
which compiles the same `examples/interop-peer/interop-peer.rs`.

Measured on GitHub-hosted runners (ubuntu-latest, 4 vCPUs):

| Check | Result |
|---|---|
| `cargo test -p rtci-video`, default features, then `--features vp8,av1,isolation` (run 45324314829, `e5e73d6a`) | 10 test binaries, 118 passed, 0 failed, 2 ignored |
| isolation (`tests/isolated.rs`) | the reproducer decoded in process: `signal: 6 (SIGABRT)`; through `IsolatedDecoder`: `Err(Corrupt("decoder process ended (signal: 6 (SIGABRT) ...)"))`, then the key frame decodes in a new child to the same picture; a child that never answers is killed after 501 ms |
| reproducer search (run 45322103402) | 711 of 19,352 single-bit flips of a key frame abort rav1d 1.1.0; 193 of 750 of phase 2's mutations (4.8) |
| AV1 fuzz, 15 min each, fork mode, AddressSanitizer + LeakSanitizer (runs 45322108334, 45324307021) | before and after the wrapper change: 1 crash artifact, 3 and 4 leak artifacts, 1 and 0 timeout artifacts; the leak input replayed leaks the same 96 bytes with either wrapper (runs 45324302343, 45324307021), from `dav1d_picture_unref` (symbolised, run 45326503227): rav1d issue 1522 (4.8) |
| `cargo test --workspace --no-run`, fresh target directory | before (`conf/vp-5-codecs`, runs 45322132676 and 45324331617): 257 s and 233 s, 384 crates, rav1d / rav1e / vp8-* among them; after (run 45324323050): 228 s, 344 crates, no codec crate |
| `cargo test --no-run` at the root (cargo.yml's first test job) | before: 190 s and 179 s, 360 crates with the four codec crates; after: 175 s, 312 crates, none |
| `cargo build -p rtci-video-interop --features pipeline` after that | 56 s, 145 crates (the codecs and the video interop peer) |

The build-time gain in wall-clock terms is small and within the runners' spread (the two
"before" runs differ by 24 s): on 4 vCPUs the codec crates compile in parallel with the rest
and are not on the critical path. What changed is that 40 to 48 crates, among them the two
largest of the dependency graph (rav1e, rav1d), are no longer built at all by any job that
does not test video, and only the browser stage (which tests video) pays the 56 s. A CI job
that tests the codecs is proposed to the train, not added: `cargo test -p rtci-video
--features vp8,av1,isolation` (pure Rust, no system library), plus `python3
scripts/check-video-codec-pins.py` after any build. `cargo check --workspace --all-features`
(cargo.yml) still compiles the codecs, by definition of `--all-features`.

### Phase 3: the send pipeline (`conf/vp-7-send`)

Synthetic sources, cadence adapter, I420 scaler, encoder driver with rate control from
`target_bitrates()`, key frames on `OnKeyFrameRequest`, simulcast (one encoder per RID),
temporal layers, SVC with the DD, the rate allocators, the encoder bitrate adjuster, encoder
statistics. Acceptance: encoded bitrate within 15 % of the allocation over 10 s windows
(vp8-encoder claims 12 %); key frame within one frame interval of a PLI; simulcast layers at
the signalled resolutions; capacity scenario with the real encoder meets phase 1's freeze
figure. Browser cells: simulcast to the browser's receiver (layers switched by the app),
resolution and frame-rate adaptation observed in the browser's inbound stats.

#### 6.5 Phase 3: what was built and measured (`conf/vp-7-send`)

Base: `conf/vp-6-codec-safety` (1624f763) with `conf/gcc-5-app-limited` (c56eeb26) merged in:
the pacer's pause (target 0 through `PacerPause`), the pacer in the default chain and
`OnPacerDiscard` are on that line, not on master yet. The merge had one conflict
(`CHANGELOG.md`, two independent "Breaking changes" bullets: both kept). Merged tree proved on
a hosted ubuntu runner: `cargo test -p rtci` 251 binaries, 2344 passed, 0 failed, 67 ignored
(run 45341081324); `cargo test -p rtci-video`, default then `--features vp8`, 50 and 54 passed
(run 45341077903).

**Built** (`rtci-video/src/send.rs`, `engine_send.rs`): `SendPipeline` (picture in, RTP packets
out) and `engine::VideoSender` (the glue to an `RTCRtpSender`: its SSRC, the negotiated
codec's payload type and payloader, `target_bitrates()`, `OnKeyFrameRequest`,
`OnPacerDiscard`, the nominated pair's round trip, `update_encoder_stats`). The encoder runs
synchronously inside `send_frame`; the pipeline is `Send`, so an application that wants it off
its network thread runs the whole pipeline on a worker (the single-slot mailbox of 5.4 is the
application's: it decides which picture to hand in). `VideoEncoder` gained `set_rates(bitrate,
framerate)` and `min_bitrate_bps()` (VP8: 30 kbit/s, libwebrtc's VP8 floor), and
`EncoderFactory` makes a new encoder on a resolution change. `picture::scale_into` is a box
filter. RTP timestamps come from the capture time on the 90 kHz clock (the application gives
the first sequence number and timestamp: RFC 3550 5.1 wants them random, and the crate draws no
randomness).

**Not built from the phase-3 list**: simulcast (one encoder per RID), temporal layers and SVC
with the Dependency Descriptor writer, the simulcast / SVC rate allocators, the encoder bitrate
adjuster, the zero-hertz cadence adapter, `abs-capture-time` stamping, CPU-overuse adaptation.
`VideoSender` drives the sender's first encoding only.

**The reactions, and the rule behind each** (default = the specification; `SendConfig::chrome()`
= libwebrtc where it differs; `rtci-video` is outside the engine's generated profile table,
`docs/behaviour-profiles.md`, so these rows live here as the receive side's
`ReceiveConfig::chrome()` does):

| Signal | Default | Chrome | Source |
|---|---|---|---|
| target (`target_bitrates()`, the estimate less the retransmission reserve) | encoder rate = target, never below the encoder's minimum; under it the encoder stays at the minimum and pictures are dropped in the ratio target / minimum | same | RFC 8834 7: "Endpoints have to be designed so they do not transmit significantly more data than the network path can support"; minimum: `video/config/simulcast.cc` kSimulcastFormatsVP8, "The min bitrate is still limited at 30 kbps" @ a222406d |
| pause (target 0) | nothing encoded until the next nonzero target; the first picture after it coded as it comes (a delta frame unless a key frame is due for another reason); `key_frame_on_resume: true` forces a key frame instead | same | no RFC asks for a key frame there: nothing encoded was lost (the pacer keeps what was written before the pause), so the receiver's references are intact; the engine's own note on `target_bitrates` says a key frame is not needed; libwebrtc encodes the held picture as it comes (`video/video_stream_encoder.cc` 2544-2558). A receiver that lost something asks (PLI / FIR) and the pacer's discards ask too |
| PLI, FIR, `OnPacerDiscard` | key frame on the next picture, not served within two round trips of the last key frame sent (500 ms until a round trip is known); requests while one is due coalesce | at most one request served per 300 ms, whenever the last key frame was | RFC 5104 3.5.1: "A receiver that receives a request closely after sending a decoder refresh point -- within 2 times the longest round trip time (RTT) known, plus any AVPF-induced RTCP packet sending delays -- should await a second request message", and "If it receives repetitions of the FIR more than 2*RTT after it has sent a decoder refresh point, it shall send a new decoder refresh point"; RFC 4585 6.3.1.1 (the sender "MAY react to a PLI by transmitting an intra-picture", "MUST consider congestion control"); RFC 8834 5.1.1 / 5.1.2 (MUST react to FIR and PLI); default round trip RFC 7728 8.1 ("SHOULD use 500 ms as the default value"); Chrome: `video/encoder_rtcp_feedback.cc` kMinKeyframeSendIntervalMs = 300, lines 32, 66-70 |
| target under what the format needs | W3C `degradationPreference` `balanced`: alternate resolution steps (3/5 of the pixels, down to 320x180) and frame-rate steps (2/3, down to 2 fps); down at once, up only with a quarter's margin and 5 s after the last change | `maintain-framerate` | webrtc-pc CR 2018-09-27 5.2.2: "degradationPreference of type RTCDegradationPreference, defaulting to "balanced""; enum text "Degrade a balance of framerate and resolution" (mst-content-hint now holds the enum: "motion" -> maintain-framerate, "detail" / "text" -> maintain-resolution); Chrome: `media/engine/webrtc_video_engine.cc` 2041-2062 ("Keep MAINTAIN_FRAMERATE by default until BALANCED has been tuned"); steps and floors: `call/adaptation/video_stream_adapter.cc` 40, 45-47, 150-158 and `api/video_codecs/video_encoder.h` 39; what a format needs: kSimulcastFormatsVP8 `min_bitrate` ("The minimum bitrate needed for encoding stream at widthxheight") interpolated in pixels, times fps / 30; hold: `quality_scaler.cc` 34-35 (2 s x 2.5 once scaled down) |

The pause row's default was a forced key frame until `conf/vp-9-no-keyframe-on-resume`
(decision 7 below); it is now libwebrtc's form and the engine note's, and the forced key frame
is the option `key_frame_on_resume`. Measured with the forced key frame, it made no difference
in the capacity call: the receiver asks for a key frame during every long pause (17 to 23
requests coalesced per run), so a key frame is due at the resume either way
(`measure_the_pause_with_the_chrome_configuration`: the same figures on seed 3). The figures
below were measured with the forced key frame (f9aa85bd).

**Measured** (`rtci-video/tests/send_rtc2rtc.rs`, the VP8 backend, 640x360 at 30 fps from
`TestSource`, both peers on the engine's default interceptors, GCC bounded to 100 kbit/s -
2.5 Mbit/s as the capacity test does; hosted ubuntu runs 45344063951 and 45344738955 at
f9aa85bd, the second with the 5 s hold):

| Scenario | Figures |
|---|---|
| open link, 30 s | target 1 Mbit/s at 0.4 s (probes), 2.5 Mbit/s cap reached; encoded / target per 10 s window 0.999, 1.000, 0.999; longest gap 35 ms; oldest picture 0.68 s; PSNR mean 40.5 dB, worst 34.6 dB; 0 decode errors |
| capacity cap (20 s open, 20 s at 300 kbit/s / 30 ms / 300 ms queue, 20 s open), six seeds | longest freeze 1.19 to 1.71 s; oldest picture from the cap on 10.17 to 11.67 s; median target under the cap 191 to 260 kbit/s; target 20 s after 1186 to 1385 kbit/s; 0 frames discarded by the pacer; 101 to 111 packets dropped at the link's queue (the half second before the estimate falls); encoded / target in the 10 s after the cap's pause 1.01 to 1.10 (without the 5 s hold 1.01 to 1.21, 4 to 8 resolution changes in 2 s of limitation; with it 0 to 4 changes, 0 to 10 s degraded); other windows 0.98 to 1.02 |
| pacer pause (same call) | every run pauses when the cap arrives: the pacer holds what the 2.5 Mbit/s source wrote and the target reads 0 for 10.0 to 11.5 s while it drains at the capped estimate; then 0 to 2 short pauses (0.3 to 1 s); 0 pictures encoded while the target read 0; every resume's first picture a key frame; first picture rendered 4 to 180 ms after each pause ended |
| 2 % loss, 25 ms + 0 to 40 ms jitter, 30 s | 146 packets retransmitted (RTX), repair mean 224 ms, max 345 ms; longest gap between rendered pictures 292 ms (bound: slowest repair + 100 ms); 886 decoded, 0 errors; PSNR worst 34.3 dB |

The oldest picture (10 to 11.7 s) is the engine's pacer backlog, not the pipeline: when the cap
arrives the source has written at 2.5 Mbit/s for the half second it takes the estimate to
fall, the pacer sends that at 100 to 250 kbit/s while the target reads 0, and the receiver
plays it late rather than skip it. The capacity test's model source measured 5.59 to 9.84 s on
the same chain. What shortens it is the stale-backlog drop planned on the congestion line.

**Since the backlog flush** (`conf/flush-1r-backlog-flush-at-collapse`, train 32: the default
pacer discards its queue at a capacity collapse and asks for a key frame; the source is not
paused) the two rows above describe `PacerBacklog::Keep`, which the pause test now asks for.
The default chain, measured (agent-test runs 46137495578 at v0.2.1, 46137469211 and
46136031324 on train 36): seed 2 no pause, 5 discards (key frames 7: requests served 4,
coalesced 1, suppressed 5), oldest picture from the cap 0.92 to 0.94 s, longest freeze 1.66 s,
median target under the cap 277 kbit/s, 20 s after 1198 to 1285 kbit/s; seed 3 no pause, 2
discards, oldest picture 0.93 s, freeze 1.05 s. The capacity-cap test's guard for the oldest
picture is now 2 s (the capacity instrument's picture requirement), not 13 s.
Guards (each about a tenth beyond the worst measured, or the capacity test's own bound): freeze
2 s, oldest picture 13 s, under the cap 180 kbit/s, recovery 800 kbit/s, encoded / target under
the cap 1.15, open-link windows 0.85 to 1.15, loss: longest gap within the slowest repair plus
100 ms.

**Mutations** (each a throwaway branch, deleted; every one fails a test): target ignored, the
encoder's minimum ignored, the pause ignored, no key frame on resume, no key-frame rate limit,
key-frame request ignored, the glue dropping `OnPacerDiscard`, degradation off, the frame-rate
step ignored (run 45343509144, `mut/vp-7-send-1`); the 5 s upgrade hold removed (run
45344729086, `mut/vp-7-send-2`).

### Phase 4: adaptation and A/V sync (`conf/vp-6-adapt`)

Quality scaler, degradation preference, CPU overuse, FEC budget, `qualityLimitation*`;
the sync module with `rtc-audio`. Acceptance: under a 300 kbit/s cap, resolution steps down
within 2 s (`quality_scaler.cc:34`) under MAINTAIN_FRAMERATE and frame rate under
MAINTAIN_RESOLUTION; audio-video skew within 30 ms (`stream_synchronization.cc:26`) after
5 s with 80 ms of extra video delay injected. Browser cells: lip-sync measured on a
flash / beep source in both directions.

### Phase 5: capture and hardware (owner decisions, section 7)

---

## 7. Decisions for the owner

| Decision | Recommendation | Meanwhile |
|---|---|---|
| 1. H.264 software encoding in scope at all | Yes, opt-in only: `openh264` with the Cisco binary loaded at run time (the only route with a patent licence that costs the application nothing, under Cisco's four conditions); building from source as a separate named feature; no pure-Rust H.264 encoder (the only candidate's provenance is unclear) | H.264 receive is fully supported by the codec-agnostic pipeline; no H.264 code is written until decided |
| 2. Accept `vp8-decoder` / `vp8-encoder` (first published 2026-11-06 by a crates.io account from 2026-11-03; one-commit repository; section 4.7) as default dependencies | Yes, pinned by exact version and checksum (`scripts/check-video-codec-pins.py` in CI) once a VP8 fuzz target is in the train's fuzz job; not vendored (4.7 gives the reasons) | `vp8` is opt-in: the default build decodes no video |
| 2b. AV1 decode with rav1d while 1.1.0 aborts on hostile input | Keep `av1` opt-in with the warning; recommend `isolation` for untrusted senders; move to rav1d's Rust API (catchable panics) when it is released; the opt-in `dav1d` backend as the robust decoder | the reproducer and a comment for rav1d#1521 are prepared, not posted |
| 3. Hardware backends: order | VideoToolbox, then Media Foundation, then VA-API; NVENC when the MSRV reaches 1.93 | none built |
| 4. Capture: where and how much | A new crate `rtci-video-devices` (camera via `nokhwa`; screen per platform), opt-in features, never run in CI | synthetic sources only |
| 5. Screen capture in scope | Yes, after camera; with the zero-hertz cadence and screen-content encoder modes it needs | the cadence adapter and screen-content mode are designed in phase 3 |
| 6. MSRV | Keep 1.89; it excludes `shiguredo_nvcodec` and newer pure-Rust codecs (`oxideav-*` 1.95, `gamut-av1` 1.92) | none of these needed now |
| 7. Key frame when a pacer pause ends (6.5) | Decided (coordinator, 2026-11-24): no forced key frame by default, as libwebrtc and the engine's note on `target_bitrates` (nothing encoded was lost; no RFC asks for one); the forced key frame is the option `SendConfig::key_frame_on_resume`, not a `Chrome` difference. Measured before: no difference in the capacity call (the receiver's PLIs make one due anyway) | `conf/vp-9-no-keyframe-on-resume` |
