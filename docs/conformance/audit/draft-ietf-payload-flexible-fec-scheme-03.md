# draft-ietf-payload-flexible-fec-scheme-03: RTP Payload Format for Flexible FEC (the implemented FlexFEC)

Spec: draft-ietf-payload-flexible-fec-scheme-03, 31 October 2016 (expired; superseded by RFC 8627, whose
payload format is not backward compatible). This is the format libwebrtc negotiates as
`video/flexfec-03` and the only FEC the engine implements (`rtci-interceptor/src/flexfec/`). Audited at
fork master 8916bc3; rows updated on branch `conf/cc-fec-flexfec` (wire-format fixes and tests). All sections with implementation requirements are covered: 4, 5.1, 5.2, 6, 8, 9.
Sections 1 to 3, 7 (examples), 10 to 13 carry no requirement on an endpoint.

The interceptors are opt-in: nothing registers `FlexFec03SendInterceptor` / `FlexFec03ReceiveInterceptor`
by default, and `video/flexfec-03` is not in `register_default_codecs`.

Two rows are `violated` on purpose and stay so (libwebrtc compatibility, decision D4 of
`docs/conformance.md`): FLEXFEC03-4.2-17 (mask bit j is SN base + j) and FLEXFEC03-5.1-5 (the subtype is
`flexfec-03`). Each is pinned by a test. Bugs 2, 3 and 6 below are fixed on `conf/cc-fec-flexfec`; bugs 1,
4 and 5 (chain order with transport-wide CC, repair packets and the arrival recorders) are fixed in the
congestion-control PR.

Totals:

- MUST: tested 35 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 4 (total 39)
- SHOULD: tested 6 / untested 0 / partial 0 / missing 1 / violated 0 / n-a 3 (total 10)
- MAY: tested 1 / untested 0 / partial 0 / missing 6 / violated 0 / n-a 0 (total 7)

Paths are relative to the repo root; `fec/` abbreviates `rtci-interceptor/src/flexfec/`, `it/` abbreviates
`rtci-interceptor/tests/`.

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| FLEXFEC03-4.1-1 | 4.1 | MUST | Source packets are sent unmodified; the FEC covers the packets as they are on the wire | tested | `rtci-interceptor/src/wire_image.rs` (`WireImageTap` at `Slot::FecWireImage`, below the TWCC sender), `fec/draft03/sender.rs` (`wire_tap`, `protect_wire_images`) | `it/fec_with_transport_cc.rs::a_lost_packet_is_recovered_as_it_was_sent_when_the_twcc_sender_rewrites_it`, `it/flexfec_send.rs::media_precedes_the_repair_packets_that_protect_it` | The encoder stays a generator at `Slot::FecEncoder` and reads the media packets from a tap below everything that edits them, so it protects the wire image; its repair packets still pass the pacer, the TWCC sender and the send history. Bugs 1, 4 and 5 below are fixed: the arrival recorders now run before the FEC decoder (`Slot::FecDecoder` 10_300), tests `a_repair_packet_is_reported_as_received_by_the_twcc_receiver`, `a_packet_recovered_by_fec_is_not_reported_as_arrived`. An application that registers the encoder without the tap keeps the old behaviour |
| FLEXFEC03-4.2-1 | 4.2 | MUST | Repair packet carries a FEC header identifying the source block and the packets protected | tested | `fec/draft03/encoder.rs:222-241` | `encoder.rs::the_header_names_the_stream_and_block_it_protects` | |
| FLEXFEC03-4.2-2 | 4.2 | MUST | Marker bit of a repair packet SHALL be 0 | tested | `fec/draft03/encoder.rs` (`encode_one`, header built with `marker` unset) | `encoder.rs::the_marker_bit_of_a_repair_packet_is_zero`, `it/flexfec03_conformance.rs::a_repair_packet_has_no_marker_bit` |  |
| FLEXFEC03-4.2-3 | 4.2 | MUST | Repair packets use a dynamic payload type determined out of band | tested | `fec/draft03/sender.rs:193-205`, `src/rtp_transceiver/rtp_sender/rtp_codec.rs:347-352` | `encoder.rs::repair_packets_form_their_own_stream`, `tests/repair_codec_negotiation.rs::flexfec_codec_is_offered_alongside_the_track_codec` | |
| FLEXFEC03-4.2-4 | 4.2 | MUST | Repair sequence number is one higher than the previous repair packet | tested | `fec/draft03/encoder.rs:243-244` | `encoder.rs::repair_packets_form_their_own_stream`, `it/flexfec_send.rs::the_repair_stream_has_its_own_identity_and_sequence_numbers` | |
| FLEXFEC03-4.2-5 | 4.2 | SHOULD | Initial repair sequence number is random | tested | `fec/draft03/sender.rs` (`bind_local_stream`: `rand::random` unless `FlexFec03SendBuilder::with_initial_sequence_number`) | `it/flexfec03_conformance.rs::the_initial_repair_sequence_number_is_random_unless_pinned` | The bare `FlexFec03Encoder` still starts at 0 unless `with_base_sequence_number` is called; the interceptor, the production path, draws a random one per repair stream |
| FLEXFEC03-4.2-6 | 4.2 | MUST | Repair timestamp SHALL correspond to the repair packet's transmission time | tested | `fec/draft03/encoder.rs` (`encode(.., timestamp)`), `fec/draft03/sender.rs` (`RepairClock::timestamp_at`) | `it/flexfec03_conformance.rs::the_repair_timestamp_follows_the_send_clock`, `it/flexfec03_conformance.rs::the_repair_timestamp_wraps`, `encoder.rs::the_repair_timestamp_is_the_send_clock_not_the_media_clock` | The timestamp is the instant the block is written with (`TaggedPacket::now`), in ticks of the stream clock rate since the first repair packet, from a random offset. Was the media timestamp of the first covered packet (Bug 6, fixed) |
| FLEXFEC03-4.2-7 | 4.2 | MUST | Repair SSRC SHALL be randomly assigned | tested | `src/peer_connection/internal.rs` (`send_encodings_from_track`: `unused_ssrc_drawn`, the CSPRNG, when the track names none) | `minted_fec_ssrcs_are_random_across_peer_connections`, `explicit_repair_ssrcs_are_used_verbatim` | A minted repair SSRC is random (64 peer connections: no repeat, every bit varies; checked to fail with a fixed one). An SSRC the application names is its own random assignment and is used as given |
| FLEXFEC03-4.2-8 | 4.2 | SHOULD | Repair flow uses the RTCP CNAME to associate itself with the source flow | tested | `src/peer_connection/sdp/mod.rs` (same `a=ssrc ... cname` for the FEC SSRC), `src/rtp_transceiver/rtp_sender/internal.rs` (`local_stream_infos` binds the FEC SSRC), `rtci-interceptor/src/rtcp_session/mod.rs` (`Role::Repair`) | `flexfec_repair_flow_is_grouped_with_fec_fr`, `the_receiver_learns_the_cname_of_the_fec_ssrc_from_its_rtcp`, `media_rtx_and_fec_ssrcs_all_send_sender_reports` | The FEC SSRC is bound with the media stream and, from its first repair packet, sends sender reports and an SDES chunk with the connection's CNAME; between two peer connections the receiver learns that CNAME for it (the audit's "not bound as a local stream" no longer holds) |
| FLEXFEC03-4.2-9 | 4.2 | MUST | SSRC collisions of the repair flow are resolved as in RFC 3550 | tested | `rtcp_session/mod.rs` (`collision`), `rtp_sender/internal.rs` (`replace_ssrc`) | `a_colliding_repair_ssrc_alone_moves_to_the_replacement`, `a_collision_with_a_sender_ssrc_is_reported_and_the_packets_dropped` | A collision on the repair SSRC is detected like any local SSRC and moves that SSRC alone (RFC 3550 8.2) |
| FLEXFEC03-4.2-10 | 4.2 | MUST | R bit is 0 in repair packets | tested | `fec/draft03/encoder.rs:203` | `encoder.rs::the_version_bits_are_not_recovered` | |
| FLEXFEC03-4.2-11 | 4.2 | MAY | Retransmission packets (R=1, Figure 15 layout) | missing | `fec/draft03/decoder.rs:333-335` (discarded) | `it/flexfec03_conformance.rs::retransmission_and_fixed_offset_repair_packets_are_discarded` (the discard) | Never sent; a received one is discarded, and that is now tested. Reason (fec4): the draft-03 coder is for the browsers' `flexfec-03`, and libwebrtc's FlexfecSender never sends R=1 (it answers NACKs with RTX, which is negotiated next to `flexfec-03`); FlexFEC's own retransmission is implemented in the RFC 8627 coder (`FlexFecSendBuilder::with_retransmissions`), the form RFC 8627 section 1.1.7 relies on |
| FLEXFEC03-4.2-12 | 4.2 | MAY | F=1 repair packets (M columns / N rows offsets, Figures 13 and 14) | missing | `fec/draft03/decoder.rs:336-338` (discarded) | `it/flexfec03_conformance.rs::retransmission_and_fixed_offset_repair_packets_are_discarded` (the discard) | Never sent; a received one is discarded (tested), so a peer using fixed offsets gets no recovery. Reason (fec4): libwebrtc sends and reads only F=0 (flexible masks); fixed M/N offsets would need a second mask layout that serves no deployed peer, and RFC 8627 replaced them with its L/D row-column form, which the RFC 8627 coder has (`FlexFecProtection::Row` / `Column` / `RowAndColumn`) |
| FLEXFEC03-4.2-13 | 4.2 | MUST | SSRCCount 0 is invalid: the packet MUST be ignored | tested | `fec/draft03/decoder.rs:339-341` | `it/flexfec03_conformance.rs::a_repair_packet_with_ssrc_count_zero_is_ignored` | Anything other than 1 is rejected |
| FLEXFEC03-4.2-14 | 4.2 | MUST | Reserved 24 bits set to zero by senders | tested | `fec/draft03/encoder.rs:223` | `encoder.rs::the_header_names_the_stream_and_block_it_protects` | |
| FLEXFEC03-4.2-15 | 4.2 | MUST | Reserved 24 bits ignored by receivers | tested | `fec/draft03/decoder.rs:329-408` (bytes 9..12 never read) | `it/flexfec03_conformance.rs::the_reserved_bits_are_ignored_on_receive` |  |
| FLEXFEC03-4.2-16 | 4.2 | MAY | One repair packet protects several SSRCs (SSRCCount > 1, one SSRC / SN base / mask block each) | missing | `fec/draft03/decoder.rs:339-341`, `fec/draft03/encoder.rs:222` | none | Sender always writes 1; receiver discards anything else. Reason (fec4): libwebrtc's FlexfecSender protects one SSRC per repair stream, so no peer sends more; several SSRCs in one draft-03 repair packet need that header layout parsed (and fuzzed) for no counterpart. The RFC 8627 coder protects several sources (CSRC list) where that is wanted |
| FLEXFEC03-4.2-17 | 4.2 | MUST | Mask bit j set means the packet SN base + j + 1 is protected (literal draft text) | n/a | `fec/draft03/decoder.rs:410-417`, `fec/draft03/encoder.rs:266-306` | `encoder.rs::mask_bit_j_names_sn_base_plus_j_as_libwebrtc_sends_it`, `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically` | Superseded for this endpoint by RFC 8627 section 4.2.2.1 (media-25), which wrote the mask down as SN base + j, the reading of libwebrtc, the only draft-03 peer; the literal +1 has no sender. The `flexfec-03` coder keeps that reading, pinned by `mask_bit_j_names_sn_base_plus_j_as_libwebrtc_sends_it`. Recorded in `docs/conformance.md` (D4) |
| FLEXFEC03-4.2-18 | 4.2 | MUST | k bit: marks whether another mask follows; masks are 15, then 31, then 63 bits | tested | `fec/draft03/encoder.rs:228-241`, `fec/draft03/decoder.rs:346-407` | `encoder.rs::a_short_block_carries_one_mask_with_the_k_bit_set`, `a_longer_block_adds_the_second_mask`, `a_block_beyond_46_packets_adds_the_third_mask` | Polarity as the draft states it and libwebrtc sends it: "k=0 denotes that there is one more k-bit set, and k=1 denotes that it is the last block of bit mask" (k=1 is the last mask); mask sizes 15, 31, 63 ("2^(v+3)-1"). An earlier note said the draft read the other way round and contradicted itself; the draft text does not (audit-9, 2026-11-27) |
| FLEXFEC03-4.2-19 | 4.2 | MUST | A repair packet describes at most 109 source packets (15 + 31 + 63 mask bits) | tested | `fec/draft03/encoder.rs` (`DRAFT03_MAX_MEDIA_PACKETS = 109`, checked in `encode`) | `it/flexfec03_conformance.rs::a_block_of_110_packets_is_refused_and_109_recover`, `encoder.rs::a_block_longer_than_the_masks_can_describe_is_refused` | Bug 2, fixed. `coverage.rs` still describes 110 positions, which is the RFC 8627 mask width; the draft-03 encoder refuses a block above 109 |
| FLEXFEC03-4.2-20 | 4.2 | MUST | A truncated FEC header is not parsed past its end | tested | `fec/draft03/decoder.rs:330-332, 363-365, 382-384` | `it/flexfec_round_trip.rs::a_truncated_repair_packet_is_discarded` | Only the 20-byte bound is tested; the 24 and 32 byte bounds are not |
| FLEXFEC03-5.1-1 | 5.1 | MUST | `rate` SHALL be larger than 1000 Hz | n/a | none | none | The application registers the codec and its rate; the engine validates neither side |
| FLEXFEC03-5.1-2 | 5.1 | SHOULD | `rate` matches the protected stream's rate | n/a | none | none | Application's codec registration |
| FLEXFEC03-5.1-3 | 5.1 | MUST | Required parameter `repair-window` (microseconds) is signalled and bounds what is sent and buffered | tested | `rtci-interceptor/src/flexfec/draft03/sender.rs` (`close_expired_block`, `poll_timeout`), `draft03/decoder.rs` (`with_repair_window`, `decode_at`), `draft03/receiver.rs` and `sender.rs` (`bind_*_stream` read `StreamInfo::sdp_fmtp_line_fec`); `media_engine.rs` (`register_codec`, `repair_window_supported`) | `a_block_is_protected_when_its_repair_window_ends`, `the_negotiated_repair_window_bounds_recovery`, `the_repair_window_bounds_what_is_held_for_recovery`; `src/peer_connection/configuration/media_engine/media_engine_test.rs::flexfec_offered_without_a_repair_window_is_not_negotiated`, `a_flexfec_format_registered_without_a_repair_window_gets_the_default_one` | The negotiated `repair-window` bounds both sides: a block is protected no later than the window after its first packet left, and the receiver holds media and repair packets for recovery no longer than the window after they arrived (the packet-count limits stay). Signalled as the application registers the codec (`a=fmtp:<pt> repair-window=...`, as browsers write it): the engine does not add the parameter to a registration without it jsep10: signalled always (a default when registered without), required of the remote format, and bounded by the registered window. |
| FLEXFEC03-5.1-4 | 5.1 | MAY | Optional parameters `L`, `D`, `ToP` | missing | none | none | Not parsed, not generated. Reason (fec4): libwebrtc's `flexfec-03` fmtp carries `repair-window` only, and RFC 8627 section 5.1 dropped L, D and ToP (its registration has `repair-window` alone), so the parameters serve neither the browsers nor the RFC; one coherent piece with 5.2.1-1 and 6.3.1.1-1 if a peer ever states them |
| FLEXFEC03-5.1-5 | 5.1 | MUST | Media subtype name is `flexfec` | n/a | `src/peer_connection/configuration/media_engine.rs` (`MIME_TYPE_FLEX_FEC03`), `rtp_codec.rs` (`is_flexfec03_mime_type`) | `rtp_codec_flexfec_test.rs::the_mime_type_match_is_exact`, `rtp_codec_flexfec_test.rs::rfc_8627_flexfec_is_not_the_draft_03_coder` | Superseded for this endpoint by RFC 8627 section 5.1 (media-25): IANA registers `flexfec` to RFC 8627, whose coder the name selects (`rfc_8627_flexfec_is_not_the_draft_03_coder`); the draft-03 coder answers to libwebrtc's `flexfec-03` (`the_mime_type_match_is_exact`). Recorded in `docs/conformance.md` (D4) |
| FLEXFEC03-5.2-1 | 5.2 | MUST | Subtype and rate go in `a=rtpmap`, remaining parameters in `a=fmtp` | tested | `src/peer_connection/sdp/mod.rs` (codec lines) | `tests/repair_codec_negotiation.rs::flexfec_codec_is_offered_alongside_the_track_codec` | |
| FLEXFEC03-5.2.1-1 | 5.2.1 | SHOULD | Receiver offered several L/D combinations chooses one with sufficient interleaving | missing | none | none | L and D are not understood. Reason (fec4): as FLEXFEC03-5.1-4: no browser states them (libwebrtc's fmtp is `repair-window` only) and RFC 8627 removed them; a `flexfec-03` format with them is still negotiated, its L and D ignored as unknown parameters |
| FLEXFEC03-5.2.1-2 | 5.2.1 | MUST | Receiver takes the offered repair-window into account for its buffering when accepting | tested | `draft03/receiver.rs` (`bind_remote_stream`), `draft03/decoder.rs` (`decode_at`) | `the_negotiated_repair_window_bounds_recovery`, `the_repair_window_bounds_what_is_held_for_recovery` | The remote description's `repair-window` sets the time bound of the decoder's buffers for the stream |
| FLEXFEC03-5.2.1-3 | 5.2.1 | MUST | Unknown fmtp options in the offer are ignored and deleted from the answer | tested | `configuration/media_engine.rs` (`local_fmtp_line`: a FlexFEC answer states this endpoint's fmtp) | `a_flexfec_03_answer_drops_unknown_options` | Was violated: the answer repeated the offer's line; fixed |
| FLEXFEC03-5.2.1-4 | 5.2.1 | MAY | Receiver removes FEC from the answer when not desired | tested | `media_engine.rs:886-960, 1178-1218` (a codec that is not registered is not answered) | `an_answer_without_fec_drops_the_fec_formats_and_their_red` | Default behaviour: `flexfec-03` offered is not answered |
| FLEXFEC03-5.2.2-1 | 5.2.2 | MUST | Declarative SDP: use the configuration provided | n/a | none | none | Offer/answer only |
| FLEXFEC03-6.2-1 | 6.2 | MUST | FEC bit string: P, X, CC, M, PT recovery are the XOR of the source headers; first two bits skipped | tested | `fec/draft03/encoder.rs:200-203` | `encoder.rs::recovery_fields_are_the_xor_of_the_protected_packets` | |
| FLEXFEC03-6.2-2 | 6.2 | MUST | Length recovery is the XOR of (packet length - 12): CSRC list, extension, payload and padding included | tested | `fec/draft03/encoder.rs:205-207` | `encoder.rs::recovery_fields_are_the_xor_of_the_protected_packets` | Tested only with packets that have no CSRC, extension or padding |
| FLEXFEC03-6.2-3 | 6.2 | MUST | TS recovery is the XOR of the source timestamps | tested | `fec/draft03/encoder.rs:212-214` | `encoder.rs::recovery_fields_are_the_xor_of_the_protected_packets` | |
| FLEXFEC03-6.2-4 | 6.2 (4.2) | MUST | SN base MUST be the lowest sequence number of the source packets this repair packet protects | tested | `fec/draft03/encoder.rs` (`encode_one`: base and mask relative to the first packet the repair packet covers) | `it/flexfec03_conformance.rs::each_repair_packet_carries_its_own_lowest_sequence_number_as_sn_base`, `encoder.rs::sn_base_is_the_lowest_sequence_number_each_repair_packet_protects`, `encoder.rs::the_declared_mask_matches_the_interleaved_coverage` | Bug 3, fixed |
| FLEXFEC03-6.2-5 | 6.2 | MUST | Repair payload is the XOR of everything after the 12-byte header; shorter packets padded with zero octets at the end | tested | `fec/draft03/encoder.rs:181-220` | `encoder.rs::the_repair_payload_is_the_xor_of_the_protected_payloads`, `the_repair_payload_is_as_long_as_the_largest_protected_packet` | |
| FLEXFEC03-6.2-6 | 6.2 | MUST | CSRC list, header extension and RTP padding of source packets are part of the protected data | tested | `fec/draft03/encoder.rs:193-196` (marshals the whole packet) | `it/flexfec03_conformance.rs::a_lost_packet_with_csrcs_an_extension_and_padding_is_recovered_byte_identically` |  |
| FLEXFEC03-6.2-7 | 6.2 | SHOULD | Repair packet (largest source + 20 to 32 bytes) should not exceed the path MTU | tested | `rtci-interceptor/src/flexfec/draft03/encoder.rs` (`DRAFT03_MAX_REPAIR_PACKET_SIZE`, `FlexFec03Encoder::with_max_packet_size`) | `rtci-interceptor/src/flexfec/draft03/encoder.rs::a_repair_packet_larger_than_the_path_allows_is_not_built` | fec2: a repair packet larger than 1436 octets (a 1500-octet path under IPv6, UDP and a 16-octet SRTP tag) is not built and takes no sequence number; the block goes without it |
| FLEXFEC03-6.3-1 | 6.3 | MUST | Whatever algorithm is used, the result is identical to the specified one | tested | `fec/draft03/decoder.rs:259-318` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically`, `one_repair_packet_covering_the_whole_block_recovers_any_single_loss` | |
| FLEXFEC03-6.3.1-1 | 6.3.1 | MUST | A repair packet with more than one missing source packet recovers nothing | tested | `fec/draft03/decoder.rs:241-246` | `it/flexfec_round_trip.rs::two_losses_under_one_repair_packet_recover_neither` | |
| FLEXFEC03-6.3.1.1-1 | 6.3.1.1 | MAY | Association signalled entirely in SDP (L, D, ToP) | missing | none | none | Not implemented. Reason (fec4): as FLEXFEC03-5.1-4 (ToP / L / D from SDP: no peer states them, RFC 8627 removed them) |
| FLEXFEC03-6.3.1.2-1 | 6.3.1.2 | MUST | Bitmask association over 15, 46 and 109 bit masks | tested | `fec/draft03/decoder.rs:346-407` | `it/flexfec_round_trip.rs::a_block_using_the_second_packet_mask_round_trips`, `a_block_using_the_third_packet_mask_round_trips`, `a_block_that_wraps_the_sequence_space_round_trips` | |
| FLEXFEC03-6.3.1.3-1 | 6.3.1.3 | MAY | Association by M and N offsets | missing | none | none | See FLEXFEC03-4.2-12 (fixed offsets: no peer sends them; RFC 8627's L/D form is implemented instead) |
| FLEXFEC03-6.3.2-1 | 6.3.2 | MUST | Recovered header: version 2; M, PT, SN (= SEQNUM), TS from the recovered bit string | tested | `fec/draft03/decoder.rs:262-300` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically` | |
| FLEXFEC03-6.3.2-2 | 6.3.2 | MUST | Recovered header: P, X and CC from the recovered bit string | tested | `fec/draft03/decoder.rs:283-289` | `it/flexfec03_conformance.rs::a_lost_packet_with_csrcs_an_extension_and_padding_is_recovered_byte_identically` | Depends on `rtp::Packet` re-marshalling a received packet as it arrived, which holds for zero padding octets (`packet/padding_size_test.rs`) |
| FLEXFEC03-6.3.2-3 | 6.3.2 | MUST | Recovered length Y is taken from the length recovery field | tested | `fec/draft03/decoder.rs:291-295` | `it/flexfec_round_trip.rs::packets_of_different_lengths_are_recovered_at_their_own_length`, `a_repair_packet_with_a_truncated_payload_recovers_nothing` | |
| FLEXFEC03-6.3.2-4 | 6.3.2 | MUST | SSRC of the recovered packet is the source stream's SSRC | tested | `fec/draft03/decoder.rs:297` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically` | |
| FLEXFEC03-6.3.3-1 | 6.3.3 | MUST | Payload recovery: XOR Y octets from octet 13 of each received packet, shorter ones zero padded at the end | tested | `fec/draft03/decoder.rs:299-311` | `it/flexfec_round_trip.rs::packets_of_different_lengths_are_recovered_at_their_own_length` | |
| FLEXFEC03-6.3.4-1 | 6.3.4 | MUST | Iterative decoding: a recovered packet is fed back so other repair packets can complete | tested | `fec/draft03/decoder.rs:232-257` (loop) | `it/flexfec03_conformance.rs::a_recovered_packet_completes_another_repair_packet` |  |
| FLEXFEC03-8-1 | 8 | SHOULD | Consider the impact of FEC in congested networks before injecting repair flows | n/a | none | none | Application decides to register the interceptor |
| FLEXFEC03-8-2 | 8 | MUST | MUST NOT arbitrarily increase the amount of FEC | tested | `rtci-interceptor/src/cc/fec_rate.rs` (`FecRate`), `fec/draft03/sender.rs` | `the_amount_of_fec_stays_at_the_configured_ratio`, `the_receivers_loss_sets_how_much_flexfec_is_sent`, `the_fec_bit_rate_is_taken_out_of_the_target_the_application_sees` | The amount changes only with the loss the receiver reports, at most half the block, and the repair bit rate is taken out of the target the application encodes at, so media and FEC together stay at the congestion controller's target. Without reports (or `with_adaptive_rate(false)`) the configured ratio |
| FLEXFEC03-8-3 | 8 | SHOULD | Do not send repair flows when they would not help recover anything | tested | `rtci-interceptor/src/cc/fec_rate.rs` (`MIN_LOSS`), `fec/draft03/sender.rs` (`protect`) | `the_receivers_loss_sets_how_much_flexfec_is_sent`, `no_loss_means_no_repair_and_more_loss_more_repair_up_to_the_bound` | Under 0.5% reported loss no repair packet is sent |
| FLEXFEC03-8-4 | 8 | SHOULD | Adjust the amount of FEC dynamically from the observed loss rate | tested | `rtci-interceptor/src/cc/fec_rate.rs` (`FecRate::on_read`, `fec_packets`) | `the_receivers_loss_sets_how_much_flexfec_is_sent`, `the_loss_is_smoothed_over_reports`, `a_fixed_flexfec_rate_ignores_the_loss` | Repair packets per block from the smoothed receiver-report loss: ceil(2 x loss x block), at most half the block. `FlexFec03SendBuilder::with_adaptive_rate(false)` keeps the configured ratio |
| FLEXFEC03-8-5 | 8 | SHOULD | Multicast: offer several repair flows with different protection | n/a | none | none | No multicast |
| FLEXFEC03-9-1 | 9 | SHOULD | Repair packets get the same confidentiality, integrity and source authentication as media (SRTP) | tested | chain write path to the SRTP handler | `tests/flexfec03_encoder_decoder.rs::flexfec03_recovers_every_dropped_packet` | End to end over DTLS-SRTP |

## Gaps, in order of importance

1. **FEC and transport-wide CC cannot be used together (S/M).** FLEXFEC03-4.1-1, Bugs 1, 4 and 5. Move the
   encoder wire-ward of everything that edits a media header (or stamp the transport-cc extension before
   the encoder and only rewrite its value in a way the receiver undoes), let repair packets be seen by the
   arrival recorders (TWCC, RFC 8888, receiver report) before the decoder swallows them, and have those
   recorders skip packets tagged `RecoveredByFec`.
2. **Wire-format corrections (S).** Done on `conf/cc-fec-flexfec`: FLEXFEC03-4.2-19 (blocks capped at 109),
   FLEXFEC03-6.2-4 (per-packet SN base), FLEXFEC03-4.2-6 (timestamp from the send clock), FLEXFEC03-4.2-5
   (random initial sequence number), FLEXFEC03-4.2-2 (marker = 0 asserted).
3. **Repair stream as an RTP source (M).** FLEXFEC03-4.2-8 done (sender reports and SDES CNAME for the
   repair SSRC, `the_receiver_learns_the_cname_of_the_fec_ssrc_from_its_rtcp`); FLEXFEC03-4.2-9 (SSRC
   collision handling of the repair flow) open.
4. **`repair-window` (M).** FLEXFEC03-5.1-3, FLEXFEC03-5.2.1-2: generate the parameter, parse the peer's,
   size the decoder's buffers from it instead of fixed packet counts, never send a block spanning more.
5. **Adaptive protection (M).** Done (`FecRate`): FLEXFEC03-8-3, FLEXFEC03-8-4: a runtime control (or a loss-driven
   controller fed from receiver reports) for the media/repair ratio, and an MTU check
   (FLEXFEC03-6.2-7) so a repair packet is not built larger than the path allows.
6. **Receive-side generality (M).** FLEXFEC03-4.2-16 (several SSRCs per repair packet), FLEXFEC03-4.2-12 /
   6.3.1.3-1 (F=1 offsets), FLEXFEC03-4.2-11 (R=1 retransmission), FLEXFEC03-5.1-4, 5.2.1-1, 6.3.1.1-1
   (L, D, ToP). libwebrtc sends none of these, so this is last.
7. **Tests for what is implemented but unproven (S).** Done on `conf/cc-fec-flexfec` for FLEXFEC03-4.2-13,
   4.2-15, 6.2-6, 6.3.2-2, 6.3.4-1, 8-2 and the R=1 / F=1 discard paths. FLEXFEC03-5.2.1-3 stays with gap 8.
8. **Answer fmtp (shared, M).** FLEXFEC03-5.2.1-3: the answer must be written from the local codec, not
   echo the offer; tracked as gap 1 of the RFC 7587 audit.

## Bugs found

1. **FEC is computed over a packet that is not the one sent, when a TWCC sender is in the chain.**
   `Slot::FecEncoder` is 5000 and `Slot::TwccSender` is 2000 (`rtci-interceptor/src/registry.rs:45,81`); the
   write walk runs high to low, so `FlexFec03SendInterceptor::handle_write` XORs the packet before
   `TwccSenderInterceptor::handle_write` (`twcc/sender.rs:112-126`) calls `set_extension`. When the
   application's packet has no extension block, that call adds one (the packet grows and X flips); when it
   has one, the 16-bit counter is rewritten. The receiver XORs the wire packets, so the recovered packet has
   the wrong length recovery and shifted, corrupt contents (or, same-size case, a corrupt extension value).
   Reproduction: build a chain with `Slot::FecEncoder` + `Slot::TwccSender` bound to one stream with the
   transport-cc extension, write 5 media packets, feed all outputs but one media packet to a
   `FlexFec03Decoder`, and compare the recovered bytes with the wire bytes of the dropped packet.
2. **(Fixed on `conf/cc-fec-flexfec`.) A 110-packet block corrupts recovery.** `fec/coverage.rs:5` allows 110 media packets, but draft-03's
   third mask has 63 bits (indices 46..108). `BitArray::mask3_draft03` (`fec/bit_array.rs:68-70`) shifts
   index 109 out, while `ProtectionCoverage::covered_by` still returns it, so `encode_one` XORs packet 109
   into the repair data without naming it in the mask. Any recovery from that repair packet is the lost
   packet XOR packet 109. Reproduction: `FlexFec03Encoder::encode(&run(110), 1)`, drop media packet 0, decode
   the rest plus the repair packet, compare with the original (expect mismatch); also
   `parse_packet_mask` of the repair payload shows bit 109 unset.
3. **(Fixed on `conf/cc-fec-flexfec`.) SN base is not the lowest protected sequence number.** `fec/draft03/encoder.rs:139,225`: with two
   repair packets over a block starting at 100, the second carries SN base 100 and a mask starting at bit 1.
   Interoperable (a decoder honours any base), but it violates the MUST and wastes mask range: an
   interleaved block reaches the second and third masks earlier than needed. Reproduction: the existing
   `the_declared_mask_matches_the_interleaved_coverage` already shows it; assert `payload[16..18]` of the
   second repair packet equals 101.
4. **Repair packets are never acknowledged to the sender's congestion controller.**
   `FlexFec03ReceiveInterceptor::handle_read` (`fec/draft03/receiver.rs:104-111`) swallows repair packets
   at slot 6000, before `TwccReceiver` (8000), `Rfc8888` (9000) and `ReceiverReport` (10000). The sending
   side numbers them (they pass `TwccSender`) and records them in its send history, then sees every one as
   lost. Reproduction: sender chain with FEC + TWCC + congestion control, receiver chain with FEC decoder +
   TWCC receiver; inspect the TWCC feedback: the repair packets' transport sequence numbers are reported
   not received.
5. **Recovered packets are reported as arrived.** `Attribute::RecoveredByFec` is attached
   (`fec/draft03/receiver.rs:191`) and documented as the way an arrival recorder tells "present" from
   "arrived" (`rtci-interceptor/src/packet.rs:61-67`), but nothing in `rtci-interceptor/src` reads it: the TWCC
   recorder, the RFC 8888 recorder and the receiver-report stream count a rebuilt packet as received at
   recovery time. Loss is hidden from the remote's congestion control and from `fraction lost`.
   Reproduction: receiver chain with FEC decoder + `ReceiverReportInterceptor`; drop one media packet that
   FEC recovers; the next RR reports 0 lost.
6. **(Fixed on `conf/cc-fec-flexfec`.) Repair timestamp is media time, not send time** (`fec/draft03/encoder.rs:256-259`), FLEXFEC03-4.2-6.
   Reproduction: encode a block whose media timestamps are constant (one large frame); every repair packet
   of every such block within the frame carries the same timestamp regardless of when it is sent.
