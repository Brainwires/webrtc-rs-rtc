use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::sctp::{SctpPath, SctpTransport};
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message;
use datachannel::message::message_channel_threshold::DataChannelThreshold;
use log::{debug, warn};
use sctp::{
    Association, AssociationError, AssociationEvent, AssociationHandle, ClientConfig,
    DatagramEvent, EndpointEvent, Event, MessagePart, Payload, PayloadProtocolIdentifier,
    ReconfigEvent, ReliabilityType, Stream, StreamEvent, StreamId,
};
use shared::error::{Error, Result};
use shared::marshal::Unmarshal;
use shared::{TransportContext, TransportMessage};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

pub(crate) struct SctpHandlerContext {
    pub(crate) sctp_transport: SctpTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    // Batch-drain state: handle_read/handle_write/handle_timeout only INGEST (set
    // `flush_dirty`); the single transmit flush runs in poll_write, once per driver
    // event-loop iteration. Paired with the driver's burst-read, N received DATA
    // chunks are processed before one flush, so the ack machine coalesces them into
    // ONE SACK (1st arms Delay, 2nd+ stay Immediate until flushed) instead of one
    // SACK per two packets — cutting sendto/recvfrom and amortizing per-iteration
    // cost. `now` carries the newest timestamp seen into that flush.
    flush_dirty: bool,

    /// Set by [`SctpHandler::request_abort`]: abort every association at the next `poll_write`.
    abort_requested: bool,

    /// Streams left with unread data because the pipeline backlog was over its bound.
    ///
    /// This set is what makes bounded draining safe. `StreamEvent::Readable` is
    /// **edge-triggered** — `association/mod.rs` emits it from `handle_data` when a *new* DATA
    /// chunk arrives, and from ForwardTSN; it is never re-emitted merely because unread data
    /// remains. So a handler that stops mid-stream gets no further notification, and the
    /// moment back-pressure works the peer stops sending, so no new chunk arrives, so no new
    /// `Readable` fires: **the stream would deadlock exactly when the feature engages.**
    /// Remembering the stream here is the level-triggered re-arm that closes that hole: a
    /// parked stream is retried from `poll_read` (the application asks for data), from
    /// `handle_read`, and from `handle_timeout`, for which `poll_timeout` reports a deadline as
    /// soon as the pipeline has room for it again (see [`SctpHandler::resumable`]).
    pending_readable: HashSet<(AssociationHandle, StreamId)>,

    /// A drain from `poll_read` took data out of a receive buffer, and the SACK that tells
    /// the peer about the space has not been flushed yet.
    ///
    /// RFC 9260 section 6.2: a receiver sends a SACK "to update the offered window as the
    /// receiving application consumes new data", and once the window advertised as closed
    /// opens again the association queues that SACK at once
    /// (`Association::on_receive_buffer_drained`). The flush runs in `poll_write`, which a
    /// caller has usually already made when it reads: without a deadline the SACK waited for
    /// whatever woke the caller next, and the peer, stopped by a zero window, for its window
    /// probe a retransmission timeout later. `poll_timeout` reports the deadline while this is
    /// set; `poll_write` and `handle_timeout` clear it.
    window_update_due: bool,

    /// Streams the peer created whose first message has not been drained yet.
    ///
    /// RFC 8832 §5.1: the Channel Type and Reliability Parameter of a `DATA_CHANNEL_OPEN`
    /// describe the data channel, and both of its directions are sent with them. The opener
    /// configures its stream from its own OPEN in `handle_write`; the accepting side has to
    /// configure its outgoing direction from the OPEN it receives, which is the first message
    /// on a stream the peer created. A stream enters this set on `StreamEvent::Opened` and
    /// leaves it when its first message is drained, so only that message can configure it,
    /// and a stream this side opened itself is never reconfigured by the peer.
    peer_opened_streams: HashSet<(AssociationHandle, StreamId)>,

    /// Unordered channels this side opened in band that have not heard from the peer yet,
    /// with the reliability they were opened with.
    ///
    /// RFC 8832 section 6: "before the DATA_CHANNEL_ACK message or any other message has been
    /// received on a data channel, all other messages containing user data and belonging to
    /// this data channel MUST be sent ordered, no matter whether the data channel is ordered
    /// or not". Until then the peer may not have seen the DATA_CHANNEL_OPEN, and an unordered
    /// message could reach it before the OPEN does: data on a stream it has no channel for,
    /// which it must answer by resetting the stream. So the stream starts out ordered and is
    /// switched to unordered when its first message from the peer is drained; a stream enters
    /// here when its OPEN is written and leaves then, or when it closes.
    ordered_until_reply: HashMap<(AssociationHandle, StreamId), (ReliabilityType, u32)>,

    /// Associations that came up here and whose `SCTPHandshakeComplete` still waits in
    /// `event_outs`.
    ///
    /// Their inbound data is held back (parked in `pending_readable`) until the event has
    /// been handed on. The event and the data travel by different queues: `Event::Connected` becomes
    /// an event, which the pipeline hands on in `poll_event`, while a `Readable` stream
    /// becomes a read, which it hands on within the same `handle_read`. Data that came in the
    /// same sweep as the COOKIE ACK (or ECHO) that brought the association up — a peer may
    /// send the moment its own side is up — would otherwise reach the data channel handler
    /// before the event on which that handler opens the negotiated channels: the message
    /// finds its channel not open yet and is dropped, though SCTP has already acknowledged
    /// it. [`SctpHandler::poll_event`] takes the association out of here as it hands the
    /// event on, and the pipeline pumps the reads right after the events, so the held data
    /// follows at once.
    unannounced: HashSet<AssociationHandle>,

    /// Transport context of the most recent inbound datagram, **per association**.
    ///
    /// A resumed drain has no triggering packet to copy this from. A single `last_transport`
    /// would be wrong the moment the endpoint carries more than one association — and it can:
    /// `sctp_associations` is a map, and `establish_two()` in the tests builds exactly that
    /// case. Messages resumed for association A would then be stamped with B's peer address.
    ///
    /// Keyed by association because the 5-tuple is a property of the association, not of the
    /// stream. An association with no entry has never received a datagram, so it cannot have
    /// parked data either.
    association_transport: HashMap<AssociationHandle, TransportContext>,

    /// What lies under the associations may have changed (ICE selected a candidate pair, or a
    /// DTLS handshake completed and with it a cipher suite): the peer connection, which sees
    /// both, works the path out again before the handler is used next
    /// ([`SctpHandlerContext::take_path_refresh`], [`SctpHandler::apply_path`]).
    path_dirty: bool,

    /// ICE selected a candidate pair since the path was last applied: the associations are
    /// told that their packets take another path (RFC 8831 section 5).
    path_changed: bool,

    /// The ICE handler's count of selected-pair changes when the path was last asked for
    /// (`IceHandlerContext::selected_pair_changes`).
    selected_pair_changes: u64,

    /// Messages SCTP gives out in parts (RFC 9260 6.9), put together here for the data
    /// channels, which deliver whole messages only (W3C webrtc 6.2, "receiving messages").
    reassembly: InboundReassembly,

    /// The newest instant a caller has supplied, seeded at construction.
    ///
    /// This is the one place in the core that genuinely needs a retained instant: the flush is
    /// armed by a `handle_*` but executed by the next `poll_write`, and `flush_transmits` does
    /// real time-dependent work there — retransmit timers, congestion window, SACK scheduling.
    /// It was `Option<Instant>` with an `unwrap_or_else(Instant::now)` fallback only because
    /// nothing seeded it; that fallback was taken on **every client connection**, for the flush
    /// that emits the INIT chunk. Seeding at construction makes the `Option` unnecessary.
    now: Instant,
}

impl SctpHandlerContext {
    pub(crate) fn new(now: Instant, sctp_transport: SctpTransport) -> Self {
        Self {
            sctp_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            flush_dirty: false,
            abort_requested: false,
            pending_readable: HashSet::new(),
            window_update_due: false,
            peer_opened_streams: HashSet::new(),
            ordered_until_reply: HashMap::new(),
            unannounced: HashSet::new(),
            association_transport: HashMap::new(),
            path_dirty: false,
            path_changed: false,
            selected_pair_changes: 0,
            reassembly: InboundReassembly::default(),
            now,
        }
    }

    /// Whether the path under the associations has to be worked out again, asked once per
    /// change: the caller then hands the answer to [`SctpHandler::apply_path`].
    ///
    /// `selected_pair_changes` is how many times ICE has selected another candidate pair so
    /// far. RFC 8831 section 5: "SCTP SHOULD be notified when an address change has
    /// happened." The association runs on a placeholder address and the selected-pair event
    /// ends at the DTLS handler, so a count that moved is how this handler learns of it.
    pub(crate) fn take_path_refresh(&mut self, selected_pair_changes: u64) -> bool {
        if selected_pair_changes != self.selected_pair_changes {
            self.selected_pair_changes = selected_pair_changes;
            self.path_dirty = true;
            self.path_changed = true;
        }
        std::mem::take(&mut self.path_dirty)
    }

    /// Records the newest instant a caller has supplied.
    ///
    /// `max` rather than assignment, and without a monotonicity assert: an outbound message
    /// carries the instant of the input that *caused* it, so `handle_write` can legitimately be
    /// handed one older than the newest seen. See the design's §9.3.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }
}

/// The limits a drain reads under: the largest message accepted (the `max-message-size` this
/// side advertised, RFC 8841 6.1) and the most bytes of incomplete messages held above an
/// association.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReceiveLimits {
    pub(crate) message: usize,
    pub(crate) partial: usize,
}

/// An incomplete message of one stream: the parts SCTP gave out so far.
#[derive(Debug)]
struct PartialMessage {
    ppi: PayloadProtocolIdentifier,
    payload: BytesMut,
    /// The message is refused (larger than this side accepts, or over the association's
    /// limit): its parts are dropped as they come, up to its end of record.
    refused: bool,
    /// It was refused for the association's limit: once it has ended, its data channel is
    /// closed.
    close_at_end: bool,
}

/// What a part made of its message.
#[derive(Debug, PartialEq)]
enum PartOutcome {
    /// More parts are to come.
    Incomplete,
    /// The message is whole.
    Complete(PayloadProtocolIdentifier, BytesMut),
    /// The message is larger than this side accepts (RFC 8841 6.1): dropped, as a whole
    /// message that large is.
    TooLarge,
    /// Holding it would take the association past its limit for incomplete messages:
    /// dropped, and its data channel fails (RFC 8831 6.6). Its stream is reset once the
    /// message has ended (`ended`), so that what is still to come of it is read and dropped
    /// rather than left in the SCTP receive buffer, where it would hold the window closed.
    OverLimit { ended: bool },
    /// A part of a message already refused; `close` when it ended a message refused for the
    /// association's limit.
    Dropped { close: bool },
}

/// Puts together the messages SCTP gives out in parts.
///
/// RFC 9260 6.9 lets the receiver hand the first fragments of a message to the upper layer
/// before the rest has arrived, which frees the SCTP receive buffer and so reopens the window
/// (6.2). The data channel API delivers whole messages only, so the parts are joined here,
/// outside the association's receive buffer. Bounded twice: each message by the
/// `max-message-size` this side advertised (RFC 8841 6.1, a larger one is dropped as before),
/// and the bytes of all incomplete messages of an association by `ReceiveLimits::partial`
/// (the larger of its receive buffer and that message size). A peer that has more in progress
/// at once than that (one message per stream at most, RFC 8260 2.2.2) loses the data channel
/// whose part would go over: RFC 8831 6.6, an error "related to the received message", for
/// which "the receiver SHOULD close the corresponding data channel".
#[derive(Debug, Default)]
pub(crate) struct InboundReassembly {
    messages: HashMap<(AssociationHandle, StreamId), PartialMessage>,
    /// Bytes held in `messages`, per association.
    held: HashMap<AssociationHandle, usize>,
}

impl InboundReassembly {
    /// Bytes of incomplete messages held for association `ch`.
    pub(crate) fn held(&self, ch: AssociationHandle) -> usize {
        self.held.get(&ch).copied().unwrap_or(0)
    }

    fn release(&mut self, ch: AssociationHandle, n: usize) {
        if let Some(held) = self.held.get_mut(&ch) {
            *held = held.saturating_sub(n);
            if *held == 0 {
                self.held.remove(&ch);
            }
        }
    }

    /// Adds `part` of the message on `(ch, id)`.
    fn add(
        &mut self,
        ch: AssociationHandle,
        id: StreamId,
        part: &MessagePart,
        limits: ReceiveLimits,
    ) -> PartOutcome {
        let key = (ch, id);
        if part.first
            && let Some(old) = self.messages.remove(&key)
        {
            self.release(ch, old.payload.len());
        }
        let len = part.chunks.len();
        if part.first && part.end_of_record && !self.messages.contains_key(&key) {
            // Whole in one part: nothing is held here.
            return match part.chunks.to_payload(limits.message) {
                Ok(payload) => PartOutcome::Complete(part.chunks.ppi, payload),
                Err(_) => PartOutcome::TooLarge,
            };
        }
        let entry = self.messages.entry(key).or_insert_with(|| PartialMessage {
            ppi: part.chunks.ppi,
            payload: BytesMut::new(),
            // A later part whose first one this side never saw (the stream was taken over
            // from a restarted association, say) cannot make a message.
            refused: !part.first,
            close_at_end: false,
        });
        let outcome = if entry.refused {
            PartOutcome::Dropped {
                close: part.end_of_record && entry.close_at_end,
            }
        } else if entry.payload.len() + len > limits.message {
            PartOutcome::TooLarge
        } else if self.held.get(&ch).copied().unwrap_or(0) + len > limits.partial {
            entry.close_at_end = true;
            PartOutcome::OverLimit {
                ended: part.end_of_record,
            }
        } else {
            let start = entry.payload.len();
            entry.payload.resize(start + len, 0);
            let _ = part.chunks.read(&mut entry.payload[start..]);
            *self.held.entry(ch).or_default() += len;
            PartOutcome::Incomplete
        };
        if matches!(
            outcome,
            PartOutcome::TooLarge | PartOutcome::OverLimit { .. }
        ) {
            entry.refused = true;
            let dropped = std::mem::take(&mut entry.payload).len();
            self.release(ch, dropped);
        }
        if part.end_of_record {
            let done = self.messages.remove(&key).expect("present");
            self.release(ch, done.payload.len());
            if outcome == PartOutcome::Incomplete {
                return PartOutcome::Complete(done.ppi, done.payload);
            }
        }
        outcome
    }

    /// Drops what is held of stream `id`'s message: it ended without its last part
    /// (`StreamEvent::PartialDeliveryAborted`), or the stream is gone. Returns whether it was
    /// refused for the association's limit, so that its data channel is to be closed now.
    pub(crate) fn forget(&mut self, ch: AssociationHandle, id: StreamId) -> bool {
        match self.messages.remove(&(ch, id)) {
            Some(old) => {
                self.release(ch, old.payload.len());
                old.close_at_end
            }
            None => false,
        }
    }

    /// Drops everything held for association `ch`.
    pub(crate) fn forget_association(&mut self, ch: AssociationHandle) {
        self.messages.retain(|(handle, _), _| *handle != ch);
        self.held.remove(&ch);
    }

    fn clear(&mut self) {
        self.messages.clear();
        self.held.clear();
    }
}

fn receive_limits(transport: &SctpTransport) -> ReceiveLimits {
    ReceiveLimits {
        message: transport.receive_message_limit,
        partial: transport.partial_message_limit,
    }
}

/// How many undelivered inbound messages the pipeline may hold before this handler stops
/// draining SCTP's reassembly queues.
///
/// Draining unconditionally is what defeats SCTP's own flow control: bytes left in a
/// reassembly queue are what `get_my_receiver_window_credit()` subtracts from
/// `max_receive_buffer_size`, and that credit is advertised as `a_rwnd` in every SACK. Empty
/// the queue on arrival and `a_rwnd` never falls, so the peer is never told to slow down and
/// the backlog reappears — unbounded — further up the pipeline. Leaving messages in the
/// reassembly queue is not a leak; it is the mechanism.
///
/// The bound is a message count, so the bytes held depend on message size; SCTP's own
/// `max_receive_buffer_size` (1 MiB by default, `SettingEngineBuilder::with_sctp_max_receive_buffer_size`)
/// is the byte-denominated bound underneath it and is what the peer actually sees.
pub(crate) const SCTP_PIPELINE_READ_BACKLOG_LIMIT: usize = 256;

/// SctpHandler implements SCTP Protocol handling
pub(crate) struct SctpHandler<'a> {
    ctx: &'a mut SctpHandlerContext,
    /// Undelivered messages already sitting in `pipeline_context.read_outs`.
    ///
    /// Passed in rather than read from `ctx` because **this handler's own `read_outs` is not
    /// where the backlog forms**: the pipeline drains it into `intermediate_routs` inside the
    /// same `handle_read` call, so it is empty again by the time anything could observe it.
    /// Bounding against it would be a no-op. The queue that actually grows when the
    /// application stops consuming is the pipeline's, one hop downstream.
    downstream_backlog: usize,
}

impl<'a> SctpHandler<'a> {
    pub(crate) fn new(ctx: &'a mut SctpHandlerContext, downstream_backlog: usize) -> Self {
        SctpHandler {
            ctx,
            downstream_backlog,
        }
    }

    /// How many more messages may be pulled out of SCTP before the pipeline is over its bound.
    fn read_budget(&self) -> usize {
        SCTP_PIPELINE_READ_BACKLOG_LIMIT
            .saturating_sub(self.downstream_backlog)
            .saturating_sub(self.ctx.read_outs.len())
    }

    /// Drain one stream while budget allows, recording it as pending if data is left behind.
    ///
    /// Returns the messages read. The budget is checked **before** each `read_sctp()` because
    /// that call consumes a message: testing afterwards would mean having already taken the
    /// thing there was no room for.
    ///
    /// Both the immediate drain in `handle_read` and the resumed one in `resume_pending_reads`
    /// come through here, so the first message of a peer-opened stream configures the stream
    /// (see [`Self::apply_peer_reliability`]) whichever of the two delivers it.
    #[allow(clippy::too_many_arguments)]
    fn drain_stream(
        ctx_pending: &mut HashSet<(AssociationHandle, StreamId)>,
        peer_opened: &mut HashSet<(AssociationHandle, StreamId)>,
        ordered_until_reply: &mut HashMap<(AssociationHandle, StreamId), (ReliabilityType, u32)>,
        unannounced: &HashSet<AssociationHandle>,
        reassembly: &mut InboundReassembly,
        conn: &mut Association,
        ch: AssociationHandle,
        id: StreamId,
        now: Instant,
        limits: ReceiveLimits,
        budget: &mut usize,
        messages: &mut Vec<SctpMessage>,
        event_outs: &mut VecDeque<TaggedRTCEventInternal>,
    ) -> Result<()> {
        // An SCTP DATA chunk may arrive in the same flight as the tail of the
        // association handshake.  Do not expose that chunk to the DataChannel
        // handler while the association is still in COOKIE-WAIT/COOKIE-ECHOED:
        // doing so can announce `OnOpen` before the underlying data transport is
        // established, and an immediate application send cannot be transmitted
        // reliably.  Keep the chunk in SCTP's reassembly queue and let the
        // level-triggered pending path retry it after Event::Connected.
        //
        // Nor once it is established but its `SCTPHandshakeComplete` has not reached the
        // DataChannel handler yet (see `SctpHandlerContext::unannounced`): that handler opens
        // the negotiated channels on that event, and would drop data for one not open yet.
        if conn.is_handshaking() || unannounced.contains(&ch) {
            ctx_pending.insert((ch, id));
            return Ok(());
        }

        let mut stream = conn.stream(id)?;
        loop {
            if *budget == 0 {
                // Leave the rest in the reassembly queue: that is what shrinks `a_rwnd`.
                ctx_pending.insert((ch, id));
                return Ok(());
            }
            // Reading the stream's last message completes a stream reset that waited for it
            // (`retry_deferred_resets`), which unregisters the stream: the next read finds it
            // closed. That is the end of its data, not an error, or the messages read in this
            // pass, the last one included, would be lost with the error.
            //
            // Read in parts (RFC 9260 6.9): a message SCTP cannot hold whole (larger than the
            // receive buffer, or one of several interleaved messages that fill it together)
            // leaves the receive buffer as it arrives and is put together here, so the window
            // opens again under RFC 9260 6.2's drop. A message that is complete when read
            // comes as one part.
            let part = match stream.read_part() {
                Ok(part) => part,
                Err(Error::ErrStreamClosed) => None,
                Err(err) => return Err(err),
            };
            let Some(part) = part else {
                ctx_pending.remove(&(ch, id));
                return Ok(());
            };
            // The peer has answered on this stream (its DATA_CHANNEL_ACK, or anything else):
            // it knows the channel, and an unordered channel sends unordered from here on
            // (RFC 8832 section 6). The stream may be gone already, its reset completed by
            // this read, and then there is nothing left to configure.
            if part.first
                && let Some((reliability_type, reliability_value)) =
                    ordered_until_reply.remove(&(ch, id))
            {
                let _ = stream.set_reliability_params(true, reliability_type, reliability_value);
            }
            let (ppi, payload) = match reassembly.add(ch, id, &part, limits) {
                PartOutcome::Complete(ppi, payload) => (ppi, payload),
                PartOutcome::Incomplete | PartOutcome::Dropped { close: false } => continue,
                PartOutcome::Dropped { close: true } => {
                    let _ = stream.close(now);
                    continue;
                }
                PartOutcome::TooLarge => {
                    // Larger than this side advertised (RFC 8841 6.1). Dropped alone:
                    // returning the error abandoned the rest of the read, and with it the
                    // messages already taken out of SCTP in this pass, which SCTP had
                    // acknowledged and nothing would deliver again.
                    warn!(
                        "dropping a message on stream {id}: over the {} byte receive limit",
                        limits.message
                    );
                    continue;
                }
                PartOutcome::OverLimit { ended } => {
                    // RFC 8831 6.6: "If ... some error condition related to the received
                    // message is detected by the receiver ..., the receiver SHOULD close the
                    // corresponding data channel." The channel fails (an error to the
                    // application); the rest of the message is read and dropped as it comes,
                    // and then its stream is reset, the closing procedure of section 6.7.
                    warn!(
                        "closing the data channel on stream {id}: its message would take the \
                         incomplete messages held for association {} past {} bytes",
                        ch.0, limits.partial
                    );
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPInboundReassemblyLimit(
                            ch.0,
                            id,
                            limits.partial,
                        ),
                    });
                    if ended {
                        let _ = stream.close(now);
                    }
                    continue;
                }
            };
            // An in-band channel is opened by a DATA_CHANNEL_OPEN on its stream (RFC 8832 §6),
            // so only the first message of a stream the peer created can be the OPEN that
            // describes it. A first message that is not DCEP belongs to an out-of-band
            // negotiated channel, which this side configured itself.
            if peer_opened.remove(&(ch, id)) && ppi == PayloadProtocolIdentifier::Dcep {
                Self::apply_peer_reliability(&mut stream, &payload)?;
            }
            messages.push(SctpMessage::Inbound(DataChannelMessage {
                association_handle: ch.0,
                stream_id: id,
                ppi,
                payload,
                negotiated: false,
            }));
            *budget -= 1;
        }
    }

    /// Turns one association's pending events into this handler's events and reads.
    ///
    /// Both `handle_read` and `handle_timeout` come through here. Events a timer raises (a
    /// handshake that ran out of retransmissions, an association closed by its T3-rtx limit,
    /// buffers released by abandoning messages) used to wait for the next inbound datagram,
    /// which after a failed handshake never comes.
    #[allow(clippy::too_many_arguments)]
    fn process_association_events(
        conn: &mut Association,
        ch: AssociationHandle,
        now: Instant,
        event_outs: &mut VecDeque<TaggedRTCEventInternal>,
        pending_readable: &mut HashSet<(AssociationHandle, StreamId)>,
        peer_opened: &mut HashSet<(AssociationHandle, StreamId)>,
        ordered_until_reply: &mut HashMap<(AssociationHandle, StreamId), (ReliabilityType, u32)>,
        unannounced: &mut HashSet<AssociationHandle>,
        reassembly: &mut InboundReassembly,
        limits: ReceiveLimits,
        budget: &mut usize,
        messages: &mut Vec<SctpMessage>,
    ) -> Result<()> {
        while let Some(event) = conn.poll() {
            match event {
                Event::HandshakeFailed { reason } => {
                    // The association closed with it, and its `AssociationClosed` (with this
                    // reason) fails the transport and the channels.
                    debug!(
                        "association_handle {} handshake failed due to {}",
                        ch.0, reason
                    );
                }
                Event::Connected => {
                    debug!("association_handle {} is connected", ch.0);
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPHandshakeComplete(ch.0),
                    });
                    // Its data waits for the event (see `unannounced`).
                    unannounced.insert(ch);
                }
                // RFC 9260 section 5.2.4 action A: the peer lost its state and set the
                // association up again. The old association's streams are gone with what was
                // remembered about them, its channels close, and the new association is
                // announced as one that just came up, its data held back until it is.
                Event::Restarted => {
                    debug!("association_handle {} was restarted by the peer", ch.0);
                    pending_readable.retain(|(handle, _)| *handle != ch);
                    peer_opened.retain(|(handle, _)| *handle != ch);
                    ordered_until_reply.retain(|(handle, _), _| *handle != ch);
                    reassembly.forget_association(ch);
                    // What each closed stream had sent, before its channel is closed: the
                    // channel's final `bufferedAmount` counts only what was never sent.
                    for (id, dequeued) in conn.streams_lost_in_restart() {
                        event_outs.push_back(TaggedRTCEventInternal {
                            now,
                            event: RTCEventInternal::SCTPStreamDequeued(ch.0, *id, *dequeued),
                        });
                    }
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPRestarted(ch.0),
                    });
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPHandshakeComplete(ch.0),
                    });
                    unannounced.insert(ch);
                }
                Event::AssociationLost { reason, id } => {
                    debug!("association_handle {} is closed due to {}", ch.0, reason);
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPStreamDequeued(
                            ch.0,
                            id,
                            conn.stream_bytes_dequeued(id),
                        ),
                    });
                    // The stream is gone, and with it what was remembered about it.
                    ordered_until_reply.remove(&(ch, id));
                    reassembly.forget(ch, id);
                    // A stream reset (either side's close) is the channel's own
                    // closing procedure; the association going away under it is
                    // a failure the channel reports first.
                    if matches!(
                        reason,
                        AssociationError::AssociationClosed
                            | AssociationError::TransportError
                            | AssociationError::TimedOut
                            | AssociationError::HandshakeFailed(_)
                    ) {
                        if let Some(cause) = conn.abort_cause_code() {
                            event_outs.push_back(TaggedRTCEventInternal {
                                now,
                                event: RTCEventInternal::SCTPFailureCause(cause),
                            });
                        }
                        event_outs.push_back(TaggedRTCEventInternal {
                            now,
                            event: RTCEventInternal::SCTPStreamFailed(ch.0, id),
                        });
                    }
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPStreamClosed(ch.0, id),
                    });
                }
                Event::AssociationClosed { reason } => {
                    if matches!(
                        reason,
                        AssociationError::AssociationClosed
                            | AssociationError::TransportError
                            | AssociationError::TimedOut
                            | AssociationError::HandshakeFailed(_)
                    ) {
                        if let Some(cause) = conn.abort_cause_code() {
                            event_outs.push_back(TaggedRTCEventInternal {
                                now,
                                event: RTCEventInternal::SCTPFailureCause(cause),
                            });
                        }
                        event_outs.push_back(TaggedRTCEventInternal {
                            now,
                            event: RTCEventInternal::SCTPAssociationFailed(ch.0),
                        });
                    }
                }
                // RFC 9260 sections 8.2 and 8.3: Path.Max.Retrans retransmissions or HEARTBEATs
                // in a row went unanswered. The association has one path and goes on trying
                // on it, so it is still `connected` (W3C webrtc 6.1: the transport is `closed`
                // when the association is) and its channels are still open; if the peer never
                // answers, Association.Max.Retrans closes it and `AssociationClosed` reports
                // the failure.
                Event::PathInactive => {
                    debug!("association_handle {} path is inactive", ch.0);
                }
                Event::PathActive => {
                    debug!("association_handle {} path is active again", ch.0);
                }
                Event::Reconfig(reconfig) => {
                    if let ReconfigEvent::OutgoingStreamsResetFailed { streams, .. } = &reconfig {
                        for &id in streams {
                            event_outs.push_back(TaggedRTCEventInternal {
                                now,
                                event: RTCEventInternal::SCTPStreamDequeued(
                                    ch.0,
                                    id,
                                    conn.stream_bytes_dequeued(id),
                                ),
                            });
                        }
                    }
                    Self::process_reconfig_event(
                        ch,
                        reconfig,
                        now,
                        event_outs,
                        ordered_until_reply,
                    );
                }
                Event::Stream(StreamEvent::Opened { id }) => {
                    // The peer's DATA created this stream. Its first message
                    // may be the OPEN this side's sends must follow.
                    peer_opened.insert((ch, id));
                }
                Event::Stream(StreamEvent::Readable { id }) => {
                    // Bounded: what is not read stays in the reassembly queue,
                    // which is what lowers `a_rwnd` and throttles the peer.
                    Self::drain_stream(
                        pending_readable,
                        peer_opened,
                        ordered_until_reply,
                        unannounced,
                        reassembly,
                        conn,
                        ch,
                        id,
                        now,
                        limits,
                        budget,
                        messages,
                        event_outs,
                    )?;
                }
                // RFC 6458 6.1.7: the message being read in parts was abandoned by the
                // sender (PR-SCTP): what was put together of it is dropped. A data channel
                // delivers whole messages, so the application sees nothing of it, as of any
                // message a partially reliable channel abandons.
                Event::Stream(StreamEvent::PartialDeliveryAborted { id, sequence, .. }) => {
                    debug!(
                        "association_handle {} stream {id}: message {sequence} abandoned while \
                         read in parts",
                        ch.0
                    );
                    if reassembly.forget(ch, id) {
                        let _ = conn.stream(id).and_then(|mut stream| stream.close(now));
                    }
                }
                Event::Stream(StreamEvent::BufferedAmountLow { id }) => {
                    debug!(
                        "association_handle {} stream id {} is buffered amount low",
                        ch.0, id
                    );
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPBufferedAmountLow(ch.0, id),
                    });
                }
                Event::Stream(StreamEvent::BufferedAmountHigh { id }) => {
                    debug!(
                        "association_handle {} stream id {} is buffered amount high",
                        ch.0, id
                    );
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPBufferedAmountHigh(ch.0, id),
                    });
                }
                Event::Stream(StreamEvent::BufferedAmountReleased { id, n_bytes }) => {
                    // Forward the exact released byte count so the data
                    // channel handler can decrement its synchronous
                    // send back-pressure counter (see DataChannelHandler).
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPBufferReleased(ch.0, id, n_bytes),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// What the outcome of a stream re-configuration (RFC 6525) means for the data channels.
    ///
    /// The only request this handler makes is the reset of an outgoing stream, which closes a
    /// data channel (RFC 8831 section 6.7). Performed, the close goes on: the channel is
    /// closed when the peer has reset its own direction, which `AssociationLost` reports.
    /// Not performed (the peer denied it, or reported an error), the closing procedure cannot
    /// complete: the channel fails, and is closed with an error instead of staying `closing`
    /// for good. The other outcomes change nothing a data channel shows: a reset of the
    /// association's TSNs and SSNs is invisible above SCTP, and streams the peer adds raise
    /// `maxChannels`, which is read from the association.
    fn process_reconfig_event(
        ch: AssociationHandle,
        reconfig: ReconfigEvent,
        now: Instant,
        event_outs: &mut VecDeque<TaggedRTCEventInternal>,
        ordered_until_reply: &mut HashMap<(AssociationHandle, StreamId), (ReliabilityType, u32)>,
    ) {
        match reconfig {
            ReconfigEvent::OutgoingStreamsResetFailed { streams, denied } => {
                warn!(
                    "association_handle {} the peer did not reset streams {:?} (denied: {})",
                    ch.0, streams, denied
                );
                for id in streams {
                    ordered_until_reply.remove(&(ch, id));
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPStreamFailed(ch.0, id),
                    });
                    event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::SCTPStreamClosed(ch.0, id),
                    });
                }
            }
            other => {
                debug!("association_handle {} reconfiguration: {:?}", ch.0, other);
            }
        }
    }

    /// Configures this side's outgoing direction of a peer-opened stream from the peer's
    /// `DATA_CHANNEL_OPEN`.
    ///
    /// RFC 8832 §5.1 defines the Channel Type and Reliability Parameter for the data channel
    /// as a whole, not for the opener's direction alone. Without this the accepting side
    /// sends every message ordered and fully reliable whatever the peer asked for: no U bit
    /// on an unordered channel, and no abandonment on a partially reliable one. This is the
    /// accept-side counterpart of the `set_reliability_params` call `handle_write` makes for
    /// an OPEN sent from this side, and uses the same Channel Type mapping.
    ///
    /// A payload that is not a well-formed OPEN is left alone: the data channel handler
    /// rejects it when it tries to accept the channel.
    fn apply_peer_reliability(stream: &mut Stream<'_>, payload: &[u8]) -> Result<()> {
        let mut buf = payload;
        if let Ok(Message::DataChannelOpen(data_channel_open)) = Message::unmarshal(&mut buf) {
            debug!(
                "sctp data channel open from peer {:?} for stream id {}",
                data_channel_open,
                stream.stream_identifier()
            );
            let (unordered, reliability_type) =
                ::datachannel::data_channel::DataChannel::get_reliability_params(
                    data_channel_open.channel_type,
                );
            stream.set_reliability_params(
                unordered,
                reliability_type,
                data_channel_open.reliability_parameter,
            )?;
            // RFC 8831 section 6.4: the channel's priority is its stream's weight (see the
            // OPEN this side writes, in `handle_write`).
            stream.set_priority(data_channel_open.priority)?;
        }
        Ok(())
    }

    /// Retry streams parked by a full pipeline. The level-triggered half of the drain.
    ///
    /// Returns whether any message was taken out of SCTP. A stream that cannot be read (its
    /// association or the stream itself is gone) is forgotten rather than retried: it has
    /// nothing left to deliver, and a parked stream that never drains would keep
    /// [`Self::resumable`], and with it `poll_timeout`, reporting work that never gets done.
    fn resume_pending_reads(&mut self, now: Instant) -> Result<bool> {
        if self.ctx.pending_readable.is_empty() {
            return Ok(false);
        }
        let mut budget = self.read_budget();
        if budget == 0 {
            return Ok(false);
        }

        let limits = receive_limits(&self.ctx.sctp_transport);
        let mut pending: Vec<(AssociationHandle, StreamId)> =
            self.ctx.pending_readable.iter().copied().collect();
        pending.sort_unstable();

        let mut drained_any = false;
        for (ch, id) in pending {
            if budget == 0 {
                break;
            }
            let Some(transport) = self.ctx.association_transport.get(&ch).copied() else {
                // Never received a datagram, so it cannot have parked data.
                self.ctx.pending_readable.remove(&(ch, id));
                continue;
            };
            let Some(conn) = self.ctx.sctp_transport.sctp_associations.get_mut(&ch) else {
                // The association went away while parked; nothing to resume. Unreachable in
                // practice — the two sites that remove an association clear both maps with it
                // — so this drops the transport entry too rather than leaving the one map to
                // outlive the other.
                self.ctx.pending_readable.remove(&(ch, id));
                self.ctx.association_transport.remove(&ch);
                continue;
            };

            // Drained per association, and stamped with *that* association's 5-tuple: a
            // shared batch would let one association's messages inherit another's transport.
            let mut messages = vec![];
            if let Err(err) = Self::drain_stream(
                &mut self.ctx.pending_readable,
                &mut self.ctx.peer_opened_streams,
                &mut self.ctx.ordered_until_reply,
                &self.ctx.unannounced,
                &mut self.ctx.reassembly,
                conn,
                ch,
                id,
                now,
                limits,
                &mut budget,
                &mut messages,
                &mut self.ctx.event_outs,
            ) {
                warn!("parked sctp stream {id} cannot be read, forgetting it: {err}");
                self.ctx.pending_readable.remove(&(ch, id));
            }

            for message in messages {
                if let SctpMessage::Inbound(message) = message {
                    drained_any = true;
                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now,
                        transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                    });
                }
            }
        }

        if drained_any {
            // Reading drops bytes out of the reassembly queue, which raises the
            // receiver-window credit — the peer only learns that from a SACK, so flush.
            self.ctx.flush_dirty = true;
        }
        Ok(drained_any)
    }

    /// Whether a parked stream can be drained now: the pipeline has room again and the
    /// stream's association is up and announced (data held back for the handshake is resumed
    /// by the event that announces it, not by a timer).
    ///
    /// While this holds, `poll_timeout` reports a deadline, so that a stream parked by
    /// back-pressure resumes by itself once the application has caught up, also when it
    /// drained the pipeline without a `poll_read` (`RTCPeerConnection::poll_data_read`) and
    /// no datagram arrives: the peer, stopped by the window, sends nothing until it hears of
    /// the space. Each `handle_timeout` for it drains at least one message, forgets a stream
    /// that cannot be read, or uses the room up, so the deadline never repeats without
    /// progress.
    fn resumable(&self) -> bool {
        !self.ctx.pending_readable.is_empty()
            && self.read_budget() > 0
            && self.ctx.pending_readable.iter().any(|(ch, _)| {
                !self.ctx.unannounced.contains(ch)
                    && self.ctx.association_transport.contains_key(ch)
                    && self
                        .ctx
                        .sctp_transport
                        .sctp_associations
                        .get(ch)
                        .is_some_and(|conn| !conn.is_handshaking())
            })
    }

    pub(crate) fn name(&self) -> &'static str {
        "SctpHandler"
    }

    /// Initiates the association the last offer/answer exchange negotiated, if there is one
    /// to initiate and none is under way.
    ///
    /// RFC 8841 section 9.3: "both SCTP endpoints MUST initiate the SCTP association", so
    /// this runs in either DTLS role, and RFC 8261 section 6.1: only once the DTLS connection
    /// is established. It is called when DTLS connects and when an association is negotiated
    /// over a DTLS transport that is connected already (a new `a=sctp-port`).
    ///
    /// An association that is alive is left alone: a DTLS handshake that completes again
    /// (after an ICE restart, RFC 8842) does not touch it. RFC 8841 section 10.5: "if a DTLS
    /// association is closed and replaced with a new DTLS association ..., the state of the
    /// SCTP association is not affected."
    pub(crate) fn connect(&mut self, now: Instant) -> Result<()> {
        let transport = &mut self.ctx.sctp_transport;
        if !transport.dtls_connected {
            return Ok(());
        }
        let Some(sctp_transport_config) = transport.sctp_transport_config.clone() else {
            // No association is negotiated (no data section, a rejected one, sctp-port 0).
            return Ok(());
        };
        if transport
            .sctp_associations
            .values()
            .any(|association| !association.is_ended())
        {
            return Ok(());
        }
        let sizes = transport.association_sizes();
        let sctp_endpoint = transport
            .sctp_endpoint
            .as_mut()
            .ok_or(Error::ErrSCTPNotEstablished)?;

        debug!("sctp endpoint initiates the association");
        let (ch, mut conn) = sctp_endpoint
            .connect(
                now,
                ClientConfig::new(sctp_transport_config),
                TransportContext::default().peer_addr,
            )
            .map_err(|e| Error::Other(e.to_string()))?;
        SctpTransport::size_association(&mut conn, sizes);
        transport.sctp_associations.insert(ch, conn);
        transport.lost = false;

        // `connect` queued the INIT. Mark dirty so poll_write emits it at the next flush
        // instead of waiting for a later handle_* (the deferred flush is the only transmit
        // path).
        self.ctx.observe(now);
        self.ctx.flush_dirty = true;
        Ok(())
    }

    /// Takes what the peer connection worked out about the path under the associations, after
    /// [`SctpHandlerContext::take_path_refresh`] asked for it. `None`: no candidate pair is
    /// selected.
    ///
    /// RFC 8831 section 5: "SCTP SHOULD be notified when an address change has happened. In
    /// this case, SCTP SHOULD retest the Path MTU and reset the congestion state to the
    /// initial state." The association's path MTU is set again from what is known of the
    /// new path (the address family, the transport and whether it is
    /// relayed, and the DTLS record overhead), first, since the initial congestion window is
    /// counted in packets of that size; then, when ICE selected another pair, the congestion
    /// control and the RTO start over, and so does path MTU discovery, from that size
    /// ([`Association::on_path_change`]).
    pub(crate) fn apply_path(&mut self, path: Option<SctpPath>) {
        let now = self.ctx.now;
        let transport = &mut self.ctx.sctp_transport;
        if let Some(path) = path {
            transport.path_mtu = Some(path.packet_budget());
            if let Some(max_ip_packet) = transport.path_mtu_discovery {
                transport.max_path_mtu = Some(path.packet_budget_within(max_ip_packet));
            }
        }
        let packet_budget = transport.packet_budget();
        let max_packet_budget = transport.max_packet_budget();
        let path_changed = std::mem::take(&mut self.ctx.path_changed) && path.is_some();
        for association in transport.sctp_associations.values_mut() {
            if association.is_ended() {
                continue;
            }
            // RFC 8899 section 6.2.3.2: the discovery's sizes are of the SCTP packet, the
            // DTLS record and the headers below having been taken off.
            if let Some(max) = max_packet_budget {
                association.set_max_path_mtu(max);
            }
            if let Some(mtu) = packet_budget {
                association.set_path_mtu(mtu);
            }
            if path_changed {
                association.on_path_change(now);
                self.ctx.flush_dirty = true;
            }
        }
    }

    /// Closes the associations because signalling said so (RFC 8841 section 10: a rejected
    /// data section, an `a=sctp-port` of zero, or a new `a=sctp-port`), ahead of
    /// [`SctpTransport::negotiate`] replacing or dropping the transport's configuration.
    ///
    /// Each is aborted, the ABORT queued for the wire, and forgotten. `replaced` says whether
    /// a new association follows; the data channel handler, which gets the event queued here,
    /// closes the channels that ran over the old one either way.
    pub(crate) fn close_for_renegotiation(&mut self, now: Instant, replaced: bool) {
        self.ctx.observe(now);
        // What each stream sent stays the final `bufferedAmount` of its channel.
        for (ch, association) in &self.ctx.sctp_transport.sctp_associations {
            let mut ids = association.stream_ids();
            ids.sort_unstable();
            for id in ids {
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPStreamDequeued(
                        ch.0,
                        id,
                        association.stream_bytes_dequeued(id),
                    ),
                });
            }
        }
        self.abort_associations();
        self.ctx.sctp_transport.sctp_associations.clear();
        self.ctx.association_transport.clear();
        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::SCTPClosedBySignalling(replaced),
        });
    }

    /// Records, after the endpoint let go of `removed` associations, whether the last one is
    /// gone without signalling having closed it.
    fn note_associations_removed(&mut self, removed: usize) {
        let transport = &mut self.ctx.sctp_transport;
        if removed > 0 && transport.is_started && transport.sctp_associations.is_empty() {
            transport.lost = true;
        }
    }

    /// Asks for every association to be aborted (W3C `close()`: "tear down the underlying SCTP
    /// association by sending an SCTP ABORT chunk").
    ///
    /// Done at this handler's next `poll_write`, not here, so the data still pending in the
    /// associations goes out first: [`Association::abort`] would discard it.
    pub(crate) fn request_abort(&mut self) {
        self.ctx.abort_requested = true;
    }

    /// Aborts every association and queues the ABORTs. The local data channels are closed
    /// abruptly, without their closing procedure (W3C `close()`), so the stream losses the aborts
    /// report are dropped rather than surfaced as `OnClose`.
    fn abort_associations(&mut self) {
        for association in self.ctx.sctp_transport.sctp_associations.values_mut() {
            if let Err(err) = association.abort() {
                warn!("failed to abort sctp association: {}", err);
            }
            while association.poll().is_some() {}
        }
        self.ctx.pending_readable.clear();
        self.ctx.peer_opened_streams.clear();
        self.ctx.ordered_until_reply.clear();
        self.ctx.unannounced.clear();
        self.ctx.reassembly.clear();
        self.flush_transmits(self.ctx.now);
    }

    /// Batch-drain flush: gather every association's pending outbound in one pass
    /// into `write_outs`. Called once per event-loop iteration from poll_write when
    /// `flush_dirty` is set, after a burst of inbound packets has been ingested, so
    /// their SACKs coalesce into a single datagram.
    fn flush_transmits(&mut self, now: Instant) {
        for conn in self.ctx.sctp_transport.sctp_associations.values_mut() {
            while let Some(x) = conn.poll_transmit(now) {
                for transmit in split_transmit(x) {
                    if let Payload::RawEncode(raw_data) = transmit.message {
                        for raw in raw_data {
                            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                                now: transmit.now,
                                transport: transmit.transport,
                                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(
                                    BytesMut::from(&raw[..]),
                                )),
                            });
                        }
                    }
                }
            }
        }
    }
}

enum SctpMessage {
    Inbound(DataChannelMessage),
    Outbound(TransportMessage<Payload>),
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for SctpHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv sctp RAW {:?}", msg.transport.peer_addr);

            if self.ctx.sctp_transport.sctp_endpoint.is_none() {
                warn!(
                    "drop sctp RAW {:?} due to sctp_endpoint is not ready yet",
                    msg.transport.peer_addr
                );
                return Ok(());
            }

            // Both are read before `sctp_transport` is split up below, which would otherwise
            // conflict with the borrow of `sctp_associations`.
            let limits = receive_limits(&self.ctx.sctp_transport);
            let sizes = self.ctx.sctp_transport.association_sizes();
            let mut budget = self.read_budget();
            let mut inbound_transport = None;

            let (sctp_endpoint, sctp_associations) = (
                self.ctx
                    .sctp_transport
                    .sctp_endpoint
                    .as_mut()
                    .ok_or(Error::ErrSCTPNotEstablished)?,
                &mut self.ctx.sctp_transport.sctp_associations,
            );

            // RFC 8841 section 9.3: "both endpoints MUST use the same SCTP port as client
            // port and server port, in order to prevent two separate SCTP associations from
            // being established". The two ports are the `a=sctp-port` values; a packet
            // between any others belongs to no association negotiated here. (Without this
            // an accepted INIT set the association's ports to whatever it carried.)
            if let Some(ports) = self.ctx.sctp_transport.negotiated_ports
                && !packet_is_between(&dtls_message, ports)
            {
                warn!(
                    "drop sctp RAW {:?}: not between the negotiated SCTP ports {:?}",
                    msg.transport.peer_addr, ports
                );
                return Ok(());
            }

            let datagram = dtls_message.freeze(); //TODO: switch API Bytes to BytesMut
            // The peer's INIT while this side's own is out is the ordinary case, since both
            // endpoints initiate (RFC 8841 section 9.3): the endpoint routes it to the
            // association this side initiated, which answers it from COOKIE-WAIT or
            // COOKIE-ECHOED (RFC 9260 section 5.2.1) so that one association results. An INIT
            // that finds no association is answered without one being made (section 5.1):
            // `handle` returns `None` and the INIT ACK is collected below; the association
            // comes with the COOKIE ECHO, as `NewAssociation`, already established.
            let routed = sctp_endpoint.handle(
                msg.now,
                msg.transport.peer_addr,
                msg.transport.ecn,
                datagram,
            );
            // What the endpoint itself answers: the INIT ACK with the State Cookie for an
            // INIT that found no association (RFC 9260 section 5.1), and what a packet that
            // belongs to none of its associations is answered with (section 8.4: an ABORT,
            // or a SHUTDOWN COMPLETE to a SHUTDOWN ACK, reflecting the packet's Verification
            // Tag). It goes back the way the packet came.
            let mut endpoint_answers = vec![];
            while let Some(transmit) = sctp_endpoint.poll_transmit() {
                if let Payload::RawEncode(raw_data) = transmit.message {
                    endpoint_answers.extend(raw_data);
                }
            }

            let mut sctp_events: HashMap<AssociationHandle, VecDeque<AssociationEvent>> =
                HashMap::new();
            if let Some((ch, event)) = routed {
                // `ch` is the association this datagram belongs to — the only safe key for
                // remembering its 5-tuple.
                inbound_transport = Some((ch, msg.transport));
                match event {
                    DatagramEvent::NewAssociation(mut conn) => {
                        SctpTransport::size_association(&mut conn, sizes);
                        sctp_associations.insert(ch, conn);
                        // An association is there again: the one before it, if it was lost
                        // (see `SctpTransport::association_lost`), no longer counts.
                        self.ctx.sctp_transport.lost = false;
                    }
                    DatagramEvent::AssociationEvent(event) => {
                        sctp_events.entry(ch).or_default().push_back(event);
                    }
                    _ => {}
                }
            }

            let mut messages = vec![];
            let removed;
            {
                let mut endpoint_events: Vec<(AssociationHandle, EndpointEvent)> = vec![];

                for (ch, conn) in sctp_associations.iter_mut() {
                    for (event_ch, conn_events) in sctp_events.iter_mut() {
                        if ch == event_ch {
                            for event in conn_events.drain(..) {
                                debug!(
                                    "association_handle {} handle_event for Datagram from {}",
                                    ch.0, msg.transport.peer_addr
                                );
                                conn.handle_event(event);
                            }
                        }
                    }

                    Self::process_association_events(
                        conn,
                        *ch,
                        now,
                        &mut self.ctx.event_outs,
                        &mut self.ctx.pending_readable,
                        &mut self.ctx.peer_opened_streams,
                        &mut self.ctx.ordered_until_reply,
                        &mut self.ctx.unannounced,
                        &mut self.ctx.reassembly,
                        limits,
                        &mut budget,
                        &mut messages,
                    )?;

                    while let Some(event) = conn.poll_endpoint_event() {
                        // Only a drained association goes; any other event (new tags
                        // after a restart, RFC 9260 5.2.4) is the endpoint's alone.
                        if event.is_drained() {
                            endpoint_events.push((*ch, event));
                        } else {
                            sctp_endpoint.handle_event(*ch, event);
                        }
                    }
                    // Transmit flush is deferred to poll_write (batch-drain) so a
                    // burst of inbound DATA coalesces into one SACK.
                }

                // Teardown safety: each association that emitted an endpoint event
                // is about to be removed below (drain/shutdown). Flush ITS pending
                // outbound now — the deferred poll_write flush runs after removal and
                // would drop its final packets. Only the draining associations are
                // touched, so non-draining ones keep coalescing and still flush
                // normally in poll_write.
                for (drained_ch, _event) in &endpoint_events {
                    if let Some(conn) = sctp_associations.get_mut(drained_ch) {
                        while let Some(x) = conn.poll_transmit(now) {
                            for transmit in split_transmit(x) {
                                messages.push(SctpMessage::Outbound(transmit));
                            }
                        }
                    }
                }

                removed = endpoint_events.len();
                for (ch, event) in endpoint_events {
                    sctp_endpoint.handle_event(ch, event); // handle drain event
                    sctp_associations.remove(&ch);
                    // Drop the per-association bookkeeping with it, or a long-lived endpoint
                    // accumulates entries for associations that no longer exist.
                    self.ctx.association_transport.remove(&ch);
                    self.ctx.pending_readable.retain(|(pch, _)| *pch != ch);
                    self.ctx.peer_opened_streams.retain(|(pch, _)| *pch != ch);
                    self.ctx
                        .ordered_until_reply
                        .retain(|(pch, _), _| *pch != ch);
                    self.ctx.unannounced.remove(&ch);
                    self.ctx.reassembly.forget_association(ch);
                }
            }
            self.note_associations_removed(removed);

            for message in messages {
                match message {
                    SctpMessage::Inbound(message) => {
                        debug!(
                            "recv sctp data channel message {:?}",
                            msg.transport.peer_addr
                        );
                        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                            now: msg.now,
                            transport: msg.transport,
                            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                        })
                    }
                    SctpMessage::Outbound(transmit) => {
                        if let Payload::RawEncode(raw_data) = transmit.message {
                            for raw in raw_data {
                                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                                    now: transmit.now,
                                    transport: transmit.transport,
                                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(
                                        BytesMut::from(&raw[..]),
                                    )),
                                });
                            }
                        }
                    }
                }
            }

            for raw in endpoint_answers {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&raw[..]))),
                });
            }

            if let Some((ch, transport)) = inbound_transport
                && let Some(conn) = self.ctx.sctp_transport.sctp_associations.get_mut(&ch)
            {
                // The association's packets arrive over another 5-tuple than before: the
                // transport underneath moved (ICE selected another candidate pair), and what
                // the association learned about the old path says nothing about this one
                // (RFC 9260 section 7.2.5): its congestion control and RTO start over.
                if self
                    .ctx
                    .association_transport
                    .insert(ch, transport)
                    .is_some_and(|before| {
                        (
                            before.local_addr,
                            before.peer_addr,
                            before.transport_protocol,
                        ) != (
                            transport.local_addr,
                            transport.peer_addr,
                            transport.transport_protocol,
                        )
                    })
                {
                    debug!(
                        "sctp association {} moved to {:?}",
                        ch.0, transport.peer_addr
                    );
                    conn.on_path_change(now);
                }
            }

            // The application may have drained while this packet was in flight, so retry
            // anything parked now rather than at the deadline `poll_timeout` reports for it.
            self.resume_pending_reads(now)?;

            // Ingest done — mark dirty so poll_write runs the single flush.
            self.ctx.flush_dirty = true;
            self.ctx.observe(now);
        } else {
            // Bypass
            debug!("bypass sctp read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        // Top up from streams parked by back-pressure. This is exactly when capacity has
        // appeared: somebody is asking for data, so the pipeline ahead has drained.
        //
        // It is also the level-triggered half of the bounded drain. `StreamEvent::Readable`
        // is edge-triggered: it fires on a *new* DATA chunk, never because unread data
        // remains. The moment back-pressure works the peer stops sending, so nothing arrives
        // to re-trigger the drain — without this the stream would deadlock precisely when the
        // feature engages.
        if self.ctx.read_outs.is_empty() && !self.ctx.pending_readable.is_empty() {
            let now = self.ctx.now;
            match self.resume_pending_reads(now) {
                // The window the peer was stopped by may have opened: the SACK saying so is
                // due now (RFC 9260 section 6.2), and the caller has most likely made its
                // `poll_write` for this turn already, so `poll_timeout` asks for another.
                Ok(true) => self.ctx.window_update_due = true,
                Ok(false) => {}
                Err(err) => warn!("failed to resume parked SCTP streams: {}", err),
            }
        }
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(mut message)) = msg.message {
            debug!(
                "send sctp data channel message to {:?}",
                msg.transport.peer_addr
            );

            // The send limit is the negotiated one: the peer's `max-message-size` (RFC 8841
            // 6.1), bounded by what this side can send. Nothing is sent before negotiation.
            // An application message is further held to 16 KB on an association without
            // message interleaving (RFC 8831 section 6.6, `SctpTransport::max_message_size`);
            // a DCEP message is not the application's, and its label and protocol may take
            // more than that (RFC 8832 section 5.1).
            if message.ppi == PayloadProtocolIdentifier::Dcep {
                let send_limit = self
                    .ctx
                    .sctp_transport
                    .negotiated_max_message_size
                    .unwrap_or(0) as usize;
                if message.payload.len() > send_limit {
                    return Err(Error::ErrOutboundPacketTooLarge);
                }
            } else if self
                .ctx
                .sctp_transport
                .negotiated_max_message_size
                .is_none()
            {
                if !message.payload.is_empty() {
                    return Err(Error::ErrOutboundPacketTooLarge);
                }
            } else {
                self.ctx
                    .sctp_transport
                    .check_message_size(message.payload.len())?;
            }

            if let Some(conn) = self
                .ctx
                .sctp_transport
                .sctp_associations
                .get_mut(&AssociationHandle(message.association_handle))
            {
                let mut is_dcep_internal_control_message = false;
                if message.ppi == PayloadProtocolIdentifier::Dcep {
                    let mut data_buf = &message.payload[..];
                    let dcep_message = Message::unmarshal(&mut data_buf)?;
                    match dcep_message {
                        Message::DataChannelOpen(data_channel_open) => {
                            debug!(
                                "sctp data channel open {:?} for stream id {}",
                                data_channel_open, message.stream_id
                            );
                            let (unordered, reliability_type) =
                                ::datachannel::data_channel::DataChannel::get_reliability_params(
                                    data_channel_open.channel_type,
                                );
                            // For pre-negotiated (out-of-band) channels both peers send
                            // DataChannelOpen simultaneously.  The remote's message may arrive
                            // before we process our own outbound one, causing get_or_create_stream
                            // to auto-create the stream first.  Treat ErrStreamAlreadyExist as
                            // non-fatal: the stream is open, just update its reliability params.
                            let mut stream = match conn.open_stream(message.stream_id, message.ppi)
                            {
                                Ok(s) => s,
                                Err(Error::ErrStreamAlreadyExist) => {
                                    conn.stream(message.stream_id)?
                                }
                                Err(e) => return Err(e),
                            };
                            // RFC 8832 section 6: until the peer has answered on the
                            // stream, user data on a channel opened in band is sent ordered
                            // even if the channel is unordered (see `ordered_until_reply`).
                            // A negotiated channel has no OPEN the data could overtake.
                            let stream_key = (
                                AssociationHandle(message.association_handle),
                                message.stream_id,
                            );
                            let ordered_until_reply = unordered && !message.negotiated;
                            stream.set_reliability_params(
                                unordered && !ordered_until_reply,
                                reliability_type,
                                data_channel_open.reliability_parameter,
                            )?;
                            // RFC 8831 section 6.4: the priority of the channel is the weight
                            // of its stream in the RFC 8260 weighted fair queueing scheduler.
                            // This is the one place a locally opened stream gets it; with
                            // another scheduler configured the weight is recorded and unused.
                            stream.set_priority(data_channel_open.priority)?;
                            if ordered_until_reply {
                                self.ctx.ordered_until_reply.insert(
                                    stream_key,
                                    (reliability_type, data_channel_open.reliability_parameter),
                                );
                            } else {
                                self.ctx.ordered_until_reply.remove(&stream_key);
                            }
                            // This side owns the stream's parameters now. A record left by an
                            // earlier, peer-created use of the same stream id must not let a
                            // later OPEN from the peer override them.
                            self.ctx.peer_opened_streams.remove(&stream_key);

                            // Out-of-band negotiated channels (W3C WebRTC
                            // `RTCDataChannelInit.negotiated`) only open the SCTP
                            // stream locally; the DCEP handshake must not be sent
                            // to the peer, which already created its own channel
                            // with the pre-agreed stream id.
                            if message.negotiated {
                                is_dcep_internal_control_message = true;
                            }
                        }
                        Message::DataChannelClose(_) => {
                            is_dcep_internal_control_message = true;
                            debug!(
                                "sctp data channel close for stream id {}",
                                message.stream_id
                            );
                            self.ctx.ordered_until_reply.remove(&(
                                AssociationHandle(message.association_handle),
                                message.stream_id,
                            ));
                            // A stream that is gone already (its reset completed while this
                            // close was on its way down) has nothing left to reset.
                            let Ok(mut stream) = conn.stream(message.stream_id) else {
                                self.ctx.flush_dirty = true;
                                self.ctx.observe(now);
                                return Ok(());
                            };
                            // Closing resets the outgoing stream; RFC 8831 section 6.7: the
                            // channel is closed, and its stream id free, once the peer has
                            // reset the incoming one in turn, which `AssociationLost` reports
                            // as the stream is unregistered. Freeing it now let a new channel
                            // take the id and be reset by the peer's reply.
                            let resets = stream.is_readable();
                            stream.close(now)?;

                            if !resets {
                                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                                    now,
                                    event: RTCEventInternal::SCTPStreamDequeued(
                                        message.association_handle,
                                        message.stream_id,
                                        conn.stream_bytes_dequeued(message.stream_id),
                                    ),
                                });
                                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                                    now,
                                    event: RTCEventInternal::SCTPStreamClosed(
                                        message.association_handle,
                                        message.stream_id,
                                    ),
                                });
                            }
                        }
                        Message::DataChannelThreshold(data_channel_threshold) => {
                            is_dcep_internal_control_message = true;
                            debug!(
                                "sctp data channel set threshold {:?} for stream id {}",
                                data_channel_threshold, message.stream_id
                            );
                            let mut stream = conn.stream(message.stream_id)?;
                            match data_channel_threshold {
                                DataChannelThreshold::Low(threshold) => {
                                    stream.set_buffered_amount_low_threshold(threshold as usize)?;
                                }
                                DataChannelThreshold::High(threshold) => {
                                    stream
                                        .set_buffered_amount_high_threshold(threshold as usize)?;
                                }
                            }
                        }
                        _ => {}
                    }
                }

                let mut stream = conn.stream(message.stream_id)?;
                if !is_dcep_internal_control_message && stream.is_writable() {
                    // The payload is owned end-to-end (the DataChannel `send` API
                    // takes the buffer by value), so hand it to SCTP zero-copy:
                    // `freeze()` is O(1) and the enqueued chunks are refcounted
                    // slices, eliminating a per-message alloc + full-payload memcpy.
                    let payload = std::mem::take(&mut message.payload).freeze();
                    stream.write_chunk_with_ppi(now, &payload, message.ppi)?;
                }

                // Transmit flush is deferred to poll_write (batch-drain).
            } else {
                return Err(Error::ErrAssociationNotExisted);
            }

            // Ingest done — mark dirty so poll_write runs the single flush.
            self.ctx.flush_dirty = true;
            self.ctx.observe(now);
        } else {
            // Bypass
            debug!("Bypass sctp write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        // Batch-drain: run the single deferred transmit flush for this event-loop
        // iteration before serving queued outbound.
        if self.ctx.flush_dirty || self.ctx.abort_requested {
            self.ctx.flush_dirty = false;
            self.ctx.window_update_due = false;
            self.flush_transmits(self.ctx.now);
        }
        // After the flush above, so data the associations still held is sent before the ABORT.
        if std::mem::take(&mut self.ctx.abort_requested) {
            self.abort_associations();
        }
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        // The event's instant arms the deferred flush below, so `poll_write` can stamp the
        // client INIT with the time the handshake completed rather than the wall clock.
        let now = evt.now;
        self.ctx.observe(now);

        // DTLSHandshakeComplete is not terminated here since SRTP handler needs it
        if matches!(&evt.event, RTCEventInternal::DTLSHandshakeComplete(_, _)) {
            debug!("sctp recv dtls handshake complete");
            self.ctx.sctp_transport.dtls_connected = true;
            // The cipher suite, and so the record overhead, is known from now on.
            self.ctx.path_dirty = true;
            self.connect(now)?;
        }

        // The peer closed the DTLS transport the associations run over, so they are over too.
        // Nothing is sent: there is no transport left to send it on. The data channel handler,
        // next in line for this event, closes the channels themselves.
        if matches!(&evt.event, RTCEventInternal::DTLSClosed) {
            debug!("sctp closing associations: dtls closed by peer");
            self.ctx.sctp_transport.dtls_connected = false;
            for association in self.ctx.sctp_transport.sctp_associations.values_mut() {
                if let Err(err) = association.close(AssociationError::ApplicationClosed) {
                    warn!("failed to close sctp association: {}", err);
                }
            }
            self.ctx.pending_readable.clear();
            self.ctx.peer_opened_streams.clear();
            self.ctx.ordered_until_reply.clear();
            self.ctx.unannounced.clear();
        }

        self.ctx.event_outs.push_back(evt);

        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        let evt = self.ctx.event_outs.pop_front()?;
        // The next handler takes this event before any read the pipeline pumps after it, so
        // the association's data may follow from now on (see `SctpHandlerContext::unannounced`).
        if let RTCEventInternal::SCTPHandshakeComplete(handle) = &evt.event {
            self.ctx.unannounced.remove(&AssociationHandle(*handle));
        }
        Some(evt)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.ctx.sctp_transport.sctp_endpoint.is_none() {
            return Ok(());
        }

        let mut transmits = vec![];
        let limits = receive_limits(&self.ctx.sctp_transport);
        let mut budget = self.read_budget();

        let (sctp_endpoint, sctp_associations) = (
            self.ctx
                .sctp_transport
                .sctp_endpoint
                .as_mut()
                .ok_or(Error::ErrSCTPNotEstablished)?,
            &mut self.ctx.sctp_transport.sctp_associations,
        );

        let mut endpoint_events: Vec<(AssociationHandle, EndpointEvent)> = vec![];
        for (ch, conn) in sctp_associations.iter_mut() {
            conn.handle_timeout(now);

            let mut messages = vec![];
            Self::process_association_events(
                conn,
                *ch,
                now,
                &mut self.ctx.event_outs,
                &mut self.ctx.pending_readable,
                &mut self.ctx.peer_opened_streams,
                &mut self.ctx.ordered_until_reply,
                &mut self.ctx.unannounced,
                &mut self.ctx.reassembly,
                limits,
                &mut budget,
                &mut messages,
            )?;
            // No datagram triggered these reads: stamp them with the association's own 5-tuple,
            // as a resumed drain is.
            let transport = self
                .ctx
                .association_transport
                .get(ch)
                .copied()
                .unwrap_or_default();
            for message in messages {
                if let SctpMessage::Inbound(message) = message {
                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now,
                        transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                    });
                }
            }

            while let Some(event) = conn.poll_endpoint_event() {
                // As in `handle_read`: only a drained association is removed.
                if event.is_drained() {
                    endpoint_events.push((*ch, event));
                } else {
                    sctp_endpoint.handle_event(*ch, event);
                }
            }
            // Transmit flush is deferred to poll_write (batch-drain).
        }

        // Teardown safety (see handle_read): flush each draining association's final
        // packets before it is removed below, so the deferred flush doesn't drop
        // them. Non-draining associations flush normally in poll_write.
        for (drained_ch, _event) in &endpoint_events {
            if let Some(conn) = sctp_associations.get_mut(drained_ch) {
                while let Some(x) = conn.poll_transmit(now) {
                    transmits.extend(split_transmit(x));
                }
            }
        }

        let removed = endpoint_events.len();
        for (ch, event) in endpoint_events {
            sctp_endpoint.handle_event(ch, event); // handle drain event
            sctp_associations.remove(&ch);
            self.ctx.association_transport.remove(&ch);
            self.ctx.pending_readable.retain(|(pch, _)| *pch != ch);
            self.ctx.peer_opened_streams.retain(|(pch, _)| *pch != ch);
            self.ctx
                .ordered_until_reply
                .retain(|(pch, _), _| *pch != ch);
            self.ctx.unannounced.remove(&ch);
            self.ctx.reassembly.forget_association(ch);
        }
        self.note_associations_removed(removed);

        for transmit in transmits {
            if let Payload::RawEncode(raw_data) = transmit.message {
                for raw in raw_data {
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now: transmit.now,
                        transport: transmit.transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(
                            &raw[..],
                        ))),
                    });
                }
            }
        }

        // The deadline `poll_timeout` reported for a parked stream the pipeline has room for
        // again (see `resumable`): drain it, so that it resumes with no datagram arriving.
        self.resume_pending_reads(now)?;

        // Timer processed — mark dirty so poll_write runs the single flush, which carries a
        // window update that was due (`window_update_due`): this deadline was for it.
        self.ctx.flush_dirty = true;
        self.ctx.window_update_due = false;
        self.ctx.observe(now);

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        // Work that is due now: a window update to flush, or a parked stream the pipeline has
        // room for again. Reported as the newest instant the handler has seen, which is no
        // later than the caller's clock; neither repeats once handled (`handle_timeout`
        // clears the first and drains the second), so a caller that answers a due deadline
        // with `handle_timeout` and its next `poll_write` does not spin.
        if self.ctx.window_update_due || self.resumable() {
            return Some(self.ctx.now);
        }

        let mut eto = None;

        for conn in self.ctx.sctp_transport.sctp_associations.values() {
            if let Some(timeout) = conn.poll_timeout() {
                eto = Some(eto.map_or(timeout, |e: Instant| e.min(timeout)));
            }
        }

        eto
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Whether an SCTP packet's common header (RFC 9260 section 3.1: source port, destination
/// port) names `(local, remote)` as its destination and source.
fn packet_is_between(packet: &[u8], (local, remote): (u16, u16)) -> bool {
    packet.len() >= 4
        && u16::from_be_bytes([packet[0], packet[1]]) == remote
        && u16::from_be_bytes([packet[2], packet[3]]) == local
}

fn split_transmit(transmit: TransportMessage<Payload>) -> Vec<TransportMessage<Payload>> {
    let mut transmits: Vec<TransportMessage<Payload>> = Vec::new();
    if let Payload::RawEncode(contents) = transmit.message {
        for content in contents {
            transmits.push(TransportMessage {
                now: transmit.now,
                transport: transmit.transport,
                message: Payload::RawEncode(vec![content]),
            })
        }
    }

    transmits
}

#[cfg(test)]
mod tests {
    //! Coverage for the batch-drain teardown-safety flush.
    //!
    //! `handle_read` / `handle_timeout` normally only INGEST and defer the transmit
    //! flush to `poll_write`. But when an association drains (graceful shutdown) it is
    //! removed in that same call — so its final packet (SHUTDOWN / SHUTDOWN_COMPLETE)
    //! would be dropped by a flush that runs *after* removal, and the peer would hang
    //! waiting for it. The teardown-safety block flushes pending outbound *before*
    //! removal. These tests drive a real client<->server SCTP handshake through the
    //! public `sctp` API (no DTLS/ICE), then verify the draining association's final
    //! packet reaches `write_outs` instead of being lost.

    use super::*;
    use crate::data_channel::registry::DataChannelRegistry;
    use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
    use crate::peer_connection::handler::datachannel::{
        DataChannelHandler, DataChannelHandlerContext,
    };
    use crate::peer_connection::message::internal::DataChannelEvent;
    use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};
    use crate::statistics::accumulator::RTCStatsAccumulator;
    use bytes::Bytes;
    use datachannel::message::message_channel_ack::DataChannelAck;
    use datachannel::message::message_channel_open::{
        CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
    };
    use sansio::Protocol;
    use sctp::{
        Association, Endpoint, EndpointConfig, ReliabilityType, ServerConfig, TransportConfig,
    };
    use shared::{TransportProtocol, marshal::Marshal};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }

    fn client_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444)
    }

    fn server_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555)
    }

    /// An established client<->server SCTP association pair, driven purely through the
    /// public `sctp` API so a handler test can operate on a real, connected
    /// association without standing up the full peer-connection stack.
    struct Established {
        client_ep: Endpoint,
        client_ch: AssociationHandle,
        client_conn: Association,
        server_ep: Endpoint,
        server_ch: AssociationHandle,
        server_conn: Association,
    }

    /// Drain every datagram an association currently wants to transmit.
    fn drain_transmits(conn: &mut Association, now: Instant) -> Vec<Bytes> {
        let mut out = vec![];
        while let Some(t) = conn.poll_transmit(now) {
            if let Payload::RawEncode(contents) = t.message {
                out.extend(contents);
            }
        }
        out
    }

    /// Run the SCTP handshake to completion and return the established pair. The
    /// shuttle plays the role the ICE handler plays in production: it rewrites each
    /// datagram's source address for the receiving endpoint.
    fn establish() -> Established {
        establish_with(TransportConfig::default())
    }

    /// [`establish`] with the client's association configured by `client_config`.
    fn establish_with(client_config: TransportConfig) -> Established {
        establish_with_both(client_config, TransportConfig::default())
    }

    /// [`establish`] with both associations' configurations.
    fn establish_with_both(
        client_config: TransportConfig,
        server_config: TransportConfig,
    ) -> Established {
        let now = Instant::now();

        let mut client_ep = Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        );
        let mut server_ep = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(server_config).into()),
        );

        let (client_ch, mut client_conn) = client_ep
            .connect(now, ClientConfig::new(client_config), server_addr())
            .expect("client connect");

        let mut server_conns: HashMap<AssociationHandle, Association> = HashMap::new();
        let mut connected = false;

        for _ in 0..50 {
            // client -> server
            let c_out = drain_transmits(&mut client_conn, now);
            let mut moved = !c_out.is_empty();
            for dgram in c_out {
                if let Some((ch, event)) = server_ep.handle(now, client_addr(), None, dgram) {
                    match event {
                        DatagramEvent::NewAssociation(conn) => {
                            server_conns.insert(ch, conn);
                        }
                        DatagramEvent::AssociationEvent(e) => {
                            if let Some(sc) = server_conns.get_mut(&ch) {
                                sc.handle_event(e);
                            }
                        }
                        _ => {}
                    }
                }
            }

            // server -> client
            let mut s_out = vec![];
            for sc in server_conns.values_mut() {
                while sc.poll().is_some() {}
                s_out.extend(drain_transmits(sc, now));
            }
            moved |= !s_out.is_empty();
            for dgram in s_out {
                if let Some((_ch, DatagramEvent::AssociationEvent(e))) =
                    client_ep.handle(now, server_addr(), None, dgram)
                {
                    client_conn.handle_event(e);
                }
            }

            while let Some(event) = client_conn.poll() {
                if let Event::Connected = event {
                    connected = true;
                }
            }

            if connected && !moved {
                break;
            }
        }

        assert!(connected, "SCTP handshake did not complete");
        assert_eq!(server_conns.len(), 1, "exactly one server association");
        let (server_ch, server_conn) = server_conns.into_iter().next().unwrap();

        Established {
            client_ep,
            client_ch,
            client_conn,
            server_ep,
            server_ch,
            server_conn,
        }
    }

    /// Build a client association that has sent COOKIE-ECHO but has not yet received COOKIE-ACK,
    /// then create one DATA datagram from the already-established server.  This is the ordering
    /// that can occur when a peer opens a DataChannel in the same flight as the final SCTP
    /// handshake packet.
    fn client_with_data_before_cookie_ack() -> (SctpHandlerContext, Vec<Bytes>, Vec<Bytes>) {
        client_with_open_before_cookie_ack(ChannelType::Reliable, 0)
    }

    /// [`client_with_data_before_cookie_ack`] with the early `DATA_CHANNEL_OPEN` carrying the
    /// given channel type and reliability parameter.
    fn client_with_open_before_cookie_ack(
        channel_type: ChannelType,
        reliability_parameter: u32,
    ) -> (SctpHandlerContext, Vec<Bytes>, Vec<Bytes>) {
        let now = Instant::now();

        let mut client_ep = Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        );
        let mut server_ep = Endpoint::new(
            server_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(TransportConfig::default()).into()),
        );

        let (client_ch, mut client_conn) = client_ep
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_addr(),
            )
            .expect("client connect");

        // Client INIT -> server association.
        let init = drain_transmits(&mut client_conn, now);
        let (server_ch, mut server_conn) = init
            .into_iter()
            .find_map(|dgram| {
                server_ep.handle(now, client_addr(), None, dgram).and_then(
                    |(ch, event)| match event {
                        DatagramEvent::NewAssociation(conn) => Some((ch, conn)),
                        _ => None,
                    },
                )
            })
            .expect("server association");

        // Server INIT-ACK -> client COOKIE-ECHO.
        let init_ack = drain_transmits(&mut server_conn, now);
        for dgram in init_ack {
            if let Some((ch, DatagramEvent::AssociationEvent(event))) =
                client_ep.handle(now, server_addr(), None, dgram)
            {
                assert_eq!(ch, client_ch);
                client_conn.handle_event(event);
            }
        }
        let cookie_echo = drain_transmits(&mut client_conn, now);

        // Server processes COOKIE-ECHO and becomes established, producing COOKIE-ACK.
        for dgram in cookie_echo {
            if let Some((ch, DatagramEvent::AssociationEvent(event))) =
                server_ep.handle(now, client_addr(), None, dgram)
            {
                assert_eq!(ch, server_ch);
                server_conn.handle_event(event);
            }
        }
        while server_conn.poll().is_some() {}
        let cookie_ack = drain_transmits(&mut server_conn, now);
        assert!(!cookie_ack.is_empty(), "server must produce COOKIE-ACK");

        // Send a DCEP OPEN before the client receives COOKIE-ACK.
        let dcep_open = Message::DataChannelOpen(DataChannelOpen {
            channel_type,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter,
            label: b"early-channel".to_vec(),
            protocol: Vec::new(),
        })
        .marshal()
        .expect("DCEP OPEN");
        {
            let mut stream = server_conn
                .open_stream(1, PayloadProtocolIdentifier::Dcep)
                .expect("open server stream");
            stream
                .write_sctp(
                    now,
                    &Bytes::from(dcep_open),
                    PayloadProtocolIdentifier::Dcep,
                )
                .expect("server data");
        }
        let early_data = drain_transmits(&mut server_conn, now);
        assert!(!early_data.is_empty(), "server must produce DCEP DATA");

        (
            client_ctx(now, client_ep, client_ch, client_conn),
            cookie_ack,
            early_data,
        )
    }

    /// Establish TWO independent associations on a single client endpoint (each to
    /// its own server), so a handler test can drain one while the other stays live.
    fn establish_two() -> (
        Endpoint,
        AssociationHandle,
        Association,
        AssociationHandle,
        Association,
    ) {
        let now = Instant::now();
        let server_a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5555);
        let server_b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6666);

        let mut client_ep = Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        );
        let mut server_a = Endpoint::new(
            server_a_addr,
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(TransportConfig::default()).into()),
        );
        let mut server_b = Endpoint::new(
            server_b_addr,
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            Some(ServerConfig::new(TransportConfig::default()).into()),
        );

        let (ch_a, mut conn_a) = client_ep
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_a_addr,
            )
            .expect("connect A");
        let (ch_b, mut conn_b) = client_ep
            .connect(
                now,
                ClientConfig::new(TransportConfig::default()),
                server_b_addr,
            )
            .expect("connect B");

        let mut sa: HashMap<AssociationHandle, Association> = HashMap::new();
        let mut sb: HashMap<AssociationHandle, Association> = HashMap::new();
        let mut a_up = false;
        let mut b_up = false;

        for _ in 0..100 {
            let mut moved = false;

            // client A -> server A, client B -> server B
            for d in drain_transmits(&mut conn_a, now) {
                moved = true;
                if let Some((ch, ev)) = server_a.handle(now, client_addr(), None, d) {
                    match ev {
                        DatagramEvent::NewAssociation(c) => {
                            sa.insert(ch, c);
                        }
                        DatagramEvent::AssociationEvent(e) => {
                            if let Some(c) = sa.get_mut(&ch) {
                                c.handle_event(e);
                            }
                        }
                        _ => {}
                    }
                }
            }
            for d in drain_transmits(&mut conn_b, now) {
                moved = true;
                if let Some((ch, ev)) = server_b.handle(now, client_addr(), None, d) {
                    match ev {
                        DatagramEvent::NewAssociation(c) => {
                            sb.insert(ch, c);
                        }
                        DatagramEvent::AssociationEvent(e) => {
                            if let Some(c) = sb.get_mut(&ch) {
                                c.handle_event(e);
                            }
                        }
                        _ => {}
                    }
                }
            }

            // servers -> client (client_ep routes back by verification tag)
            let mut back = vec![];
            for c in sa.values_mut() {
                while c.poll().is_some() {}
                for d in drain_transmits(c, now) {
                    back.push((server_a_addr, d));
                }
            }
            for c in sb.values_mut() {
                while c.poll().is_some() {}
                for d in drain_transmits(c, now) {
                    back.push((server_b_addr, d));
                }
            }
            for (from, d) in back {
                moved = true;
                if let Some((ch, DatagramEvent::AssociationEvent(e))) =
                    client_ep.handle(now, from, None, d)
                {
                    if ch == ch_a {
                        conn_a.handle_event(e);
                    } else if ch == ch_b {
                        conn_b.handle_event(e);
                    }
                }
            }

            while let Some(ev) = conn_a.poll() {
                if let Event::Connected = ev {
                    a_up = true;
                }
            }
            while let Some(ev) = conn_b.poll() {
                if let Event::Connected = ev {
                    b_up = true;
                }
            }

            if a_up && b_up && !moved {
                break;
            }
        }

        assert!(a_up && b_up, "both associations must connect");
        (client_ep, ch_a, conn_a, ch_b, conn_b)
    }

    /// Wrap an established client endpoint + association in a handler context.
    fn client_ctx(
        now: Instant,
        client_ep: Endpoint,
        ch: AssociationHandle,
        conn: Association,
    ) -> SctpHandlerContext {
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport.receive_message_limit = SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize;
        // As `SctpTransport::start` sets it by default.
        transport.partial_message_limit =
            crate::peer_connection::transport::sctp::DEFAULT_INBOUND_REASSEMBLY_LIMIT;
        transport.negotiated_max_message_size = Some(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
        // An association made by hand from `TransportConfig::default()` does not interleave;
        // this test is not about the 16 KB limit that follows from that (see
        // `a_message_over_16_kb_is_refused_without_interleaving`).
        transport.limit_message_size_without_interleaving = false;
        transport.sctp_endpoint = Some(client_ep);
        transport.sctp_associations.insert(ch, conn);
        SctpHandlerContext::new(now, transport)
    }

    // First-chunk types we assert on (RFC 9260 §3.2). The `sctp` crate keeps its
    // `CT_*` constants crate-private, so we decode the wire format directly.
    const CT_PAYLOAD_DATA: u8 = 0;
    const CT_SHUTDOWN: u8 = 7;
    const CT_SHUTDOWN_COMPLETE: u8 = 14;

    /// First SCTP chunk type of every datagram flushed into `write_outs`. The SCTP
    /// common header is a fixed 12 bytes (RFC 9260 §3.1), so the first chunk's type
    /// field is byte 12.
    fn flushed_chunk_types(ctx: &SctpHandlerContext) -> Vec<u8> {
        ctx.write_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) if raw.len() > 12 => Some(raw[12]),
                _ => None,
            })
            .collect()
    }

    const CT_SACK: u8 = 3;

    /// The advertised receiver window (`a_rwnd`) from the first flushed SACK.
    ///
    /// Asserting on the wire rather than on the association's internal credit: `a_rwnd` is
    /// what the peer actually reads, and `get_my_receiver_window_credit()` is `pub(crate)` to
    /// the `sctp` crate anyway. Layout is RFC 9260 §3.3.4 — 12-byte common header, then the
    /// 4-byte chunk header, then a 4-byte Cumulative TSN Ack, then `a_rwnd`.
    fn flushed_sack_a_rwnd(flushed: &[TaggedRTCMessageInternal]) -> Option<u32> {
        flushed.iter().find_map(|m| match &m.message {
            RTCMessageInternal::Dtls(DTLSMessage::Raw(raw))
                if raw.len() >= 24 && raw[12] == CT_SACK =>
            {
                Some(u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]))
            }
            _ => None,
        })
    }

    /// Feed `dgrams` to a client handler with the given downstream backlog, flush, and return
    /// the resulting context.
    fn run_client(
        now: Instant,
        e: Established,
        dgrams: Vec<Bytes>,
        backlog: usize,
    ) -> (SctpHandlerContext, Vec<TaggedRTCMessageInternal>) {
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        let mut flushed = vec![];
        let mut handler = SctpHandler::new(&mut ctx, backlog);
        for dgram in dgrams {
            handler.handle_read(raw_read(now, dgram)).expect("read");
        }
        // The first DATA arms a *delayed* ack, so without letting that timer expire there is
        // no SACK to read `a_rwnd` from. Harmless in the parked case: the backlog is still
        // over the bound there, so the resume finds no budget and changes nothing.
        handler
            .handle_timeout(now + Duration::from_millis(500))
            .expect("delayed-ack timer");
        // `poll_write` *pops*: collect, or the evidence is thrown away.
        while let Some(m) = handler.poll_write() {
            flushed.push(m);
        }
        (ctx, flushed)
    }

    /// Push `count` messages from the server onto `stream_id` and return the datagrams the
    /// client must receive. Returns raw wire bytes so the test drives the real
    /// `handle_read` path rather than poking handler internals.
    fn server_datagrams_carrying(
        e: &mut Established,
        stream_id: StreamId,
        count: usize,
        now: Instant,
    ) -> Vec<Bytes> {
        {
            let mut stream = e
                .server_conn
                .open_stream(stream_id, PayloadProtocolIdentifier::Binary)
                .expect("open server stream");
            for i in 0..count {
                stream
                    .write_sctp(
                        now,
                        &Bytes::from(vec![i as u8; 64]),
                        PayloadProtocolIdentifier::Binary,
                    )
                    .expect("server write");
            }
        }
        while e.server_conn.poll().is_some() {}
        drain_transmits(&mut e.server_conn, now)
    }

    fn raw_read(now: Instant, dgram: Bytes) -> TaggedRTCMessageInternal {
        TaggedRTCMessageInternal {
            now,
            transport: TransportContext {
                local_addr: client_addr(),
                peer_addr: server_addr(),
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&dgram[..]))),
        }
    }

    /// An SCTP DATA message that overtakes the COOKIE-ACK finds the association in
    /// COOKIE-ECHOED, where RFC 9260 section 6 has it discarded ("DATA chunks MUST only be
    /// received ... in the ESTABLISHED, SHUTDOWN-PENDING, and SHUTDOWN-SENT states. ... A
    /// DATA chunk received in any other state SHOULD be discarded"): nothing reaches the
    /// DataChannel handler and nothing is parked. Once COOKIE-ACK has established the
    /// association the peer's retransmission of the message is delivered, once, so the
    /// DataChannel handler announces `OnOpen` only after SCTP is ready.
    #[test]
    fn inbound_data_waits_for_sctp_handshake() {
        let now = Instant::now();
        let (mut ctx, cookie_ack, early_data) = client_with_data_before_cookie_ack();

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for dgram in early_data.clone() {
                handler
                    .handle_read(raw_read(now, dgram))
                    .expect("early DATA");
            }
        }

        assert!(
            ctx.read_outs.is_empty(),
            "handshaking SCTP data must not reach the DataChannel handler"
        );
        assert!(
            ctx.pending_readable.is_empty(),
            "DATA in COOKIE-ECHOED is discarded, not kept"
        );

        let inbound = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for dgram in cookie_ack {
                handler
                    .handle_read(raw_read(now, dgram))
                    .expect("COOKIE-ACK");
            }
            assert!(handler.poll_read().is_none(), "nothing was kept");
            let mut announced = false;
            while let Some(evt) = handler.poll_event() {
                announced |= matches!(evt.event, RTCEventInternal::SCTPHandshakeComplete(_));
            }
            assert!(announced, "the association must say it is up");
            // The peer sends the message again (it was never acknowledged).
            for dgram in early_data {
                handler
                    .handle_read(raw_read(now, dgram))
                    .expect("retransmitted DATA");
            }
            handler.poll_read().expect("delivered DCEP")
        };

        assert!(
            ctx.pending_readable.is_empty(),
            "the stream must be drained after SCTP becomes established"
        );
        assert!(
            ctx.read_outs.is_empty(),
            "early DCEP must be delivered once"
        );
        assert!(matches!(
            &inbound.message,
            RTCMessageInternal::Dtls(DTLSMessage::Sctp(data))
                if data.ppi == PayloadProtocolIdentifier::Dcep
        ));

        // The DataChannel handler now sees the DCEP message only after SCTP has become
        // established. It can therefore accept the channel, emit Open, and queue its ACK
        // without attempting a write in CookieEchoed.
        let mut data_channel_ctx = DataChannelHandlerContext::new(now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();
        {
            let mut handler = DataChannelHandler::new(
                &mut data_channel_ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Client,
                None,
            );
            handler
                .handle_read(inbound)
                .expect("accept DCEP after SCTP handshake");
        }
        assert!(
            data_channel_ctx.read_outs.iter().any(|message| matches!(
                &message.message,
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open)
            )),
            "the DataChannel Open event must follow SCTP establishment"
        );
    }

    /// Data the peer sends the moment its side is up can arrive in the same sweep as the
    /// COOKIE-ACK that brings this side up. It must not reach the DataChannel handler before
    /// the `SCTPHandshakeComplete` on which that handler opens the negotiated channels, or the
    /// handler drops it for a channel not open yet, after SCTP has acknowledged it.
    #[test]
    fn data_right_after_cookie_ack_waits_for_the_handshake_event() {
        let now = Instant::now();
        let (mut ctx, cookie_ack, early_data) = client_with_data_before_cookie_ack();
        let mut handler = SctpHandler::new(&mut ctx, 0);
        for dgram in cookie_ack.into_iter().chain(early_data) {
            handler
                .handle_read(raw_read(now, dgram))
                .expect("COOKIE-ACK, then DATA");
        }
        // The pipeline pumps this handler's reads within `handle_read`, before its events.
        assert!(
            handler.poll_read().is_none(),
            "data must not overtake SCTPHandshakeComplete"
        );
        let mut announced = false;
        while let Some(evt) = handler.poll_event() {
            announced |= matches!(evt.event, RTCEventInternal::SCTPHandshakeComplete(_));
        }
        assert!(announced, "the association must say it is up");
        let inbound = handler
            .poll_read()
            .expect("the data, once the event has gone");
        assert!(matches!(
            &inbound.message,
            RTCMessageInternal::Dtls(DTLSMessage::Sctp(data))
                if data.ppi == PayloadProtocolIdentifier::Dcep
        ));
        assert!(handler.poll_read().is_none(), "delivered once");
    }

    /// With the pipeline already at its bound, inbound DATA must be left in the reassembly
    /// queue rather than pulled into the pipeline — and the peer must be *told*, by the only
    /// channel SCTP has for saying so: a smaller `a_rwnd` in the SACK.
    ///
    /// Draining unconditionally is exactly what defeats this. The bytes sitting in the
    /// reassembly queue are what `max_receive_buffer_size` is measured against, so emptying
    /// it on arrival keeps `a_rwnd` pinned at maximum however far behind the application is.
    #[test]
    fn a_full_pipeline_parks_the_stream_and_shrinks_the_advertised_window() {
        let now = Instant::now();

        // Same traffic, two identical associations: one allowed to drain, one at the bound.
        let mut e_free = establish();
        let free_dgrams = server_datagrams_carrying(&mut e_free, 1, 8, now);
        let mut e_full = establish();
        let full_dgrams = server_datagrams_carrying(&mut e_full, 1, 8, now);
        assert!(!full_dgrams.is_empty(), "server produced no DATA");

        let (ctx_free, flushed_free) = run_client(now, e_free, free_dgrams, 0);
        let (ctx_full, flushed_full) =
            run_client(now, e_full, full_dgrams, SCTP_PIPELINE_READ_BACKLOG_LIMIT);

        assert!(
            !ctx_free.read_outs.is_empty(),
            "control: an empty pipeline must receive the messages"
        );
        assert!(
            ctx_free.pending_readable.is_empty(),
            "control: nothing should be parked when there is room"
        );

        assert!(
            ctx_full.read_outs.is_empty(),
            "a full pipeline must not be handed more messages, got {}",
            ctx_full.read_outs.len()
        );
        assert!(
            !ctx_full.pending_readable.is_empty(),
            "the stream must be remembered, or the edge-triggered Readable is lost forever"
        );

        let free = flushed_sack_a_rwnd(&flushed_free).expect("control flushed no SACK");
        let full = flushed_sack_a_rwnd(&flushed_full).expect("parked run flushed no SACK");
        assert!(
            full < free,
            "undrained bytes must shrink the window advertised to the peer: \
             parked a_rwnd {full} should be below drained a_rwnd {free}"
        );
    }

    /// **The deadlock this feature would otherwise create.**
    ///
    /// `StreamEvent::Readable` is edge-triggered: `association/mod.rs` emits it when a *new*
    /// DATA chunk arrives, never because unread data remains. So the moment back-pressure
    /// works — the peer throttled, no new chunk coming — a stream parked mid-drain would
    /// never be revisited, and the connection would stall exactly when the feature engaged.
    ///
    /// This drives `handle_timeout` with **no new inbound datagram** and requires the parked
    /// data to come through anyway.
    #[test]
    fn a_parked_stream_resumes_without_a_new_inbound_chunk() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_datagrams_carrying(&mut e, 1, 8, now);

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in dgrams {
                handler.handle_read(raw_read(now, dgram)).expect("read");
            }
        }
        assert!(ctx.read_outs.is_empty(), "precondition: nothing drained");
        assert!(!ctx.pending_readable.is_empty(), "precondition: parked");

        // The application drains, so the pipeline has room again. Nothing else happens: no
        // packet arrives, and the peer — correctly throttled — sends nothing. The only call
        // is the one the pipeline makes when it wants data.
        let resumed = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler.poll_read()
        };

        assert!(
            resumed.is_some(),
            "parked stream never resumed — this is the edge-triggered Readable deadlock: \
             the peer is throttled so no new chunk will arrive to re-trigger the drain"
        );
        assert!(
            ctx.pending_readable.is_empty(),
            "a fully drained stream must stop being remembered"
        );
    }

    /// A resumed drain must be stamped with **its own** association's 5-tuple.
    ///
    /// The first version of this kept a single `last_transport` — the most recent inbound
    /// datagram's context — and reused it for every resumed message. With more than one
    /// association on the endpoint (which `sctp_associations` being a map allows, and
    /// `establish_two` exercises) that hands association A's messages association B's peer
    /// address, because whichever datagram arrived last wins.
    #[test]
    fn a_resumed_drain_uses_its_own_associations_transport() {
        let now = Instant::now();

        // Two associations to two different peers, each carrying parked data.
        let mut e_a = establish();
        let a_dgrams = server_datagrams_carrying(&mut e_a, 1, 4, now);
        let mut e_b = establish();
        let b_dgrams = server_datagrams_carrying(&mut e_b, 1, 4, now);

        let peer_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7001);
        let peer_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7002);

        let mut ctx = client_ctx(now, e_a.client_ep, e_a.client_ch, e_a.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in a_dgrams {
                let mut msg = raw_read(now, dgram);
                msg.transport.peer_addr = peer_a;
                handler.handle_read(msg).expect("read A");
            }
        }
        assert!(!ctx.pending_readable.is_empty(), "A must be parked");

        // A datagram from a *different* peer arrives afterwards. Under the old single
        // `last_transport` this is the value A's resumed messages would inherit.
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in b_dgrams {
                let mut msg = raw_read(now, dgram);
                msg.transport.peer_addr = peer_b;
                // Belongs to no association on this endpoint; under the old single
                // `last_transport` it would still have overwritten it.
                let _ = handler.handle_read(msg);
            }
        }

        // Now let A resume, through the path that actually resumes it.
        let mut resumed = vec![];
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            while let Some(msg) = handler.poll_read() {
                resumed.push(msg);
            }
        }

        assert!(!resumed.is_empty(), "A never resumed");
        for msg in &resumed {
            assert_eq!(
                msg.transport.peer_addr, peer_a,
                "a resumed message must carry its own association's peer address, not \
                 whichever datagram happened to arrive most recently"
            );
        }
    }

    /// A parked stream resumes by itself once the pipeline has room again: `poll_timeout`
    /// reports a deadline for it, `handle_timeout` drains it, and the SACK that reopens the
    /// window is flushed with no inbound datagram (RFC 9260 section 6.2).
    ///
    /// While the pipeline is full the deadline must not be reported. The only instant here
    /// is the retained one, never later than the caller's clock, and a caller that answers a
    /// due deadline with `handle_timeout` and `continue` (`tests/ice_tcp_active_passive.rs`)
    /// would skip its socket reads for as long as it repeated: so it is reported only when
    /// handling it makes progress, and not again once it has.
    #[test]
    fn a_parked_stream_resumes_from_the_timer_once_the_pipeline_has_room() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_datagrams_carrying(&mut e, 1, 8, now);

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in dgrams {
                handler.handle_read(raw_read(now, dgram)).expect("read");
            }
            while handler.poll_write().is_some() {}
        }
        assert!(!ctx.pending_readable.is_empty(), "precondition: parked");

        // No room: nothing the timer could do, so no deadline at or before `now`.
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            if let Some(eto) = handler.poll_timeout() {
                assert!(
                    eto > now,
                    "a parked stream with no room must not put a due deadline in front of \
                     the caller: callers read that as zero delay and skip their I/O"
                );
            }
        }

        // The application drained the pipeline without a `poll_read` here, and nothing
        // arrives: the deadline is due at once, and handling it drains the stream.
        let later = now + Duration::from_millis(10);
        let mut handler = SctpHandler::new(&mut ctx, 0);
        assert!(
            handler.poll_timeout().is_some_and(|eto| eto <= now),
            "a parked stream the pipeline has room for must report a due deadline"
        );
        handler.handle_timeout(later).expect("timeout");
        let mut resumed = 0;
        while handler.poll_read().is_some() {
            resumed += 1;
        }
        assert!(resumed > 0, "the timer did not resume the parked stream");
        assert!(
            handler.ctx.pending_readable.is_empty(),
            "a fully drained stream must stop being remembered"
        );
        // Handled: the deadline is not repeated.
        assert!(
            handler.poll_timeout().is_none_or(|eto| eto > later),
            "a handled deadline must not stay due"
        );
    }

    /// A drain from `poll_read` that took data out of SCTP makes the next `poll_write` due:
    /// the caller has usually made its `poll_write` for this turn before it reads, and the
    /// SACK telling the peer of the space (RFC 9260 section 6.2) must not wait for whatever
    /// wakes the caller next.
    #[test]
    fn a_resume_from_poll_read_makes_the_window_update_due() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_datagrams_carrying(&mut e, 1, 8, now);

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            for dgram in dgrams {
                handler.handle_read(raw_read(now, dgram)).expect("read");
            }
            while handler.poll_write().is_some() {}
        }
        let mut handler = SctpHandler::new(&mut ctx, 0);
        assert!(handler.poll_read().is_some(), "precondition: resumed");
        assert!(
            handler.poll_timeout().is_some_and(|eto| eto <= now),
            "the window update after a resumed drain must be due at once"
        );
        while handler.poll_write().is_some() {}
        while handler.poll_read().is_some() {}
        assert!(
            handler.poll_timeout().is_none_or(|eto| eto > now),
            "once flushed, the window update is not due any more"
        );
    }

    // handle_timeout teardown-safety block: a graceful shutdown queues both the
    // `Drained` endpoint event AND the final SHUTDOWN datagram. handle_timeout
    // collects the drain (removing the association) and must flush the SHUTDOWN
    // *before* removal, or the peer would never learn the association closed.
    #[test]
    fn handle_timeout_flushes_final_packet_before_drain() {
        let now = Instant::now();
        let e = establish();
        let mut client_conn = e.client_conn;
        client_conn
            .shutdown()
            .expect("shutdown from Established queues Drained + SHUTDOWN");

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, client_conn);
        assert_eq!(ctx.sctp_transport.sctp_associations.len(), 1);

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler
                .handle_timeout(Instant::now())
                .expect("handle_timeout");
        }

        assert!(
            ctx.sctp_transport.sctp_associations.is_empty(),
            "draining association must be removed"
        );
        let flushed = flushed_chunk_types(&ctx);
        assert!(
            flushed.contains(&CT_SHUTDOWN),
            "the final SHUTDOWN must be flushed before removal, not dropped \
             (flushed chunk types: {flushed:?})"
        );
    }

    const CT_ABORT: u8 = 6;

    // `close()` asks for an abort (W3C close(): "tear down the underlying SCTP association by
    // sending an SCTP ABORT chunk"). The data still queued must go out before the ABORT, which
    // would otherwise discard it, and the stream losses the abort reports must not stay queued
    // for a later read to surface as OnClose: the local channels close without their closing
    // procedure.
    #[test]
    fn abort_sends_pending_data_then_abort_and_drops_local_events() {
        let now = Instant::now();
        let e = establish();
        let mut client_conn = e.client_conn;
        client_conn
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .and_then(|mut s| {
                s.write_chunk_with_ppi(
                    now,
                    &Bytes::from_static(b"last words"),
                    PayloadProtocolIdentifier::Binary,
                )
            })
            .expect("queue DATA");

        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, client_conn);
        let mut sent = vec![];
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler.request_abort();
            while let Some(msg) = handler.poll_write() {
                sent.push(msg);
            }
        }
        let types: Vec<u8> = sent
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) if raw.len() > 12 => Some(raw[12]),
                _ => None,
            })
            .collect();
        let data = types.iter().position(|t| *t == CT_PAYLOAD_DATA);
        let abort = types.iter().position(|t| *t == CT_ABORT);
        assert!(
            matches!((data, abort), (Some(d), Some(a)) if d < a),
            "the pending DATA must be sent, then the ABORT (chunk types: {types:?})"
        );

        for association in ctx.sctp_transport.sctp_associations.values_mut() {
            assert!(association.is_closed(), "the association is closed");
            assert!(
                association.poll().is_none(),
                "the abort's stream losses must not stay queued"
            );
        }
    }

    // handle_read teardown-safety block (+ the SctpMessage::Outbound arm): when the
    // client, mid graceful-shutdown, receives the peer's SHUTDOWN_ACK it must emit a
    // SHUTDOWN_COMPLETE. That inbound arrives via handle_read, which collects the
    // Drained and removes the association — so the SHUTDOWN_COMPLETE has to be flushed
    // in the same call.
    #[test]
    fn handle_read_flushes_final_packet_before_drain() {
        let e = establish();
        let mut client_conn = e.client_conn;
        let mut server_ep = e.server_ep;
        let mut server_conn = e.server_conn;
        let server_ch = e.server_ch;
        let now = Instant::now();

        // Client initiates graceful shutdown -> emits SHUTDOWN.
        client_conn.shutdown().expect("shutdown");
        let shutdown_dgrams = drain_transmits(&mut client_conn, now);
        assert!(!shutdown_dgrams.is_empty(), "shutdown emits SHUTDOWN");

        // Server processes SHUTDOWN -> replies SHUTDOWN_ACK.
        for d in shutdown_dgrams {
            if let Some((ch, DatagramEvent::AssociationEvent(ev))) =
                server_ep.handle(now, client_addr(), None, d)
            {
                assert_eq!(ch, server_ch);
                server_conn.handle_event(ev);
            }
        }
        while server_conn.poll().is_some() {}
        let ack_dgrams = drain_transmits(&mut server_conn, now);
        assert!(!ack_dgrams.is_empty(), "server replies SHUTDOWN_ACK");

        // Feed SHUTDOWN_ACK to the client HANDLER via handle_read.
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, client_conn);
        assert_eq!(ctx.sctp_transport.sctp_associations.len(), 1);
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for d in ack_dgrams {
                let msg = TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext {
                        local_addr: client_addr(),
                        peer_addr: server_addr(),
                        transport_protocol: TransportProtocol::UDP,
                        ecn: None,
                    },
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&d[..]))),
                };
                handler.handle_read(msg).expect("handle_read");
            }
        }

        assert!(
            ctx.sctp_transport.sctp_associations.is_empty(),
            "draining association must be removed"
        );
        let flushed = flushed_chunk_types(&ctx);
        assert!(
            flushed.contains(&CT_SHUTDOWN_COMPLETE),
            "the final SHUTDOWN_COMPLETE must be flushed before removal, not dropped \
             (flushed chunk types: {flushed:?})"
        );
    }

    /// W3C webrtc-pc 6.1.2: the transport is "closed" when "the SCTP association ... is
    /// closed, either because an SCTP SHUTDOWN or ABORT chunk was received". Here the peer
    /// shuts the association down gracefully: its SHUTDOWN reaches this side's handler, which
    /// completes the shutdown, and the transport reads "closed".
    #[test]
    fn a_received_shutdown_closes_the_sctp_transport() {
        use crate::peer_connection::transport::RTCSctpTransportState;
        let e = establish();
        let now = Instant::now();
        let mut server_ep = e.server_ep;
        let mut server_conn = e.server_conn;
        let server_ch = e.server_ch;
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        // As `SctpTransport::start` leaves it.
        ctx.sctp_transport.is_started = true;
        assert_eq!(ctx.sctp_transport.state(), RTCSctpTransportState::Connected);

        server_conn.shutdown().expect("shutdown");
        let mut to_client = drain_transmits(&mut server_conn, now);
        assert!(!to_client.is_empty(), "the peer sends its SHUTDOWN");
        let mut rounds = 0;
        while !to_client.is_empty() {
            rounds += 1;
            assert!(rounds < 10, "the shutdown does not end");
            let mut to_server = vec![];
            {
                let mut handler = SctpHandler::new(&mut ctx, 0);
                for d in to_client.drain(..) {
                    handler
                        .handle_read(TaggedRTCMessageInternal {
                            now,
                            transport: TransportContext {
                                local_addr: client_addr(),
                                peer_addr: server_addr(),
                                transport_protocol: TransportProtocol::UDP,
                                ecn: None,
                            },
                            message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(
                                &d[..],
                            ))),
                        })
                        .expect("handle_read");
                }
                handler.handle_timeout(now).expect("handle_timeout");
                while let Some(out) = handler.poll_write() {
                    if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = out.message {
                        to_server.push(raw.freeze());
                    }
                }
            }
            for d in to_server {
                if let Some((ch, DatagramEvent::AssociationEvent(ev))) =
                    server_ep.handle(now, client_addr(), None, d)
                {
                    assert_eq!(ch, server_ch);
                    server_conn.handle_event(ev);
                }
            }
            while server_conn.poll().is_some() {}
            to_client = drain_transmits(&mut server_conn, now);
        }
        assert_eq!(
            ctx.sctp_transport.state(),
            RTCSctpTransportState::Closed,
            "a received SHUTDOWN closes the transport"
        );
    }

    // The teardown-safety flush must touch ONLY the draining association. With two
    // live associations, draining A must flush A's final SHUTDOWN and remove A while
    // leaving B — and B's queued DATA — untouched (B keeps coalescing and is flushed
    // later in poll_write). The over-broad "flush every association" form would drain
    // B's DATA here too; this test rejects that.
    #[test]
    fn teardown_flush_targets_only_the_draining_association() {
        let now = Instant::now();
        let (client_ep, ch_a, mut conn_a, ch_b, mut conn_b) = establish_two();

        // A: graceful shutdown -> Drained + a pending SHUTDOWN.
        conn_a.shutdown().expect("shutdown A");
        // B: queue DATA that is NOT yet flushed (stays pending in the association).
        conn_b
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .and_then(|mut s| {
                s.write_chunk_with_ppi(
                    now,
                    &Bytes::from_static(b"pending payload on B"),
                    PayloadProtocolIdentifier::Binary,
                )
            })
            .expect("queue DATA on B");

        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport.receive_message_limit = SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize;
        // As `SctpTransport::start` sets it by default.
        transport.partial_message_limit =
            crate::peer_connection::transport::sctp::DEFAULT_INBOUND_REASSEMBLY_LIMIT;
        transport.negotiated_max_message_size = Some(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
        // An association made by hand from `TransportConfig::default()` does not interleave;
        // this test is not about the 16 KB limit that follows from that (see
        // `a_message_over_16_kb_is_refused_without_interleaving`).
        transport.limit_message_size_without_interleaving = false;
        transport.sctp_endpoint = Some(client_ep);
        transport.sctp_associations.insert(ch_a, conn_a);
        transport.sctp_associations.insert(ch_b, conn_b);
        let mut ctx = SctpHandlerContext::new(now, transport);

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler
                .handle_timeout(Instant::now())
                .expect("handle_timeout");
        }

        // A (draining) removed; B (live) retained.
        assert!(
            !ctx.sctp_transport.sctp_associations.contains_key(&ch_a),
            "draining association A must be removed"
        );
        assert!(
            ctx.sctp_transport.sctp_associations.contains_key(&ch_b),
            "live association B must be retained"
        );

        // Only A's SHUTDOWN was flushed; B's DATA was NOT.
        let flushed = flushed_chunk_types(&ctx);
        assert!(
            flushed.contains(&CT_SHUTDOWN),
            "A's final SHUTDOWN must be flushed (flushed chunk types: {flushed:?})"
        );
        assert!(
            !flushed.contains(&CT_PAYLOAD_DATA),
            "B's DATA must NOT be flushed by A's teardown (flushed chunk types: {flushed:?})"
        );

        // ...and B's DATA is still pending in the association, ready for poll_write.
        let b = ctx
            .sctp_transport
            .sctp_associations
            .get_mut(&ch_b)
            .expect("B present");
        assert!(
            b.poll_transmit(Instant::now()).is_some(),
            "B's queued DATA must remain pending, not consumed by A's teardown"
        );
    }

    // Design §3.7's worked example. The client INIT is queued by `connect` inside
    // `handle_event` and emitted by the *next* `poll_write` — so before C3-01 gave the event
    // channel a timestamp, the retained instant was still unset at that point and the flush
    // fell back to `Instant::now()`. That was not a defensive branch: it was the path taken on
    // every client connection. Now the INIT is stamped from the event that armed it.
    #[test]
    fn client_init_flush_is_stamped_from_the_event_that_armed_it() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport.receive_message_limit = SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE as usize;
        // As `SctpTransport::start` sets it by default.
        transport.partial_message_limit =
            crate::peer_connection::transport::sctp::DEFAULT_INBOUND_REASSEMBLY_LIMIT;
        transport.negotiated_max_message_size = Some(SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE);
        // An association made by hand from `TransportConfig::default()` does not interleave;
        // this test is not about the 16 KB limit that follows from that (see
        // `a_message_over_16_kb_is_refused_without_interleaving`).
        transport.limit_message_size_without_interleaving = false;
        transport.sctp_endpoint = Some(Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        ));
        transport.sctp_transport_config = Some(TransportConfig::default());
        let mut ctx = SctpHandlerContext::new(t(0), transport);

        // No inbound SCTP has been seen, so nothing but the event has moved the retained
        // instant off its construction seed.
        assert_eq!(ctx.now, t(0));

        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now: t(7),
                    event: RTCEventInternal::DTLSHandshakeComplete(None, None),
                })
                .expect("handle_event");
        }
        assert_eq!(
            ctx.now,
            t(7),
            "the event's instant must arm the deferred flush"
        );

        let flushed = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            let mut out = vec![];
            while let Some(msg) = handler.poll_write() {
                out.push(msg);
            }
            out
        };

        assert!(!flushed.is_empty(), "poll_write must emit the client INIT");
        for msg in &flushed {
            assert_eq!(
                msg.now,
                t(7),
                "the INIT carries the instant of the event that caused it, not the wall clock"
            );
        }
    }

    /// RFC 9260 section 8.4: a packet that belongs to no association of the endpoint is "out
    /// of the blue", and one carrying DATA is answered with an ABORT that reflects its
    /// Verification Tag. `Endpoint::handle` queues that answer in the endpoint, not in an
    /// association, so the handler has to poll the endpoint for it.
    #[test]
    fn a_packet_for_no_association_is_answered_with_the_endpoints_abort() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_datagrams_carrying(&mut e, 1, 1, now);
        assert!(!dgrams.is_empty());
        let tag = dgrams[0][4..8].to_vec();

        // An endpoint that has lost the association the server still holds.
        let mut transport = SctpTransport::new(
            SctpMaxMessageSize::default(),
            None,
            None,
            test_transport_id(TransportKind::Sctp),
            test_transport_id(TransportKind::Dtls),
        );
        transport.sctp_endpoint = Some(Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        ));
        let mut ctx = SctpHandlerContext::new(now, transport);
        let mut handler = SctpHandler::new(&mut ctx, 0);
        for dgram in dgrams {
            handler.handle_read(raw_read(now, dgram)).expect("read");
        }
        let mut sent = vec![];
        while let Some(m) = handler.poll_write() {
            sent.push(m);
        }
        assert_eq!(sent.len(), 1, "one answer");
        let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = &sent[0].message else {
            panic!("an SCTP packet");
        };
        assert_eq!(raw[12], CT_ABORT, "an ABORT");
        assert_eq!(&raw[4..8], &tag[..], "with the packet's Verification Tag");
        // RFC 9260 section 8.4 rule 8: the T bit says the tag is reflected.
        assert_eq!(raw[13] & 1, 1, "T bit");
        // Back the way the packet came.
        assert_eq!(sent[0].transport.peer_addr, server_addr());
    }

    /// RFC 9260 section 7.2.5 as `Association::on_path_change` implements it: when the
    /// association's packets start to arrive over another 5-tuple (ICE selected another
    /// candidate pair), the congestion window goes back to its initial value. Packets that
    /// keep arriving over the same 5-tuple leave it alone.
    #[test]
    fn an_association_whose_packets_arrive_over_another_path_starts_congestion_control_over() {
        let now = Instant::now();
        let mut e = establish();
        let initial = e.client_conn.congestion_window();

        // The client sends enough for slow start to open the window, and the server
        // acknowledges it.
        {
            let mut stream = e
                .client_conn
                .open_stream(1, PayloadProtocolIdentifier::Binary)
                .expect("open client stream");
            for _ in 0..24 {
                stream
                    .write_sctp(
                        now,
                        &Bytes::from(vec![7u8; 1000]),
                        PayloadProtocolIdentifier::Binary,
                    )
                    .expect("client write");
            }
        }
        let mut sacks = vec![];
        let mut at = now;
        for _ in 0..40 {
            let out = drain_transmits(&mut e.client_conn, at);
            for dgram in out {
                if let Some((_, DatagramEvent::AssociationEvent(event))) =
                    e.server_ep.handle(at, client_addr(), None, dgram)
                {
                    e.server_conn.handle_event(event);
                }
            }
            while e.server_conn.poll().is_some() {}
            at += Duration::from_millis(250);
            e.server_conn.handle_timeout(at);
            let acks = drain_transmits(&mut e.server_conn, at);
            if acks.is_empty() {
                break;
            }
            for dgram in &acks {
                if let Some((_, DatagramEvent::AssociationEvent(event))) =
                    e.client_ep.handle(at, server_addr(), None, dgram.clone())
                {
                    e.client_conn.handle_event(event);
                }
            }
            sacks = acks;
        }
        let opened = e.client_conn.congestion_window();
        assert!(
            opened > initial,
            "slow start opened the window: {initial} -> {opened}"
        );
        assert!(!sacks.is_empty());

        // One more datagram from the server, over the path every packet took so far.
        let same_path = server_datagrams_carrying(&mut e, 3, 1, at);
        let other_path = server_datagrams_carrying(&mut e, 5, 1, at);
        let ch = e.client_ch;
        let mut ctx = client_ctx(at, e.client_ep, e.client_ch, e.client_conn);
        let mut handler = SctpHandler::new(&mut ctx, 0);
        // The first datagram the handler sees records the path; the second confirms it.
        handler
            .handle_read(raw_read(at, sacks[0].clone()))
            .expect("read");
        for dgram in same_path {
            handler.handle_read(raw_read(at, dgram)).expect("read");
        }
        assert_eq!(
            handler.ctx.sctp_transport.sctp_associations[&ch].congestion_window(),
            opened,
            "the same path: nothing starts over"
        );

        let moved = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5556);
        for dgram in other_path {
            let mut read = raw_read(at, dgram);
            read.transport.peer_addr = moved;
            handler.handle_read(read).expect("read");
        }
        assert_eq!(
            handler.ctx.sctp_transport.sctp_associations[&ch].congestion_window(),
            initial,
            "another path: the congestion window is the initial one again"
        );
    }

    // C4-04 replaced `last_now: Option<Instant>` + `unwrap_or_else(Instant::now)` with a
    // construction-seeded `now: Instant`. The *point* of the deferred flush is batching — N
    // inbound DATA chunks ingested before one flush, so the ack machine coalesces them into a
    // single SACK instead of one per two packets. Nothing in the suite pinned that invariant,
    // and the workspace has no SCTP throughput benchmark to measure it with, so this asserts it
    // structurally: a burst of reads must arm the flush once and produce one flush's worth of
    // output, not one per packet.
    #[test]
    fn a_burst_of_reads_produces_one_flush_not_one_per_packet() {
        let base = Instant::now();
        let t = |millis| base + Duration::from_millis(millis);

        let e = establish();
        let mut server_conn = e.server_conn;
        let server_ch = e.server_ch;
        let mut ctx = client_ctx(t(0), e.client_ep, e.client_ch, e.client_conn);

        // Server sends several DATA chunks; each becomes its own inbound datagram.
        let mut stream = server_conn
            .open_stream(1, PayloadProtocolIdentifier::Binary)
            .expect("open stream");
        for i in 0..4u8 {
            stream
                .write_chunk_with_ppi(
                    base,
                    &Bytes::from(vec![i; 1024]),
                    PayloadProtocolIdentifier::Binary,
                )
                .expect("queue DATA");
        }
        let dgrams = drain_transmits(&mut server_conn, t(0));
        assert!(
            dgrams.len() >= 2,
            "the burst must be more than one datagram to be worth batching, got {}",
            dgrams.len()
        );
        let _ = server_ch;

        // Ingest the whole burst. Every read arms the flush; none performs it.
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for (i, d) in dgrams.iter().enumerate() {
                handler
                    .handle_read(TaggedRTCMessageInternal {
                        now: t(i as u64),
                        transport: TransportContext {
                            local_addr: client_addr(),
                            peer_addr: server_addr(),
                            transport_protocol: TransportProtocol::UDP,
                            ecn: None,
                        },
                        message: RTCMessageInternal::Dtls(DTLSMessage::Raw(BytesMut::from(&d[..]))),
                    })
                    .expect("handle_read");
            }
        }
        assert!(
            ctx.write_outs.is_empty(),
            "ingest must not flush: that is what makes the SACKs coalesce"
        );
        assert_eq!(
            ctx.now,
            t(dgrams.len() as u64 - 1),
            "the retained instant is the newest of the burst, which is what stamps the flush"
        );

        // One poll_write runs the single flush for the whole burst.
        let flushed = {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            let mut out = vec![];
            while let Some(msg) = handler.poll_write() {
                out.push(msg);
            }
            out
        };
        assert!(
            !flushed.is_empty(),
            "the flush must emit the coalesced SACK"
        );
        assert!(
            flushed.len() < dgrams.len(),
            "batching must emit fewer datagrams than it ingested ({} in, {} out)",
            dgrams.len(),
            flushed.len()
        );
    }

    // Accept-side DCEP reliability. RFC 8832 §5.1 defines the Channel Type and Reliability
    // Parameter of a DATA_CHANNEL_OPEN for the data channel, so the side that *accepts* the
    // channel must send with them too. These tests let the server play the peer that opens the
    // channel and assert on what the client handler then puts on the wire.

    /// The stream the server (the peer) opens its data channel on.
    const PEER_STREAM: StreamId = 1;

    // RFC 9260 §3.3.1 DATA chunk flags, and the RFC 3758 §3.2 FORWARD TSN chunk type.
    const DATA_FLAG_UNORDERED: u8 = 0x04;
    const DATA_FLAG_BEGINNING: u8 = 0x02;
    const DATA_FLAG_ENDING: u8 = 0x01;
    const CT_FORWARD_TSN: u8 = 192;

    // RFC 8831 §8 payload protocol identifiers, as they appear on the wire.
    const PPID_DCEP: u32 = 50;
    const PPID_BINARY: u32 = 53;

    /// RFC 8832 §5.2 message type of a DATA_CHANNEL_ACK.
    const DCEP_ACK: u8 = 0x02;

    /// How far the timer-driven tests advance the clock. Long enough for T3-rtx to fire three
    /// times (RTO 1 s, then 2 s and 4 s of backoff), short of the 30 s heartbeat.
    const TIMER_HORIZON: Duration = Duration::from_secs(10);

    /// One chunk of an SCTP packet: type, flags and the value after the 4-byte chunk header.
    struct WireChunk {
        kind: u8,
        flags: u8,
        value: Vec<u8>,
    }

    /// Every chunk of an SCTP packet, not only the first: the association bundles SACKs and
    /// FORWARD TSNs with DATA.
    fn wire_chunks(packet: &[u8]) -> Vec<WireChunk> {
        let mut chunks = vec![];
        let mut at = 12;
        while at + 4 <= packet.len() {
            let len = u16::from_be_bytes([packet[at + 2], packet[at + 3]]) as usize;
            if len < 4 || at + len > packet.len() {
                break;
            }
            chunks.push(WireChunk {
                kind: packet[at],
                flags: packet[at + 1],
                value: packet[at + 4..at + len].to_vec(),
            });
            at += len.next_multiple_of(4);
        }
        chunks
    }

    /// The fields of a DATA chunk these tests assert on (RFC 9260 §3.3.1).
    #[derive(Debug, Clone, Copy)]
    struct WireData {
        tsn: u32,
        stream_id: StreamId,
        ppid: u32,
        flags: u8,
        first_byte: Option<u8>,
    }

    impl WireData {
        fn unordered(&self) -> bool {
            self.flags & DATA_FLAG_UNORDERED != 0
        }
    }

    fn wire_data(packet: &[u8]) -> Vec<WireData> {
        wire_chunks(packet)
            .into_iter()
            .filter(|c| c.kind == CT_PAYLOAD_DATA && c.value.len() >= 12)
            .map(|c| WireData {
                tsn: u32::from_be_bytes([c.value[0], c.value[1], c.value[2], c.value[3]]),
                stream_id: u16::from_be_bytes([c.value[4], c.value[5]]),
                ppid: u32::from_be_bytes([c.value[8], c.value[9], c.value[10], c.value[11]]),
                flags: c.flags,
                first_byte: c.value.get(12).copied(),
            })
            .collect()
    }

    /// The New Cumulative TSN of every FORWARD TSN chunk in the packet (RFC 3758 §3.2).
    fn wire_forward_tsns(packet: &[u8]) -> Vec<u32> {
        wire_chunks(packet)
            .into_iter()
            .filter(|c| c.kind == CT_FORWARD_TSN && c.value.len() >= 4)
            .map(|c| u32::from_be_bytes([c.value[0], c.value[1], c.value[2], c.value[3]]))
            .collect()
    }

    /// The `a_rwnd` of the last SACK among `packets` (RFC 9260 §3.3.4).
    fn last_sack_a_rwnd(packets: &[Bytes]) -> Option<u32> {
        packets
            .iter()
            .flat_map(|p| wire_chunks(p))
            .filter(|c| c.kind == CT_SACK && c.value.len() >= 8)
            .map(|c| u32::from_be_bytes([c.value[4], c.value[5], c.value[6], c.value[7]]))
            .last()
    }

    fn dcep_open(channel_type: ChannelType, reliability_parameter: u32) -> Bytes {
        Bytes::from(
            Message::DataChannelOpen(DataChannelOpen {
                channel_type,
                priority: CHANNEL_PRIORITY_NORMAL,
                reliability_parameter,
                label: b"accepted".to_vec(),
                protocol: Vec::new(),
            })
            .marshal()
            .expect("DCEP OPEN"),
        )
    }

    /// A well-formed DCEP message that is not a `DATA_CHANNEL_OPEN`.
    fn dcep_ack() -> Bytes {
        Bytes::from(
            Message::DataChannelAck(DataChannelAck)
                .marshal()
                .expect("DCEP ACK"),
        )
    }

    /// Queue `messages` on the server's `stream_id`, creating the stream on its first use, and
    /// return the datagrams the server sends for them.
    fn server_send(
        server_conn: &mut Association,
        stream_id: StreamId,
        messages: &[(PayloadProtocolIdentifier, Bytes)],
        now: Instant,
    ) -> Vec<Bytes> {
        // Fails when the stream already exists; either way it exists afterwards.
        let _ = server_conn.open_stream(stream_id, PayloadProtocolIdentifier::Dcep);
        {
            let mut stream = server_conn.stream(stream_id).expect("server stream");
            for (ppi, payload) in messages {
                stream.write_sctp(now, payload, *ppi).expect("server write");
            }
        }
        while server_conn.poll().is_some() {}
        drain_transmits(server_conn, now)
    }

    fn deliver_to_server(
        server_ep: &mut Endpoint,
        server_conn: &mut Association,
        dgrams: Vec<Bytes>,
        now: Instant,
    ) {
        for dgram in dgrams {
            if let Some((_, DatagramEvent::AssociationEvent(event))) =
                server_ep.handle(now, client_addr(), None, dgram)
            {
                server_conn.handle_event(event);
            }
        }
        while server_conn.poll().is_some() {}
    }

    fn client_read(ctx: &mut SctpHandlerContext, backlog: usize, dgrams: Vec<Bytes>, now: Instant) {
        let mut handler = SctpHandler::new(ctx, backlog);
        for dgram in dgrams {
            handler
                .handle_read(raw_read(now, dgram))
                .expect("client read");
        }
    }

    fn client_write(
        ctx: &mut SctpHandlerContext,
        now: Instant,
        ch: AssociationHandle,
        stream_id: StreamId,
        ppi: PayloadProtocolIdentifier,
        payload: &[u8],
    ) {
        SctpHandler::new(ctx, 0)
            .handle_write(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                    association_handle: ch.0,
                    stream_id,
                    ppi,
                    payload: BytesMut::from(payload),
                    negotiated: false,
                })),
            })
            .expect("client write");
    }

    /// A client handshake that nobody answers ends when INIT runs out of retransmissions.
    /// Its failure is raised by a timer, with no datagram ever arriving, so `handle_timeout` has
    /// to surface it: the transport becomes `closed` and the channels are failed (B5). The
    /// events used to wait for a `handle_read` that never came.
    #[test]
    fn a_handshake_that_times_out_fails_the_association() {
        let start = Instant::now();
        let mut client_ep = Endpoint::new(
            client_addr(),
            TransportProtocol::UDP,
            EndpointConfig::default().into(),
            None,
        );
        let (ch, conn) = client_ep
            .connect(
                start,
                ClientConfig::new(TransportConfig::default()),
                server_addr(),
            )
            .expect("client connect");
        let mut ctx = client_ctx(start, client_ep, ch, conn);

        let mut failed = false;
        for _ in 0..64 {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            while handler.poll_write().is_some() {}
            let Some(at) = handler.poll_timeout() else {
                break;
            };
            handler.handle_timeout(at).expect("timeout");
            while let Some(evt) = handler.poll_event() {
                failed |=
                    matches!(evt.event, RTCEventInternal::SCTPAssociationFailed(h) if h == ch.0);
            }
            if failed {
                break;
            }
        }
        assert!(
            failed,
            "the failed handshake never reached the data channels"
        );
        assert_eq!(
            crate::peer_connection::transport::sctp::state::RTCSctpTransportState::Closed,
            ctx.sctp_transport.state()
        );
    }

    /// Audit finding R-L12: one message over this side's receive limit is dropped on its own.
    /// It used to fail the whole read, losing the messages around it that SCTP had already
    /// acknowledged.
    #[test]
    fn an_oversized_message_is_dropped_without_losing_the_others() {
        let now = Instant::now();
        let mut e = establish();
        let dgrams = server_send(
            &mut e.server_conn,
            1,
            &[
                (
                    PayloadProtocolIdentifier::Binary,
                    Bytes::from_static(b"small"),
                ),
                (
                    PayloadProtocolIdentifier::Binary,
                    Bytes::from(vec![0u8; 64]),
                ),
                (
                    PayloadProtocolIdentifier::Binary,
                    Bytes::from_static(b"after"),
                ),
            ],
            now,
        );
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        ctx.sctp_transport.receive_message_limit = 8;
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            for dgram in dgrams {
                handler
                    .handle_read(raw_read(now, dgram))
                    .expect("an oversized message is not a read error");
            }
        }
        let payloads: Vec<Vec<u8>> = ctx
            .read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(msg)) => Some(msg.payload.to_vec()),
                _ => None,
            })
            .collect();
        assert_eq!(vec![b"small".to_vec(), b"after".to_vec()], payloads);
    }

    /// Run the deferred flush and return the datagrams the client handler sends.
    fn flush(ctx: &mut SctpHandlerContext) -> Vec<Bytes> {
        let mut handler = SctpHandler::new(ctx, 0);
        let mut out = vec![];
        while let Some(msg) = handler.poll_write() {
            if let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = msg.message {
                out.push(raw.freeze());
            }
        }
        out
    }

    /// The only association of a single-association context.
    fn only_association(ctx: &SctpHandlerContext) -> AssociationHandle {
        let mut handles = ctx.sctp_transport.sctp_associations.keys();
        let ch = *handles.next().expect("one association");
        assert!(handles.next().is_none(), "exactly one association");
        ch
    }

    /// A client handler that has received the peer's DATA_CHANNEL_OPEN on `PEER_STREAM`, with
    /// the server end of the association kept for further peer traffic.
    struct Accepted {
        now: Instant,
        ctx: SctpHandlerContext,
        ch: AssociationHandle,
        server_ep: Endpoint,
        server_conn: Association,
    }

    fn accept_peer_open(channel_type: ChannelType, reliability_parameter: u32) -> Accepted {
        let now = Instant::now();
        let e = establish();
        let (server_ep, mut server_conn) = (e.server_ep, e.server_conn);
        let open = server_send(
            &mut server_conn,
            PEER_STREAM,
            &[(
                PayloadProtocolIdentifier::Dcep,
                dcep_open(channel_type, reliability_parameter),
            )],
            now,
        );
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_read(&mut ctx, 0, open, now);
        assert!(
            matches!(
                ctx.read_outs.front().map(|m| &m.message),
                Some(RTCMessageInternal::Dtls(DTLSMessage::Sctp(m)))
                    if m.ppi == PayloadProtocolIdentifier::Dcep && m.stream_id == PEER_STREAM
            ),
            "precondition: the peer's OPEN is delivered"
        );
        Accepted {
            now,
            ctx,
            ch,
            server_ep,
            server_conn,
        }
    }

    /// Write one Binary message on `stream_id` and return the DATA chunk that carries it.
    fn send_probe(
        ctx: &mut SctpHandlerContext,
        ch: AssociationHandle,
        stream_id: StreamId,
        now: Instant,
    ) -> WireData {
        client_write(
            ctx,
            now,
            ch,
            stream_id,
            PayloadProtocolIdentifier::Binary,
            b"probe",
        );
        let data: Vec<WireData> = flush(ctx)
            .iter()
            .flat_map(|p| wire_data(p))
            .filter(|d| d.stream_id == stream_id && d.ppid == PPID_BINARY)
            .collect();
        assert_eq!(data.len(), 1, "one DATA chunk carries the probe: {data:?}");
        data[0]
    }

    /// What the client sends once the probe is lost: its timers run up to `TIMER_HORIZON` and
    /// nothing it sends reaches the peer, so nothing is ever acknowledged.
    struct AfterLoss {
        /// Instants at which the probe's TSN was sent again.
        retransmits: Vec<Instant>,
        /// Instant and New Cumulative TSN of every FORWARD TSN sent.
        forward_tsns: Vec<(Instant, u32)>,
    }

    fn lose_probe(ctx: &mut SctpHandlerContext, probe: WireData, from: Instant) -> AfterLoss {
        let mut after = AfterLoss {
            retransmits: vec![],
            forward_tsns: vec![],
        };
        // Bounded twice: by the horizon on the virtual clock and by an iteration count.
        for _ in 0..64 {
            let mut handler = SctpHandler::new(ctx, 0);
            let Some(at) = handler.poll_timeout() else {
                break;
            };
            if at > from + TIMER_HORIZON {
                break;
            }
            handler.handle_timeout(at).expect("handle_timeout");
            while let Some(msg) = handler.poll_write() {
                let RTCMessageInternal::Dtls(DTLSMessage::Raw(raw)) = msg.message else {
                    continue;
                };
                if wire_data(&raw).iter().any(|d| d.tsn == probe.tsn) {
                    after.retransmits.push(at);
                }
                for new_cumulative_tsn in wire_forward_tsns(&raw) {
                    after.forward_tsns.push((at, new_cumulative_tsn));
                }
            }
        }
        after
    }

    /// How a lost message on the channel must be recovered.
    enum Recovery {
        /// Fully reliable: retransmitted, never skipped.
        Retransmit,
        /// `maxRetransmits` 0: skipped with a FORWARD TSN at the first retry, never resent.
        AbandonAtFirstRetry,
        /// `maxPacketLifeTime`: resent while the lifetime lasts, skipped after it.
        AbandonAfter(Duration),
    }

    fn assert_recovery(after: &AfterLoss, probe: WireData, sent_at: Instant, recovery: Recovery) {
        match recovery {
            Recovery::Retransmit => {
                assert!(
                    !after.retransmits.is_empty(),
                    "a reliable channel must retransmit a lost message"
                );
                assert!(
                    after.forward_tsns.is_empty(),
                    "a reliable channel must never skip a message: {:?}",
                    after.forward_tsns
                );
            }
            Recovery::AbandonAtFirstRetry => {
                assert!(
                    after.retransmits.is_empty(),
                    "maxRetransmits 0 forbids any retransmission, sent again at {:?}",
                    after.retransmits
                );
                let (_, new_cumulative_tsn) = *after.forward_tsns.first().expect(
                    "maxRetransmits 0: the lost message must be abandoned with a FORWARD TSN",
                );
                assert_eq!(
                    new_cumulative_tsn, probe.tsn,
                    "the FORWARD TSN must skip exactly the abandoned message"
                );
            }
            Recovery::AbandonAfter(lifetime) => {
                let deadline = sent_at + lifetime;
                assert!(
                    after.retransmits.iter().any(|at| *at < deadline),
                    "within its lifetime a lost message is still retransmitted"
                );
                assert!(
                    after.retransmits.iter().all(|at| *at < deadline),
                    "past its lifetime a message must not be retransmitted"
                );
                let (at, new_cumulative_tsn) = *after
                    .forward_tsns
                    .first()
                    .expect("past its lifetime the message must be abandoned with a FORWARD TSN");
                assert!(
                    at >= deadline,
                    "a message must not be abandoned before its lifetime ends"
                );
                assert_eq!(
                    new_cumulative_tsn, probe.tsn,
                    "the FORWARD TSN must skip exactly the abandoned message"
                );
            }
        }
    }

    /// The peer opens a channel of `channel_type`; the client then sends on it and loses the
    /// message. Both the U bit and the recovery must follow the peer's OPEN.
    fn assert_accepted_channel_follows_peer_open(
        channel_type: ChannelType,
        reliability_parameter: u32,
        unordered: bool,
        recovery: Recovery,
    ) {
        let mut a = accept_peer_open(channel_type, reliability_parameter);
        let probe = send_probe(&mut a.ctx, a.ch, PEER_STREAM, a.now);
        assert_eq!(
            probe.unordered(),
            unordered,
            "{channel_type:?}: the U bit of this side's DATA must follow the peer's OPEN"
        );
        let after = lose_probe(&mut a.ctx, probe, a.now);
        assert_recovery(&after, probe, a.now, recovery);
    }

    #[test]
    fn accepted_reliable_channel_sends_ordered_and_retransmits() {
        assert_accepted_channel_follows_peer_open(
            ChannelType::Reliable,
            0,
            false,
            Recovery::Retransmit,
        );
    }

    #[test]
    fn accepted_reliable_unordered_channel_sends_unordered_and_retransmits() {
        assert_accepted_channel_follows_peer_open(
            ChannelType::ReliableUnordered,
            0,
            true,
            Recovery::Retransmit,
        );
    }

    #[test]
    fn accepted_rexmit_channel_abandons_instead_of_retransmitting() {
        assert_accepted_channel_follows_peer_open(
            ChannelType::PartialReliableRexmit,
            0,
            false,
            Recovery::AbandonAtFirstRetry,
        );
    }

    #[test]
    fn accepted_rexmit_unordered_channel_sends_unordered_and_abandons() {
        assert_accepted_channel_follows_peer_open(
            ChannelType::PartialReliableRexmitUnordered,
            0,
            true,
            Recovery::AbandonAtFirstRetry,
        );
    }

    /// The lifetime outlasts the first RTO (1 s) and ends before the second retry (3 s), so a
    /// single run shows both halves: retransmitted within it, abandoned after it.
    const TIMED_LIFETIME: Duration = Duration::from_millis(2500);

    #[test]
    fn accepted_timed_channel_abandons_after_its_lifetime() {
        assert_accepted_channel_follows_peer_open(
            ChannelType::PartialReliableTimed,
            TIMED_LIFETIME.as_millis() as u32,
            false,
            Recovery::AbandonAfter(TIMED_LIFETIME),
        );
    }

    #[test]
    fn accepted_timed_unordered_channel_sends_unordered_and_abandons_after_its_lifetime() {
        assert_accepted_channel_follows_peer_open(
            ChannelType::PartialReliableTimedUnordered,
            TIMED_LIFETIME.as_millis() as u32,
            true,
            Recovery::AbandonAfter(TIMED_LIFETIME),
        );
    }

    /// A stream configured as `PartialReliableRexmitUnordered` with 0 retransmits: sends carry
    /// the U bit, and a lost one is skipped rather than resent.
    fn assert_sends_unordered_without_retransmits(
        ctx: &mut SctpHandlerContext,
        ch: AssociationHandle,
        now: Instant,
    ) {
        let probe = send_probe(ctx, ch, PEER_STREAM, now);
        assert!(
            probe.unordered(),
            "the peer's unordered channel type must reach this side's DATA"
        );
        let after = lose_probe(ctx, probe, now);
        assert_recovery(&after, probe, now, Recovery::AbandonAtFirstRetry);
    }

    /// The OPEN arrives in the same flight as the end of the handshake, before COOKIE-ACK,
    /// and is discarded there (RFC 9260 section 6: no DATA in COOKIE-ECHOED). The copy the
    /// peer sends again once the association is up is the first message of its stream, and
    /// must still configure the stream.
    #[test]
    fn an_open_received_before_cookie_ack_still_configures_the_stream() {
        let now = Instant::now();
        let (mut ctx, cookie_ack, early_data) =
            client_with_open_before_cookie_ack(ChannelType::PartialReliableRexmitUnordered, 0);
        let ch = only_association(&ctx);

        client_read(&mut ctx, 0, early_data.clone(), now);
        assert!(
            ctx.read_outs.is_empty(),
            "precondition: not delivered before COOKIE-ACK"
        );
        assert!(
            ctx.peer_opened_streams.is_empty() && ctx.pending_readable.is_empty(),
            "the discarded OPEN created no stream"
        );

        client_read(&mut ctx, 0, cookie_ack, now);
        {
            let mut handler = SctpHandler::new(&mut ctx, 0);
            while handler.poll_event().is_some() {}
        }
        // The peer's retransmission.
        client_read(&mut ctx, 0, early_data, now);
        let delivered = SctpHandler::new(&mut ctx, 0).poll_read();
        assert!(
            matches!(
                delivered.as_ref().map(|m| &m.message),
                Some(RTCMessageInternal::Dtls(DTLSMessage::Sctp(m)))
                    if m.ppi == PayloadProtocolIdentifier::Dcep && m.stream_id == PEER_STREAM
            ),
            "precondition: the OPEN is delivered"
        );
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "draining the first message ends the record"
        );

        assert_sends_unordered_without_retransmits(&mut ctx, ch, now);
    }

    /// The OPEN arrives while the pipeline is at its bound, so the stream is parked and the OPEN
    /// is only drained later, from `poll_read`. That drain must configure the stream too.
    #[test]
    fn an_open_parked_by_backpressure_still_configures_the_stream() {
        let (now, mut ctx, ch) = parked_peer_open();

        let resumed = SctpHandler::new(&mut ctx, 0).poll_read();
        assert!(
            matches!(
                resumed.as_ref().map(|m| &m.message),
                Some(RTCMessageInternal::Dtls(DTLSMessage::Sctp(m)))
                    if m.ppi == PayloadProtocolIdentifier::Dcep
            ),
            "precondition: the parked OPEN is delivered on resume"
        );
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "draining the first message ends the record"
        );

        assert_sends_unordered_without_retransmits(&mut ctx, ch, now);
    }

    /// The peer's `PartialReliableRexmitUnordered` OPEN, parked behind a full pipeline: the
    /// stream is recorded as peer-opened and its first message is still undrained.
    fn parked_peer_open() -> (Instant, SctpHandlerContext, AssociationHandle) {
        let now = Instant::now();
        let e = establish();
        let mut server_conn = e.server_conn;
        let open = server_send(
            &mut server_conn,
            PEER_STREAM,
            &[(
                PayloadProtocolIdentifier::Dcep,
                dcep_open(ChannelType::PartialReliableRexmitUnordered, 0),
            )],
            now,
        );
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_read(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT, open, now);
        assert!(ctx.read_outs.is_empty(), "precondition: the OPEN is parked");
        assert!(
            ctx.peer_opened_streams.contains(&(ch, PEER_STREAM)),
            "precondition: the stream is recorded as peer-opened"
        );
        (now, ctx, ch)
    }

    /// The accepting side answers with a DATA_CHANNEL_ACK on the channel's own stream. DCEP
    /// messages are always sent ordered and reliable (RFC 8832 §6), so configuring that stream
    /// as unordered must not leak into the ACK.
    #[test]
    fn the_dcep_ack_stays_ordered_on_an_accepted_unordered_channel() {
        let mut a = accept_peer_open(ChannelType::PartialReliableRexmitUnordered, 0);
        let inbound = a.ctx.read_outs.pop_front().expect("the OPEN");

        let mut data_channel_ctx = DataChannelHandlerContext::new(a.now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();
        let mut replies = vec![];
        {
            let mut handler = DataChannelHandler::new(
                &mut data_channel_ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Client,
                None,
            );
            handler.handle_read(inbound).expect("accept the channel");
            while let Some(msg) = handler.poll_write() {
                replies.push(msg);
            }
        }
        assert!(!replies.is_empty(), "accepting must queue the ACK");
        {
            let mut handler = SctpHandler::new(&mut a.ctx, 0);
            for reply in replies {
                handler.handle_write(reply).expect("send the ACK");
            }
        }

        let dcep: Vec<WireData> = flush(&mut a.ctx)
            .iter()
            .flat_map(|p| wire_data(p))
            .filter(|d| d.stream_id == PEER_STREAM && d.ppid == PPID_DCEP)
            .collect();
        assert_eq!(dcep.len(), 1, "one DCEP message is sent: {dcep:?}");
        assert_eq!(dcep[0].first_byte, Some(DCEP_ACK), "it is the ACK");
        assert!(
            !dcep[0].unordered(),
            "DCEP messages must be sent ordered (RFC 8832 §6)"
        );

        // Control: the stream itself is unordered, so the ACK's ordering is not the default.
        let probe = send_probe(&mut a.ctx, a.ch, PEER_STREAM, a.now);
        assert!(
            probe.unordered(),
            "precondition: user data on the channel is unordered"
        );
    }

    /// This side opened the stream itself, so the peer's DATA arrives on an existing stream and
    /// is not a peer-created one. A DATA_CHANNEL_OPEN the peer sends there must not reconfigure
    /// it.
    #[test]
    fn a_peer_open_on_a_stream_this_side_opened_does_not_reconfigure_it() {
        let now = Instant::now();
        let e = establish();
        let mut server_conn = e.server_conn;
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);

        client_write(
            &mut ctx,
            now,
            ch,
            PEER_STREAM,
            PayloadProtocolIdentifier::Dcep,
            &dcep_open(ChannelType::Reliable, 0),
        );
        let _ = flush(&mut ctx);

        let open = server_send(
            &mut server_conn,
            PEER_STREAM,
            &[(
                PayloadProtocolIdentifier::Dcep,
                dcep_open(ChannelType::PartialReliableRexmitUnordered, 0),
            )],
            now,
        );
        client_read(&mut ctx, 0, open, now);
        assert_eq!(
            ctx.read_outs.len(),
            1,
            "precondition: the peer's OPEN is read"
        );

        let probe = send_probe(&mut ctx, ch, PEER_STREAM, now);
        assert!(
            !probe.unordered(),
            "this side's ordered stream stays ordered"
        );
        let after = lose_probe(&mut ctx, probe, now);
        assert_recovery(&after, probe, now, Recovery::Retransmit);
    }

    /// `handle_write` drops the peer-opened record of a stream this side opens, so a stale
    /// record from an earlier, peer-created use of the same stream id cannot let a later peer
    /// OPEN override this side's parameters.
    ///
    /// The record is seeded directly: leaving one behind through the wire takes a full stream
    /// reset round trip with the first message never drained. The contract under test is the
    /// one stated where `handle_write` removes it.
    #[test]
    fn opening_a_stream_locally_drops_a_stale_peer_opened_record() {
        let now = Instant::now();
        let e = establish();
        let mut server_conn = e.server_conn;
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        ctx.peer_opened_streams.insert((ch, PEER_STREAM));

        client_write(
            &mut ctx,
            now,
            ch,
            PEER_STREAM,
            PayloadProtocolIdentifier::Dcep,
            &dcep_open(ChannelType::Reliable, 0),
        );
        let _ = flush(&mut ctx);
        assert!(
            !ctx.peer_opened_streams.contains(&(ch, PEER_STREAM)),
            "a stream this side opens is no longer peer-opened"
        );

        let open = server_send(
            &mut server_conn,
            PEER_STREAM,
            &[(
                PayloadProtocolIdentifier::Dcep,
                dcep_open(ChannelType::PartialReliableRexmitUnordered, 0),
            )],
            now,
        );
        client_read(&mut ctx, 0, open, now);
        assert_eq!(
            ctx.read_outs.len(),
            1,
            "precondition: the peer's OPEN is read"
        );

        let probe = send_probe(&mut ctx, ch, PEER_STREAM, now);
        assert!(
            !probe.unordered(),
            "this side's ordered stream stays ordered"
        );
        let after = lose_probe(&mut ctx, probe, now);
        assert_recovery(&after, probe, now, Recovery::Retransmit);
    }

    /// A peer-created stream whose first message is not DCEP belongs to an out-of-band
    /// negotiated channel. Only the first message can be the OPEN that describes a channel, so a
    /// DATA_CHANNEL_OPEN arriving after it must not reconfigure the stream.
    #[test]
    fn a_peer_stream_whose_first_message_is_not_dcep_is_not_reconfigured() {
        let now = Instant::now();
        let e = establish();
        let mut server_conn = e.server_conn;
        let messages = server_send(
            &mut server_conn,
            PEER_STREAM,
            &[
                (
                    PayloadProtocolIdentifier::Binary,
                    Bytes::from_static(b"negotiated"),
                ),
                (
                    PayloadProtocolIdentifier::Dcep,
                    dcep_open(ChannelType::PartialReliableRexmitUnordered, 0),
                ),
            ],
            now,
        );
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_read(&mut ctx, 0, messages, now);
        assert_eq!(
            ctx.read_outs.len(),
            2,
            "precondition: both messages are read"
        );
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "the first message ends the record whatever it is"
        );

        let probe = send_probe(&mut ctx, ch, PEER_STREAM, now);
        assert!(!probe.unordered(), "the stream keeps its ordered default");
        let after = lose_probe(&mut ctx, probe, now);
        assert_recovery(&after, probe, now, Recovery::Retransmit);
    }

    /// The first message of a peer-created stream can carry the DCEP PPI without being a
    /// `DATA_CHANNEL_OPEN`: a `DATA_CHANNEL_ACK`, or bytes that do not parse. The stream keeps
    /// the ordered, fully reliable default, the message is still delivered, and the record ends,
    /// so a later OPEN cannot configure it either.
    #[test]
    fn a_dcep_first_message_that_is_not_an_open_leaves_the_stream_unchanged() {
        for (label, first) in [
            ("ACK", dcep_ack()),
            ("unparsed", Bytes::from_static(&[0xff])),
        ] {
            let now = Instant::now();
            let e = establish();
            let mut server_conn = e.server_conn;
            let messages = server_send(
                &mut server_conn,
                PEER_STREAM,
                &[
                    (PayloadProtocolIdentifier::Dcep, first),
                    (
                        PayloadProtocolIdentifier::Dcep,
                        dcep_open(ChannelType::PartialReliableRexmitUnordered, 0),
                    ),
                ],
                now,
            );
            let ch = e.client_ch;
            let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
            client_read(&mut ctx, 0, messages, now);
            assert_eq!(
                ctx.read_outs.len(),
                2,
                "{label}: both messages are delivered"
            );
            assert!(
                matches!(
                    ctx.read_outs.front().map(|m| &m.message),
                    Some(RTCMessageInternal::Dtls(DTLSMessage::Sctp(m)))
                        if m.ppi == PayloadProtocolIdentifier::Dcep && m.stream_id == PEER_STREAM
                ),
                "{label}: the non-OPEN DCEP message is still delivered"
            );
            assert!(
                ctx.peer_opened_streams.is_empty(),
                "{label}: the first message ends the record"
            );

            let probe = send_probe(&mut ctx, ch, PEER_STREAM, now);
            assert!(
                !probe.unordered(),
                "{label}: the stream keeps its ordered default"
            );
            let after = lose_probe(&mut ctx, probe, now);
            assert_recovery(&after, probe, now, Recovery::Retransmit);
        }
    }

    #[test]
    fn a_peer_opened_stream_is_forgotten_once_its_first_message_is_drained() {
        // Drained at once by the `Readable` that announced it.
        let a = accept_peer_open(ChannelType::Reliable, 0);
        assert!(
            a.ctx.peer_opened_streams.is_empty(),
            "the record must end with the immediate drain of the first message"
        );

        // Parked first, drained later by the resume.
        let (_, mut ctx, ch) = parked_peer_open();
        assert!(ctx.peer_opened_streams.contains(&(ch, PEER_STREAM)));
        while SctpHandler::new(&mut ctx, 0).poll_read().is_some() {}
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "the record must end with the resumed drain of the first message"
        );
    }

    #[test]
    fn removing_an_association_forgets_its_peer_opened_streams() {
        let (now, mut ctx, ch) = parked_peer_open();
        ctx.sctp_transport
            .sctp_associations
            .get_mut(&ch)
            .expect("association")
            .shutdown()
            .expect("shutdown");

        SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
            .handle_timeout(now)
            .expect("handle_timeout");

        assert!(
            !ctx.sctp_transport.sctp_associations.contains_key(&ch),
            "precondition: the drained association is removed"
        );
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "a removed association's streams must not stay recorded"
        );
    }

    #[test]
    fn aborting_forgets_peer_opened_streams() {
        let (_, mut ctx, _) = parked_peer_open();
        {
            let mut handler = SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT);
            handler.request_abort();
            while handler.poll_write().is_some() {}
        }
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "an aborted association's streams must not stay recorded"
        );
    }

    #[test]
    fn dtls_closed_forgets_peer_opened_streams() {
        let (now, mut ctx, _) = parked_peer_open();
        SctpHandler::new(&mut ctx, SCTP_PIPELINE_READ_BACKLOG_LIMIT)
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::DTLSClosed,
            })
            .expect("handle_event");
        assert!(
            ctx.peer_opened_streams.is_empty(),
            "closed associations' streams must not stay recorded"
        );
    }

    /// An accepted unordered channel must also *receive* as one: when the peer abandons a
    /// fragmented message and sends FORWARD TSN, the fragments already here are dropped, or they
    /// hold receive window for good. The association drops unordered fragments on FORWARD TSN
    /// only for a stream marked unordered, which is the accept-side configuration.
    #[test]
    fn an_accepted_unordered_stream_drops_abandoned_fragments_on_forward_tsn() {
        let mut a = accept_peer_open(ChannelType::PartialReliableRexmitUnordered, 0);
        a.ctx.read_outs.clear();
        // The opener configures its own stream from the OPEN it sent, as `handle_write` does.
        a.server_conn
            .stream(PEER_STREAM)
            .and_then(|mut s| s.set_reliability_params(true, ReliabilityType::Rexmit, 0))
            .expect("configure the peer's stream");

        let t0 = a.now + Duration::from_millis(500);
        SctpHandler::new(&mut a.ctx, 0)
            .handle_timeout(t0)
            .expect("delayed-ack timer");
        let acks = flush(&mut a.ctx);
        let empty_window = last_sack_a_rwnd(&acks).expect("the OPEN is acknowledged");
        deliver_to_server(&mut a.server_ep, &mut a.server_conn, acks, t0);

        // One message in three fragments; the middle one is lost.
        let message = Bytes::from(vec![0xab; 3000]);
        let (lost, kept): (Vec<Bytes>, Vec<Bytes>) = server_send(
            &mut a.server_conn,
            PEER_STREAM,
            &[(PayloadProtocolIdentifier::Binary, message)],
            t0,
        )
        .into_iter()
        .partition(|p| {
            wire_data(p)
                .iter()
                .any(|d| d.flags & (DATA_FLAG_BEGINNING | DATA_FLAG_ENDING) == 0)
        });
        assert_eq!(lost.len(), 1, "precondition: one middle fragment");
        let kept_fragments: Vec<WireData> = kept.iter().flat_map(|p| wire_data(p)).collect();
        assert_eq!(
            kept_fragments.len(),
            2,
            "precondition: first and last fragment: {kept_fragments:?}"
        );
        assert!(
            kept_fragments.iter().all(WireData::unordered),
            "precondition: the peer sends the message unordered"
        );

        client_read(&mut a.ctx, 0, kept, t0);
        assert!(a.ctx.read_outs.is_empty(), "an incomplete message is held");
        let t1 = t0 + Duration::from_millis(500);
        SctpHandler::new(&mut a.ctx, 0)
            .handle_timeout(t1)
            .expect("delayed-ack timer");
        let gap_acks = flush(&mut a.ctx);
        let held_window = last_sack_a_rwnd(&gap_acks).expect("the fragments are acknowledged");
        assert!(
            held_window < empty_window,
            "precondition: the held fragments occupy receive window ({held_window} vs {empty_window})"
        );
        deliver_to_server(&mut a.server_ep, &mut a.server_conn, gap_acks, t1);

        // The peer may not retransmit, so its T3-rtx abandons the message with a FORWARD TSN.
        let mut forward = None;
        for _ in 0..16 {
            let Some(at) = a.server_conn.poll_timeout() else {
                break;
            };
            a.server_conn.handle_timeout(at);
            let out = drain_transmits(&mut a.server_conn, at);
            if out.iter().any(|p| !wire_forward_tsns(p).is_empty()) {
                forward = Some((at, out));
                break;
            }
        }
        let (at, forward) = forward.expect("the peer abandons the message with a FORWARD TSN");

        client_read(&mut a.ctx, 0, forward, at);
        SctpHandler::new(&mut a.ctx, 0)
            .handle_timeout(at + Duration::from_millis(500))
            .expect("delayed-ack timer");
        let after = last_sack_a_rwnd(&flush(&mut a.ctx)).expect("the FORWARD TSN is acknowledged");
        assert_eq!(
            after, empty_window,
            "the abandoned fragments must be dropped and their window given back"
        );
    }

    fn dcep_open_with_priority(channel_type: ChannelType, priority: u16) -> Bytes {
        Bytes::from(
            Message::DataChannelOpen(DataChannelOpen {
                channel_type,
                priority,
                reliability_parameter: 0,
                label: b"weighted".to_vec(),
                protocol: Vec::new(),
            })
            .marshal()
            .expect("DCEP OPEN"),
        )
    }

    /// What the data channel handler writes for a channel negotiated out of band: the OPEN
    /// that configures the stream and is never sent.
    fn client_write_negotiated_open(
        ctx: &mut SctpHandlerContext,
        now: Instant,
        ch: AssociationHandle,
        stream_id: StreamId,
        open: &[u8],
    ) {
        SctpHandler::new(ctx, 0)
            .handle_write(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                    association_handle: ch.0,
                    stream_id,
                    ppi: PayloadProtocolIdentifier::Dcep,
                    payload: BytesMut::from(open),
                    negotiated: true,
                })),
            })
            .expect("negotiated open");
    }

    /// The DATA chunks the client sends for `stream_id`, in order.
    fn flushed_data(ctx: &mut SctpHandlerContext, stream_id: StreamId) -> Vec<WireData> {
        flush(ctx)
            .iter()
            .flat_map(|p| wire_data(p))
            .filter(|d| d.stream_id == stream_id)
            .collect()
    }

    /// A client that opened an unordered channel in band on stream 0 and sent one message
    /// on it at once, as RFC 8832 section 6 allows. Returns what it put on the wire.
    fn open_unordered_and_send_early(channel_type: ChannelType) -> (Accepted, Vec<Bytes>) {
        let now = Instant::now();
        let e = establish();
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_write(
            &mut ctx,
            now,
            ch,
            0,
            PayloadProtocolIdentifier::Dcep,
            &dcep_open(channel_type, 0),
        );
        client_write(
            &mut ctx,
            now,
            ch,
            0,
            PayloadProtocolIdentifier::Binary,
            b"early",
        );
        let sent = flush(&mut ctx);
        (
            Accepted {
                now,
                ctx,
                ch,
                server_ep: e.server_ep,
                server_conn: e.server_conn,
            },
            sent,
        )
    }

    /// RFC 8832 section 6: "before the DATA_CHANNEL_ACK message or any other message has been
    /// received on a data channel, all other messages containing user data and belonging to
    /// this data channel MUST be sent ordered, no matter whether the data channel is ordered
    /// or not. After the DATA_CHANNEL_ACK or any other message has been received on the data
    /// channel, messages containing user data ... MUST be sent unordered on unordered data
    /// channels." The stream used to be unordered from the moment the OPEN was written, so
    /// early data could reach the peer before the OPEN it depends on.
    #[test]
    fn data_sent_before_the_ack_is_ordered_on_an_unordered_channel() {
        for channel_type in [
            ChannelType::ReliableUnordered,
            ChannelType::PartialReliableRexmitUnordered,
            ChannelType::PartialReliableTimedUnordered,
        ] {
            // What ends the ordered phase: the peer's ACK, or any other message from it.
            for reply in [
                (PayloadProtocolIdentifier::Dcep, dcep_ack()),
                (PayloadProtocolIdentifier::Binary, Bytes::from_static(b"hi")),
            ] {
                let (mut a, sent) = open_unordered_and_send_early(channel_type);
                let data: Vec<WireData> = sent
                    .iter()
                    .flat_map(|p| wire_data(p))
                    .filter(|d| d.stream_id == 0)
                    .collect();
                assert_eq!(data.len(), 2, "{channel_type:?}: the OPEN and the message");
                assert_eq!(data[0].ppid, PPID_DCEP);
                assert!(
                    !data[0].unordered(),
                    "{channel_type:?}: the OPEN is ordered"
                );
                assert_eq!(data[1].ppid, PPID_BINARY);
                assert!(
                    !data[1].unordered(),
                    "{channel_type:?}: user data before any reply must be sent ordered"
                );

                // Still nothing from the peer: still ordered.
                let probe = send_probe(&mut a.ctx, a.ch, 0, a.now);
                assert!(!probe.unordered(), "{channel_type:?}: no reply yet");

                deliver_to_server(&mut a.server_ep, &mut a.server_conn, sent, a.now);
                let reply_ppi = reply.0;
                let reply = server_send(&mut a.server_conn, 0, &[reply], a.now);
                client_read(&mut a.ctx, 0, reply, a.now);

                let probe = send_probe(&mut a.ctx, a.ch, 0, a.now);
                assert!(
                    probe.unordered(),
                    "{channel_type:?}: after the peer's {reply_ppi} the channel sends unordered"
                );
                assert!(a.ctx.ordered_until_reply.is_empty());
            }
        }
    }

    /// The reliability of the channel is in force from its first message: only the ordering
    /// waits for the peer's reply. A message lost before the ACK on a `maxRetransmits: 0`
    /// channel is abandoned, not retransmitted.
    #[test]
    fn data_sent_before_the_ack_already_has_the_channels_reliability() {
        let (mut a, sent) =
            open_unordered_and_send_early(ChannelType::PartialReliableRexmitUnordered);
        let early = sent
            .iter()
            .flat_map(|p| wire_data(p))
            .find(|d| d.ppid == PPID_BINARY)
            .expect("the early message");
        // Nothing reaches the peer: the OPEN comes back, the early message does not.
        let after = lose_probe(&mut a.ctx, early, a.now);
        assert!(
            after.retransmits.is_empty(),
            "maxRetransmits 0 holds before the ACK too: resent at {:?}",
            after.retransmits
        );
    }

    /// A channel negotiated out of band has no DATA_CHANNEL_OPEN its data could overtake, so
    /// an unordered one sends unordered from its first message. An ordered channel opened in
    /// band stays ordered after the ACK.
    #[test]
    fn only_an_in_band_unordered_channel_waits_for_the_peers_reply() {
        let now = Instant::now();
        let e = establish();
        let ch = e.client_ch;
        let (mut server_ep, mut server_conn) = (e.server_ep, e.server_conn);
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);

        client_write_negotiated_open(
            &mut ctx,
            now,
            ch,
            4,
            &dcep_open(ChannelType::ReliableUnordered, 0),
        );
        assert!(send_probe(&mut ctx, ch, 4, now).unordered());
        assert!(ctx.ordered_until_reply.is_empty());

        client_write(
            &mut ctx,
            now,
            ch,
            0,
            PayloadProtocolIdentifier::Dcep,
            &dcep_open(ChannelType::Reliable, 0),
        );
        let open = flush(&mut ctx);
        assert!(ctx.ordered_until_reply.is_empty());
        deliver_to_server(&mut server_ep, &mut server_conn, open, now);
        let ack = server_send(
            &mut server_conn,
            0,
            &[(PayloadProtocolIdentifier::Dcep, dcep_ack())],
            now,
        );
        client_read(&mut ctx, 0, ack, now);
        assert!(!send_probe(&mut ctx, ch, 0, now).unordered());
    }

    /// A channel closed before the peer answered is forgotten with its stream.
    #[test]
    fn closing_a_channel_forgets_that_it_waited_for_a_reply() {
        let (mut a, _sent) = open_unordered_and_send_early(ChannelType::ReliableUnordered);
        assert_eq!(a.ctx.ordered_until_reply.len(), 1);
        client_write(
            &mut a.ctx,
            a.now,
            a.ch,
            0,
            PayloadProtocolIdentifier::Dcep,
            &[0x01],
        );
        assert!(a.ctx.ordered_until_reply.is_empty());
    }

    /// RFC 8832 section 6: "All DCEP messages MUST be sent using ordered delivery and reliable
    /// transmission", whatever the channel they open: the DATA_CHANNEL_OPEN of an unordered
    /// `maxRetransmits: 0` channel that is lost is retransmitted, never abandoned.
    #[test]
    fn a_lost_open_is_retransmitted_on_a_partially_reliable_channel() {
        let now = Instant::now();
        let e = establish();
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_write(
            &mut ctx,
            now,
            ch,
            0,
            PayloadProtocolIdentifier::Dcep,
            &dcep_open(ChannelType::PartialReliableRexmitUnordered, 0),
        );
        let open = flushed_data(&mut ctx, 0);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].ppid, PPID_DCEP);
        assert!(!open[0].unordered());
        let after = lose_probe(&mut ctx, open[0], now);
        assert_recovery(&after, open[0], now, Recovery::Retransmit);
    }

    /// RFC 8832 section 6: "Other messages MUST NOT be sent using this PPID." What the data
    /// channel layer hands down under PPID 50 besides OPEN and ACK (the OPEN of a negotiated
    /// channel, buffered-amount thresholds, the close) is this stack's own signalling and
    /// stays off the wire.
    #[test]
    fn internal_dcep_messages_put_no_data_on_the_wire() {
        use datachannel::message::message_channel_close::DataChannelClose;
        let now = Instant::now();
        let e = establish();
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_write_negotiated_open(&mut ctx, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        for message in [
            Message::DataChannelThreshold(DataChannelThreshold::Low(1024)),
            Message::DataChannelThreshold(DataChannelThreshold::High(1 << 20)),
            Message::DataChannelClose(DataChannelClose),
        ] {
            client_write(
                &mut ctx,
                now,
                ch,
                4,
                PayloadProtocolIdentifier::Dcep,
                &message.marshal().expect("marshal"),
            );
        }
        let sent = flush(&mut ctx);
        assert!(
            sent.iter().flat_map(|p| wire_data(p)).next().is_none(),
            "no DATA chunk at all, under PPID 50 or any other"
        );
        const CT_RECONFIG: u8 = 130;
        assert!(
            sent.iter()
                .flat_map(|p| wire_chunks(p))
                .any(|c| c.kind == CT_RECONFIG),
            "the close is the stream reset of RFC 8831 section 6.7"
        );
    }

    /// A client whose association schedules by weighted fair queueing, and its peer.
    fn weighted_pair() -> Accepted {
        let now = Instant::now();
        let e = establish_with(
            TransportConfig::default()
                .with_stream_scheduler(sctp::StreamScheduler::WeightedFairQueueing),
        );
        let ch = e.client_ch;
        Accepted {
            now,
            ctx: client_ctx(now, e.client_ep, ch, e.client_conn),
            ch,
            server_ep: e.server_ep,
            server_conn: e.server_conn,
        }
    }

    /// Queues the same backlog on both streams, then returns how many of the first 36
    /// messages to leave belong to `heavy` and how many to `light`.
    fn shares_of_two_backlogged_streams(
        a: &mut Accepted,
        heavy: StreamId,
        light: StreamId,
    ) -> (usize, usize) {
        for _ in 0..64 {
            for stream_id in [light, heavy] {
                client_write(
                    &mut a.ctx,
                    a.now,
                    a.ch,
                    stream_id,
                    PayloadProtocolIdentifier::Binary,
                    &[stream_id as u8; 1024],
                );
            }
        }
        let mut order: Vec<StreamId> = vec![];
        let mut seen = HashSet::new();
        let mut at = a.now;
        for _ in 0..64 {
            let sent = flush(&mut a.ctx);
            for data in sent.iter().flat_map(|p| wire_data(p)) {
                if data.ppid == PPID_BINARY && seen.insert(data.tsn) {
                    order.push(data.stream_id);
                }
            }
            if order.len() >= 36 {
                break;
            }
            deliver_to_server(&mut a.server_ep, &mut a.server_conn, sent, at);
            // Past the peer's delayed-acknowledgement timer, short of this side's T3-rtx.
            at += Duration::from_millis(250);
            a.server_conn.handle_timeout(at);
            let sacks = drain_transmits(&mut a.server_conn, at);
            client_read(&mut a.ctx, 0, sacks, at);
        }
        assert!(order.len() >= 36, "only {} messages left", order.len());
        let first = &order[..36];
        (
            first.iter().filter(|s| **s == heavy).count(),
            first.iter().filter(|s| **s == light).count(),
        )
    }

    fn assert_eight_to_one((heavy, light): (usize, usize)) {
        assert!(
            heavy.abs_diff(8 * light) <= 8 && heavy > 4 * light,
            "priority 1024 against 128: {heavy} and {light} of the first 36 messages"
        );
    }

    /// RFC 8831 section 6.4: "These priorities MUST be interpreted as weighted-fair-queuing
    /// scheduling priorities". The priority a channel is created with is carried in its OPEN
    /// and weighs its stream: with equal backlogs, a channel of priority 1024 ("extra high")
    /// gets eight times the share of one of priority 128 ("below normal"). The priority used
    /// to be reported and never applied, so the two shared the line evenly.
    #[test]
    fn the_priority_of_a_local_channel_weighs_its_stream() {
        let mut a = weighted_pair();
        // Negotiated channels, so that no OPEN shares the line with the backlog.
        for (stream_id, priority) in [(0, 128), (2, 1024)] {
            client_write_negotiated_open(
                &mut a.ctx,
                a.now,
                a.ch,
                stream_id,
                &dcep_open_with_priority(ChannelType::Reliable, priority),
            );
        }
        assert_eight_to_one(shares_of_two_backlogged_streams(&mut a, 2, 0));
    }

    /// The same for a channel the peer opened: the priority in the peer's OPEN weighs this
    /// side's sends on that channel.
    #[test]
    fn the_priority_in_the_peers_open_weighs_the_stream() {
        let mut a = weighted_pair();
        for (stream_id, priority) in [(1, 1024), (3, 128)] {
            let open = server_send(
                &mut a.server_conn,
                stream_id,
                &[(
                    PayloadProtocolIdentifier::Dcep,
                    dcep_open_with_priority(ChannelType::Reliable, priority),
                )],
                a.now,
            );
            client_read(&mut a.ctx, 0, open, a.now);
        }
        // The acknowledgements of the two OPENs go out before the backlog is queued.
        let sacks = flush(&mut a.ctx);
        deliver_to_server(&mut a.server_ep, &mut a.server_conn, sacks, a.now);
        assert_eight_to_one(shares_of_two_backlogged_streams(&mut a, 1, 3));
    }

    const CT_INIT: u8 = 1;

    /// A handler context whose transport was negotiated for the SCTP ports `local` and
    /// `remote` (`a=sctp-port` of this side and of the peer), DTLS not connected yet. The
    /// transport is the one a peer connection builds: weighted fair queueing, message
    /// interleaving and the zero checksum announced, State Cookies with a MAC.
    fn negotiated_ctx(now: Instant, local: u16, remote: u16) -> SctpHandlerContext {
        negotiated_ctx_with(now, local, remote, |transport| transport)
    }

    /// [`negotiated_ctx`] with the transport changed by `configure` before it starts.
    fn negotiated_ctx_with(
        now: Instant,
        local: u16,
        remote: u16,
        configure: impl FnOnce(SctpTransport) -> SctpTransport,
    ) -> SctpHandlerContext {
        let mut transport = configure(
            SctpTransport::new(
                SctpMaxMessageSize::default(),
                None,
                None,
                test_transport_id(TransportKind::Sctp),
                test_transport_id(TransportKind::Dtls),
            )
            .with_cookie_provider(crypto::default_provider().expect("test crypto provider")),
        );
        transport
            .start(
                crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                local,
                remote,
            )
            .expect("start");
        SctpHandlerContext::new(now, transport)
    }

    fn dtls_connects(ctx: &mut SctpHandlerContext, now: Instant) {
        SctpHandler::new(ctx, 0)
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::DTLSHandshakeComplete(None, None),
            })
            .expect("handle_event");
    }

    /// Whether `ctx` has announced its association established since the last call.
    fn announced_connected(ctx: &mut SctpHandlerContext) -> bool {
        let mut handler = SctpHandler::new(ctx, 0);
        let mut connected = false;
        while let Some(evt) = handler.poll_event() {
            connected |= matches!(evt.event, RTCEventInternal::SCTPHandshakeComplete(_));
        }
        connected
    }

    /// (source port, destination port, verification tag, first chunk type) of an SCTP packet.
    fn packet_header(packet: &[u8]) -> (u16, u16, u32, u8) {
        (
            u16::from_be_bytes([packet[0], packet[1]]),
            u16::from_be_bytes([packet[2], packet[3]]),
            u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            packet[12],
        )
    }

    /// Two negotiated endpoints, `a` on SCTP port 5000 and `b` on 5001, whose DTLS transport
    /// has just connected: each has its INIT ready to go.
    fn two_initiating_endpoints(now: Instant) -> (SctpHandlerContext, SctpHandlerContext) {
        let mut a = negotiated_ctx(now, 5000, 5001);
        let mut b = negotiated_ctx(now, 5001, 5000);
        dtls_connects(&mut a, now);
        dtls_connects(&mut b, now);
        (a, b)
    }

    /// Exchanges what the two endpoints send until neither sends anything more, without
    /// moving the clock: no retransmission timer takes part. `lost` says which packets
    /// never arrive, by sender (`true` for `a`) and by how many packets that sender has sent
    /// before. Returns whether each announced its association established.
    fn exchange(
        a: &mut SctpHandlerContext,
        b: &mut SctpHandlerContext,
        now: Instant,
        lost: impl Fn(bool, usize) -> bool,
    ) -> (bool, bool) {
        let (mut a_up, mut b_up) = (false, false);
        let (mut a_sent, mut b_sent) = (0, 0);
        for _ in 0..32 {
            let from_a = flush(a);
            let from_b = flush(b);
            if from_a.is_empty() && from_b.is_empty() {
                break;
            }
            for dgram in from_a {
                if !lost(true, a_sent) {
                    client_read(b, 0, vec![dgram], now);
                }
                a_sent += 1;
            }
            for dgram in from_b {
                if !lost(false, b_sent) {
                    client_read(a, 0, vec![dgram], now);
                }
                b_sent += 1;
            }
            a_up |= announced_connected(a);
            b_up |= announced_connected(b);
        }
        (a_up, b_up)
    }

    /// The one live association of `ctx` must be established; returns its handle.
    fn established_association(ctx: &SctpHandlerContext) -> AssociationHandle {
        let live: Vec<_> = ctx
            .sctp_transport
            .sctp_associations
            .iter()
            .filter(|(_, association)| !association.is_ended())
            .collect();
        assert_eq!(live.len(), 1, "one association, not two");
        assert!(!live[0].1.is_handshaking(), "established");
        *live[0].0
    }

    /// A message written on `from` arrives on `to`: the two ends are one association.
    fn assert_data_flows(from: &mut SctpHandlerContext, to: &mut SctpHandlerContext, now: Instant) {
        let ch = established_association(from);
        established_association(to);
        client_write_negotiated_open(from, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        client_write(
            from,
            now,
            ch,
            4,
            PayloadProtocolIdentifier::Binary,
            b"across",
        );
        let sent = flush(from);
        client_read(to, 0, sent, now);
        assert!(
            to.read_outs.iter().any(|m| matches!(
                &m.message,
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(msg))
                    if msg.stream_id == 4 && &msg.payload[..] == b"across"
            )),
            "the message did not arrive"
        );
        to.read_outs.clear();
    }

    /// RFC 8841 section 9.3: "both SCTP endpoints MUST initiate the SCTP association (i.e.,
    /// both SCTP endpoints take the 'active' role). In addition, both endpoints MUST use the
    /// same SCTP port as client port and server port". Whatever the DTLS role (the transport
    /// is not told it), an INIT leaves when DTLS connects, from this side's `a=sctp-port` to
    /// the peer's. Only the DTLS client used to initiate.
    #[test]
    fn the_association_is_initiated_when_dtls_connects() {
        let now = Instant::now();
        let mut ctx = negotiated_ctx(now, 5002, 6001);
        assert!(
            flush(&mut ctx).is_empty(),
            "RFC 8261 section 6.1: nothing before DTLS is established"
        );
        dtls_connects(&mut ctx, now);
        let sent = flush(&mut ctx);
        assert_eq!(sent.len(), 1);
        assert_eq!(packet_header(&sent[0]), (5002, 6001, 0, CT_INIT));
    }

    /// The simultaneous open that results: the two INITs cross, each side answers the
    /// other's from the association it initiated (RFC 9260 section 5.2.1), and there is one
    /// association at each end, the same one. The peer's INIT used to be refused by the
    /// endpoint that had initiated, as the start of a second association.
    #[test]
    fn inits_that_cross_make_one_association() {
        let now = Instant::now();
        let (mut a, mut b) = two_initiating_endpoints(now);
        assert_eq!(
            exchange(&mut a, &mut b, now, |_, _| false),
            (true, true),
            "both associations come up, with no retransmission"
        );
        assert_data_flows(&mut a, &mut b, now);
        assert_data_flows(&mut b, &mut a, now);
    }

    /// One side's INIT is lost and the other's arrives: the association is established from
    /// the INIT that got through, at once, where it used to wait for T1-init to send the lost
    /// one again (or for good, against a peer that leaves initiating to this side).
    #[test]
    fn the_peers_init_is_answered_when_this_sides_is_lost() {
        for a_loses_its_init in [true, false] {
            let now = Instant::now();
            let (mut a, mut b) = two_initiating_endpoints(now);
            assert_eq!(
                exchange(&mut a, &mut b, now, |from_a, sent| sent == 0
                    && from_a == a_loses_its_init),
                (true, true),
                "a's INIT lost: {a_loses_its_init}"
            );
            assert_data_flows(&mut a, &mut b, now);
            assert_data_flows(&mut b, &mut a, now);
        }
    }

    /// An endpoint that has not initiated yet (its DTLS handshake completes a moment after
    /// the peer's) answers the peer's INIT, keeping nothing (RFC 9260 section 5.1), and
    /// initiates when its own DTLS handshake completes (RFC 8841 section 9.3: both do). The
    /// peer's COOKIE ECHO for the first answer then finds the association this side
    /// initiated, which is not the one the cookie stands for, and is discarded; the peer
    /// answers this side's INIT from COOKIE-ECHOED (RFC 9260 section 5.2.1) and the two ends
    /// meet in one association, with no retransmission.
    #[test]
    fn an_init_that_comes_first_is_accepted_and_no_second_association_started() {
        let now = Instant::now();
        let mut a = negotiated_ctx(now, 5000, 5001);
        let mut b = negotiated_ctx(now, 5001, 5000);
        dtls_connects(&mut a, now);
        // A timer that fires before anything has arrived finds no association to lose.
        SctpHandler::new(&mut b, 0)
            .handle_timeout(now)
            .expect("timeout");
        let init = flush(&mut a);
        client_read(&mut b, 0, init, now);
        dtls_connects(&mut b, now);
        assert_eq!(exchange(&mut a, &mut b, now, |_, _| false), (true, true));
        assert_data_flows(&mut a, &mut b, now);
        for ctx in [&a, &b] {
            assert!(
                !ctx.sctp_transport.association_lost(),
                "an association that is up is not one that was lost"
            );
            assert_eq!(
                ctx.sctp_transport.offer_port(),
                ctx.sctp_transport.local_port,
                "so the next offer keeps the port"
            );
        }
    }

    /// RFC 8841 section 10.5: "if a DTLS association is closed and replaced with a new DTLS
    /// association ..., the state of the SCTP association is not affected." A DTLS handshake
    /// that completes again starts no second association.
    #[test]
    fn a_later_dtls_handshake_leaves_the_association_alone() {
        let now = Instant::now();
        let (mut a, mut b) = two_initiating_endpoints(now);
        exchange(&mut a, &mut b, now, |_, _| false);
        let ch = established_association(&a);
        dtls_connects(&mut a, now);
        assert_eq!(established_association(&a), ch);
        assert!(
            flush(&mut a).iter().all(|p| packet_header(p).3 != CT_INIT),
            "no new INIT"
        );
        assert_data_flows(&mut a, &mut b, now);
    }

    /// RFC 8841 section 9.3: the ports of the association are the two `a=sctp-port` values,
    /// "in order to prevent two separate SCTP associations from being established". An INIT
    /// from another port, or to another port, is not for this transport; the accepting side
    /// used to adopt whatever ports the INIT carried.
    #[test]
    fn a_packet_between_other_sctp_ports_is_dropped() {
        let now = Instant::now();
        for (peer_local, peer_remote, accepted) in
            [(6000, 5000, true), (6001, 5000, false), (6000, 5001, false)]
        {
            let mut ctx = negotiated_ctx(now, 5000, 6000);
            let mut peer = negotiated_ctx(now, peer_local, peer_remote);
            dtls_connects(&mut peer, now);
            let init = flush(&mut peer);
            assert_eq!(packet_header(&init[0]).3, CT_INIT);
            client_read(&mut ctx, 0, init, now);
            assert!(
                ctx.sctp_transport.sctp_associations.is_empty(),
                "RFC 9260 section 5.1: an INIT makes no association"
            );
            let answers = flush(&mut ctx);
            assert_eq!(
                answers.len(),
                usize::from(accepted),
                "INIT from port {peer_local} to port {peer_remote}"
            );
            assert!(answers.iter().all(|p| packet_header(p).3 == CT_INIT_ACK));
        }
    }

    /// RFC 8841 sections 10.3 and 10.4: an association that signalling closes is closed on
    /// the wire (here with an ABORT, so the peer learns it even if it applies the description
    /// later), forgotten, and reported so its data channels are closed.
    #[test]
    fn closing_for_renegotiation_aborts_and_forgets_the_association() {
        for replaced in [false, true] {
            let now = Instant::now();
            let (mut a, mut b) = two_initiating_endpoints(now);
            exchange(&mut a, &mut b, now, |_, _| false);
            established_association(&a);

            SctpHandler::new(&mut a, 0).close_for_renegotiation(now, replaced);
            assert!(a.sctp_transport.sctp_associations.is_empty());
            let sent = flush(&mut a);
            assert!(
                sent.iter().any(|p| packet_header(p).3 == CT_ABORT),
                "an ABORT closes it"
            );
            let mut events = vec![];
            {
                let mut handler = SctpHandler::new(&mut a, 0);
                while let Some(evt) = handler.poll_event() {
                    events.push(evt.event);
                }
            }
            assert!(
                matches!(
                    events.as_slice(),
                    [RTCEventInternal::SCTPClosedBySignalling(r)] if *r == replaced
                ),
                "one event, and none of the aborted association's own"
            );

            // The peer's association ends with the ABORT, and it reports the loss: with no
            // signalling of its own it needs a new exchange, with a new port (section 9.3).
            client_read(&mut b, 0, sent, now);
            let mut at = now;
            for _ in 0..8 {
                let Some(next) = SctpHandler::new(&mut b, 0).poll_timeout() else {
                    break;
                };
                at = at.max(next);
                SctpHandler::new(&mut b, 0)
                    .handle_timeout(at)
                    .expect("timeout");
                if b.sctp_transport.sctp_associations.is_empty() {
                    break;
                }
            }
            assert!(
                b.sctp_transport
                    .sctp_associations
                    .values()
                    .all(|association| association.is_ended())
            );
            assert_eq!(
                b.sctp_transport.state(),
                crate::peer_connection::transport::sctp::state::RTCSctpTransportState::Closed
            );
        }
    }

    /// RFC 8841 section 9.3: "SCTP associations might be closed without SDP signaling -- for
    /// example, in case of a failure. ... New (different than the ones currently used) SCTP
    /// ports MUST be used by both endpoints." The transport is `closed`, and the next offer
    /// or answer carries a new port.
    #[test]
    fn an_association_lost_without_signalling_asks_for_a_new_port() {
        let now = Instant::now();
        let (mut a, mut b) = two_initiating_endpoints(now);
        exchange(&mut a, &mut b, now, |_, _| false);
        assert_eq!(a.sctp_transport.offer_port(), 5000);

        // A stream this side has open, to see what becomes of it.
        let a_ch = established_association(&a);
        client_write_negotiated_open(&mut a, now, a_ch, 4, &dcep_open(ChannelType::Reliable, 0));

        // The peer shuts the association down and this side follows.
        let ch = established_association(&b);
        b.sctp_transport
            .sctp_associations
            .get_mut(&ch)
            .expect("association")
            .shutdown()
            .expect("shutdown");
        b.flush_dirty = true;
        let mut at = now;
        let mut stream_closed = false;
        for _ in 0..32 {
            let from_b = flush(&mut b);
            let from_a = flush(&mut a);
            let idle = from_a.is_empty() && from_b.is_empty();
            client_read(&mut a, 0, from_b, at);
            client_read(&mut b, 0, from_a, at);
            {
                let mut handler = SctpHandler::new(&mut a, 0);
                while let Some(evt) = handler.poll_event() {
                    stream_closed |= matches!(evt.event, RTCEventInternal::SCTPStreamClosed(_, 4));
                }
            }
            if a.sctp_transport.association_lost() {
                break;
            }
            if idle {
                let Some(next) = SctpHandler::new(&mut a, 0).poll_timeout() else {
                    break;
                };
                at = at.max(next);
                SctpHandler::new(&mut a, 0)
                    .handle_timeout(at)
                    .expect("timeout");
            }
        }
        assert!(
            stream_closed,
            "RFC 8831 section 6.2: an association closed gracefully closes its data channels, \
             each of which hears of its stream"
        );
        assert!(a.sctp_transport.association_lost());
        assert_eq!(
            a.sctp_transport.state(),
            crate::peer_connection::transport::sctp::state::RTCSctpTransportState::Closed
        );
        assert_eq!(a.sctp_transport.offer_port(), 5001);
        assert_eq!(a.sctp_transport.answer_port(5001), 5001);
    }

    /// RFC 8831 section 6.6: "The sender SHOULD disable the Nagle algorithm (see [RFC1122])
    /// to minimize the latency": a small message is not held back for data in flight to be
    /// acknowledged. Three messages well under a packet each leave at the flush that follows
    /// their write, though nothing sent before has been acknowledged.
    #[test]
    fn a_small_message_is_sent_at_once_while_data_is_outstanding() {
        let now = Instant::now();
        let e = establish();
        let ch = e.client_ch;
        let mut ctx = client_ctx(now, e.client_ep, ch, e.client_conn);
        client_write_negotiated_open(&mut ctx, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        let tsns: Vec<u32> = (0..3)
            .map(|_| send_probe(&mut ctx, ch, 4, now).tsn)
            .collect();
        assert_eq!(tsns[1], tsns[0].wrapping_add(1));
        assert_eq!(tsns[2], tsns[1].wrapping_add(1));
    }
    const CT_INIT_ACK: u8 = 2;
    const CT_COOKIE_ECHO: u8 = 10;
    const CT_I_DATA: u8 = 64;

    /// The fields of an I-DATA chunk (RFC 8260 section 2.1) these tests assert on.
    #[derive(Debug, Clone, Copy)]
    struct WireIData {
        tsn: u32,
        stream_id: StreamId,
        /// The E bit: the last fragment of its message.
        ending: bool,
        len: usize,
    }

    fn wire_i_data(packet: &[u8]) -> Vec<WireIData> {
        wire_chunks(packet)
            .into_iter()
            .filter(|c| c.kind == CT_I_DATA && c.value.len() >= 16)
            .map(|c| WireIData {
                tsn: u32::from_be_bytes([c.value[0], c.value[1], c.value[2], c.value[3]]),
                stream_id: u16::from_be_bytes([c.value[4], c.value[5]]),
                ending: c.flags & DATA_FLAG_ENDING != 0,
                len: c.value.len() - 16,
            })
            .collect()
    }

    /// Two endpoints as a peer connection builds them, their transports changed by
    /// `configure_a` and `configure_b`, with their association established.
    fn established_pair(
        now: Instant,
        configure_a: impl FnOnce(SctpTransport) -> SctpTransport,
        configure_b: impl FnOnce(SctpTransport) -> SctpTransport,
    ) -> (SctpHandlerContext, SctpHandlerContext) {
        let mut a = negotiated_ctx_with(now, 5000, 5001, configure_a);
        let mut b = negotiated_ctx_with(now, 5001, 5000, configure_b);
        dtls_connects(&mut a, now);
        dtls_connects(&mut b, now);
        assert_eq!(exchange(&mut a, &mut b, now, |_, _| false), (true, true));
        (a, b)
    }

    fn live_association(ctx: &SctpHandlerContext) -> &Association {
        let ch = established_association(ctx);
        &ctx.sctp_transport.sctp_associations[&ch]
    }

    fn try_client_write(
        ctx: &mut SctpHandlerContext,
        now: Instant,
        ch: AssociationHandle,
        stream_id: StreamId,
        ppi: PayloadProtocolIdentifier,
        payload: &[u8],
    ) -> Result<()> {
        SctpHandler::new(ctx, 0).handle_write(TaggedRTCMessageInternal {
            now,
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                association_handle: ch.0,
                stream_id,
                ppi,
                payload: BytesMut::from(payload),
                negotiated: false,
            })),
        })
    }

    /// The binary messages `ctx` has handed up, as (stream, length), in order; they are taken.
    fn take_received(ctx: &mut SctpHandlerContext) -> Vec<(StreamId, usize)> {
        ctx.read_outs
            .drain(..)
            .filter_map(|m| match m.message {
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(msg))
                    if msg.ppi == PayloadProtocolIdentifier::Binary =>
                {
                    Some((msg.stream_id, msg.payload.len()))
                }
                _ => None,
            })
            .collect()
    }

    /// Carries what `from` sends to `to` and `to`'s acknowledgements back, moving the clock
    /// past the delayed-acknowledgement timer each round, until `from` has nothing more to
    /// send or `rounds` have passed. Returns everything `from` sent, and the time reached.
    fn pump(
        from: &mut SctpHandlerContext,
        to: &mut SctpHandlerContext,
        mut at: Instant,
        rounds: usize,
    ) -> (Vec<Bytes>, Instant) {
        let mut all = vec![];
        for _ in 0..rounds {
            let sent = flush(from);
            if sent.is_empty() {
                break;
            }
            all.extend(sent.iter().cloned());
            client_read(to, 0, sent, at);
            // Past the peer's delayed-acknowledgement timer, short of this side's T3-rtx.
            at += Duration::from_millis(250);
            SctpHandler::new(to, 0).handle_timeout(at).expect("timeout");
            let sacks = flush(to);
            client_read(from, 0, sacks, at);
        }
        (all, at)
    }

    /// RFC 9260 section 5.1: the endpoint that receives an INIT answers with an INIT ACK and
    /// "MUST NOT allocate any resources or keep any states for the new association";
    /// section 5.1.3: the State Cookie carries a MAC, made with a key only this endpoint
    /// has; section 5.1.5: the association is made when a COOKIE ECHO brings back a cookie
    /// whose MAC verifies. The peer connection gives the endpoint its crypto provider for
    /// that. Here the INIT leaves no association behind, another endpoint (another key)
    /// refuses the cookie without a word, and the endpoint that made it builds the
    /// association from it, established at once. The association used to be made, and
    /// held, from the INIT on, with a cookie of random bytes compared against a copy.
    #[test]
    fn the_association_is_made_at_the_cookie_echo_from_an_authenticated_cookie() {
        let now = Instant::now();
        let mut a = negotiated_ctx(now, 5000, 5001);
        let mut b = negotiated_ctx(now, 5001, 5000);
        dtls_connects(&mut a, now);

        let init = flush(&mut a);
        assert_eq!(packet_header(&init[0]).3, CT_INIT);
        client_read(&mut b, 0, init, now);
        assert!(
            b.sctp_transport.sctp_associations.is_empty(),
            "nothing is kept for an INIT"
        );
        let init_ack = flush(&mut b);
        assert_eq!(init_ack.len(), 1);
        assert_eq!(packet_header(&init_ack[0]).3, CT_INIT_ACK);

        client_read(&mut a, 0, init_ack, now);
        let cookie_echo = flush(&mut a);
        assert_eq!(cookie_echo.len(), 1);
        assert_eq!(packet_header(&cookie_echo[0]).3, CT_COOKIE_ECHO);

        // An endpoint negotiated for the same ports that did not make this cookie.
        let mut other = negotiated_ctx(now, 5001, 5000);
        client_read(&mut other, 0, cookie_echo.clone(), now);
        assert!(
            other.sctp_transport.sctp_associations.is_empty(),
            "a cookie whose MAC does not verify makes no association"
        );
        assert!(flush(&mut other).is_empty(), "and is discarded silently");

        client_read(&mut b, 0, cookie_echo, now);
        established_association(&b);
        assert!(announced_connected(&mut b));
        assert!(!b.sctp_transport.association_lost());

        // The endpoint's own DTLS handshake completes now: it has its association already
        // and initiates no second one.
        dtls_connects(&mut b, now);
        let from_b = flush(&mut b);
        assert!(
            from_b.iter().all(|p| packet_header(p).3 != CT_INIT),
            "no INIT from an endpoint that has its association"
        );
        client_read(&mut a, 0, from_b, now);
        assert!(announced_connected(&mut a), "the COOKIE ACK");
        assert_data_flows(&mut a, &mut b, now);
        assert_data_flows(&mut b, &mut a, now);
    }

    /// RFC 8831 section 6.1: "The support for message interleaving as defined in [RFC8260]
    /// SHOULD be used." It is announced by default, and used (user data travels in I-DATA
    /// chunks) when the peer announces it too; a peer that does not gets DATA chunks, and
    /// the message arrives either way.
    #[test]
    fn user_data_is_interleaved_when_the_peer_announces_it_and_not_otherwise() {
        for (peer_interleaves, chunk) in [(true, CT_I_DATA), (false, CT_PAYLOAD_DATA)] {
            let now = Instant::now();
            let (mut a, mut b) = established_pair(
                now,
                |t| t,
                |t| t.with_message_interleaving(peer_interleaves),
            );
            for ctx in [&a, &b] {
                assert_eq!(
                    live_association(ctx).message_interleaving(),
                    peer_interleaves
                );
            }
            for a_sends in [true, false] {
                let (from, to) = if a_sends {
                    (&mut a, &mut b)
                } else {
                    (&mut b, &mut a)
                };
                let ch = established_association(from);
                client_write_negotiated_open(
                    from,
                    now,
                    ch,
                    4,
                    &dcep_open(ChannelType::Reliable, 0),
                );
                client_write(
                    from,
                    now,
                    ch,
                    4,
                    PayloadProtocolIdentifier::Binary,
                    &[7u8; 3000],
                );
                let sent = flush(from);
                let kinds: HashSet<u8> = sent
                    .iter()
                    .flat_map(|p| wire_chunks(p))
                    .map(|c| c.kind)
                    .filter(|kind| [CT_I_DATA, CT_PAYLOAD_DATA].contains(kind))
                    .collect();
                assert_eq!(
                    kinds,
                    HashSet::from([chunk]),
                    "the peer interleaves: {peer_interleaves}"
                );
                client_read(to, 0, sent, now);
                assert_eq!(take_received(to), vec![(4, 3000)]);
            }
        }
    }

    /// RFC 9653 section 5.2: over DTLS, which is an alternate error detection method
    /// (section 6), an endpoint "SHOULD use zero as the checksum" towards a peer that
    /// announced it accepts one. It is announced by default; the INIT always carries its
    /// CRC32c (section 5.2), and so does every packet for a peer that did not announce the
    /// same.
    #[test]
    fn the_checksum_is_zero_when_the_peer_accepts_it_and_a_crc32c_otherwise() {
        for peer_accepts in [true, false] {
            let now = Instant::now();
            let mut a = negotiated_ctx(now, 5000, 5001);
            let mut b =
                negotiated_ctx_with(now, 5001, 5000, |t| t.with_zero_checksum(peer_accepts));
            dtls_connects(&mut a, now);
            dtls_connects(&mut b, now);
            let init = flush(&mut a);
            assert_eq!(packet_header(&init[0]).3, CT_INIT);
            assert_ne!(&init[0][8..12], &[0u8; 4], "an INIT has its CRC32c");
            client_read(&mut b, 0, init, now);
            assert_eq!(exchange(&mut a, &mut b, now, |_, _| false), (true, true));

            for ctx in [&a, &b] {
                assert_eq!(live_association(ctx).zero_checksum(), peer_accepts);
            }
            for a_sends in [true, false] {
                let (from, to) = if a_sends {
                    (&mut a, &mut b)
                } else {
                    (&mut b, &mut a)
                };
                let ch = established_association(from);
                client_write_negotiated_open(
                    from,
                    now,
                    ch,
                    4,
                    &dcep_open(ChannelType::Reliable, 0),
                );
                client_write(
                    from,
                    now,
                    ch,
                    4,
                    PayloadProtocolIdentifier::Binary,
                    b"checked",
                );
                let sent = flush(from);
                assert!(!sent.is_empty());
                for packet in &sent {
                    assert_eq!(
                        packet[8..12] == [0u8; 4],
                        peer_accepts,
                        "the peer accepts a zero checksum: {peer_accepts}"
                    );
                }
                client_read(to, 0, sent, now);
                assert_eq!(take_received(to), vec![(4, 7)]);
            }
        }
    }

    /// RFC 8831 section 6.6: "As long as message interleaving is not supported, the sender
    /// SHOULD limit the maximum message size to 16 KB to avoid monopolization." On an
    /// association that does not interleave, `maxMessageSize` is 16384 and a larger message
    /// is refused; with interleaving, or with the limit lifted (what browsers do), the peer's
    /// `max-message-size` is the only limit. A DATA_CHANNEL_OPEN is not an application
    /// message and may be larger (its label alone may take 65535 bytes).
    #[test]
    fn a_message_over_16_kb_is_refused_without_interleaving() {
        let now = Instant::now();
        let negotiated = SctpMaxMessageSize::DEFAULT_MESSAGE_SIZE;
        let big = vec![3u8; 16 * 1024 + 1];
        let fits = vec![3u8; 16 * 1024];
        let binary = PayloadProtocolIdentifier::Binary;

        // Interleaving: the negotiated limit.
        let (mut a, _b) = established_pair(now, |t| t, |t| t);
        let ch = established_association(&a);
        assert_eq!(a.sctp_transport.max_message_size(), Some(negotiated));
        client_write_negotiated_open(&mut a, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        try_client_write(&mut a, now, ch, 4, binary, &big)
            .expect("with interleaving a message over 16 KB is sent");

        // No interleaving: 16 KB.
        let (mut a, _b) = established_pair(now, |t| t, |t| t.with_message_interleaving(false));
        let ch = established_association(&a);
        assert_eq!(a.sctp_transport.max_message_size(), Some(16 * 1024));
        let open = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: vec![b'l'; 20_000],
            protocol: Vec::new(),
        })
        .marshal()
        .expect("DCEP OPEN");
        try_client_write(&mut a, now, ch, 4, PayloadProtocolIdentifier::Dcep, &open)
            .expect("a DATA_CHANNEL_OPEN over 16 KB is sent");
        let refused = try_client_write(&mut a, now, ch, 4, binary, &big);
        assert_eq!(
            refused,
            Err(Error::ErrMessageTooLargeWithoutInterleaving {
                size: 16 * 1024 + 1,
                limit: 16 * 1024,
            })
        );
        let text = refused.unwrap_err().to_string();
        assert!(
            text.contains("16384")
                && text.contains("with_sctp_message_size_limit_without_interleaving(false)"),
            "the error names the limit and the setting that lifts it: {text}"
        );
        try_client_write(&mut a, now, ch, 4, binary, &fits).expect("16 KB is within the limit");

        // No interleaving, and the limit lifted.
        let (mut a, _b) = established_pair(
            now,
            |t| t.with_message_size_limit_without_interleaving(false),
            |t| t.with_message_interleaving(false),
        );
        let ch = established_association(&a);
        assert_eq!(a.sctp_transport.max_message_size(), Some(negotiated));
        client_write_negotiated_open(&mut a, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        try_client_write(&mut a, now, ch, 4, binary, &big).expect("the limit is lifted");
    }

    /// RFC 8831 section 6.4 with the defaults of a peer connection (the weighted fair
    /// queueing scheduler, and interleaving, so that it chooses for every chunk): of two
    /// channels with the same backlog, the one of priority 1024 gets eight times the line of
    /// the one of priority 128, whichever was written to first. With the scheduler turned off
    /// the two are served in the order their messages were written, which is half each.
    #[test]
    fn by_default_two_channels_share_the_line_by_their_priorities() {
        for (weighted, light_stream_first) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let now = Instant::now();
            let (mut a, mut b) =
                established_pair(now, |t| t.with_weighted_fair_queueing(weighted), |t| t);
            let ch = established_association(&a);
            let (light, heavy): (StreamId, StreamId) =
                if light_stream_first { (0, 2) } else { (2, 0) };
            for (stream_id, priority) in [(light, 128), (heavy, 1024)] {
                client_write_negotiated_open(
                    &mut a,
                    now,
                    ch,
                    stream_id,
                    &dcep_open_with_priority(ChannelType::Reliable, priority),
                );
            }
            for _ in 0..64 {
                for stream_id in [light, heavy] {
                    client_write(
                        &mut a,
                        now,
                        ch,
                        stream_id,
                        PayloadProtocolIdentifier::Binary,
                        &[stream_id as u8; 1024],
                    );
                }
            }
            let (sent, _) = pump(&mut a, &mut b, now, 64);
            let mut seen = HashSet::new();
            let order: Vec<StreamId> = sent
                .iter()
                .flat_map(|p| wire_i_data(p))
                .filter(|chunk| seen.insert(chunk.tsn))
                .map(|chunk| chunk.stream_id)
                .collect();
            assert_eq!(order.len(), 128, "every message left, in one chunk each");
            let first = &order[..36];
            let shares = (
                first.iter().filter(|s| **s == heavy).count(),
                first.iter().filter(|s| **s == light).count(),
            );
            if weighted {
                assert_eight_to_one(shares);
            } else {
                assert_eq!(shares, (18, 18), "first come, first served");
            }
        }
    }

    /// RFC 8831 section 6.6: without interleaving "sending a large user message can
    /// monopolize the SCTP association. To overcome this limitation, [RFC8260] defines an
    /// extension to support message interleaving, which SHOULD be used." A small message
    /// written on one channel while a large one is on its way on another leaves in the next
    /// flight, between the fragments of the large one, and reaches the application first.
    /// Against a peer that does not interleave it waits until the large message is through.
    #[test]
    fn a_large_message_does_not_hold_up_another_channel_when_interleaving() {
        const LARGE: usize = 60_000;
        for peer_interleaves in [true, false] {
            let now = Instant::now();
            let (mut a, mut b) = established_pair(
                now,
                |t| t.with_message_size_limit_without_interleaving(false),
                |t| t.with_message_interleaving(peer_interleaves),
            );
            let ch = established_association(&a);
            for stream_id in [0, 2] {
                client_write_negotiated_open(
                    &mut a,
                    now,
                    ch,
                    stream_id,
                    &dcep_open(ChannelType::Reliable, 0),
                );
            }
            client_write(
                &mut a,
                now,
                ch,
                0,
                PayloadProtocolIdentifier::Binary,
                &vec![1u8; LARGE],
            );
            // The first congestion window of the large message is on its way.
            let first_flight = flush(&mut a);
            assert!(!first_flight.is_empty());
            client_write(
                &mut a,
                now,
                ch,
                2,
                PayloadProtocolIdentifier::Binary,
                &[2u8; 100],
            );

            client_read(&mut b, 0, first_flight, now);
            let at = now + Duration::from_millis(250);
            SctpHandler::new(&mut b, 0)
                .handle_timeout(at)
                .expect("timeout");
            let sacks = flush(&mut b);
            client_read(&mut a, 0, sacks, at);

            let second_flight = flush(&mut a);
            let small_in_second_flight = if peer_interleaves {
                second_flight
                    .iter()
                    .flat_map(|p| wire_i_data(p))
                    .any(|c| c.stream_id == 2 && c.ending)
            } else {
                second_flight
                    .iter()
                    .flat_map(|p| wire_data(p))
                    .any(|c| c.stream_id == 2)
            };
            assert_eq!(
                small_in_second_flight, peer_interleaves,
                "the peer interleaves: {peer_interleaves}"
            );

            client_read(&mut b, 0, second_flight, at);
            let mut received = take_received(&mut b);
            let at = at + Duration::from_millis(250);
            SctpHandler::new(&mut b, 0)
                .handle_timeout(at)
                .expect("timeout");
            let sacks = flush(&mut b);
            client_read(&mut a, 0, sacks, at);
            for _ in 0..40 {
                let (sent, _) = pump(&mut a, &mut b, at, 200);
                received.extend(take_received(&mut b));
                if sent.is_empty() {
                    break;
                }
            }
            assert_eq!(
                received,
                if peer_interleaves {
                    vec![(2, 100), (0, LARGE)]
                } else {
                    vec![(0, LARGE), (2, 100)]
                },
                "the peer interleaves: {peer_interleaves}"
            );
        }
    }

    /// RFC 8831 section 5: "SCTP SHOULD be notified when an address change has happened. In
    /// this case, SCTP SHOULD retest the Path MTU and reset the congestion state to the
    /// initial state ... setting the congestion window and slow-start threshold to its
    /// initial values." When the ICE handler's count of selected pairs moves the handler asks
    /// for the path, takes the packet size that fits it (here from IPv4 to IPv6: 1135 to 1195
    /// bytes) and has the association start its congestion control over. A DTLS handshake
    /// that completes changes what is known of the path (the cipher suite) and nothing else.
    #[test]
    fn a_selected_pair_change_sets_the_path_mtu_and_restarts_congestion_control() {
        let now = Instant::now();
        let ipv4 = SctpPath {
            ipv6: false,
            tcp: false,
            relayed: false,
            dtls_record_overhead: SctpPath::DEFAULT_DTLS_RECORD_OVERHEAD,
        };
        let ipv6 = SctpPath { ipv6: true, ..ipv4 };

        let mut a = negotiated_ctx(now, 5000, 5001);
        let mut b = negotiated_ctx(now, 5001, 5000);
        // ICE selects its first pair, then DTLS connects: the order of a real connection.
        for ctx in [&mut a, &mut b] {
            assert!(!ctx.take_path_refresh(0), "nothing has changed yet");
            assert!(
                ctx.take_path_refresh(1),
                "ICE selected a pair: the path is asked for"
            );
            assert!(!ctx.take_path_refresh(1), "once");
            SctpHandler::new(ctx, 0).apply_path(Some(ipv4));
            dtls_connects(ctx, now);
            assert!(ctx.take_path_refresh(1), "the cipher suite is known now");
            SctpHandler::new(ctx, 0).apply_path(Some(ipv4));
        }
        assert_eq!(exchange(&mut a, &mut b, now, |_, _| false), (true, true));
        for ctx in [&a, &b] {
            assert_eq!(
                live_association(ctx).path_mtu(),
                1135,
                "1200 - 20 (IPv4) - 8 (UDP) - 13 - 24 (DTLS)"
            );
        }
        let initial = live_association(&a).congestion_window();

        // Slow start opens the window.
        let ch = established_association(&a);
        client_write_negotiated_open(&mut a, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        for _ in 0..48 {
            client_write(
                &mut a,
                now,
                ch,
                4,
                PayloadProtocolIdentifier::Binary,
                &[9u8; 1000],
            );
        }
        let (sent, at) = pump(&mut a, &mut b, now, 64);
        assert!(
            sent.iter().all(|p| p.len() <= 1135),
            "no packet over the path MTU"
        );
        assert_eq!(take_received(&mut b).len(), 48);
        let grown = live_association(&a).congestion_window();
        assert!(
            grown > initial,
            "cwnd {grown} after slow start, {initial} before"
        );

        // A DTLS handshake that completes again: the path is looked at, nothing restarts.
        dtls_connects(&mut a, at);
        assert!(a.take_path_refresh(1));
        SctpHandler::new(&mut a, 0).apply_path(Some(ipv4));
        assert_eq!(live_association(&a).congestion_window(), grown);

        // ICE selects another pair.
        SctpHandler::new(&mut a, 0)
            .handle_timeout(at)
            .expect("timeout");
        assert!(a.take_path_refresh(2));
        SctpHandler::new(&mut a, 0).apply_path(Some(ipv6));
        let association = live_association(&a);
        assert_eq!(
            association.path_mtu(),
            1195,
            "1280 - 40 (IPv6) - 8 (UDP) - 13 - 24 (DTLS)"
        );
        assert!(
            association.congestion_window() < grown,
            "the congestion window started over: {} after {grown}",
            association.congestion_window()
        );
        assert!(
            association.congestion_window() <= 4 * 1195,
            "at its initial value, at most four packets (RFC 9260 section 7.2.1)"
        );
        assert!(
            association.slow_start_threshold() >= grown,
            "and the slow start threshold is high again"
        );

        // The association goes on over the new path.
        client_write(
            &mut a,
            at,
            ch,
            4,
            PayloadProtocolIdentifier::Binary,
            b"after the move",
        );
        pump(&mut a, &mut b, at, 8);
        assert_eq!(take_received(&mut b), vec![(4, 14)]);
    }

    /// RFC 9260 sections 8.2 and 8.3: past Path.Max.Retrans unanswered retransmissions the
    /// path is inactive, and the association, which has no other, goes on trying. That is
    /// no state of an `RTCSctpTransport` (W3C webrtc 6.1: `connecting`, `connected`,
    /// `closed`) and no data channel event: the transport stays `connected` with its
    /// channels open, and when the peer answers again the data arrives.
    #[test]
    fn an_inactive_path_leaves_the_transport_connected_and_its_channels_open() {
        use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;

        let now = Instant::now();
        let (mut a, mut b) = established_pair(now, |t| t, |t| t);
        let ch = established_association(&a);
        client_write_negotiated_open(&mut a, now, ch, 4, &dcep_open(ChannelType::Reliable, 0));
        client_write(
            &mut a,
            now,
            ch,
            4,
            PayloadProtocolIdentifier::Binary,
            b"late",
        );
        let lost = flush(&mut a);
        assert!(!lost.is_empty());

        // Seven retransmissions go unanswered: more than Path.Max.Retrans (5), fewer than
        // Association.Max.Retrans (10).
        let mut at = now;
        let mut retransmissions = 0;
        let mut last = vec![];
        for _ in 0..64 {
            if retransmissions == 7 {
                break;
            }
            let Some(next) = SctpHandler::new(&mut a, 0).poll_timeout() else {
                break;
            };
            at = at.max(next);
            SctpHandler::new(&mut a, 0)
                .handle_timeout(at)
                .expect("timeout");
            let sent = flush(&mut a);
            if sent.iter().any(|p| !wire_i_data(p).is_empty()) {
                retransmissions += 1;
                last = sent;
            }
        }
        assert_eq!(retransmissions, 7);
        let mut events = vec![];
        {
            let mut handler = SctpHandler::new(&mut a, 0);
            while let Some(evt) = handler.poll_event() {
                events.push(evt.event);
            }
        }
        assert!(
            events.is_empty(),
            "no failure and no closed stream is reported for an inactive path"
        );
        assert_eq!(a.sctp_transport.state(), RTCSctpTransportState::Connected);

        // The path answers again.
        client_read(&mut b, 0, last, at);
        assert_eq!(take_received(&mut b), vec![(4, 4)]);
        let sacks = flush(&mut b);
        client_read(&mut a, 0, sacks, at);
        assert_data_flows(&mut a, &mut b, at);
        assert_eq!(a.sctp_transport.state(), RTCSctpTransportState::Connected);
    }

    /// RFC 8831 section 6.7: a data channel is closed by resetting its outgoing stream, and
    /// is closed when the peer has reset its own. A peer that answers the reset request with
    /// "denied" or an error (RFC 6525 section 4.4) will never do that: the channel fails and
    /// is closed with an error instead of staying `closing`. The other outcomes of a
    /// re-configuration report nothing to the data channels.
    #[test]
    fn a_stream_reset_the_peer_does_not_perform_fails_the_channel() {
        let now = Instant::now();
        let ch = AssociationHandle(3);
        let mut event_outs = VecDeque::new();
        let mut ordered_until_reply = HashMap::new();
        ordered_until_reply.insert((ch, 4), (ReliabilityType::Reliable, 0));

        SctpHandler::process_reconfig_event(
            ch,
            ReconfigEvent::OutgoingStreamsReset { streams: vec![6] },
            now,
            &mut event_outs,
            &mut ordered_until_reply,
        );
        SctpHandler::process_reconfig_event(
            ch,
            ReconfigEvent::AssociationReset {
                local_next_tsn: 1,
                remote_next_tsn: 2,
            },
            now,
            &mut event_outs,
            &mut ordered_until_reply,
        );
        assert!(event_outs.is_empty());

        SctpHandler::process_reconfig_event(
            ch,
            ReconfigEvent::OutgoingStreamsResetFailed {
                streams: vec![4],
                denied: true,
            },
            now,
            &mut event_outs,
            &mut ordered_until_reply,
        );
        let events: Vec<RTCEventInternal> = event_outs.into_iter().map(|e| e.event).collect();
        assert!(
            matches!(
                events.as_slice(),
                [
                    RTCEventInternal::SCTPStreamFailed(3, 4),
                    RTCEventInternal::SCTPStreamClosed(3, 4)
                ]
            ),
            "the channel on stream 4 fails, then closes"
        );
        assert!(ordered_until_reply.is_empty());
    }

    /// Runs the client handler and the server association against each other, 10 ms a step,
    /// for up to `steps` steps or until `done`. Returns the largest number of bytes of
    /// incomplete messages the client handler held at once.
    fn exchange_with_server(
        ctx: &mut SctpHandlerContext,
        server_ep: &mut Endpoint,
        server_conn: &mut Association,
        mut dgrams: Vec<Bytes>,
        start: Instant,
        steps: u32,
        mut done: impl FnMut(&SctpHandlerContext) -> bool,
    ) -> usize {
        let ch = only_association(ctx);
        let mut held = 0;
        let mut now = start;
        for _ in 0..steps {
            client_read(ctx, 0, dgrams, now);
            held = held.max(ctx.reassembly.held(ch));
            if done(ctx) {
                break;
            }
            now += Duration::from_millis(10);
            SctpHandler::new(ctx, 0)
                .handle_timeout(now)
                .expect("client timeout");
            held = held.max(ctx.reassembly.held(ch));
            let back = flush(ctx);
            deliver_to_server(server_ep, server_conn, back, now);
            if server_conn.poll_timeout().is_some_and(|at| at <= now) {
                server_conn.handle_timeout(now);
            }
            while server_conn.poll().is_some() {}
            dgrams = drain_transmits(server_conn, now);
        }
        held
    }

    fn delivered(ctx: &SctpHandlerContext) -> Vec<(StreamId, Vec<u8>)> {
        ctx.read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(msg)) => {
                    Some((msg.stream_id, msg.payload.to_vec()))
                }
                _ => None,
            })
            .collect()
    }

    fn pattern(seed: u8, len: usize) -> Bytes {
        Bytes::from(
            (0..len)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed))
                .collect::<Vec<u8>>(),
        )
    }

    /// RFC 9260 6.9 and 6.2 through the data channel layer: a 48 KiB message to a receiver
    /// with a 16 KiB SCTP receive buffer, under RFC 9260 6.2's drop (no overcommit). The
    /// handler reads it in parts and puts it together above the association, so the window
    /// opens again as it arrives, and the data channel gets it whole, once (W3C: whole
    /// messages only). What was held above the association is released with it.
    #[test]
    fn a_message_larger_than_the_receive_buffer_reaches_the_data_channel_whole() {
        let now = Instant::now();
        let e = establish_with(TransportConfig::default().with_max_receive_buffer_size(16 * 1024));
        let (mut server_ep, mut server_conn) = (e.server_ep, e.server_conn);
        let payload = pattern(3, 48 * 1024);
        let dgrams = server_send(
            &mut server_conn,
            1,
            &[(PayloadProtocolIdentifier::Binary, payload.clone())],
            now,
        );
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        let held = exchange_with_server(
            &mut ctx,
            &mut server_ep,
            &mut server_conn,
            dgrams,
            now,
            3000,
            |ctx| !delivered(ctx).is_empty(),
        );
        assert_eq!(delivered(&ctx), vec![(1, payload.to_vec())]);
        assert!(held > 0, "it was put together above the association");
        assert_eq!(ctx.reassembly.held(e.client_ch), 0, "and released");
    }

    /// RFC 8260 with RFC 9260 6.9: the bytes of incomplete messages held above an association
    /// are bounded by the inbound reassembly limit (here set to 64 KiB, the advertised
    /// `max-message-size`). Three interleaved 28 KiB messages (84 KiB in all) to a receiver
    /// with a 16 KiB buffer: what is held never exceeds the limit, the message whose part
    /// would take it past is dropped and only its data channel fails, with an event naming
    /// the limit (RFC 8831 6.6: "the receiver SHOULD close the corresponding data channel"),
    /// and the other two messages arrive whole.
    #[test]
    fn incomplete_messages_held_above_an_association_are_bounded() {
        const LIMIT: usize = 64 * 1024;
        let now = Instant::now();
        let e = establish_with_both(
            TransportConfig::default()
                .with_max_receive_buffer_size(16 * 1024)
                .with_message_interleaving(true),
            TransportConfig::default()
                .with_message_interleaving(true)
                .with_stream_scheduler(sctp::StreamScheduler::WeightedFairQueueing),
        );
        let (mut server_ep, mut server_conn) = (e.server_ep, e.server_conn);
        let streams = [1u16, 3, 5];
        let payloads: Vec<Bytes> = (0..3).map(|i| pattern(i, 28 * 1024)).collect();
        for (&id, payload) in streams.iter().zip(&payloads) {
            server_conn
                .open_stream(id, PayloadProtocolIdentifier::Binary)
                .expect("open")
                .write_sctp(now, payload, PayloadProtocolIdentifier::Binary)
                .expect("write");
        }
        while server_conn.poll().is_some() {}
        let dgrams = drain_transmits(&mut server_conn, now);
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        ctx.sctp_transport.partial_message_limit = LIMIT;
        assert!(
            ctx.sctp_transport
                .sctp_associations
                .values()
                .all(|a| a.message_interleaving()),
            "I-DATA negotiated"
        );
        let held = exchange_with_server(
            &mut ctx,
            &mut server_ep,
            &mut server_conn,
            dgrams,
            now,
            6000,
            |ctx| delivered(ctx).len() == 2,
        );
        assert!(held <= LIMIT, "{held} bytes held, bound {LIMIT}");
        let failed: Vec<u16> = ctx
            .event_outs
            .iter()
            .filter_map(|e| match e.event {
                RTCEventInternal::SCTPInboundReassemblyLimit(_, id, limit) => {
                    assert_eq!(limit, LIMIT, "the event names the limit");
                    Some(id)
                }
                RTCEventInternal::SCTPStreamFailed(_, id) => panic!("stream {id} failed"),
                _ => None,
            })
            .collect();
        assert_eq!(failed.len(), 1, "one channel fails: {failed:?}");
        let mut got = delivered(&ctx);
        got.sort();
        let want: Vec<(u16, Vec<u8>)> = streams
            .iter()
            .zip(&payloads)
            .filter(|(id, _)| **id != failed[0])
            .map(|(id, p)| (*id, p.to_vec()))
            .collect();
        assert_eq!(got, want, "the other two arrive whole");
        assert_eq!(ctx.reassembly.held(e.client_ch), 0);
    }

    /// `n` interleaved 64 KiB messages, one per stream, to a receiver with the default 1 MiB
    /// buffer, `max-message-size` and inbound reassembly limit: whether all arrive whole,
    /// whether a channel failed, and the most bytes held above the association at once.
    fn concurrent_interleaved_messages(n: u16) -> (bool, bool, usize) {
        const SIZE: usize = 64 * 1024;
        let now = Instant::now();
        let e = establish_with_both(
            TransportConfig::default().with_message_interleaving(true),
            TransportConfig::default()
                .with_message_interleaving(true)
                .with_stream_scheduler(sctp::StreamScheduler::WeightedFairQueueing),
        );
        let (mut server_ep, mut server_conn) = (e.server_ep, e.server_conn);
        let streams: Vec<u16> = (0..n).map(|i| 2 * i + 1).collect();
        let payloads: Vec<Bytes> = (0..n).map(|i| pattern(i as u8, SIZE)).collect();
        for (&id, payload) in streams.iter().zip(&payloads) {
            server_conn
                .open_stream(id, PayloadProtocolIdentifier::Binary)
                .expect("open")
                .write_sctp(now, payload, PayloadProtocolIdentifier::Binary)
                .expect("write");
        }
        while server_conn.poll().is_some() {}
        let dgrams = drain_transmits(&mut server_conn, now);
        let mut ctx = client_ctx(now, e.client_ep, e.client_ch, e.client_conn);
        let held = exchange_with_server(
            &mut ctx,
            &mut server_ep,
            &mut server_conn,
            dgrams,
            now,
            20_000,
            |ctx| delivered(ctx).len() == usize::from(n),
        );
        let failed = ctx.event_outs.iter().any(|e| {
            matches!(
                e.event,
                RTCEventInternal::SCTPInboundReassemblyLimit(..)
                    | RTCEventInternal::SCTPStreamFailed(..)
            )
        });
        let mut got = delivered(&ctx);
        got.sort();
        let want: Vec<(u16, Vec<u8>)> = streams
            .iter()
            .zip(&payloads)
            .map(|(id, p)| (*id, p.to_vec()))
            .collect();
        (got == want, failed, held)
    }

    /// RFC 8260 2.2.2 and RFC 8841 6.1: a conforming peer has at most one message in progress
    /// per stream, each at most the advertised `max-message-size`. 16 and 64 concurrent
    /// 64 KiB messages over I-DATA (1 and 4 MiB in progress) all arrive whole under the
    /// default inbound reassembly limit, and no channel fails. With 64 more than 2 MiB is held
    /// above the association at once, which the first bound of sctp-15 (the larger of the
    /// receive buffer and `max-message-size` added to the buffer) refused.
    #[test]
    fn concurrent_messages_a_conforming_peer_may_send_all_arrive_under_the_default_limit() {
        for n in [16u16, 64] {
            let (all, failed, held) = concurrent_interleaved_messages(n);
            assert!(all, "{n} messages: not all arrived whole");
            assert!(!failed, "{n} messages: a channel failed");
            if n == 64 {
                assert!(held > 2 * 1024 * 1024, "{held} bytes held at most");
            }
        }
    }
}
