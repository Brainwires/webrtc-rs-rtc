use crate::data_channel::RTCDataChannelId;
use crate::data_channel::internal::RTCDataChannelInternal;
use crate::data_channel::message::RTCDataChannelMessage;
use crate::data_channel::registry::DataChannelRegistry;
use crate::data_channel::state::RTCDataChannelState;
use crate::peer_connection::event::data_channel_event::RTCDataChannelEvent;
use crate::peer_connection::event::{
    RTCEventInternal, RTCPeerConnectionEvent, TaggedRTCEventInternal,
};
use crate::peer_connection::message::internal::{
    ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::statistics::accumulator::RTCStatsAccumulator;
use bytes::BytesMut;
use datachannel::data_channel::DataChannelMessage;
use datachannel::message::Message as DcepMessage;
use datachannel::message::message_channel_close::DataChannelClose;
use log::{debug, warn};
use sctp::{PayloadProtocolIdentifier, StreamId};
use shared::TransportContext;
use shared::error::{Error, Result};
use shared::marshal::Marshal;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(crate) struct DataChannelHandlerContext {
    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// The newest instant a caller has supplied, seeded at construction.
    ///
    /// `poll_write` drains each channel's outbound queue, and a message can still be sitting
    /// there from an earlier `handle_*` — the datachannel layer buffers when SCTP back-pressures
    /// it. Stamping those with the instant of the input that caused them is the right answer;
    /// this field is what a `poll_*` has instead of a parameter.
    now: Instant,
}

impl DataChannelHandlerContext {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            now,
        }
    }

    /// Records the newest instant a caller has supplied. See the design's §9.3 for why there is
    /// no monotonicity assert alongside the `max`.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }
}

/// DataChannelHandler implements DataChannel Protocol handling
pub(crate) struct DataChannelHandler<'a> {
    ctx: &'a mut DataChannelHandlerContext,
    data_channels: &'a mut DataChannelRegistry,
    stats: &'a mut RTCStatsAccumulator,
    /// Configured DCEP handshake timeout for in-band channels. `None` disables it.
    dcep_handshake_timeout: Option<Duration>,
    /// The DTLS role this endpoint negotiated, which RFC 8832 §6 turns into the parity of the
    /// stream ids assigned at `SCTPHandshakeComplete`. Resolved by the time an association
    /// exists, so the handler never has to guess it.
    dtls_role: RTCDtlsRole,
    /// Negotiated stream limit, bounding stream-id assignment. `None` until the association
    /// reports one.
    max_channels: Option<u16>,
}

impl<'a> DataChannelHandler<'a> {
    pub(crate) fn new(
        ctx: &'a mut DataChannelHandlerContext,
        data_channels: &'a mut DataChannelRegistry,
        stats: &'a mut RTCStatsAccumulator,
        dcep_handshake_timeout: Option<Duration>,
        dtls_role: RTCDtlsRole,
        max_channels: Option<u16>,
    ) -> Self {
        DataChannelHandler {
            ctx,
            data_channels,
            stats,
            dcep_handshake_timeout,
            dtls_role,
            max_channels,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "DataChannelHandler"
    }

    /// Fires `OnClose` for a channel that has been removed, and counts it as closed.
    ///
    /// The event names the channel by handle, as every application-facing event does; the
    /// stream id was only how SCTP referred to it. A channel already closed by handshake timeout
    /// has already fired `OnClose` and been counted, so it is not announced twice.
    fn announce_closed(&mut self, now: Instant, dc: RTCDataChannelInternal) {
        if dc.close_emitted {
            return;
        }
        let channel_id = dc.id;
        self.stats.peer_connection.on_data_channel_closed();
        if let Some(dc_stats) = self.stats.data_channels.get_mut(&channel_id) {
            dc_stats.on_state_changed(RTCDataChannelState::Closed);
        }
        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::RTCPeerConnectionEvent(RTCPeerConnectionEvent::OnDataChannel(
                RTCDataChannelEvent::OnClose(channel_id),
            )),
        });
    }

    /// Whether the peer may open an in-band channel on `stream_id`.
    ///
    /// RFC 8832 §6: the DTLS client opens channels on even stream ids and the DTLS server on
    /// odd ones, so the peer's ids have the parity this side's do not. An id of this side's
    /// parity is one `assign_stream_ids` may hand to a local channel; accepting the peer's
    /// OPEN on it would let the peer take that stream first. With the role unresolved there
    /// is no parity to judge by, and no stream is accepted.
    fn is_peer_stream_id(&self, stream_id: StreamId) -> bool {
        let local_parity = match self.dtls_role {
            RTCDtlsRole::Client => 0,
            RTCDtlsRole::Server => 1,
            _ => return false,
        };
        stream_id % 2 != local_parity
    }

    /// Asks SCTP to reset `stream_id`, through the same DCEP close a local `close()` sends, so
    /// a stream the peer was not allowed to open does not linger half-open in the
    /// association.
    fn reset_stream(
        &mut self,
        now: Instant,
        association_handle: usize,
        stream_id: StreamId,
    ) -> Result<()> {
        let payload = DcepMessage::DataChannelClose(DataChannelClose).marshal()?;
        self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
            now,
            transport: TransportContext::default(),
            message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(DataChannelMessage {
                association_handle,
                stream_id,
                ppi: PayloadProtocolIdentifier::Dcep,
                payload: BytesMut::from(&payload[..]),
                negotiated: false,
            })),
        });
        Ok(())
    }

    /// Emit the `DataChannelEvent::Open` application message and record the
    /// corresponding peer-connection and per-channel statistics.
    ///
    /// The caller must have already ensured the channel's `ready_state` is `Open`.
    fn emit_data_channel_opened(
        &mut self,
        now: Instant,
        transport: TransportContext,
        id: RTCDataChannelId,
    ) -> Result<()> {
        let dc = self
            .data_channels
            .get(&id)
            .ok_or(Error::ErrDataChannelNotExisted)?;

        self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
            now,
            transport,
            message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                data_channel_id: id,
                data_channel_event: DataChannelEvent::Open,
            })),
        });

        // The channel is open, so it necessarily has a stream id by now; record it as the
        // W3C `dataChannelIdentifier`, which is the wire value rather than the handle the
        // accumulator is keyed by.
        let stream_id = dc.stream_id;
        let (label, protocol) = (dc.label.clone(), dc.protocol.clone());

        self.stats.peer_connection.on_data_channel_opened();
        self.stats
            .get_or_create_data_channel(id, &label, &protocol)
            .on_state_changed(RTCDataChannelState::Open);
        if let Some(stream_id) = stream_id {
            self.stats.set_data_channel_stream_id(id, stream_id);
        }
        Ok(())
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for DataChannelHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        self.ctx.observe(now);

        if let RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)) = msg.message {
            debug!(
                "recv SCTP DataChannelMessage from {:?}",
                msg.transport.peer_addr
            );

            let stream_id = message.stream_id;
            let transport = msg.transport;

            // SCTP addresses channels by stream id; everything leaving this handler towards
            // the application is keyed by handle instead.
            let opened = if let Some(data_channel_internal) =
                self.data_channels.get_by_stream_mut(&stream_id)
            {
                // A closed channel is terminal: ignore any late DCEP or user data.
                if data_channel_internal.ready_state == RTCDataChannelState::Closed {
                    return Ok(());
                }

                // Process the inbound message, then check whether a still-connecting
                // in-band channel just completed its DCEP handshake (initiator side).
                // If so, promote it to Open and emit the open event.
                let mut opened = false;
                let data_channel = data_channel_internal
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                data_channel.handle_read(message)?;
                if data_channel.is_handshake_complete()
                    && data_channel_internal.ready_state == RTCDataChannelState::Connecting
                {
                    data_channel_internal.ready_state = RTCDataChannelState::Open;
                    data_channel_internal.handshake_deadline = None;
                    opened = true;
                }
                opened
            } else {
                // A stream no channel is registered for is one the peer is opening in-band.
                // Out-of-band negotiated channels are registered under their id on both
                // sides, so they are found above and never get here, whatever their parity.
                if !self.is_peer_stream_id(stream_id) {
                    warn!(
                        "rejecting stream {stream_id} the peer opened: RFC 8832 §6 gives ids of \
                         that parity to this side (DTLS {})",
                        self.dtls_role
                    );
                    self.reset_stream(now, message.association_handle, stream_id)?;
                    return Ok(());
                }
                let data_channel_internal = RTCDataChannelInternal::accept(
                    message.association_handle,
                    message.stream_id,
                    message.ppi,
                    &message.payload,
                )?;

                self.data_channels.insert(data_channel_internal);
                true
            };

            // From here on the channel is addressed by handle, which is what the application
            // and every event it receives use.
            let channel_id = self
                .data_channels
                .handle_of_stream(&stream_id)
                .ok_or(Error::ErrDataChannelNotExisted)?;

            if opened {
                self.emit_data_channel_opened(now, transport, channel_id)?;
            }

            // Get label/protocol before taking mutable borrow for the loop
            let (label, protocol) = {
                let dc = self
                    .data_channels
                    .get(&channel_id)
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                (dc.label.clone(), dc.protocol.clone())
            };

            // Only deliver application messages once the channel is Open. Messages that
            // arrive while it is still Connecting stay buffered in the underlying
            // DataChannel's read queue; they drain once the channel opens, or are
            // discarded on close/timeout.
            let is_open = self
                .data_channels
                .get(&channel_id)
                .is_some_and(|dc| dc.ready_state == RTCDataChannelState::Open);

            let data_channel = self
                .data_channels
                .get_mut(&channel_id)
                .ok_or(Error::ErrDataChannelNotExisted)?
                .data_channel
                .as_mut()
                .ok_or(Error::ErrDataChannelNotExisted)?;

            if is_open {
                while let Some(data_channel_message) = data_channel.poll_read() {
                    let payload_len = data_channel_message.payload.len();
                    debug!("recv application message {:?}", msg.transport.peer_addr);

                    // Track received message stats
                    self.stats
                        .get_or_create_data_channel(channel_id, &label, &protocol)
                        .on_message_received(payload_len);

                    // https://datatracker.ietf.org/doc/html/rfc8831#section-6.6
                    // When receiving an SCTP user message with one of these [Empty]
                    // PPIDs, the receiver MUST ignore the SCTP user message and
                    // process it as an empty message.
                    let message_data = if matches!(
                        data_channel_message.ppi,
                        PayloadProtocolIdentifier::StringEmpty
                            | PayloadProtocolIdentifier::BinaryEmpty
                    ) {
                        Default::default()
                    } else {
                        data_channel_message.payload
                    };

                    self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                        now: msg.now,
                        transport: msg.transport,
                        message: RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                            ApplicationMessage {
                                data_channel_id: channel_id,
                                data_channel_event: DataChannelEvent::Message(
                                    RTCDataChannelMessage {
                                        is_string: matches!(
                                            data_channel_message.ppi,
                                            PayloadProtocolIdentifier::String
                                                | PayloadProtocolIdentifier::StringEmpty
                                        ),
                                        data: message_data,
                                    },
                                ),
                            },
                        )),
                    });
                }
            }

            while let Some(data_channel_message) = data_channel.poll_write() {
                debug!("send data channel message from handle_read");
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                });
            }
        } else {
            // Bypass
            debug!("bypass DataChannel read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        let now = msg.now;
        self.ctx.observe(now);

        if let RTCMessageInternal::Dtls(DTLSMessage::DataChannel(message)) = msg.message {
            debug!("send application message {:?}", msg.transport.peer_addr);

            if let DataChannelEvent::Message(RTCDataChannelMessage { is_string, data }) =
                message.data_channel_event
            {
                let data_len = data.len();
                let channel_id = message.data_channel_id;

                // Get label/protocol before taking mutable borrow
                let dc_internal = self
                    .data_channels
                    .get(&channel_id)
                    .ok_or(Error::ErrDataChannelNotExisted)?;
                let label = dc_internal.label.clone();
                let protocol = dc_internal.protocol.clone();

                let data_channel = self
                    .data_channels
                    .get_mut(&channel_id)
                    .ok_or(Error::ErrDataChannelNotExisted)?
                    .data_channel
                    .as_mut()
                    .ok_or(Error::ErrDataChannelNotExisted)?;

                let data_channel_message =
                    ::datachannel::data_channel::DataChannel::get_data_channel_message(
                        is_string, data,
                    );
                data_channel.handle_write(data_channel_message)?;

                // Track sent message stats
                self.stats
                    .get_or_create_data_channel(channel_id, &label, &protocol)
                    .on_message_sent(data_len);

                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from handle_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            } else {
                warn!(
                    "drop unsupported DATACHANNEL message to {}",
                    msg.transport.peer_addr
                );
            }
        } else {
            // Bypass
            debug!("bypass DataChannel write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        for data_channel_internal in self.data_channels.values_mut() {
            if let Some(data_channel) = data_channel_internal.data_channel.as_mut() {
                while let Some(data_channel_message) = data_channel.poll_write() {
                    debug!("send data channel message from poll_write");
                    self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                        now: self.ctx.now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_channel_message)),
                    });
                }
            }
        }

        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        let now = evt.now;
        match evt.event {
            RTCEventInternal::SCTPHandshakeComplete(association_handle) => {
                // The W3C "RTCSctpTransport connected procedure": the association is up, so
                // the DTLS role is resolved and the negotiated stream count is known. This is
                // the first moment a stream id can be chosen correctly, and therefore the
                // moment it is chosen at all (RFC 8832 §6).
                self.data_channels
                    .assign_stream_ids(self.dtls_role, self.max_channels)?;

                // Out-of-band negotiated channels have no DCEP handshake, so they are
                // open immediately and fire the open event here. In-band channels stay
                // connecting until their `DATA_CHANNEL_ACK` arrives in `handle_read`.
                let mut opened = Vec::new();
                for data_channel_internal in self.data_channels.values_mut() {
                    // Only dial channels that have not been dialed yet. An in-band channel stays
                    // Connecting after dialing, so the ready_state guard alone does not
                    // exclude it from a second SCTPHandshakeComplete.
                    if data_channel_internal.ready_state == RTCDataChannelState::Connecting
                        && data_channel_internal.data_channel.is_none()
                    {
                        data_channel_internal.dial(association_handle)?;

                        if data_channel_internal.negotiated {
                            opened.push(data_channel_internal.id);
                        } else {
                            // In-band channels have a DCEP handshake to complete; arm a
                            // deadline so a lost ACK cannot leave them Connecting forever.
                            data_channel_internal.handshake_deadline =
                                self.dcep_handshake_timeout.map(|timeout| now + timeout);
                        }

                        let data_channel = data_channel_internal
                            .data_channel
                            .as_mut()
                            .ok_or(Error::ErrDataChannelNotExisted)?;

                        while let Some(data_channel_message) = data_channel.poll_write() {
                            debug!("send data channel message from handle_event");
                            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                                now,
                                transport: TransportContext::default(),
                                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(
                                    data_channel_message,
                                )),
                            });
                        }
                    }
                }

                for id in opened {
                    self.emit_data_channel_opened(now, TransportContext::default(), id)?;
                }
            }

            RTCEventInternal::SCTPStreamClosed(_association_handle, stream_id) => {
                if let Some(dc) = self.data_channels.remove_by_stream(&stream_id) {
                    self.announce_closed(now, dc);
                }
            }

            // The peer closed the DTLS transport, and with it the SCTP transport every channel
            // runs over: every channel is closed now (rtc#255).
            RTCEventInternal::DTLSClosed => {
                for dc in self.data_channels.drain() {
                    self.announce_closed(now, dc);
                }
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::DTLSClosed,
                });
            }

            RTCEventInternal::SCTPBufferReleased(_association_handle, stream_id, n_bytes) => {
                // Pure accounting: SCTP released (acked or abandoned) `n_bytes` of
                // this channel's outgoing buffer. Decrement the synchronous send
                // back-pressure counter; do NOT forward the event further.
                if let Some(dc) = self.data_channels.get_by_stream_mut(&stream_id) {
                    dc.outstanding_bytes = dc.outstanding_bytes.saturating_sub(n_bytes);
                }
            }
            // The SCTP layer knows only stream ids; the application-facing events name the
            // channel by handle, like every other event it receives. This is the layer that
            // owns the mapping, so the translation happens here.
            RTCEventInternal::SCTPBufferedAmountLow(_association_handle, stream_id) => {
                if let Some(channel_id) = self.data_channels.handle_of_stream(&stream_id) {
                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnDataChannel(
                                RTCDataChannelEvent::OnBufferedAmountLow(channel_id),
                            ),
                        ),
                    });
                }
            }

            RTCEventInternal::SCTPBufferedAmountHigh(_association_handle, stream_id) => {
                if let Some(channel_id) = self.data_channels.handle_of_stream(&stream_id) {
                    self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::RTCPeerConnectionEvent(
                            RTCPeerConnectionEvent::OnDataChannel(
                                RTCDataChannelEvent::OnBufferedAmountHigh(channel_id),
                            ),
                        ),
                    });
                }
            }

            // Events propagate rather than being re-stamped: the forwarded event keeps the
            // instant at which its condition was observed, not the instant this hop ran.
            event => {
                self.ctx
                    .event_outs
                    .push_back(TaggedRTCEventInternal { now, event });
            }
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.ctx.observe(now);

        // Close in-band channels whose DCEP handshake did not complete in time.
        let mut timed_out = Vec::new();
        for dc in self.data_channels.values() {
            if let Some(deadline) = dc.handshake_deadline
                && dc.ready_state == RTCDataChannelState::Connecting
                && deadline <= now
            {
                timed_out.push(dc.id);
            }
        }

        for id in timed_out {
            if let Some(dc) = self.data_channels.get_mut(&id) {
                dc.handshake_deadline = None;
                dc.ready_state = RTCDataChannelState::Closed;
                if let Some(data_channel) = dc.data_channel.as_mut() {
                    data_channel.close()?;
                }

                self.stats.peer_connection.on_data_channel_closed();
                self.stats
                    .get_or_create_data_channel(id, &dc.label, &dc.protocol)
                    .on_state_changed(RTCDataChannelState::Closed);

                dc.close_emitted = true;
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id)),
                    ),
                });
            }
        }

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.data_channels
            .values()
            .filter_map(|dc| {
                if dc.ready_state == RTCDataChannelState::Connecting {
                    dc.handshake_deadline
                } else {
                    None
                }
            })
            .min()
    }

    fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Timing contract for the DCEP handshake-complete signal.
    //!
    //! These drive `DataChannelHandler` directly and pin
    //! *when* the open event fires and `ready_state` flips, which the integration
    //! tests cannot see: they only require the open event to fire *eventually*, so
    //! they pass whether the channel is promoted at dial time or on the ACK.

    use super::*;
    use crate::data_channel::parameters::DataChannelParameters;
    use crate::statistics::accumulator::RTCStatsAccumulator;
    use bytes::BytesMut;
    use datachannel::data_channel::DataChannelMessage;
    use datachannel::message::Message;
    use datachannel::message::message_channel_ack::DataChannelAck;
    use sansio::Protocol;
    use sctp::StreamId;
    use shared::marshal::Marshal;

    /// An in-band channel that already has its stream id, i.e. one past the point where
    /// `assign_stream_ids` would have run. These tests are about DCEP open/ack timing, not
    /// about stream-id assignment.
    fn in_band_channel(stream_id: StreamId) -> RTCDataChannelInternal {
        let mut dc = RTCDataChannelInternal::new(DataChannelParameters {
            label: "timing-test".to_string(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: None,
        });
        dc.stream_id = Some(stream_id);
        dc
    }

    fn negotiated_channel(stream_id: StreamId) -> RTCDataChannelInternal {
        RTCDataChannelInternal::new(DataChannelParameters {
            label: "timing-test".to_string(),
            protocol: String::new(),
            ordered: true,
            max_packet_life_time: None,
            max_retransmits: None,
            negotiated: Some(stream_id),
        })
    }

    /// A registry seeded with `channels`, returning it alongside their handles in the order
    /// given.
    fn registry(
        channels: Vec<RTCDataChannelInternal>,
    ) -> (DataChannelRegistry, Vec<RTCDataChannelId>) {
        let mut reg = DataChannelRegistry::new();
        let handles = channels.into_iter().map(|dc| reg.insert(dc)).collect();
        (reg, handles)
    }

    fn ack(association_handle: usize, stream_id: u16) -> DataChannelMessage {
        let ack = Message::DataChannelAck(DataChannelAck {})
            .marshal()
            .unwrap();
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: BytesMut::from(&ack[..]),
            negotiated: false,
        }
    }

    fn data_message(association_handle: usize, stream_id: u16, data: &[u8]) -> DataChannelMessage {
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::String,
            payload: BytesMut::from(data),
            negotiated: false,
        }
    }

    fn message_events(ctx: &DataChannelHandlerContext) -> Vec<DataChannelEvent> {
        ctx.read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app)) => {
                    Some(app.data_channel_event.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// An in-band channel is dialed at `SCTPHandshakeComplete` but stays
    /// `Connecting` with no open event; the open event fires exactly once, and
    /// `ready_state` flips to `Open`, only when the peer's `DATA_CHANNEL_ACK`
    /// is processed.
    #[test]
    fn in_band_channel_fires_open_only_when_ack_is_processed() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        let dc = data_channels.get(&handle).unwrap();
        assert!(
            dc.data_channel.is_some(),
            "SCTPHandshakeComplete must dial the in-band channel"
        );
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Connecting,
            "an in-band channel must stay Connecting after the SCTP handshake"
        );
        assert!(
            ctx.read_outs.iter().all(|m| !matches!(
                &m.message,
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open)
            )),
            "no open event may fire at SCTPHandshakeComplete time"
        );

        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
                })
                .unwrap();
        }

        assert_eq!(
            data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Open,
            "ready_state flips to Open exactly when the ACK is processed"
        );

        let open_events: Vec<RTCDataChannelId> = ctx
            .read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open) =>
                {
                    Some(app.data_channel_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            open_events,
            vec![handle],
            "exactly one open event, fired on the ACK"
        );
        assert_eq!(
            stats.peer_connection.data_channels_opened, 1,
            "open stats recorded exactly once"
        );
    }

    /// A negotiated (out-of-band) channel has no DCEP handshake: it dials open
    /// immediately and fires the open event at `SCTPHandshakeComplete`.
    #[test]
    fn negotiated_channel_fires_open_at_handshake_complete() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![negotiated_channel(1)]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        handler
            .handle_event(TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::SCTPHandshakeComplete(0),
            })
            .unwrap();

        let dc = data_channels.get(&handle).unwrap();
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Open,
            "a negotiated channel is open immediately at SCTPHandshakeComplete"
        );
        assert!(
            dc.handshake_deadline.is_none(),
            "a negotiated channel has no DCEP handshake deadline"
        );

        let open_events: Vec<RTCDataChannelId> = ctx
            .read_outs
            .iter()
            .filter_map(|m| match &m.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(app))
                    if matches!(app.data_channel_event, DataChannelEvent::Open) =>
                {
                    Some(app.data_channel_id)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            open_events,
            vec![handle],
            "exactly one open event at SCTPHandshakeComplete for a negotiated channel"
        );
        assert_eq!(
            stats.peer_connection.data_channels_opened, 1,
            "open stats recorded for the negotiated channel"
        );
    }

    /// `emit_data_channel_opened` returns an error when the channel does not exist.
    #[test]
    fn emit_data_channel_opened_missing_channel_returns_error() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let mut data_channels = DataChannelRegistry::new();
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        let err = handler
            .emit_data_channel_opened(now, TransportContext::default(), 99)
            .unwrap_err();
        assert_eq!(err, Error::ErrDataChannelNotExisted);
    }

    /// A second `SCTPHandshakeComplete` must not re-dial an already-dialed
    /// in-band channel: it stays Connecting after dialing, so the
    /// `data_channel.is_none()` guard is what excludes it.
    #[test]
    fn sctp_handshake_complete_does_not_redial() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let _handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        // Fire SCTPHandshakeComplete once; this dials the channel and queues its OPEN.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }
        let first_writes = ctx.write_outs.len();
        assert!(
            first_writes >= 1,
            "dialing must queue the DATA_CHANNEL_OPEN"
        );
        ctx.write_outs.clear();

        // Fire it again: no new dial, so nothing new is queued.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }
        assert_eq!(
            ctx.write_outs.len(),
            0,
            "a second SCTPHandshakeComplete must not re-dial the channel"
        );
    }

    /// A straggler `DATA_CHANNEL_ACK` on a channel that has already been closed
    /// must be ignored: it must not flip state or emit an open event.
    #[test]
    fn ack_on_closed_channel_is_ignored() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let mut dc = in_band_channel(1);
        dc.ready_state = RTCDataChannelState::Closed;
        let (mut data_channels, handles) = registry(vec![dc]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        let mut handler = DataChannelHandler::new(
            &mut ctx,
            &mut data_channels,
            &mut stats,
            None,
            RTCDtlsRole::Server,
            None,
        );
        handler
            .handle_read(TaggedRTCMessageInternal {
                now,
                transport: TransportContext::default(),
                message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
            })
            .unwrap();

        assert_eq!(
            data_channels.get(&handle).unwrap().ready_state,
            RTCDataChannelState::Closed,
            "a closed channel must ignore a late ACK"
        );
        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Open)),
            "no open event may fire for a closed channel"
        );
    }

    /// An in-band channel whose ACK never arrives must time out: it transitions
    /// to Closed, fires OnClose and is counted exactly once (closed without opened).
    #[test]
    fn in_band_channel_times_out_without_ack() {
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        // Dial the in-band channel and arm a deadline.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // A deadline must be reported.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            let deadline = handler
                .poll_timeout()
                .expect("a dialed in-band channel must have a deadline");
            assert!(deadline <= now + timeout);
        }

        // Advance past the deadline and let handle_timeout fire.
        let later = now + timeout + Duration::from_secs(1);
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler.handle_timeout(later).unwrap();
        }

        let dc = data_channels.get(&handle).unwrap();
        assert_eq!(
            dc.ready_state,
            RTCDataChannelState::Closed,
            "a timed-out channel must be Closed"
        );
        assert!(
            dc.handshake_deadline.is_none(),
            "timeout must clear the deadline"
        );
        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Open)),
            "no open event for a timed-out channel"
        );

        let closes = ctx
            .event_outs
            .iter()
            .filter(|e| {
                matches!(
                    &e.event,
                    RTCEventInternal::RTCPeerConnectionEvent(
                        RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(id))
                    ) if *id == handle
                )
            })
            .count();
        assert_eq!(closes, 1, "exactly one OnClose for the timed-out channel");

        assert_eq!(stats.peer_connection.data_channels_opened, 0);
        assert_eq!(stats.peer_connection.data_channels_closed, 1);

        // No further deadlines remain.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            assert!(
                handler.poll_timeout().is_none(),
                "no deadline after the timeout fired"
            );
        }
    }

    /// A user message arriving before the ACK is buffered and delivered only
    /// after the channel opens, with the open event first.
    #[test]
    fn pre_open_data_is_buffered_until_open() {
        let now = Instant::now();
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let _handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        // Dial first.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // A user data message arrives while the channel is still Connecting.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_message(
                        0, 1, b"hello",
                    ))),
                })
                .unwrap();
        }

        // No message event yet.
        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Message(_))),
            "no message may be delivered before the channel is open"
        );

        // The ACK arrives: the channel opens and the buffered message is delivered,
        // with the open event first.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                None,
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(ack(0, 1))),
                })
                .unwrap();
        }

        let events = message_events(&ctx);
        assert!(
            matches!(events.first(), Some(DataChannelEvent::Open)),
            "open event must fire first"
        );
        assert!(
            matches!(events.get(1), Some(DataChannelEvent::Message(_))),
            "the buffered message must be delivered after the open event"
        );
    }

    /// A user message buffered before the ACK is discarded if the channel times
    /// out: it must never be delivered to the application.
    #[test]
    fn pre_open_data_is_dropped_on_timeout() {
        let now = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut ctx = DataChannelHandlerContext::new(now);
        let (mut data_channels, handles) = registry(vec![in_band_channel(1)]);
        let _handle = handles[0];
        let mut stats = RTCStatsAccumulator::new();

        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
        }

        // Buffer a user message while Connecting.
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler
                .handle_read(TaggedRTCMessageInternal {
                    now,
                    transport: TransportContext::default(),
                    message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(data_message(
                        0, 1, b"bye",
                    ))),
                })
                .unwrap();
        }

        // Time out; the channel closes and the buffered message must not be delivered.
        let later = now + timeout + Duration::from_secs(1);
        {
            let mut handler = DataChannelHandler::new(
                &mut ctx,
                &mut data_channels,
                &mut stats,
                Some(timeout),
                RTCDtlsRole::Server,
                None,
            );
            handler.handle_timeout(later).unwrap();
        }

        assert!(
            !message_events(&ctx)
                .iter()
                .any(|e| matches!(e, DataChannelEvent::Message(_))),
            "a buffered message must never be delivered after the timeout"
        );
    }

    /// A DCEP OPEN from the peer, on `stream_id`.
    fn open_message(association_handle: usize, stream_id: u16) -> DataChannelMessage {
        use datachannel::message::message_channel_open::{
            CHANNEL_PRIORITY_NORMAL, ChannelType, DataChannelOpen,
        };
        let open = Message::DataChannelOpen(DataChannelOpen {
            channel_type: ChannelType::Reliable,
            priority: CHANNEL_PRIORITY_NORMAL,
            reliability_parameter: 0,
            label: b"peer".to_vec(),
            protocol: Vec::new(),
        })
        .marshal()
        .unwrap();
        DataChannelMessage {
            association_handle,
            stream_id,
            ppi: PayloadProtocolIdentifier::Dcep,
            payload: BytesMut::from(&open[..]),
            negotiated: false,
        }
    }

    /// RFC 8832 §6: the DTLS client opens channels on even stream ids and the server on odd
    /// ones. An OPEN from the peer on an id of this side's parity is refused, and the stream
    /// reset, so the peer cannot take an id `assign_stream_ids` may give a local channel.
    /// Negotiated channels are registered on both sides and keep working on either parity.
    #[test]
    fn peer_open_with_this_sides_stream_parity_is_rejected() {
        // (this side's role, an id of the peer's parity, an id of this side's parity)
        for (role, peer_id, own_id) in [(RTCDtlsRole::Client, 3, 2), (RTCDtlsRole::Server, 2, 3)] {
            let now = Instant::now();
            let mut ctx = DataChannelHandlerContext::new(now);
            let (mut data_channels, handles) =
                registry(vec![negotiated_channel(4), negotiated_channel(5)]);
            let mut stats = RTCStatsAccumulator::new();
            let mut handler =
                DataChannelHandler::new(&mut ctx, &mut data_channels, &mut stats, None, role, None);
            handler
                .handle_event(TaggedRTCEventInternal {
                    now,
                    event: RTCEventInternal::SCTPHandshakeComplete(0),
                })
                .unwrap();
            while handler.poll_write().is_some() {}
            while handler.poll_read().is_some() {}

            let read = |handler: &mut DataChannelHandler<'_>, message: DataChannelMessage| {
                handler
                    .handle_read(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Sctp(message)),
                    })
                    .unwrap()
            };

            read(&mut handler, open_message(0, own_id));
            assert!(
                handler.poll_read().is_none(),
                "{role}: the peer opened a channel on stream {own_id}, of this side's parity"
            );
            let reset = handler.poll_write().expect("the refused stream is reset");
            match reset.message {
                RTCMessageInternal::Dtls(DTLSMessage::Sctp(m)) => {
                    use shared::marshal::Unmarshal;
                    assert_eq!(m.stream_id, own_id);
                    assert!(matches!(
                        Message::unmarshal(&mut &m.payload[..]),
                        Ok(Message::DataChannelClose(_))
                    ));
                }
                _ => panic!("{role}: expected a DCEP close for the refused stream"),
            }

            read(&mut handler, open_message(0, peer_id));
            assert!(
                matches!(
                    handler.poll_read().map(|m| m.message),
                    Some(RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                        ApplicationMessage {
                            data_channel_event: DataChannelEvent::Open,
                            ..
                        }
                    )))
                ),
                "{role}: the peer's OPEN on stream {peer_id} opens a channel"
            );
            while handler.poll_read().is_some() {}

            // Negotiated channels, whichever parity they were given, still carry data.
            for (handle, stream_id) in [(handles[0], 4), (handles[1], 5)] {
                read(&mut handler, data_message(0, stream_id, b"hi"));
                assert!(
                    matches!(
                        handler.poll_read().map(|m| m.message),
                        Some(RTCMessageInternal::Dtls(DTLSMessage::DataChannel(
                            ApplicationMessage {
                                data_channel_id,
                                data_channel_event: DataChannelEvent::Message(_),
                            }
                        ))) if data_channel_id == handle
                    ),
                    "{role}: negotiated stream {stream_id} lost its data"
                );
            }
            drop(handler);
            assert_eq!(data_channels.len(), 3);
        }
    }
}
