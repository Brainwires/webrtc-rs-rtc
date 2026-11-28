use crate::alert::{AlertDescription, AlertLevel};
use crate::conn::*;
use crate::content::*;
use shared::error::*;

use log::*;
use std::fmt;
use std::time::Instant;

//use std::io::BufWriter;

// [RFC6347 Section-4.2.4]
//                      +-----------+
//                +---> | PREPARING | <--------------------+
//                |     +-----------+                      |
//                |           |                            |
//                |           | Buffer next flight         |
//                |           |                            |
//                |          \|/                           |
//                |     +-----------+                      |
//                |     |  SENDING  |<------------------+  | Send
//                |     +-----------+                   |  | HelloRequest
//        Receive |           |                         |  |
//           next |           | Send flight             |  | or
//         flight |  +--------+                         |  |
//                |  |        | Set retransmit timer    |  | Receive
//                |  |       \|/                        |  | HelloRequest
//                |  |  +-----------+                   |  | Send
//                +--)--|  WAITING  |-------------------+  | ClientHello
//                |  |  +-----------+   Timer expires   |  |
//                |  |         |                        |  |
//                |  |         +------------------------+  |
//        Receive |  | Send           Read retransmit      |
//           last |  | last                                |
//         flight |  | flight                              |
//                |  |                                     |
//               \|/\|/                                    |
//            +-----------+                                |
//            | FINISHED  | -------------------------------+
//            +-----------+
//                 |  /|\
//                 |   |
//                 +---+
//              Read retransmit
//           Retransmit last flight

#[derive(Copy, Clone, PartialEq)]
pub(crate) enum HandshakeState {
    Errored,
    Preparing,
    Sending,
    Waiting,
    Finished,
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HandshakeState::Errored => write!(f, "Errored"),
            HandshakeState::Preparing => write!(f, "Preparing"),
            HandshakeState::Sending => write!(f, "Sending"),
            HandshakeState::Waiting => write!(f, "Waiting"),
            HandshakeState::Finished => write!(f, "Finished"),
        }
    }
}

pub(crate) fn srv_cli_str(is_client: bool) -> String {
    if is_client {
        return "client".to_owned();
    }
    "server".to_owned()
}

impl DTLSConn {
    /// Advances the handshake state machine as far as it can go now.
    ///
    /// A handshake that errors has given up: a flight failed to parse or generate (a fatal alert
    /// has been queued for the peer where one applies), or the retransmissions ran out. The
    /// association is then failed and stays failed (W3C webrtc 5.5.1 RTCDtlsTransport "failed").
    pub(crate) fn handshake(&mut self, now: Instant) -> Result<()> {
        self.state.clock = Some(now);
        if self.v13.is_some() {
            return self.drive_dtls13(now, false);
        }
        if self.failed {
            return Err(Error::ErrConnClosed);
        }
        // The handshake deadline counts from the first time the handshake is driven.
        self.handshake_started.get_or_insert(now);
        let peer_repeated_flight = std::mem::take(&mut self.peer_repeated_flight);
        let flight_before = self.current_flight.to_string();
        let mut result = self.handshake_steps(now);
        if result.is_ok()
            && peer_repeated_flight
            && self.current_handshake_state == HandshakeState::Waiting
            && self.current_flight.to_string() == flight_before
        {
            result = self.retransmit_for_repeated_flight(now);
        }
        if result.is_err() {
            self.fail();
        }
        result
    }

    /// Advances the DTLS 1.3 association to `now`: sets the timers that what has happened
    /// since armed, and with `timeout` acts on those that are due.
    pub(crate) fn drive_dtls13(&mut self, now: Instant, timeout: bool) -> Result<()> {
        let Some(v13) = &mut self.v13 else {
            return Ok(());
        };
        let result = if timeout {
            v13.handle_timeout(now)
        } else {
            v13.drive(now)
        };
        self.sync_dtls13();
        result
    }

    /// RFC 6347 4.2.4: the peer sent again a flight we had already processed, so the flight we
    /// answered it with was lost. Retransmit that flight now instead of when our timer fires;
    /// sending it restarts the timer. Only while still waiting for the peer's next flight, and
    /// out of the same retransmission budget the timer uses. A spent budget means no answer
    /// here: giving up stays the timer's decision.
    fn retransmit_for_repeated_flight(&mut self, now: Instant) -> Result<()> {
        if !self.retransmit || self.current_retransmit_count >= self.maximum_retransmit_number {
            return Ok(());
        }
        debug!(
            "[handshake:{}] {} peer repeated its flight, retransmitting",
            srv_cli_str(self.state.is_client),
            self.current_flight
        );
        self.current_retransmit_count += 1;
        self.current_handshake_state = HandshakeState::Sending;
        self.handshake_steps(now)
    }

    fn handshake_steps(&mut self, now: Instant) -> Result<()> {
        loop {
            debug!(
                "[handshake:{}] {}: {}",
                srv_cli_str(self.state.is_client),
                self.current_flight,
                self.current_handshake_state
            );

            if self.current_handshake_state == HandshakeState::Finished
                && !self.is_handshake_completed()
            {
                self.set_handshake_completed();
                let started = *self.handshake_started.get_or_insert(now);
                self.handshake_completed_after_ns =
                    u64::try_from(now.saturating_duration_since(started).as_nanos())
                        .unwrap_or(u64::MAX - 1);
                debug!(
                    "[handshake:{}] is completed",
                    srv_cli_str(self.state.is_client),
                );
                return Ok(());
            }

            let previous_handshake_state = self.current_handshake_state;
            self.current_handshake_state = match previous_handshake_state {
                HandshakeState::Preparing => self.prepare()?,
                HandshakeState::Sending => self.send(now)?,
                HandshakeState::Waiting => self.wait()?,
                HandshakeState::Finished => self.finish()?,
                _ => return Err(Error::ErrInvalidFsmTransition),
            };

            if previous_handshake_state == self.current_handshake_state
                && matches!(
                    previous_handshake_state,
                    HandshakeState::Waiting | HandshakeState::Finished
                )
            {
                // Wait for a timeout or an incoming packet. `Finished` self transitions for the same
                // reason `Waiting` does, and has to terminate for a stronger one: an association
                // re-entered here after completing (the RFC 6347 4.2.4 last flight retransmission)
                // has already passed the loop head guard, which only returns while
                // `!is_handshake_completed()`. `send()` queues the flight and yields `Finished`,
                // `finish()` yields `Finished` again, and without this the loop would spin.
                return Ok(());
            }
        }
    }

    fn prepare(&mut self) -> Result<HandshakeState> {
        self.flights = None;

        // Prepare flights
        self.current_retransmit_count = 0;
        self.early_data_retransmit_done = false;
        self.retransmit = self.current_flight.has_retransmit();

        let result =
            self.current_flight
                .generate(&mut self.state, &self.cache, &self.handshake_config);

        match result {
            Err((a, err)) => {
                if let Some(a) = a {
                    self.notify(a.alert_level, a.alert_description);
                }
                if let Some(err) = err {
                    return Err(err);
                }
            }
            Ok(pkts) => self.flights = Some(pkts),
        };

        let epoch = self.handshake_config.initial_epoch;
        let mut next_epoch = epoch;
        if let Some(pkts) = &mut self.flights {
            for p in pkts {
                p.record.record_layer_header.epoch += epoch;
                if p.record.record_layer_header.epoch > next_epoch {
                    next_epoch = p.record.record_layer_header.epoch;
                }
                if let Content::Handshake(h) = &mut p.record.content {
                    h.handshake_header.message_sequence = self.state.handshake_send_sequence as u16;
                    self.state.handshake_send_sequence += 1;
                }
            }
        }
        if epoch != next_epoch {
            debug!(
                "[handshake:{}] -> changeCipherSpec (epoch: {})",
                srv_cli_str(self.state.is_client),
                next_epoch
            );
            self.set_local_epoch(next_epoch);
        }

        Ok(HandshakeState::Sending)
    }
    fn send(&mut self, now: Instant) -> Result<HandshakeState> {
        // Send flights
        if let Some(pkts) = self.flights.clone() {
            self.write_packets(pkts);
        }

        // A Sending reached after the association has completed is an RFC 6347 4.2.4
        // retransmission of our own last flight (the peer repeated its final flight), so it returns
        // to Finished and never re-arms the receive timer. Only `Flight6` (the server) overrides
        // `is_last_send_flight`, so on its own that check would send the client — whose last flight
        // is `Flight5` — back into Waiting, where a failed `Flight5::parse` would strand a completed
        // association forever. Gating on completion keeps both roles terminal here.
        if self.current_flight.is_last_send_flight() || self.is_handshake_completed() {
            Ok(HandshakeState::Finished)
        } else {
            // RFC 6347 4.2.4.1: the timer's current value, which doubles at each expiry.
            self.current_retransmit_timer = Some(now + self.current_retransmit_interval);
            Ok(HandshakeState::Waiting)
        }
    }

    /// When the handshake is given up, if a limit is configured and it has started.
    pub(crate) fn handshake_deadline(&self) -> Option<Instant> {
        if self.is_handshake_completed() || self.failed {
            return None;
        }
        Some(self.handshake_started? + self.handshake_config.handshake_timeout?)
    }

    /// When this association next needs [`Self::handle_timeout`]: its retransmission timer or,
    /// if sooner, the handshake deadline.
    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        if let Some(v13) = &self.v13 {
            return v13.next_timeout();
        }
        match (self.current_retransmit_timer, self.handshake_deadline()) {
            (Some(timer), Some(deadline)) => Some(timer.min(deadline)),
            (timer, deadline) => timer.or(deadline),
        }
    }

    /// Advances the association's timers to `now`: gives the handshake up at its deadline,
    /// retransmits the current flight when the retransmission timer has expired.
    ///
    /// # Errors
    ///
    /// `ErrHandshakeTimeout` when the handshake did not complete in the configured time. The
    /// association has then failed.
    pub(crate) fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.v13.is_some() {
            return self.drive_dtls13(now, true);
        }
        if self
            .handshake_deadline()
            .is_some_and(|deadline| now >= deadline)
        {
            warn!(
                "[handshake:{}] {} did not complete in time",
                srv_cli_str(self.state.is_client),
                self.current_flight,
            );
            self.current_handshake_state = HandshakeState::Errored;
            self.fail();
            return Err(Error::ErrHandshakeTimeout);
        }
        if self
            .current_retransmit_timer
            .is_some_and(|timer| now >= timer)
        {
            self.current_retransmit_timer = None;
            if !self.is_handshake_completed() {
                self.handshake_timeout(now)?;
            }
        }
        Ok(())
    }
    fn wait(&mut self) -> Result<HandshakeState> {
        if self.handshake_rx.take().is_some() {
            debug!(
                "[handshake:{}] {} received handshake packets",
                srv_cli_str(self.state.is_client),
                self.current_flight
            );
            let result = self.current_flight.parse(
                /*&mut self.handle_queue_tx,*/ &mut self.state,
                &self.cache,
                &self.handshake_config,
            );
            match result {
                Err((alert, err)) => {
                    debug!(
                        "[handshake:{}] {} result alert:{:?}, err:{:?}",
                        srv_cli_str(self.state.is_client),
                        self.current_flight,
                        alert,
                        err
                    );

                    if let Some(alert) = alert {
                        self.notify(alert.alert_level, alert.alert_description);
                    }
                    if let Some(err) = err {
                        // A flight that failed (a fatal alert has been sent) stays failed: it is
                        // never parsed again, however many more handshake records arrive.
                        self.current_retransmit_timer = None;
                        self.current_handshake_state = HandshakeState::Errored;
                        return Err(err);
                    }
                }
                Ok(next_flight) => {
                    // A partial or repeated flight must not cancel retransmission.
                    // Only a complete next flight advances the handshake (RFC 6347 4.2.4).
                    self.current_retransmit_timer = None;
                    // RFC 6347 4.2.4.1: the backed-off timer value is kept until a flight gets
                    // through without loss, and this one did if it was never retransmitted.
                    if self.current_retransmit_count == 0 {
                        self.current_retransmit_interval =
                            self.handshake_config.retransmit_interval;
                    }
                    debug!(
                        "[handshake:{}] {} -> {}",
                        srv_cli_str(self.state.is_client),
                        self.current_flight,
                        next_flight
                    );
                    if next_flight.is_last_recv_flight()
                        && self.current_flight.to_string() == next_flight.to_string()
                    {
                        return Ok(HandshakeState::Finished);
                    }
                    if self.current_flight.verifies_cookie()
                        && !next_flight.verifies_cookie()
                        && let Err(err) = self.on_peer_address_verified()
                    {
                        self.notify(AlertLevel::Fatal, AlertDescription::IllegalParameter);
                        return Err(err);
                    }
                    self.current_flight = next_flight;
                    return Ok(HandshakeState::Preparing);
                }
            }
        }

        Ok(HandshakeState::Waiting)
    }

    /// The client has echoed our cookie, so the address it sends from is its own (RFC 6347
    /// 4.2.1). Only now does a server do the per-association work a spoofed source address
    /// must not be able to cause: its ECDHE key pair.
    fn on_peer_address_verified(&mut self) -> Result<()> {
        self.address_verified = true;
        if self.state.local_keypair.is_none() {
            let keypair = self
                .state
                .named_curve
                .generate_keypair_with_crypto(self.handshake_config.provider().crypto())?;
            self.state.local_keypair = Some(keypair);
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<HandshakeState> {
        if self.handshake_rx.take().is_some() {
            debug!(
                "[handshake:{}] {} received handshake packets",
                srv_cli_str(self.state.is_client),
                self.current_flight
            );
            self.current_retransmit_timer = None;
            let result = self.current_flight.parse(
                /*&mut self.handle_queue_tx,*/ &mut self.state,
                &self.cache,
                &self.handshake_config,
            );
            if let Err((alert, err)) = result {
                if let Some(alert) = alert {
                    self.notify(alert.alert_level, alert.alert_description);
                }
                if let Some(err) = err {
                    return Err(err);
                }
            };
        }

        Ok(HandshakeState::Finished)
    }

    /// When the handshake completed, if it has.
    pub(crate) fn handshake_completed_at(&self) -> Option<Instant> {
        if self.handshake_completed_after_ns == u64::MAX {
            return None;
        }
        self.handshake_started.map(|started| {
            started + std::time::Duration::from_nanos(self.handshake_completed_after_ns)
        })
    }

    pub(crate) fn handshake_timeout(&mut self, now: Instant) -> Result<()> {
        self.state.clock = Some(now);
        let next_handshake_state = if self.current_handshake_state == HandshakeState::Waiting {
            debug!(
                "[handshake:{}] {} retransmit_timer",
                srv_cli_str(self.state.is_client),
                self.current_flight
            );
            debug!(
                "[handshake:{}] {} current_retransmit_count {} vs maximum_retransmit_number {}",
                srv_cli_str(self.state.is_client),
                self.current_flight,
                self.current_retransmit_count,
                self.maximum_retransmit_number,
            );
            if self.retransmit {
                // RFC 6347 4.2.4.1: retransmit, and double the timer up to its maximum. There
                // is no count of retransmissions to run out of: the handshake deadline
                // (`handle_timeout`) is what gives a handshake up.
                self.current_retransmit_count += 1;
                self.current_retransmit_interval = (self.current_retransmit_interval * 2)
                    .min(self.handshake_config.maximum_retransmit_interval)
                    .max(self.handshake_config.retransmit_interval);
                // RFC 6347 4.1.1.1: when retransmissions go unanswered the records may be too
                // large for the path, so they are cut smaller.
                if self.current_retransmit_count > RETRANSMITS_BEFORE_MTU_BACKOFF {
                    self.handshake_mtu = (self.handshake_mtu / 2)
                        .max(FALLBACK_HANDSHAKE_MTU)
                        .min(self.handshake_mtu);
                }
                Some(HandshakeState::Sending)
            } else {
                self.current_retransmit_timer =
                    Some(now + self.handshake_config.retransmit_interval);
                Some(HandshakeState::Waiting)
            }
        } else if self.current_handshake_state == HandshakeState::Finished {
            // RFC 6347 4.2.4: "for at least twice the default MSL defined for [TCP], when in
            // the FINISHED state, the node that transmits the last flight [...] MUST respond to
            // a retransmit of the peer's last flight with a retransmit of the last flight". So
            // every repeat within FINAL_FLIGHT_ANSWER_PERIOD (240 s) of completing is answered,
            // however many there are, and none after it: the association is established, so
            // this never takes it to Errored the way the Waiting branch does.
            //
            // The bound against amplification is one answer per repeat, never more: the caller
            // comes here only for a datagram that carried an authenticated (epoch 1) handshake
            // record of the peer (`received_handshake_in_last_datagram`), and the replay window
            // drops a copy of one already read, so every answer is to a record only the peer
            // could have made, fresh. Plaintext (epoch 0) handshake records are never answered.
            // The RFC asks for "at least" 240 s and sets no end; ending there is what DTLS 1.3
            // does when it lets go of its handshake keys (RFC 9147 5.8.1).
            let elapsed = self
                .handshake_completed_at()
                .map(|at| now.saturating_duration_since(at));
            if elapsed.is_some_and(|elapsed| elapsed <= FINAL_FLIGHT_ANSWER_PERIOD) {
                Some(HandshakeState::Sending)
            } else {
                debug!(
                    "[handshake:{}] {} peer repeated its last flight {:?} after the handshake, past {:?}: not answered",
                    srv_cli_str(self.state.is_client),
                    self.current_flight,
                    elapsed,
                    FINAL_FLIGHT_ANSWER_PERIOD,
                );
                None
            }
        } else {
            None
        };

        if let Some(next_handshake_state) = next_handshake_state {
            self.current_handshake_state = next_handshake_state;
            self.handshake(now)
        } else {
            Ok(())
        }
    }
}
