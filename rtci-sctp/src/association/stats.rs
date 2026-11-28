/// Association statistics
#[derive(Default, Debug, Copy, Clone)]
pub struct AssociationStats {
    n_datas: u64,
    n_sacks: u64,
    n_t3timeouts: u64,
    n_ack_timeouts: u64,
    n_fast_retrans: u64,
    n_retransmissions: u64,
    n_partially_reliable_retransmissions: u64,
    n_abandoned_messages: u64,
    n_forward_tsns: u64,
    n_fast_retrans_abandoned: u64,
    t3_wait_ms: u64,
    n_sack_losses: u64,
}

impl AssociationStats {
    /// Counts one DATA chunk received.
    pub fn inc_datas(&mut self) {
        self.n_datas += 1;
    }

    /// The number of DATA chunks received.
    pub fn get_num_datas(&mut self) -> u64 {
        self.n_datas
    }

    /// Counts one SACK chunk received.
    pub fn inc_sacks(&mut self) {
        self.n_sacks += 1;
    }

    /// The number of SACK chunks received.
    pub fn get_num_sacks(&mut self) -> u64 {
        self.n_sacks
    }

    /// Counts one T3-rtx retransmission timeout.
    pub fn inc_t3timeouts(&mut self) {
        self.n_t3timeouts += 1;
    }

    /// The number of T3-rtx retransmission timeouts, a signal of loss or a stalled path.
    pub fn get_num_t3timeouts(&mut self) -> u64 {
        self.n_t3timeouts
    }

    /// Counts one delayed-acknowledgement timeout.
    pub fn inc_ack_timeouts(&mut self) {
        self.n_ack_timeouts += 1;
    }

    /// The number of delayed-acknowledgement timeouts.
    pub fn get_num_ack_timeouts(&mut self) -> u64 {
        self.n_ack_timeouts
    }

    /// Counts one fast retransmission.
    pub fn inc_fast_retrans(&mut self) {
        self.n_fast_retrans += 1;
    }

    /// The number of fast retransmissions, triggered by SACK gap reports rather than a timeout.
    pub fn get_num_fast_retrans(&mut self) -> u64 {
        self.n_fast_retrans
    }

    /// Counts one DATA chunk sent again (by T3-rtx, Fast Retransmit or with a repeated COOKIE
    /// ACK).
    pub fn inc_retransmissions(&mut self) {
        self.n_retransmissions += 1;
    }

    /// The number of DATA chunks sent again, whatever made them go again.
    pub fn get_num_retransmissions(&mut self) -> u64 {
        self.n_retransmissions
    }

    /// Counts one DATA chunk of a partially reliable message (RFC 3758: a lifetime or a
    /// retransmission limit, RFC 7496) sent again.
    pub fn inc_partially_reliable_retransmissions(&mut self) {
        self.n_partially_reliable_retransmissions += 1;
    }

    /// Of [`Self::get_num_retransmissions`], the DATA chunks of partially reliable messages
    /// (RFC 3758, RFC 7496: sent with a lifetime or a retransmission limit) sent again; the rest
    /// are reliable messages (on a WebRTC association, the DCEP messages, RFC 8832 section 5,
    /// beside the reliable channels). With a limit of zero retransmissions (RFC 8831 section
    /// 6.6, `maxRetransmits` 0) and the peer's support for partial reliability, a message's
    /// chunks are never counted here. Without that support (RFC 3758 3.3) partially reliable
    /// messages are retransmitted as reliable ones, and counted here.
    pub fn get_num_partially_reliable_retransmissions(&mut self) -> u64 {
        self.n_partially_reliable_retransmissions
    }

    /// Counts one message abandoned (RFC 3758 3.5 A2): sent in part or whole and never to be
    /// sent again, or dropped before it was sent.
    pub fn inc_abandoned_messages(&mut self) {
        self.n_abandoned_messages += 1;
    }

    /// The number of messages abandoned under their partial reliability policy.
    pub fn get_num_abandoned_messages(&mut self) -> u64 {
        self.n_abandoned_messages
    }

    /// Counts one FORWARD TSN (or I-FORWARD TSN) chunk sent.
    pub fn inc_forward_tsns(&mut self) {
        self.n_forward_tsns += 1;
    }

    /// The number of FORWARD TSN (or I-FORWARD TSN) chunks sent (RFC 3758 3.5 C3, A5).
    pub fn get_num_forward_tsns(&mut self) -> u64 {
        self.n_forward_tsns
    }

    /// Counts one chunk that Fast Retransmit would have sent again and abandoned instead: its
    /// message's retransmission budget was spent (RFC 3758 3.5 A2, RFC 7496).
    pub fn inc_fast_retrans_abandoned(&mut self) {
        self.n_fast_retrans_abandoned += 1;
    }

    /// The number of losses Fast Retransmit found in partially reliable messages whose budget
    /// was spent, so that they were abandoned (and skipped by FORWARD TSN) without waiting for
    /// T3-rtx.
    pub fn get_num_fast_retrans_abandoned(&mut self) -> u64 {
        self.n_fast_retrans_abandoned
    }

    /// Adds the RTO, in milliseconds, that a T3-rtx expiry waited out.
    pub fn add_t3_wait(&mut self, rto_ms: u64) {
        self.t3_wait_ms = self.t3_wait_ms.saturating_add(rto_ms);
    }

    /// The sum of the RTOs the T3-rtx expiries waited out (each the RTO in force when the
    /// timer expired, before the back-off of RFC 9260 6.3.3 E2): how much of a transfer's time
    /// the retransmission timer accounts for.
    pub fn get_t3_wait(&mut self) -> std::time::Duration {
        std::time::Duration::from_millis(self.t3_wait_ms)
    }

    /// Counts one SACK loss found from a Duplicate TSN report (RFC 9260 6.2).
    pub fn inc_sack_losses(&mut self) {
        self.n_sack_losses += 1;
    }

    /// The SACKs found lost (RFC 9260 6.2: the sender "MAY use the duplicate TSN information
    /// to determine if SACK chunk loss is occurring"): DATA this side sent again on a
    /// retransmission timeout that the peer then reported as a duplicate, which it had
    /// received before, so the SACK that acknowledged it did not arrive in time.
    pub fn get_num_sack_losses(&mut self) -> u64 {
        self.n_sack_losses
    }

    /// Zeroes every counter.
    pub fn reset(&mut self) {
        self.n_datas = 0;
        self.n_sacks = 0;
        self.n_t3timeouts = 0;
        self.n_ack_timeouts = 0;
        self.n_fast_retrans = 0;
        self.n_retransmissions = 0;
        self.n_partially_reliable_retransmissions = 0;
        self.n_abandoned_messages = 0;
        self.n_forward_tsns = 0;
        self.n_fast_retrans_abandoned = 0;
        self.t3_wait_ms = 0;
        self.n_sack_losses = 0;
    }
}
