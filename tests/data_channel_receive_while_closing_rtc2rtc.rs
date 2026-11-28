//! W3C webrtc-pc 6.2.8 (receiving a message): "If channel.[[ReadyState]] is not "open", abort
//! these steps and discard rawData."
//!
//! Which states that are not "open" can receive user data at all. "connecting": an in-band
//! channel's user data ahead of the DATA_CHANNEL_ACK completes its handshake first (RFC 8832
//! section 6: "the DATA_CHANNEL_ACK or any other message"), so the channel is open when the
//! data is handed on; the peer's own channel is open from its DATA_CHANNEL_OPEN. "closed": once
//! this side's close has reached the SCTP stream, the stream stops reading and abandons what
//! still arrives (rtci-sctp `Stream::stop`), and the handler drops anything for a closed
//! channel. "closing" after the peer's close: the peer resets its stream after its data, so
//! that data arrives while the channel is open. What remains is "closing" after this side's
//! `close()`: the close is queued behind what the application sent (`write_data_channel_close`)
//! and reaches the SCTP stream only when the writes are flushed, so a datagram read before
//! then carries user data for a channel that is "closing", on a stream that still reads. That
//! is the case here.

mod dc_common;

use anyhow::{Result, ensure};
use dc_common::Pair;
use rtci::data_channel::{RTCDataChannelId, RTCDataChannelState};
use rtci::peer_connection::transport::RTCDtlsRole;
use std::time::Duration;

/// Opens `label` from the offerer and returns its handle there and the answerer's handle.
fn open(p: &mut Pair, label: &str) -> Result<(RTCDataChannelId, RTCDataChannelId)> {
    let offerer = p.offerer.pc.create_data_channel(label, None)?.id();
    let before = p.answerer.opened().len();
    ensure!(
        p.run_until(
            |p| p.offerer.opened().contains(&offerer) && p.answerer.opened().len() > before
        )?,
        "{label} never opened"
    );
    let answerer = *p.answerer.opened().last().expect("opened");
    Ok((offerer, answerer))
}

/// The offerer sends a message on channel `m` and one on its sibling `l`; before the
/// datagrams carrying them arrive, the answerer calls `close()` on `m`, which is then
/// "closing". Both messages are read in the same turn: `l`'s reaches the application, `m`'s
/// does not, then or after the close completes.
#[test]
fn a_message_read_after_close_is_called_is_discarded() -> Result<()> {
    let (mut p, _first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let (l_offerer, l_answerer) = open(&mut p, "l")?;
    let (m_offerer, m_answerer) = open(&mut p, "m")?;
    // Both channels work before.
    ensure!(p.deliver(false, m_offerer, b"before")?, "m carries data");
    ensure!(p.deliver(false, l_offerer, b"before")?, "l carries data");
    let got = |p: &Pair, id: RTCDataChannelId| {
        p.answerer
            .received
            .iter()
            .filter(|(channel, _, _)| *channel == id)
            .map(|(_, _, data)| data.clone())
            .collect::<Vec<_>>()
    };
    ensure!(got(&p, m_answerer) == vec![b"before".to_vec()]);

    let now = p.now;
    p.offerer
        .pc
        .data_channel(m_offerer)
        .expect("m on the offerer")
        .send_text(now, "late")?;
    p.offerer
        .pc
        .data_channel(l_offerer)
        .expect("l on the offerer")
        .send_text(now, "alive")?;
    // Nothing has run since: the offerer has not written the messages yet.
    let mut m = p
        .answerer
        .pc
        .data_channel(m_answerer)
        .expect("m on the answerer");
    m.close()?;
    ensure!(
        m.ready_state() == RTCDataChannelState::Closing,
        "close() makes the channel closing: {:?}",
        m.ready_state()
    );

    ensure!(
        p.run_until(|p| got(p, l_answerer).len() == 2)?,
        "the sibling's message never arrived"
    );
    p.run_until(|p| p.answerer.closed(m_answerer) && p.offerer.closed(m_offerer))?;
    p.run_for(Duration::from_secs(1))?;
    assert_eq!(
        got(&p, l_answerer),
        vec![b"before".to_vec(), b"alive".to_vec()]
    );
    assert_eq!(
        got(&p, m_answerer),
        vec![b"before".to_vec()],
        "a message reached the application on a channel that was closing"
    );
    Ok(())
}
