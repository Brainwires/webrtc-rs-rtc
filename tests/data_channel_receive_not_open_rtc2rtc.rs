//! W3C webrtc-pc 6.2.8 (receiving a message): "If channel.[[ReadyState]] is not "open",
//! abort these steps and discard rawData." A message that reaches a channel this side has
//! closed, before the peer has heard of the close, is not handed to the application.

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

/// The answerer closes channel `m` (it is "closing": its stream reset is lost on the way), and
/// the offerer, which still has it open, sends on it and on a sibling channel. The sibling's
/// message arrives; `m`'s does not reach the application, then or after the close completes.
#[test]
fn a_message_on_a_closing_channel_is_discarded() -> Result<()> {
    let (mut p, _first) = Pair::connected(RTCDtlsRole::Client, "first")?;
    let (l_offerer, l_answerer) = open(&mut p, "l")?;
    let (m_offerer, m_answerer) = open(&mut p, "m")?;
    p.answerer.tolerate_read_errors = true;

    p.answerer
        .pc
        .data_channel(m_answerer)
        .expect("m on the answerer")
        .close()?;
    p.answerer.drop_outgoing = true;
    p.run_for(Duration::from_millis(1))?;
    p.answerer.drop_outgoing = false;
    ensure!(
        !p.offerer.closed(m_offerer),
        "the offerer must not know of the close yet"
    );
    let state = p
        .answerer
        .pc
        .data_channel(m_answerer)
        .map(|dc| dc.ready_state());
    ensure!(
        state.is_none_or(|s| s != RTCDataChannelState::Open),
        "m is no longer open on the answerer: {state:?}"
    );

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
    let got = |p: &Pair, id: RTCDataChannelId| {
        p.answerer
            .received
            .iter()
            .filter(|(channel, _, _)| *channel == id)
            .map(|(_, _, data)| data.clone())
            .collect::<Vec<_>>()
    };
    ensure!(
        p.run_until(|p| !got(p, l_answerer).is_empty())?,
        "the sibling's message never arrived"
    );
    p.run_until(|p| p.answerer.closed(m_answerer) && p.offerer.closed(m_offerer))?;
    p.run_for(Duration::from_secs(1))?;
    assert_eq!(got(&p, l_answerer), vec![b"alive".to_vec()]);
    assert!(
        got(&p, m_answerer).is_empty(),
        "a message reached the application on a channel that was not open: {:?}",
        got(&p, m_answerer)
    );
    Ok(())
}
