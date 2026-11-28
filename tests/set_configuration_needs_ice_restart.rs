//! RFC 9429 section 4.1.18: "Any changes to the STUN/TURN servers to use affect the next
//! gathering phase. If an ICE gathering phase has already started or completed, the
//! 'needs-ice-restart' bit mentioned in Section 3.5.1 will be set. This will cause the next
//! call to createOffer to generate new ICE credentials" (and the same for a change of the ICE
//! candidate policy). The bit is W3C's [[LocalIceCredentialsToReplace]], which `restartIce`
//! sets: the negotiation-needed flag is updated, so the application sees
//! `negotiationneeded`, and the next offer restarts ICE. libwebrtc does the same
//! (`PeerConnection::SetConfiguration`). W3C's own "set the configuration" text leaves the
//! restart to the script; JSEP is followed (the project's rule: the RFC text by default).

use anyhow::Result;
use rtci::peer_connection::configuration::{
    RTCConfiguration, RTCConfigurationBuilder, RTCIceServer, RTCIceTransportPolicy,
};
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::sansio::Protocol;
use std::time::Instant;

mod common;

fn config(url: &str) -> RTCConfiguration {
    RTCConfigurationBuilder::new()
        .with_ice_servers(vec![RTCIceServer {
            urls: vec![url.to_owned()],
            ..Default::default()
        }])
        .build()
}

fn ufrag(sdp: &str) -> String {
    sdp.lines()
        .find_map(|l| l.strip_prefix("a=ice-ufrag:"))
        .expect("an ice-ufrag")
        .to_owned()
}

/// A connection with an applied offer / answer, its events drained.
fn negotiated() -> Result<RTCPeerConnection> {
    common::install_crypto_provider();
    let now = Instant::now();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(config("stun:192.0.2.30:3478"))
        .build(now)?;
    pc.create_data_channel("d", None)?;
    let offer = pc.create_offer(None)?;
    pc.set_local_description(now, offer.clone())?;
    let mut answerer = RTCPeerConnectionBuilder::new().build(now)?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    pc.set_remote_description(now, answer)?;
    while pc.poll_event().is_some() {}
    Ok(pc)
}

fn negotiation_needed(pc: &mut RTCPeerConnection) -> bool {
    let mut needed = false;
    while let Some(e) = pc.poll_event() {
        needed |= matches!(e, RTCPeerConnectionEvent::OnNegotiationNeededEvent);
    }
    needed
}

#[test]
fn new_servers_after_gathering_make_the_next_offer_restart_ice() -> Result<()> {
    let mut pc = negotiated()?;
    let before = ufrag(&pc.local_description().expect("applied").sdp);
    pc.set_configuration(config("stun:192.0.2.31:3478"))?;
    assert!(negotiation_needed(&mut pc), "negotiationneeded");
    let offer = pc.create_offer(None)?;
    assert_ne!(ufrag(&offer.sdp), before, "the offer restarts ICE");
    Ok(())
}

#[test]
fn a_new_candidate_policy_after_gathering_makes_the_next_offer_restart_ice() -> Result<()> {
    let mut pc = negotiated()?;
    let before = ufrag(&pc.local_description().expect("applied").sdp);
    pc.set_configuration(
        RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec!["stun:192.0.2.30:3478".to_owned()],
                ..Default::default()
            }])
            .with_ice_transport_policy(RTCIceTransportPolicy::Relay)
            .build(),
    )?;
    assert!(negotiation_needed(&mut pc), "negotiationneeded");
    let offer = pc.create_offer(None)?;
    assert_ne!(ufrag(&offer.sdp), before, "the offer restarts ICE");
    Ok(())
}

#[test]
fn the_same_servers_change_nothing() -> Result<()> {
    let mut pc = negotiated()?;
    let before = ufrag(&pc.local_description().expect("applied").sdp);
    pc.set_configuration(config("stun:192.0.2.30:3478"))?;
    assert!(!negotiation_needed(&mut pc), "no negotiationneeded");
    let offer = pc.create_offer(None)?;
    assert_eq!(ufrag(&offer.sdp), before, "no restart");
    Ok(())
}
