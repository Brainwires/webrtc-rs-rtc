//! WebRTC peer connection event types.
//!
//! This module defines all events that can be emitted by an `RTCPeerConnection`
//! according to the WebRTC specification. These events notify applications about
//! state changes, incoming media tracks, data channels, ICE candidates, and errors.
//!
//! # Sans-I/O Event Pattern
//!
//! This crate uses a sans-I/O design where events are polled from the peer connection
//! rather than delivered via callbacks. Applications drive the event loop by calling
//! `poll_event()` and handling the returned events.
//!
//! # Examples
//!
//! ## Basic event loop pattern
//!
//! `poll_event()`, `poll_timeout()` and `handle_timeout()` come from the
//! [`sansio::Protocol`] implementation on [`RTCPeerConnection`](crate::peer_connection::RTCPeerConnection),
//! so that trait must be in
//! scope to call them.
//!
//! ```no_run
//! use rtci::peer_connection::RTCPeerConnectionBuilder;
//! use rtci::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtci::peer_connection::event::RTCPeerConnectionEvent;
//! use rtci::sansio::Protocol;
//! use std::time::Instant;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RTCConfigurationBuilder::new().build();
//! let mut peer_connection = RTCPeerConnectionBuilder::new()
//!     .with_configuration(config)
//!     .build(Instant::now())?;
//!
//! loop {
//!     // Poll and handle events
//!     while let Some(event) = peer_connection.poll_event() {
//!         match event {
//!             RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
//!                 println!("New ICE candidate");
//!                 // Send candidate to remote peer via signaling
//!             }
//!             RTCPeerConnectionEvent::OnTrack(_track_event) => {
//!                 println!("New track received");
//!             }
//!             _ => {}
//!         }
//!     }
//!
//!     // Handle timeouts
//!     if let Some(timeout) = peer_connection.poll_timeout() {
//!         if timeout <= Instant::now() {
//!             peer_connection.handle_timeout(Instant::now())?;
//!         }
//!     }
//!     
//!     break; // Exit for example
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Handling connection state changes
//!
//! ```
//! use rtci::peer_connection::event::RTCPeerConnectionEvent;
//! use rtci::peer_connection::state::RTCPeerConnectionState;
//!
//! # fn handle_events(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
//!         match state {
//!             RTCPeerConnectionState::Connected => {
//!                 println!("Peer connection established!");
//!             }
//!             RTCPeerConnectionState::Failed => {
//!                 println!("Connection failed - cleanup required");
//!             }
//!             RTCPeerConnectionState::Disconnected => {
//!                 println!("Connection lost - may reconnect");
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Handling data channels
//!
//! ```
//! use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCDataChannelEvent};
//!
//! # fn handle_events(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
//!         match dc_event {
//!             RTCDataChannelEvent::OnOpen(channel_id) => {
//!                 println!("Data channel opened: {:?}", channel_id);
//!             }
//!             RTCDataChannelEvent::OnClose(channel_id) => {
//!                 println!("Data channel closed: {:?}", channel_id);
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## Handling incoming tracks
//!
//! ```
//! use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
//!
//! # fn handle_events(event: RTCPeerConnectionEvent) {
//! match event {
//!     RTCPeerConnectionEvent::OnTrack(track_event) => {
//!         match track_event {
//!             RTCTrackEvent::OnOpen(init) => {
//!                 println!("Track opened with receiver: {:?}", init.receiver_id);
//!             }
//!             _ => {}
//!         }
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! # Event Types
//!
//! - **Negotiation**: [`OnNegotiationNeededEvent`](RTCPeerConnectionEvent::OnNegotiationNeededEvent) - Signals need for renegotiation
//! - **ICE**: [`OnIceCandidateEvent`](RTCPeerConnectionEvent::OnIceCandidateEvent) - New ICE candidate available
//! - **ICE Error**: [`OnIceCandidateErrorEvent`](RTCPeerConnectionEvent::OnIceCandidateErrorEvent) - ICE gathering error
//! - **State Changes**: Various state change events for signaling, ICE, and connection
//! - **Media**: [`OnTrack`](RTCPeerConnectionEvent::OnTrack) - Incoming media track
//! - **Data**: [`OnDataChannel`](RTCPeerConnectionEvent::OnDataChannel) - Incoming data channel
//!
//! # See Also
//!
//! - [W3C WebRTC Events](https://www.w3.org/TR/webrtc/#rtcpeerconnection-interface)
//! - [`RTCPeerConnection`](crate::peer_connection::RTCPeerConnection)

use crate::peer_connection::rtc_error::RTCError;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::candidate_pair::RTCIceCandidatePair;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;
use srtp::context::Context;
use std::time::Instant;

pub(crate) mod data_channel_event;
pub(crate) mod ice_error_event;
pub(crate) mod ice_event;
pub(crate) mod key_frame_request_event;
pub(crate) mod track_event;
pub(crate) mod transport_event;

pub use crate::peer_connection::states_events::ICE_SERVER_UNREACHABLE;
pub use data_channel_event::RTCDataChannelEvent;
pub use ice_error_event::RTCPeerConnectionIceErrorEvent;
pub use ice_event::RTCPeerConnectionIceEvent;
pub use key_frame_request_event::{RTCKeyFrameRequestEvent, RTCKeyFrameRequestOrigin};
pub use track_event::{
    RTCRemoteStreamsChange, RTCRemoteTrackEventInit, RTCTrackEvent, RTCTrackEventInit,
};
pub use transport_event::{
    RTCLocalCandidatesNeededEvent, RTCLocalCandidatesNeededReason, RTCTransportEvent,
    RTCTransportEventKind,
};

/// Events that can be emitted by an `RTCPeerConnection`.
///
/// This enum represents all the events defined in the WebRTC specification that
/// can occur during the lifecycle of a peer connection. Applications should handle
/// these events to respond to state changes, receive tracks, handle ICE candidates,
/// and manage the connection lifecycle.
///
/// # Event Categories
///
/// ## Negotiation Events
/// - [`OnNegotiationNeededEvent`](Self::OnNegotiationNeededEvent) - Triggered when SDP renegotiation is needed
///
/// ## ICE Events
/// - [`OnIceCandidateEvent`](Self::OnIceCandidateEvent) - New ICE candidate discovered
/// - [`OnIceCandidateErrorEvent`](Self::OnIceCandidateErrorEvent) - Error during ICE gathering
/// - [`OnIceConnectionStateChangeEvent`](Self::OnIceConnectionStateChangeEvent) - ICE connection state changed
/// - [`OnIceGatheringStateChangeEvent`](Self::OnIceGatheringStateChangeEvent) - ICE gathering state changed
///
/// ## State Change Events
/// - [`OnSignalingStateChangeEvent`](Self::OnSignalingStateChangeEvent) - Offer/answer state changed
/// - [`OnConnectionStateChangeEvent`](Self::OnConnectionStateChangeEvent) - Overall connection state changed
///
/// ## Media & Data Events
/// - [`OnTrack`](Self::OnTrack) - New incoming media track
/// - [`OnDataChannel`](Self::OnDataChannel) - New incoming data channel
///
/// # Examples
///
/// ## Pattern matching on events
///
/// ```
/// use rtci::peer_connection::event::RTCPeerConnectionEvent;
/// use rtci::peer_connection::state::RTCPeerConnectionState;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
///         match state {
///             RTCPeerConnectionState::Connected => {
///                 println!("Peer connection established!");
///             }
///             RTCPeerConnectionState::Failed => {
///                 println!("Connection failed");
///             }
///             _ => {}
///         }
///     }
///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
///         // Send candidate to remote peer
///         println!("ICE candidate: {:?}", ice_event.candidate);
///     }
///     RTCPeerConnectionEvent::OnTrack(track_event) => {
///         println!("New track received");
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specification
///
/// See [RTCPeerConnection Events](https://www.w3.org/TR/webrtc/#rtcpeerconnection-interface)
#[allow(clippy::enum_variant_names)]
#[derive(Default, Clone, Debug)]
#[non_exhaustive]
pub enum RTCPeerConnectionEvent {
    /// Fired when negotiation is needed to maintain the connection.
    ///
    /// This event indicates that renegotiation is needed, usually because:
    /// - Media tracks have been added or removed
    /// - Transceiver direction has changed
    /// - Data channels have been created
    ///
    /// When this event fires, the application should create a new offer
    /// by calling `create_offer()`, set it as the local description, and
    /// send it to the remote peer.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn example(event: RTCPeerConnectionEvent) {
    /// if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
    ///     println!("Negotiation needed - create new offer");
    ///     // Call peer_connection.create_offer()
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [negotiationneeded](https://www.w3.org/TR/webrtc/#event-negotiation)
    #[default]
    OnNegotiationNeededEvent,

    /// Fired when a new ICE candidate is available.
    ///
    /// This event provides an ICE candidate that should be sent to the remote peer
    /// over the signaling channel. The remote peer will use this candidate to
    /// establish connectivity.
    ///
    /// Candidates are generated during the ICE gathering process after
    /// `setLocalDescription` is called.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
    ///         // Send ice_event to remote peer via signaling
    ///         if let Some(candidate) = ice_event.candidate {
    ///             println!("Send ICE candidate: {}", candidate.address);
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [icecandidate](https://www.w3.org/TR/webrtc/#event-icecandidate)
    OnIceCandidateEvent(RTCPeerConnectionIceEvent),

    /// Fired when an error occurs during ICE candidate gathering.
    ///
    /// This event provides details about errors encountered while gathering
    /// ICE candidates, such as STUN/TURN server failures or network issues.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceCandidateErrorEvent(error) => {
    ///         eprintln!("ICE error: {} - {}", error.error_code, error.error_text);
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [icecandidateerror](https://www.w3.org/TR/webrtc/#event-icecandidateerror)
    OnIceCandidateErrorEvent(RTCPeerConnectionIceErrorEvent),

    /// Fired when the signaling state changes.
    ///
    /// The signaling state describes where the peer connection is in the
    /// offer/answer negotiation process (stable, have-local-offer, etc.).
    ///
    /// # State Transitions
    ///
    /// - `Stable` → `HaveLocalOffer` (after creating offer)
    /// - `Stable` → `HaveRemoteOffer` (after receiving offer)
    /// - `HaveLocalOffer` → `Stable` (after receiving answer)
    /// - `HaveRemoteOffer` → `Stable` (after creating answer)
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
    ///         println!("Signaling state: {:?}", state);
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [signalingstatechange](https://www.w3.org/TR/webrtc/#event-signalingstatechange)
    OnSignalingStateChangeEvent(RTCSignalingState),

    /// Fired when the ICE connection state changes.
    ///
    /// This indicates the state of the ICE connection: new, checking, connected,
    /// completed, failed, disconnected, or closed.
    ///
    /// # Important States
    ///
    /// - `Connected` - ICE has successfully connected
    /// - `Completed` - ICE has finished gathering and checking
    /// - `Failed` - ICE has failed to connect
    /// - `Disconnected` - ICE connection lost (may recover)
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # use rtci::peer_connection::state::RTCIceConnectionState;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
    ///         match state {
    ///             RTCIceConnectionState::Connected => println!("ICE connected!"),
    ///             RTCIceConnectionState::Failed => println!("ICE failed"),
    ///             RTCIceConnectionState::Disconnected => println!("ICE disconnected"),
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [iceconnectionstatechange](https://www.w3.org/TR/webrtc/#event-iceconnectionstatechange)
    OnIceConnectionStateChangeEvent(RTCIceConnectionState),

    /// Fired when the ICE gathering state changes.
    ///
    /// This indicates whether ICE is gathering candidates, has completed
    /// gathering, or is in the initial state.
    ///
    /// # States
    ///
    /// - `New` - ICE gathering has not started
    /// - `Gathering` - ICE agent is gathering candidates
    /// - `Complete` - ICE gathering has finished
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # use rtci::peer_connection::state::RTCIceGatheringState;
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(state) => {
    ///         if state == RTCIceGatheringState::Complete {
    ///             println!("ICE gathering complete");
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [icegatheringstatechange](https://www.w3.org/TR/webrtc/#event-icegatheringstatechange)
    OnIceGatheringStateChangeEvent(RTCIceGatheringState),

    /// Fired when the peer connection state changes.
    ///
    /// This represents the overall connection state and is the recommended
    /// event to monitor for connection health. It aggregates ICE and DTLS states.
    ///
    /// # States
    ///
    /// - `New` - Initial state
    /// - `Connecting` - Establishing connection
    /// - `Connected` - Connection established and ready
    /// - `Disconnected` - Connection lost (may recover)
    /// - `Failed` - Connection failed permanently
    /// - `Closed` - Connection has been closed
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::RTCPeerConnectionEvent;
    /// # use rtci::peer_connection::state::RTCPeerConnectionState;
    /// # fn handle_event(event: RTCPeerConnectionEvent) -> bool {
    /// match event {
    ///     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
    ///         match state {
    ///             RTCPeerConnectionState::Connected => {
    ///                 println!("Peer connection ready!");
    ///             }
    ///             RTCPeerConnectionState::Failed => {
    ///                 println!("Connection failed - cleanup");
    ///                 return false; // Exit event loop
    ///             }
    ///             RTCPeerConnectionState::Disconnected => {
    ///                 println!("Connection lost - may reconnect");
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # true
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [connectionstatechange](https://www.w3.org/TR/webrtc/#event-connectionstatechange)
    OnConnectionStateChangeEvent(RTCPeerConnectionState),

    /// Fired when a new data channel is received from the remote peer.
    ///
    /// This event is triggered when the remote peer creates a data channel.
    /// The application should handle the data channel events (OnOpen, OnMessage, etc.)
    /// by polling and matching on the channel ID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCDataChannelEvent};
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnDataChannel(dc_event) => {
    ///         match dc_event {
    ///             RTCDataChannelEvent::OnOpen(channel_id) => {
    ///                 println!("New data channel: {:?}", channel_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [datachannel](https://www.w3.org/TR/webrtc/#event-datachannel)
    OnDataChannel(RTCDataChannelEvent),

    /// Fired when a new media track is received from the remote peer.
    ///
    /// This event provides access to the incoming media stream. The event includes
    /// the track ID, receiver ID, transceiver ID, and associated stream IDs.
    /// Use these IDs to access the actual objects via the peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtci::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
    /// # fn handle_event(event: RTCPeerConnectionEvent) {
    /// match event {
    ///     RTCPeerConnectionEvent::OnTrack(track_event) => {
    ///         match track_event {
    ///             RTCTrackEvent::OnOpen(init) => {
    ///                 println!("New track with receiver: {:?}", init.receiver_id);
    ///             }
    ///             _ => {}
    ///         }
    ///     }
    ///     _ => {}
    /// }
    /// # }
    /// ```
    ///
    /// # Specification
    ///
    /// See [track](https://www.w3.org/TR/webrtc/#event-track)
    OnTrack(RTCTrackEvent),

    /// Fired when a remote source is heard using one of this connection's sender SSRCs
    /// (RFC 3550 section 8.2), or a remote description describes one (RFC 5576 section 5),
    /// once per SSRC.
    ///
    /// Two sources of one RTP session cannot share an SSRC. The engine has already moved the
    /// sender to a new SSRC: the old one says BYE, what the application still writes with it
    /// goes out with the new one, the sender's parameters and statistics show the new one, and
    /// negotiation-needed is raised so that the next description signals it with
    /// `previous-ssrc`. Inbound packets carrying the old SSRC are dropped. The SSRC the
    /// connection reports from when it sends no media is replaced without this event.
    ///
    /// Not a W3C event: a fork addition.
    OnSsrcCollision(crate::rtp_transceiver::SSRC),

    /// The remote source with this SSRC named another CNAME in its RTCP SDES than the remote
    /// description declares for it (`a=ssrc:<ssrc> cname:`), once per SSRC and declared
    /// CNAME; [`RTCPeerConnection::remote_rtcp_cname`](crate::peer_connection::RTCPeerConnection::remote_rtcp_cname)
    /// gives the one it named.
    ///
    /// RFC 5576 section 6.1: the receiver "SHOULD assume there has been an SSRC collision and
    /// that the description of the source that was carried in the SDP description is not
    /// applicable to the actual source being received". A collision between remote sources:
    /// no local SSRC moves (that is [`Self::OnSsrcCollision`]) and no negotiation is asked
    /// for. The media keeps flowing: a stream already established stays on its track; one
    /// not established yet that is its receiver's only stream is received from then on as
    /// one of an SSRC the description does not mention (by its section, MID or payload type,
    /// without the repair flows the description paired with it), where its packets can be
    /// placed that way; a later description that still declares the SSRC with that CNAME is
    /// not applied to it again.
    ///
    /// Not a W3C event: a fork addition.
    OnRemoteCnameMismatch(crate::rtp_transceiver::SSRC),

    /// RTP media of this SSRC arrived that no media section or track could take, and was
    /// discarded: the first such packet of each SSRC (at most 64 SSRCs per connection are
    /// reported).
    ///
    /// RFC 8830 section 3.1: media of a peer that signals no `a=msid` (or arrives before the
    /// description that places it) may need buffering until it can be associated; "If the
    /// implementation wishes to limit this buffering, it MUST signal to the user that media
    /// has been discarded". The engine buffers none: a packet whose stream cannot be bound to
    /// a receiver (RFC 9143 section 9.2: "Otherwise, drop the packet") is dropped at once and
    /// this event says so. `RTCPeerConnection::discarded_rtp_packets` counts every one.
    ///
    /// Not a W3C event: a fork addition.
    OnUnassociatedRtpDiscarded(crate::rtp_transceiver::SSRC),

    /// W3C `RTCIceTransport` `statechange`: the connection's ICE transport changed state.
    ///
    /// Comes before the `OnIceConnectionStateChangeEvent` and the
    /// `OnConnectionStateChangeEvent` the same change causes (webrtc-pc section 5.6, "update
    /// the ICE transport state"). Not fired by `close()`.
    OnIceTransportStateChange(RTCIceTransportState),

    /// W3C `RTCIceTransport` `gatheringstatechange`: the ICE transport's gatherer changed
    /// state. Comes before the `OnIceGatheringStateChangeEvent` of the same change.
    OnIceGathererStateChange(RTCIceGatheringState),

    /// W3C `RTCIceTransport` `selectedcandidatepairchange`: ICE selected a new candidate pair
    /// to send over (the one `RTCIceTransport::get_selected_candidate_pair` now reports).
    OnSelectedCandidatePairChange(RTCIceCandidatePair),

    /// webrtc-extensions 7 `icecandidatepairadd`: the ICE agent formed a candidate pair and
    /// put it on its list (`RTCIceTransport::get_candidate_pairs`).
    OnIceCandidatePairAdd(RTCIceCandidatePair),

    /// webrtc-extensions 7 `icecandidatepairnominate`, cancelable: with
    /// `SettingEngineBuilder::with_candidate_pair_proposals(true)`, the ICE agent picked this
    /// pair to nominate and waits: `RTCPeerConnection::resolve_candidate_pair_nomination`
    /// accepts it or cancels it (`[[ProposalPending]]` until then).
    OnIceCandidatePairNominate(RTCIceCandidatePair),

    /// webrtc-extensions 7 `icecandidatepairremove`: a candidate pair left the ICE agent's
    /// list: replaced on a full checklist, dropped by an ICE restart, or removed by
    /// `RTCPeerConnection::remove_candidate_pair`. Not cancelable here.
    OnIceCandidatePairRemove(RTCIceCandidatePair),

    /// webrtc-extensions 11 `ssrcchange` on a receiver: the synchronization source of the
    /// last frame it received changed (`RTCRtpReceiver::get_synchronization_sources`). After
    /// both lists were updated, and before the `OnCsrcChange` of the same packet.
    OnSsrcChange(crate::rtp_transceiver::RTCRtpReceiverId),

    /// webrtc-extensions 11 `csrcchange` on a receiver: the contributing sources of the last
    /// frame it received changed (`RTCRtpReceiver::get_contributing_sources`).
    OnCsrcChange(crate::rtp_transceiver::RTCRtpReceiverId),

    /// webrtc-encoded-transform 6.4 `keyframerequest`: a Picture Loss Indication or Full
    /// Intra Request (RFC 4585 6.3.1, RFC 5104 4.3.1) arrived for an SSRC this sender sends;
    /// the encoder (the application's) should generate a key frame for that layer. `rid` is
    /// the layer's RID, `None` when the sender's encoding has none (not simulcast). The PLI /
    /// FIR itself is delivered as well (`RTCMessage::RtcpPacket`).
    ///
    /// Raised for the engine's own requests too (the pacer's discard and flush, the NACK
    /// responder's give-up: a PLI with sender SSRC 0), which this variant does not tell apart
    /// from the remote peer's: [`Self::OnKeyFrameRequestOrigin`] follows each one and does.
    /// (Its fields cannot grow here without breaking a `match` that names them all, so the
    /// origin is a second event; see the CHANGELOG for the form planned for 0.3.0.)
    OnKeyFrameRequest {
        /// The sender whose stream the request names.
        sender: crate::rtp_transceiver::RTCRtpSenderId,
        /// The RID of the requested layer.
        rid: Option<String>,
    },

    /// The same key-frame request as the [`Self::OnKeyFrameRequest`] just before it, with
    /// where it came from ([`RTCKeyFrameRequestOrigin`]): a Picture Loss Indication or Full
    /// Intra Request the remote peer sent, or a request the engine made itself
    /// ([`RTCKeyFrameRequestOrigin::Local`]: the pacer discarded a frame or gave its queue up,
    /// or the NACK responder gave the stream's repair up). Raised once for every
    /// `OnKeyFrameRequest`, right after it.
    ///
    /// An application that answers the two differently (a remote request with a key frame at
    /// once, the engine's own by a policy of its own, `OnPacerDiscard` beside it) reads this
    /// one and ignores `OnKeyFrameRequest`.
    ///
    /// Not a W3C event (webrtc-encoded-transform 6.4 `keyframerequest` has no origin): a fork
    /// addition.
    OnKeyFrameRequestOrigin(RTCKeyFrameRequestEvent),

    /// The engine's pacer discarded media of this sender for want of room in the congestion
    /// controller's target (the default chain's `PacerQueueOverflow::Drop`): whole frames of
    /// one stream that waited the pacer's queue time bound (2 s by default), or the oldest of a
    /// full queue. **The source is above the target**: what the application writes has to come
    /// down to the target it is given (`RTCRtpSender::target_bitrates`). The stream also needs a
    /// key frame: a Picture Loss Indication for it (sender SSRC 0) is delivered with this
    /// (`RTCMessage::RtcpPacket`, `OnKeyFrameRequest`), and the NACK responder does not resend
    /// the discarded packets. See `rtci_interceptor::PacerDiscard`.
    OnPacerDiscard {
        /// The sender whose stream lost the frames.
        sender: crate::rtp_transceiver::RTCRtpSenderId,
        /// The RID of the layer, `None` when the sender's encoding has none.
        rid: Option<String>,
        /// How many frames were discarded (0 for the rest of a frame already discarded).
        frames: u32,
        /// How many packets were discarded.
        packets: usize,
        /// Their octets (RTP header and payload).
        octets: usize,
        /// The pacer's target at the discard, bits per second.
        target_bitrate: f64,
    },

    /// The RTP circuit breaker (RFC 8083, in the default interceptor set) **ceased a flow of
    /// this sender**, or a ceased flow was restarted (by the application, or by the breaker).
    /// While a flow is ceased every RTP packet written for it is dropped: the stream is silent
    /// at the far end, and its encoding takes no share of the congestion controller's target
    /// (`RTCRtpSender::target_bitrates`).
    ///
    /// RFC 8083 section 4.5: "RTP flows halted by the circuit breaker SHOULD NOT be restarted
    /// automatically unless the sender has received information that the congestion has
    /// dissipated or can reasonably be expected to have dissipated. [...] Ideally, a human
    /// user will be involved in the decision to try to restart the flow", and restarts are
    /// rate limited "so that the reaction to a triggered circuit breaker lasts for at least
    /// the triggering interval".
    ///
    /// **What restarts a ceased flow.** The breaker does, once `restart_after` has passed,
    /// when the receiver's reports on another flow of the same transport show that what
    /// stopped this one has gone (a voice stream stopped by the media timeout while the video
    /// beside it is still arriving; a video stream stopped for congestion once the voice
    /// stream's reports show no such loss any more): a second event with `ceased: None`
    /// follows. That information exists only while another flow of the transport is being
    /// sent. **When every flow of the transport has ceased** (a call with one stream, or all
    /// of them stopped at once) nothing is sent that a report could speak of, and the flows
    /// stay silent until the application restarts them: after `restart_after`, call
    /// `DefaultInterceptorHandles::circuit_breaker` `.restart(ssrc, now)` (refused before
    /// `restart_after`), or stop writing and tell the user. A flow that trips again soon
    /// after a restart is held twice as long each time.
    /// `DefaultInterceptorOptions::circuit_breaker_automatic_restart` set to `false` leaves
    /// every restart to the application.
    ///
    /// **How fast a breaker trips** follows the receiver's reporting interval, as the RFC has
    /// it: the media timeout after five reports that show no new packet of a flow that is
    /// being sent, each a round trip at least after a packet they do not cover (section 4.2);
    /// the congestion breaker when the flow has been above ten times the TCP throughput for
    /// ten round trips and still is (section 4.3). Under RTP/AVPF without a `T_rr_interval` a
    /// peer reports every few tens of milliseconds beside a video stream, so five reports are
    /// a quarter of a second or less, and a burst that loses six voice packets in a row is
    /// enough to stop the voice stream; a peer that reports every second (a browser) needs
    /// five seconds of it.
    OnCircuitBreaker {
        /// The sender whose flow it is.
        sender: crate::rtp_transceiver::RTCRtpSenderId,
        /// The RID of the encoding, `None` when it has none.
        rid: Option<String>,
        /// The flow: the encoding's media, RTX or FEC SSRC. What
        /// `CircuitBreakerHandle::restart` takes.
        ssrc: crate::rtp_transceiver::SSRC,
        /// The breaker that tripped; `None` when the flow was restarted.
        ceased: Option<interceptor::CircuitBreakerReason>,
        /// For a ceased flow: how long until a restart is accepted.
        restart_after: std::time::Duration,
    },

    /// W3C `RTCDtlsTransport` `statechange`. Comes before the `OnConnectionStateChangeEvent` it
    /// causes, and after the `OnDtlsTransportError` of a failure. Not fired by `close()`.
    OnDtlsTransportStateChange(RTCDtlsTransportState),

    /// W3C `RTCDtlsTransport` `error`: the DTLS transport failed, with `dtls-failure` (and the
    /// fatal alert sent or received) or `fingerprint-failure`. Comes right before the
    /// `OnDtlsTransportStateChange` to `Failed`.
    OnDtlsTransportError(RTCError),

    /// W3C `RTCSctpTransport` `statechange`: the SCTP transport (the one
    /// `RTCPeerConnection::sctp` returns) changed state. Not fired by `close()`.
    OnSctpTransportStateChange(RTCSctpTransportState),

    /// W3C `RTCDTMFSender` `tonechange`: a tone began playing out (`,` for a pause), or the
    /// tone buffer ran out (an empty tone). See
    /// [`RTCRtpSender::dtmf`](crate::rtp_transceiver::rtp_sender::RTCRtpSender::dtmf).
    OnDtmfToneChange(crate::rtp_transceiver::rtp_sender::dtmf::RTCDTMFToneChangeEvent),

    /// The SRTP master key of this side's outbound (`outbound` true) or the peer's inbound
    /// stream has used fifteen sixteenths of its lifetime (RFC 3711 section 9.2): `remaining`
    /// more packets of `rtcp` (SRTCP) or RTP may be protected with it. The connection then
    /// asks for a new DTLS association by itself (RFC 5764 section 4.4; negotiation-needed
    /// follows), unless `SettingEngineBuilder::with_srtp_automatic_rekeying(false)`. At the
    /// limit the connection's DTLS transport fails. Not a W3C event: a fork addition.
    OnSrtpKeyLifetimeExpiring {
        /// Whether it is the key this side sends with.
        outbound: bool,
        /// Whether it is the SRTCP count.
        rtcp: bool,
        /// Packets left.
        remaining: u64,
    },

    /// Cryptex is required and the peer sent an authentic packet on `ssrc` whose header
    /// extensions or CSRCs were not protected with it (RFC 9335 section 5.2); the packet was
    /// dropped. Not a W3C event: a fork addition.
    OnCryptexRequiredViolation(u32),

    /// An event of one of the connection's transports, with the transport's ids: the ICE
    /// transport's `statechange`, `gatheringstatechange` and `selectedcandidatepairchange`,
    /// the candidate pair events, and the DTLS transport's `statechange` and `error` (W3C
    /// webrtc-pc 5.5, 5.6; webrtc-extensions 7).
    ///
    /// Fired for every transport, the default one included. The single-transport variants
    /// (`OnIceTransportStateChange`, `OnIceGathererStateChange`,
    /// `OnSelectedCandidatePairChange`, `OnIceCandidatePair*`, `OnDtlsTransportStateChange`,
    /// `OnDtlsTransportError`) name no transport and are fired for the default transport only
    /// (the one every section is on while all are bundled), each right before its
    /// `OnTransportEvent`.
    OnTransportEvent(RTCTransportEvent),
    /// A transport needs a new set of local candidates, on transport addresses the previous
    /// DTLS association did not use: the engine dropped the candidates it had and refuses
    /// their UDP addresses (RFC 8842 section 5.1: a new DTLS association over UDP "MUST"
    /// have a new 3-tuple). The application, which owns the sockets, binds new ports, adds
    /// their candidates for `mids[0]`, signals them and ends the generation; see
    /// [`RTCLocalCandidatesNeededEvent`] and the crate documentation's "Gathering" section.
    ///
    /// Fired when the description that sets the transport up is applied locally
    /// (`set_local_description`), where W3C webrtc-pc 5.6 has the ICE agent begin gathering
    /// the transport's generation, right before that transport's `gatheringstatechange` to
    /// "gathering": for an ICE restart made for a new DTLS association (this side's or the
    /// peer's, automatic SRTP re-keying included) when the offer or the answer that carries it
    /// is set, and for the transport that replaced one closed by an answer rejecting every m=
    /// section, when the next description is set. Also for an ICE restart with
    /// `with_discard_local_candidates_during_ice_restart(true)` (any addresses then).
    ///
    /// Not fired with `SettingEngineBuilder::with_dtls_new_association_on_previous_addresses(true)`:
    /// the candidates are kept and their addresses accepted. Not a W3C event: a fork addition
    /// (a browser gathers by itself).
    OnLocalCandidatesNeeded(RTCLocalCandidatesNeededEvent),
    /// A packet from the peer was discarded by SRTP: a replay (`replay` true), or one whose
    /// authentication tag did not verify (RFC 3711 section 3.3, steps 2 and 5: "the event
    /// SHOULD be logged"; the engine also logs it at `warn`). `ssrc` and `index` (the RTP
    /// sequence number or the SRTCP index) are what the packet says, unauthenticated for an
    /// authentication failure. At most 64 such events wait per SRTP context: a flood of
    /// forged packets is not queued without bound. Not a W3C event: a fork addition.
    OnSrtpPacketDiscarded {
        /// SRTCP (`true`) or SRTP.
        rtcp: bool,
        /// The SSRC the packet names.
        ssrc: u32,
        /// Its sequence number or SRTCP index.
        index: u64,
        /// A replay; otherwise an authentication failure.
        replay: bool,
    },
    /// The ECN validation of the outbound stream `ssrc` detected a failure (RFC 6679 sections
    /// 7.2.1 and 7.4.2: an initiation that failed, or ECT packets lost after it). The stream
    /// sends Not-ECT, initiates again later, or keeps ECN off, as `failure` says. The RFC asks
    /// for such failures to be logged "to enable follow up": they are, and this hands them to
    /// the application as well. Not a W3C event: a fork addition.
    OnEcnFailure {
        /// The outbound stream.
        ssrc: u32,
        /// What was detected.
        failure: interceptor::EcnFailure,
    },
    /// One of the engine's TURN allocations over UDP has been let go: a Refresh of LIFETIME 0
    /// (RFC 8656 section 8) was answered, or answered 437 (the server no longer held it), or
    /// its STUN transaction timed out (RFC 8489 section 6.2.1; the server then drops it when
    /// its lifetime runs out); or an Allocate still under way when the engine stopped needing
    /// it was answered, its allocation deleted, or timed out. The engine sends nothing more
    /// from `local_address` to that server: an application that bound that socket for it alone
    /// may close it. Raised after `close()` too, which keeps the peer connection serving these
    /// transactions (`poll_write`, `handle_read`, `poll_timeout`, `handle_timeout`) until the
    /// last one is done: `poll_timeout` is then `None`. Not a W3C event: a fork addition.
    OnTurnAllocationReleased {
        /// The server's URL (`turn:host:port?transport=udp`).
        url: String,
        /// The local address (a UDP host candidate's base) the allocation was made from.
        local_address: std::net::SocketAddr,
        /// The relayed address, when an allocation had been made.
        relayed_address: Option<std::net::SocketAddr>,
    },
    /// A new ICE generation needed an allocation on a server from the only UDP base the
    /// transport has, which the allocation the previous generation uses holds (an allocation is
    /// its 5-tuple's, RFC 8656 section 2.2): that one was released first, so the relayed path
    /// is broken until the new generation selects a pair (break before make). An application
    /// that adds a host candidate on a second local address while the restart is staged
    /// (before `set_local_description` of the restart offer, or of the answer to one) gets the
    /// new allocation from there instead, and data keeps flowing. Not a W3C event: a fork
    /// addition.
    OnTurnAllocationReplacedInPlace {
        /// The server's URL (`turn:host:port?transport=udp`).
        url: String,
        /// The local address both allocations use.
        local_address: std::net::SocketAddr,
    },
    /// A request of one of the engine's TURN links was finally refused by the server (after
    /// the retries the TURN client makes: 401 or 438 once more, RFC 8489 section 9.2.5), or,
    /// for an Allocate, refused with 437 (Allocation Mismatch, RFC 8656 section 7.4: the
    /// 5-tuple is held by an allocation the engine does not know: one a peer connection
    /// closed without releasing, or another client's). Not a W3C event: a fork addition.
    OnTurnRequestRejected {
        /// The server's URL (`turn:host:port?transport=udp`).
        url: String,
        /// The relayed address of the allocation the request was for, if it has one.
        relay: Option<std::net::SocketAddr>,
        /// The request: `Allocate`, `Refresh`, `CreatePermission` or `ChannelBind`.
        method: &'static str,
        /// The STUN error code (401, 437, 438, 441, ...).
        error_code: u16,
    },
}

/// Reserved for future use.
///
/// This enum is currently empty but reserved for potential future event types.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RTCEvent {}

/// An [`RTCEvent`] together with the instant its condition was observed at.
///
/// The counterpart of [`TaggedRTCMessage`](crate::peer_connection::message::TaggedRTCMessage)
/// for the event channel, so that all three of the core's input channels carry a timestamp
/// rather than two of them carrying one and the third leaving the core to ask the clock.
///
/// [`RTCEvent`] is currently uninhabited, so no value of this type can be constructed yet; it
/// exists so the signature is already right when the first event variant is added.
pub struct TaggedRTCEvent {
    /// When the condition this event reports was observed.
    pub now: Instant,
    /// The event itself.
    pub event: RTCEvent,
}

/// Internal event types for WebRTC implementation.
///
/// These events are used internally by the WebRTC stack to coordinate between
/// different components (ICE, DTLS, SCTP). They are not exposed to the public API.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RTCEventInternal {
    /// Public RTC event (currently unused)
    RTCEvent(RTCEvent),

    /// Public peer connection event
    RTCPeerConnectionEvent(RTCPeerConnectionEvent),

    /// ICE selected candidate pair has changed
    ICESelectedCandidatePairChange,

    /// DTLS handshake completed successfully
    ///
    /// Parameters:
    /// - Remote socket address
    /// - Optional SRTP context (send)
    /// - Optional SRTCP context (receive)
    DTLSHandshakeComplete(
        Option<Context>, /*local_srtp_context*/
        Option<Context>, /*remote_srtp_context*/
    ),

    /// The peer closed the DTLS transport with a `close_notify` alert.
    ///
    /// Everything that runs over it ends with it: the SCTP handler closes its associations and
    /// the data channel handler closes every data channel.
    DTLSClosed,

    /// SCTP handshake completed successfully
    ///
    /// Parameter: Association handle
    SCTPHandshakeComplete(usize /*AssociationHandle*/),

    /// The SCTP association was closed by signalling (RFC 8841 section 10): its data section
    /// was rejected, an `a=sctp-port` of zero closed it, or a new `a=sctp-port` replaces it.
    /// The data channels that ran over it are closed.
    ///
    /// Parameter: whether a new association replaces it (the channels not yet opened wait
    /// for that one) or none does (they are closed too).
    SCTPClosedBySignalling(bool /*replaced*/),

    /// An SRTP master key reached its lifetime (RFC 3711 section 9.2): nothing more is
    /// protected or accepted with it, and the DTLS transport that keyed it fails.
    SRTPKeyExhausted,

    /// A thirty-second of an SRTP master key's lifetime is left: the DTLS server's threshold
    /// for asking for a new association by itself
    /// (`SettingEngineBuilder::with_srtp_rekeying_dtls_client_first`).
    SrtpRekeyingDue,

    /// An SRTP master key has no more packets left than it protects, at the rate it is used,
    /// in the time a re-keying needs (measured on the handshake that keyed it), and that is
    /// more than the sixteenth of its lifetime the lifetime warning leaves: the re-keying
    /// starts as at that warning (`SettingEngineBuilder::with_srtp_key_lifetime`).
    SrtpRekeyingMarginReached,

    /// The application bytes that left a stream's send queue, reported once as the stream is
    /// closed or lost (just before its `SCTPStreamFailed` / `SCTPStreamClosed`, or before
    /// signalling closes the association), so the channel's final `bufferedAmount` stays
    /// readable after it closed (W3C webrtc-pc 6.2: not reset when the channel closes).
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    /// - Bytes taken from the stream's send queue
    SCTPStreamDequeued(usize /*AssociationHandle*/, u16 /*StreamID*/, u64),

    /// SCTP stream has been closed
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    SCTPStreamClosed(usize /*AssociationHandle*/, u16 /*StreamID*/),

    /// The SCTP association a stream ran over was lost to an error: the peer's ABORT, a
    /// protocol violation or a timeout. Reported for each stream just before its
    /// `SCTPStreamClosed`, so the channel on it fires `OnError` before `OnClose` (W3C
    /// "announce the data channel as closed" with an error, `sctp-failure`).
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    SCTPStreamFailed(usize /*AssociationHandle*/, u16 /*StreamID*/),

    /// A message read in parts (RFC 9260 6.9) would have taken the incomplete messages held
    /// for the association past the inbound reassembly limit
    /// (`SettingEngineBuilder::with_sctp_inbound_reassembly_limit`): the data channel on the
    /// stream fails, with an error naming the limit (RFC 8831 6.6). Its stream is reset by
    /// the SCTP handler once the rest of the message has been read and dropped.
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    /// - The limit, in bytes
    SCTPInboundReassemblyLimit(
        usize, /*AssociationHandle*/
        u16,   /*StreamID*/
        usize,
    ),

    /// The SCTP cause code of the failure the next `SCTPStreamFailed` / `SCTPAssociationFailed`
    /// report (W3C `RTCError.sctpCauseCode`), when the association was aborted with one.
    SCTPFailureCause(u16),

    /// The SCTP association was lost to an error (see `SCTPStreamFailed`): every data channel
    /// over it fails, including one that never carried data and so has no SCTP stream.
    ///
    /// Parameter: Association handle
    SCTPAssociationFailed(usize /*AssociationHandle*/),

    /// The peer restarted the SCTP association (RFC 9260 section 5.2.4 action A): the
    /// association is a new one, with no streams. Every data channel that ran over the old one
    /// is closed with an error (W3C webrtc 6.2: its underlying data transport is gone); an
    /// `SCTPHandshakeComplete` for the new association follows, which dials the channels that
    /// were waiting for one and opens the negotiated ones.
    ///
    /// Parameter: Association handle
    SCTPRestarted(usize /*AssociationHandle*/),

    /// SCTP released outgoing buffered bytes (acknowledged or abandoned) for a
    /// stream, used to decrement the per-channel send back-pressure counter.
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    /// - Bytes released
    SCTPBufferReleased(
        usize, /*AssociationHandle*/
        u16,   /*StreamID*/
        usize, /*n_bytes*/
    ),

    /// A stream's outgoing buffer fell to or below its low threshold.
    ///
    /// Carries the SCTP stream id, because that is all the SCTP layer knows. The data channel
    /// handler translates it into the public
    /// [`RTCDataChannelEvent::OnBufferedAmountLow`](crate::peer_connection::event::RTCDataChannelEvent::OnBufferedAmountLow),
    /// which names the channel by handle like every other application-facing event.
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    SCTPBufferedAmountLow(usize /*AssociationHandle*/, u16 /*StreamID*/),

    /// A stream's outgoing buffer rose to or above its high threshold. The handle/stream-id
    /// note on [`Self::SCTPBufferedAmountLow`] applies here too.
    ///
    /// Parameters:
    /// - Association handle
    /// - Stream ID
    SCTPBufferedAmountHigh(usize /*AssociationHandle*/, u16 /*StreamID*/),
}

pub(crate) struct TaggedRTCEventInternal {
    pub(crate) now: Instant,
    pub(crate) event: RTCEventInternal,
}
