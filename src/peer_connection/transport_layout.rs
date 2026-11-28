//! Which m= section runs over which transport (RFC 9429 sections 4.1.1, 5.2.1, 5.3.1; RFC 9143
//! section 7).
//!
//! A BUNDLE group is one transport; every other m= section that is not rejected has a transport
//! of its own, with its own ICE credentials and candidates, DTLS association and SRTP keys. The
//! layout follows the descriptions:
//!
//! - a remote offer gives each section outside its BUNDLE group a transport, created then and
//!   started with the answer;
//! - an offer this side makes under the `max-compat` bundle policy gives each section a
//!   transport of its own;
//! - an answer, remote or local, settles it: the sections it bundles move to the transport of
//!   the group's tagged section, and a transport left without a section is closed;
//! - a rollback restores the layout of the current descriptions.
//!
//! The first transport (the one the connection is built with) carries the first group. Its
//! description handling is the one the single-transport engine had; the other transports are
//! started from the part of the description that names their sections.

use super::*;
use crate::peer_connection::configuration::RTCBundlePolicy;
use crate::peer_connection::event::RTCLocalCandidatesNeededReason;
use crate::peer_connection::handler::dtls::DtlsHandlerContext;
use crate::peer_connection::handler::ice::IceHandlerContext;
use crate::peer_connection::handler::srtp::SrtpHandlerContext;
use crate::peer_connection::handler::transport_set::TransportId;
use crate::peer_connection::sdp::{
    ATTR_KEY_BUNDLE_ONLY, ATTR_KEY_TLS_ID, add_candidates_to_media_descriptions, bundle_groups,
    extract_fingerprints, extract_ice_details, get_mid_value, is_rejected_media,
    set_default_destination,
};
use crate::peer_connection::transport::ice::IceTransport;
use crate::peer_connection::transport::ice::candidate::rtc_ice_candidates_from_ice_candidates;
use crate::peer_connection::transport::{RTCDtlsTransport, RTCTransportId, TransportKind};
use ::sdp::description::common::Attribute;
use ::sdp::description::session::{ATTR_KEY_GROUP, SessionDescription};
use rand::RngExt;

/// The ICE attributes that belong to a transport (RFC 8859 category TRANSPORT): each
/// transport's sections carry its own.
const TRANSPORT_ICE_ATTRIBUTES: [&str; 4] =
    ["ice-ufrag", "ice-pwd", "candidate", "end-of-candidates"];

/// The m= sections of a description, grouped by the transport they share: each BUNDLE group's
/// sections that are not rejected (RFC 9143 section 5: a description may carry several
/// groups, each a transport), then each other section that is not rejected on its own, in the
/// order of the first section of each.
pub(crate) fn transport_groups(desc: &SessionDescription) -> Vec<Vec<String>> {
    let bundles: Vec<Vec<&str>> = bundle_groups(desc);
    let live: Vec<&str> = desc
        .media_descriptions
        .iter()
        .filter(|m| !is_rejected_media(m))
        .filter_map(|m| get_mid_value(m).map(String::as_str))
        .collect();
    let mut groups: Vec<Vec<String>> = vec![];
    // Where each BUNDLE group's sections are collected, once its first live section is seen.
    let mut bundled_at: Vec<Option<usize>> = vec![None; bundles.len()];
    for mid in live {
        match bundles.iter().position(|group| group.contains(&mid)) {
            Some(bundle) => match bundled_at[bundle] {
                Some(index) => groups[index].push(mid.to_owned()),
                None => {
                    bundled_at[bundle] = Some(groups.len());
                    groups.push(vec![mid.to_owned()]);
                }
            },
            None => groups.push(vec![mid.to_owned()]),
        }
    }
    groups
}

/// The part of `desc` that describes the sections `mids`: the session's attributes, with the
/// BUNDLE groups restricted to them, and their m= sections. It is what one transport is
/// started and checked from.
pub(crate) fn description_for(desc: &SessionDescription, mids: &[String]) -> SessionDescription {
    let mut part = desc.clone();
    part.media_descriptions
        .retain(|m| get_mid_value(m).is_some_and(|mid| mids.contains(mid)));
    let bundles: Vec<Vec<String>> = bundle_groups(desc)
        .into_iter()
        .map(|group| {
            group
                .into_iter()
                .filter(|mid| mids.iter().any(|m| m == mid))
                .map(str::to_owned)
                .collect::<Vec<String>>()
        })
        .filter(|group| !group.is_empty())
        .collect();
    part.attributes.retain(|a| {
        a.key != ATTR_KEY_GROUP
            || !a
                .value
                .as_deref()
                .is_some_and(|value| value.starts_with("BUNDLE"))
    });
    for bundle in bundles {
        part.attributes.push(Attribute::new(
            ATTR_KEY_GROUP.to_owned(),
            Some(format!("BUNDLE {}", bundle.join(" "))),
        ));
    }
    part
}

impl RTCPeerConnection {
    /// Adds a transport with the connection's settings: a new ICE agent (its own
    /// credentials), a DTLS transport with the connection's certificates, and SRTP contexts
    /// that follow the connection's header encryption.
    pub(crate) fn add_transport(&mut self) -> Result<TransportId> {
        let own_credentials = self.setting_engine.unique_transport_credentials;
        let (ice, dtls, srtp) = self.new_transport_parts(own_credentials)?;
        Ok(self.pipeline_context.transports.insert(ice, dtls, srtp))
    }

    /// What a new transport is made of, with the connection's settings. `own_credentials`:
    /// ICE credentials of its own, else the first transport's.
    fn new_transport_parts(
        &mut self,
        own_credentials: bool,
    ) -> Result<(IceHandlerContext, DtlsHandlerContext, SrtpHandlerContext)> {
        let now = self.pipeline_context.now;
        let mut agent_config =
            internal::ice_agent_config(&self.configuration, &self.setting_engine)?;
        agent_config.multicast_dns_publishing = self.mdns_publishing;
        if let Some(reported) = self.mdns_destination_reported {
            agent_config.multicast_dns_destination_reported = reported;
        }
        // A transport's credentials are the first transport's, as the browsers have them,
        // unless each transport is to have its own (RFC 9429 section 5.2.1;
        // `with_unique_transport_credentials`). Fixed ones from the settings are the first
        // transport's.
        if own_credentials {
            agent_config.local_ufrag = String::new();
            agent_config.local_pwd = String::new();
        } else {
            let (ufrag, pwd) = self.shared_transport_credentials();
            agent_config.local_ufrag = ufrag;
            agent_config.local_pwd = pwd;
        }
        let crypto_provider = self
            .setting_engine
            .crypto_provider
            .clone()
            .unwrap_or_else(|| self.dtls_transport().crypto_provider.clone());
        let nonce: u64 = rand::rng().random();
        let ice_transport_id = RTCTransportId::new(nonce, TransportKind::Ice);
        let dtls_transport_id = RTCTransportId::new(nonce, TransportKind::Dtls);
        let mut ice_transport =
            IceTransport::new(now, agent_config, crypto_provider.clone(), ice_transport_id)?;
        ice_transport
            .agent
            .set_temporary_ipv6_addresses(self.temporary_ipv6_addresses.clone());
        ice_transport.agent.set_failed_without_end_of_candidates(
            self.setting_engine.ice_failed_without_end_of_candidates,
        );
        let certificates = self.dtls_transport().certificates.clone();
        let resumption = self.dtls_transport().resumption.clone();
        let dtls_transport = internal::new_dtls_transport(
            &self.setting_engine,
            certificates,
            dtls_transport_id,
            ice_transport_id,
            crypto_provider,
            resumption,
        )?;
        let default_srtp = &self
            .pipeline_context
            .transports
            .default()
            .srtp_handler_context;
        let mut srtp = SrtpHandlerContext {
            rtp_header_encryption_policy: default_srtp.rtp_header_encryption_policy,
            ..Default::default()
        };
        srtp.set_cryptex(default_srtp.cryptex);
        srtp.set_encrypted_header_extensions(default_srtp.encrypted_header_extensions);
        Ok((
            IceHandlerContext::new(ice_transport),
            DtlsHandlerContext::new(dtls_transport),
            srtp,
        ))
    }

    /// Closes the transport `id`, which no m= section uses any more (W3C webrtc-pc "set a
    /// session description", once stable: "close the RTCDtlsTransports and their associated
    /// RTCIceTransports. This results in events firing on these objects"): its DTLS and ICE
    /// `statechange` to "closed", then its ICE agent is closed and the transport dropped.
    ///
    /// The set always holds a transport, the one a later description sets up. So the last
    /// one is not taken out but replaced, in its place, by a new one: a new ICE agent with
    /// credentials of its own (a new generation; a closed agent cannot restart), a new DTLS
    /// transport and new SRTP contexts, in the state "new" with nothing announced. The DTLS
    /// association the next description sets up on it runs on a new 3-tuple (RFC 8842
    /// section 5.1): the closed transport's local candidates are not kept and their UDP
    /// addresses are refused, so the application gathers on new ports. With
    /// `with_dtls_new_association_on_previous_addresses(true)` they are the new agent's too,
    /// as an ICE restart keeps them (unless `with_discard_local_candidates_during_ice_restart`).
    fn close_transport(&mut self, id: TransportId) -> Result<()> {
        log::debug!("transport {id:?} carries no m= section any more: closed");
        self.with_transport(id, |pc| pc.announce_transport_closed());
        let closed = if self.pipeline_context.transports.len() > 1 {
            self.pipeline_context.remove_transport(id)
        } else {
            // The next description sets up a new DTLS association on the new transport, on a
            // new 3-tuple (RFC 8842 section 5.1, `restart_needs_new_local_addresses`): the
            // closed transport's candidates are not kept, their UDP addresses are refused
            // until an ICE restart that is not for a new association, and the engine's TURN
            // links allocate again. `with_dtls_new_association_on_previous_addresses(true)`
            // keeps them, as an ICE restart keeps them.
            let on_new_addresses = !self
                .setting_engine
                .dtls_new_association_on_previous_addresses;
            let kept: Vec<ice::candidate::Candidate> = if on_new_addresses
                || self
                    .setting_engine
                    .candidates
                    .discard_local_candidates_during_ice_restart
            {
                vec![]
            } else {
                self.ice_transport_of(id)
                    .agent
                    .get_local_candidates_to_signal()
            };
            let retired = if on_new_addresses {
                self.ice_transport_of(id).current_generation_udp_addresses()
            } else {
                vec![]
            };
            // Its own credentials: there is no other transport to share them with, and the
            // closed one's belong to its generation.
            let (mut ice, dtls, srtp) = self.new_transport_parts(true)?;
            for candidate in kept {
                if let Err(err) = ice.ice_transport.add_local_candidate(candidate) {
                    log::debug!("a local candidate is not kept for the new transport: {err}");
                }
            }
            ice.ice_transport.previous_association_addresses = retired;
            // The next description that sets the transport up tells the application to
            // gather for it (`OnLocalCandidatesNeeded`), unless it keeps the candidates.
            ice.ice_transport.candidates_needed = if on_new_addresses {
                Some(RTCLocalCandidatesNeededReason::TransportReplaced)
            } else if self
                .setting_engine
                .candidates
                .discard_local_candidates_during_ice_restart
            {
                Some(RTCLocalCandidatesNeededReason::DiscardedBySetting)
            } else {
                None
            };
            let closed = self.pipeline_context.transports.renew(id, ice, dtls, srtp);
            self.pipeline_context.sync_transport_stats();
            if on_new_addresses {
                let now = self.pipeline_context.now;
                self.with_transport(id, |pc| {
                    pc.forget_srflx_of_refused_bases();
                    pc.reallocate_turn_links_of_active_transport(now)
                });
            }
            closed
        };
        if let Some(mut bundle) = closed {
            let _ = sansio::Protocol::close(&mut bundle.ice_handler_context.ice_transport.agent);
        }
        Ok(())
    }

    /// W3C webrtc-pc "set a session description", once the state is stable after an answer:
    /// the transports "no longer referenced by a non-stopped transceiver" are closed. An
    /// answer that leaves no m= section (every one rejected: RFC 9429 section 5.11, "unless a
    /// non-rejected "m=" section is bundled with this "m=" section, discard any associated
    /// ICE components") leaves no transport in use: each is closed, the last of them replaced
    /// by the one the next description sets up ([`Self::close_transport`]).
    pub(crate) fn close_transports_without_sections(&mut self) -> Result<()> {
        // What the description queued for the peer (the RTCP BYE of each stream that stopped,
        // the SCTP ABORT of a rejected data section) leaves over the transports it was
        // queued for, before they go.
        self.flush_writes();
        let default = self.pipeline_context.transports.default_id();
        // The others first: the default one, which is replaced, is the one that stays.
        let mut ids = self.pipeline_context.transports.ids();
        ids.retain(|id| *id != default);
        ids.push(default);
        for id in ids {
            self.close_transport(id)?;
        }
        self.pipeline_context.describe_section_transports();
        // The connection's states are aggregates over the transports there are now.
        self.update_gathering_state();
        self.update_aggregate_connection_states();
        Ok(())
    }

    /// The ICE credentials a transport added beside the first one takes when the transports
    /// share theirs: the default transport's, the ones of a restart it has staged (an offer
    /// being created with an ICE restart advertises those) included.
    fn shared_transport_credentials(&self) -> (String, String) {
        let credentials = self
            .ice_transport_of(self.pipeline_context.transports.default_id())
            .agent
            .get_local_credentials();
        (credentials.ufrag.clone(), credentials.pwd.clone())
    }

    /// Puts each group of m= sections on one transport: the one a section of the group is on
    /// already (its first section's first), else a new one. The first group is on the
    /// default transport. Sections in no group are taken off their transport, and a
    /// transport left without a section is closed.
    pub(crate) fn apply_transport_layout(&mut self, groups: &[Vec<String>]) -> Result<()> {
        if groups.is_empty() {
            return Ok(());
        }
        let mut targets: Vec<TransportId> = vec![];
        for (index, group) in groups.iter().enumerate() {
            let transports = &self.pipeline_context.transports;
            let existing = group
                .iter()
                .filter_map(|mid| transports.assignment(mid))
                .find(|id| !targets.contains(id));
            let target = match existing {
                Some(id) => id,
                // The first group, nothing assigned yet: the transport the connection has.
                None if index == 0 && !targets.contains(&transports.default_id()) => {
                    transports.default_id()
                }
                None => self.add_transport()?,
            };
            targets.push(target);
        }
        let in_groups: Vec<&String> = groups.iter().flatten().collect();
        let transports = &mut self.pipeline_context.transports;
        for (group, target) in groups.iter().zip(&targets) {
            for mid in group {
                transports.assign(mid, *target);
            }
        }
        transports.set_default(targets[0]);
        // Every section outside the groups leaves its transport: a transceiver's, and also a
        // data section (which has no transceiver), else the transport a rolled-back offer
        // gave a new data section would outlive the rollback (RFC 9429 section 5.7).
        let outside: Vec<String> = transports
            .ids()
            .into_iter()
            .flat_map(|id| transports.mids_on(id))
            .chain(self.rtp_transceivers.iter().filter_map(|t| t.mid().clone()))
            .filter(|mid| !in_groups.contains(&mid))
            .collect();
        for mid in outside {
            self.pipeline_context.transports.unassign(&mid);
        }
        let data = self.data_section_mid_in(groups);
        let transports = &mut self.pipeline_context.transports;
        if let Some(data) = data {
            let id = transports.transport_id_for(&data);
            transports.set_data(id);
        } else {
            transports.set_data(targets[0]);
        }
        let default = transports.default_id();
        for id in transports.ids() {
            if id != default && self.pipeline_context.transports.mids_on(id).is_empty() {
                self.close_transport(id)?;
            }
        }
        self.pipeline_context.describe_section_transports();
        // A transport that closed no longer counts in the connection's gathering state.
        self.update_gathering_state();
        self.update_aggregate_connection_states();
        Ok(())
    }

    /// W3C 4.3.3 and 4.3.4 after the set of transports changed: the ICE connection state and
    /// the connection state are aggregates over the transports there are, so one that closed
    /// (an answer left it without a section, or a rollback took it back) stops holding them
    /// at "new" or "connecting". Transport state changes recompute them too; this covers a
    /// change of the set itself, which fires none of those.
    pub(crate) fn update_aggregate_connection_states(&mut self) {
        if self.is_closed() {
            return;
        }
        let aggregate = self.ice_connection_state();
        if aggregate != self.pipeline_context.announced_ice_connection_state {
            self.pipeline_context.announced_ice_connection_state = aggregate;
            self.pipeline_context
                .event_outs
                .push_back(crate::peer_connection::event::RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(aggregate));
        }
        self.update_connection_state(false);
    }

    /// The mid of the data section among `groups`: the one no transceiver has.
    fn data_section_mid_in(&self, groups: &[Vec<String>]) -> Option<String> {
        groups.iter().flatten().find_map(|mid| {
            (!self
                .rtp_transceivers
                .iter()
                .any(|t| t.mid().as_deref() == Some(mid.as_str())))
            .then(|| mid.clone())
        })
    }

    /// The layout of the current descriptions, after a rollback (RFC 9429 section 5.7): the
    /// most recent answer's, or one transport for everything before there was one.
    pub(crate) fn restore_transport_layout(&mut self) {
        let answer = [
            &self.current_local_description,
            &self.current_remote_description,
        ]
        .into_iter()
        .flatten()
        .find(|d| d.sdp_type == RTCSdpType::Answer)
        .and_then(|d| d.parsed.clone());
        let groups = answer.as_ref().map(transport_groups).unwrap_or_default();
        if groups.is_empty() {
            let transports = &self.pipeline_context.transports;
            let default = transports.default_id();
            for id in transports.ids() {
                if id != default {
                    self.pipeline_context.remove_transport(id);
                }
            }
            for mid in self
                .rtp_transceivers
                .iter()
                .filter_map(|t| t.mid().clone())
                .collect::<Vec<_>>()
            {
                self.pipeline_context.transports.unassign(&mid);
            }
            self.pipeline_context.describe_section_transports();
            self.update_gathering_state();
            self.update_aggregate_connection_states();
            return;
        }
        if let Err(err) = self.apply_transport_layout(&groups) {
            log::warn!("restoring the transport layout: {err}");
        }
    }

    /// The part of `desc` the default transport is set up from: all of it while there is one
    /// transport, else the sections on the default transport.
    pub(crate) fn default_transport_view(&self, desc: &SessionDescription) -> SessionDescription {
        let transports = &self.pipeline_context.transports;
        if transports.len() == 1 {
            return desc.clone();
        }
        let default = transports.default_id();
        let mids: Vec<String> = desc
            .media_descriptions
            .iter()
            .filter_map(get_mid_value)
            .filter(|mid| transports.transport_id_for(mid) == default)
            .cloned()
            .collect();
        description_for(desc, &mids)
    }

    /// RFC 9429 section 5.8.3 for each transport a remote description sets up: its ICE
    /// credentials, candidates and fingerprints are present, well formed and do not
    /// conflict, and a transport in use is not given a new DTLS association without an ICE
    /// restart (sections 5.8.3 and 5.11, `check_dtls_change_restarts_ice`).
    pub(crate) fn check_remote_transports(
        &self,
        desc: &SessionDescription,
        answers: bool,
    ) -> Result<()> {
        let groups = transport_groups(desc);
        let transports = &self.pipeline_context.transports;
        // Before any section has a transport of its own the connection has one: the first
        // group is on it.
        let none_assigned = self
            .rtp_transceivers
            .iter()
            .filter_map(|t| t.mid().clone())
            .all(|mid| transports.assignment(&mid).is_none());
        for (index, group) in groups.iter().enumerate() {
            let part = description_for(desc, group);
            let Some(ice) = extract_ice_details(&part)? else {
                continue;
            };
            let fingerprints = extract_fingerprints(&part)?;
            // The transport the group is on now; a group that has none yet starts a new one,
            // which has no association to continue.
            let transport = group
                .iter()
                .find_map(|mid| transports.assignment(mid))
                .or_else(|| (index == 0 && none_assigned).then(|| transports.default_id()));
            if let Some(transport) = transport {
                self.check_dtls_change_restarts_ice(
                    transport,
                    &part,
                    answers,
                    &ice.ufrag,
                    &ice.pwd,
                    &fingerprints,
                )?;
            }
        }
        if groups.is_empty()
            && let Some(ice) = extract_ice_details(desc)?
        {
            let fingerprints = extract_fingerprints(desc)?;
            self.check_dtls_change_restarts_ice(
                transports.default_id(),
                desc,
                answers,
                &ice.ufrag,
                &ice.pwd,
                &fingerprints,
            )?;
        }
        Ok(())
    }

    /// `set_remote_description`: the layout the description implies, then the transports
    /// take its parameters (an answer's now, an offer's with the local answer).
    pub(crate) fn apply_remote_transports(
        &mut self,
        now: Instant,
        parsed: &SessionDescription,
        we_offer: bool,
    ) -> Result<()> {
        let groups = transport_groups(parsed);
        if groups.len() > 1 || self.pipeline_context.transports.len() > 1 {
            self.apply_transport_layout(&groups)?;
        }
        let view = self.default_transport_view(parsed);
        if we_offer {
            self.apply_remote_transport(now, &view, true, None)?;
            self.start_other_transports(now, parsed, true)?;
            self.settle_dtls_session();
        } else {
            self.defer_remote_transport(&view)?;
            if self.pipeline_context.transports.len() > 1 {
                self.defer_other_remote_transports(parsed)?;
            }
        }
        Ok(())
    }

    /// `set_local_description` of an answer: the layout the answer settles, then the
    /// default transport takes the remote offer's parameters as it did with one transport,
    /// and every other transport is set up from its sections of the offer.
    pub(crate) fn apply_local_answer_transports(
        &mut self,
        now: Instant,
        local_answer: Option<&SessionDescription>,
    ) -> Result<()> {
        let groups = local_answer.map(transport_groups).unwrap_or_default();
        if self.pipeline_context.transports.len() > 1 {
            self.apply_transport_layout(&groups)?;
        }
        let remote = self.remote_description().and_then(|r| r.parsed.clone());
        if let Some(pending) = self.pending_remote_transport.take()
            && let Some(parsed) = &remote
        {
            // The offer's sections the answer accepted on the default transport: a section
            // the answer rejected (under `balanced`, a second one of a type offered outside a
            // BUNDLE group) is no transport's.
            let transports = &self.pipeline_context.transports;
            let default = transports.default_id();
            let accepted: Vec<String> = groups
                .iter()
                .flatten()
                .filter(|mid| transports.transport_id_for(mid) == default)
                .cloned()
                .collect();
            let live = transport_groups(parsed);
            let view = if local_answer.is_none()
                || live.iter().flatten().all(|mid| accepted.contains(mid))
            {
                self.default_transport_view(parsed)
            } else {
                description_for(parsed, &accepted)
            };
            self.apply_remote_transport(now, &view, false, Some(pending.ice_restart))?;
        }
        if let Some(parsed) = &remote {
            self.start_other_transports(now, parsed, false)?;
        }
        self.settle_dtls_session();
        Ok(())
    }

    /// RFC 5764 section 3 is about the transports a negotiation sets up: once a description
    /// has started them, no later association joins the connection's DTLS session, and those
    /// it admitted take part when their DTLS role has more than one of them
    /// (`DtlsTransport::engage_session`). A connection with one transport (every section
    /// bundled) has nothing to share: it runs as it would without the session, asking for and
    /// issuing no ticket.
    fn settle_dtls_session(&mut self) {
        let default = &self
            .pipeline_context
            .transports
            .default()
            .dtls_handler_context
            .dtls_transport;
        if default.state == RTCDtlsTransportState::New {
            return;
        }
        let Some(group) = default.resumption.clone() else {
            return;
        };
        group.close_admission();
        for bundle in self.pipeline_context.transports.iter_mut() {
            let transport = &mut bundle.dtls_handler_context.dtls_transport;
            if let Err(err) = transport.engage_session() {
                log::warn!("a transport runs outside the connection's DTLS session: {err}");
            }
        }
        group.settle();
    }

    /// Gives every transport but the default one the parameters of its sections of the remote
    /// description: the first time it starts it, later it follows them as the default
    /// transport does (`apply_remote_transport`).
    fn start_other_transports(
        &mut self,
        now: Instant,
        parsed: &SessionDescription,
        we_offer: bool,
    ) -> Result<()> {
        let default = self.pipeline_context.transports.default_id();
        for id in self.pipeline_context.transports.ids() {
            if id == default {
                continue;
            }
            let mids = self.pipeline_context.transports.mids_on(id);
            let part = description_for(parsed, &mids);
            if part.media_descriptions.is_empty() {
                continue;
            }
            self.with_transport(id, |pc| {
                pc.apply_remote_transport(now, &part, we_offer, None)
            })?;
        }
        Ok(())
    }

    /// The transports of an offer this side makes (RFC 9429 sections 4.1.1 and 5.2.1: "each
    /// m= section that is not bundle-only has its own ICE credentials and candidates").
    ///
    /// - `max-compat` gathers "for each media track": each section that has no transport yet
    ///   gets one of its own, in every offer.
    /// - `balanced` (the default) gathers "for each media type in use": in an initial offer the
    ///   first section of each type has a transport of its own and the later ones are
    ///   bundle-only, on the BUNDLE transport. A later offer gives a new section the BUNDLE
    ///   transport, or a transport of its own when the offer puts it in a group of new
    ///   sections only (a new BUNDLE group, as after an answer without BUNDLE).
    /// - `must-bundle` gathers for one track: every section but the first is bundle-only.
    ///
    /// A section keeps the transport it has. The first section of an initial offer keeps the
    /// connection's first transport.
    pub(crate) fn plan_offer_transports(&mut self, d: &SessionDescription) -> Result<()> {
        let own_transports = self.effective_bundle_policy() == RTCBundlePolicy::MaxCompat;
        // An initial BUNDLE offer (RFC 9143 section 2): no offer/answer exchange completed.
        let initial = self.is_initial_exchange();
        let transports = &self.pipeline_context.transports;
        // RFC 9143 section 7.5.2: a section this offer moves out of its BUNDLE group (outside
        // every group of `d` and on the transport of a section still in one) gets a transport
        // of its own; the group keeps its transport. Only sections that have a transport
        // count: a section new in this offer has none yet, and a group of new sections alone
        // moves nothing out of the transport the others are on.
        let offered_groups = bundle_groups(d);
        let grouped = |mid: &str| offered_groups.iter().any(|group| group.contains(&mid));
        // The sections the current exchange negotiated: one with no assignment of its own is
        // on the default transport (a single transport assigns none).
        let negotiated: Vec<String> = self
            .current_local_description
            .as_ref()
            .and_then(|desc| desc.parsed.as_ref())
            .map(|parsed| {
                parsed
                    .media_descriptions
                    .iter()
                    .filter(|m| !is_rejected_media(m))
                    .filter_map(|m| get_mid_value(m).cloned())
                    .collect()
            })
            .unwrap_or_default();
        let on = |mid: &str| {
            transports.assignment(mid).or_else(|| {
                negotiated
                    .iter()
                    .any(|known| known == mid)
                    .then(|| transports.default_id())
            })
        };
        let moved_out = |mid: &str| {
            !initial
                && !grouped(mid)
                && on(mid).is_some()
                && d.media_descriptions.iter().any(|m| {
                    !is_rejected_media(m)
                        && get_mid_value(m).is_some_and(|other| {
                            other != mid && grouped(other) && on(other) == on(mid)
                        })
                })
        };
        // A group of the offer none of whose sections has a transport is a new BUNDLE group
        // (RFC 9143 section 5: a description may carry several, each a transport): its tagged
        // section is not bundle-only and has a transport of its own, which the group's other
        // new sections share. `new_groups` maps such an offered group to its entry in
        // `groups`.
        let new_group_of = |mid: &str| {
            offered_groups.iter().position(|group| {
                group.contains(&mid) && group.iter().all(|other| on(other).is_none())
            })
        };
        let mut new_groups: Vec<(usize, usize)> = vec![];
        let mut groups: Vec<(Option<TransportId>, Vec<String>)> = vec![];
        // The indexes in `groups` of the sections moved out, in order.
        let mut moved: Vec<usize> = vec![];
        // The group a section without a transport of its own joins: the BUNDLE transport's.
        let mut bundle_group: Option<usize> = None;
        for m in &d.media_descriptions {
            if is_rejected_media(m) {
                continue;
            }
            let Some(mid) = get_mid_value(m) else {
                continue;
            };
            let bundle_only = m.attribute(ATTR_KEY_BUNDLE_ONLY).is_some();
            let index = match transports.assignment(mid) {
                _ if moved_out(mid) => None,
                Some(id) => groups
                    .iter()
                    .position(|(on, _)| *on == Some(id))
                    .or_else(|| {
                        groups.push((Some(id), vec![]));
                        Some(groups.len() - 1)
                    }),
                // A bundle-only section has no transport of its own (RFC 9143 section 6).
                None if bundle_only => bundle_group,
                // A section of an initial offer that is not bundle-only has one; in a later
                // offer, only under `max-compat`, or in a new BUNDLE group of the offer.
                None if own_transports || initial => None,
                // So has a new section the offer keeps outside every BUNDLE group although it
                // has groups (`set_bundle_request(Some(false))`, RFC 9143 section 7.5.2; a
                // FEC session's section, RFC 5109 section 14.1).
                None if !offered_groups.is_empty() && !grouped(mid) => None,
                None => match new_group_of(mid) {
                    Some(offered) => new_groups
                        .iter()
                        .find(|(group, _)| *group == offered)
                        .map(|(_, index)| *index)
                        .or_else(|| {
                            groups.push((None, vec![]));
                            new_groups.push((offered, groups.len() - 1));
                            Some(groups.len() - 1)
                        }),
                    None => bundle_group,
                },
            };
            let index = index.unwrap_or_else(|| {
                groups.push((None, vec![]));
                groups.len() - 1
            });
            groups[index].1.push(mid.clone());
            if moved_out(mid) {
                moved.push(index);
            } else {
                bundle_group.get_or_insert(index);
            }
        }
        // The sections moved out last: the group keeps the transport it has.
        let mut moved_groups = vec![];
        for index in moved.into_iter().rev() {
            moved_groups.insert(0, groups.remove(index));
        }
        groups.extend(moved_groups);
        // The default transport's group first: it is the one the first section had.
        let default = transports.default_id();
        if let Some(index) = groups.iter().position(|(on, _)| *on == Some(default)) {
            let group = groups.remove(index);
            groups.insert(0, group);
        }
        let groups: Vec<Vec<String>> = groups
            .into_iter()
            .map(|(_, group)| group)
            .filter(|group| !group.is_empty())
            .collect();
        if groups.len() <= 1 && self.pipeline_context.transports.len() == 1 {
            // One transport for everything, as the connection has.
            return Ok(());
        }
        self.apply_transport_layout(&groups)
    }

    /// Writes into a description this side generates each transport's own ICE attributes in
    /// the sections on a transport other than the default one that carry transport attributes:
    /// its credentials, its candidates (in its first such section, RFC 9429 section 5.2.1)
    /// and its default destination in `m=` / `c=`. The default transport's sections keep what
    /// `populate_sdp` wrote.
    ///
    /// `offer` is `Some` while an offer (`true`) or an answer (`false`) is being made: a
    /// transport with an ICE restart staged lists the candidates
    /// [`Self::restart_offered_local_candidates`] gives, as the default transport does
    /// (`offered_local_candidates`). `None` when a description already set is read back
    /// (`populate_local_candidates`): the candidates the transport holds.
    pub(crate) fn write_transport_attributes(
        &self,
        d: &mut SessionDescription,
        offer: Option<bool>,
    ) {
        let transports = &self.pipeline_context.transports;
        if transports.len() == 1 {
            return;
        }
        let default = transports.default_id();
        // RFC 8842 section 5: `a=tls-id` names each transport's own DTLS association; a
        // description that carries one (in the default transport's tagged section) gives every
        // transport its own.
        let with_tls_id = d.media_descriptions.iter().any(|m| {
            !is_rejected_media(m) && m.attributes.iter().any(|a| a.key == ATTR_KEY_TLS_ID)
        });
        // `tls-id` is IDENTICAL (RFC 8842 section 4, RFC 9143 section 7.1.3): within a BUNDLE
        // group it is the tagged section's, which the group keeps once it is answered. A
        // transport speaks with its own only in a section outside every group, or as the tag
        // of a group of its own (several groups, RFC 9143 section 5).
        let groups: Vec<Vec<String>> = bundle_groups(d)
            .into_iter()
            .map(|group| group.into_iter().map(str::to_owned).collect())
            .collect();
        let speaks_for_itself = |mid: &str, id: TransportId| {
            groups
                .iter()
                .find(|group| group.iter().any(|m| m == mid))
                .is_none_or(|group| {
                    group
                        .first()
                        .is_some_and(|tag| transports.transport_id_for(tag) == id)
                })
        };
        for id in transports.ids() {
            if id == default {
                continue;
            }
            let Some(bundle) = transports.transport(id) else {
                continue;
            };
            let dtls = &bundle.dtls_handler_context.dtls_transport;
            let tls_id = dtls
                .staged_local_tls_id
                .clone()
                .unwrap_or_else(|| dtls.local_tls_id.clone());
            let ice = &bundle.ice_handler_context.ice_transport;
            let (ufrag, pwd) = ice.get_local_user_credentials();
            let staged = match offer {
                Some(offer) => self
                    .restart_offered_local_candidates(id, offer)
                    .unwrap_or_default(),
                None => None,
            };
            let candidates = staged.unwrap_or_else(|| {
                rtc_ice_candidates_from_ice_candidates(&ice.agent.get_local_candidates_to_signal())
            });
            let mut first = true;
            for m in &mut d.media_descriptions {
                if is_rejected_media(m)
                    || !get_mid_value(m).is_some_and(|mid| transports.transport_id_for(mid) == id)
                {
                    continue;
                }
                // Only the sections that carry the transport's attributes: in an answer and a
                // later offer that is the tagged section of the group alone (RFC 9143 section
                // 7.1.3), in an initial offer every section that is not bundle-only.
                if m.attribute("ice-ufrag").is_none() {
                    continue;
                }
                // Media-level `a=ice-options` (`with_ice_options_in_media_sections`) stays
                // after `a=ice-pwd`, where it was written.
                let ice_options = m
                    .attributes
                    .iter()
                    .position(|a| a.key == "ice-options")
                    .map(|at| m.attributes.remove(at));
                m.attributes.retain(|a| {
                    !TRANSPORT_ICE_ATTRIBUTES.contains(&a.key.as_str()) && a.key != ATTR_KEY_TLS_ID
                });
                // The dummy destination until the transport has a candidate (RFC 9429 section
                // 5.2.1: port 9, `c=IN IP4 0.0.0.0` and `a=rtcp:9 IN IP4 0.0.0.0`), not the
                // default transport's.
                set_default_destination(m, std::net::Ipv4Addr::UNSPECIFIED.into(), 9);
                m.attributes.push(Attribute::new(
                    "ice-ufrag".to_owned(),
                    Some(ufrag.to_owned()),
                ));
                m.attributes
                    .push(Attribute::new("ice-pwd".to_owned(), Some(pwd.to_owned())));
                m.attributes.extend(ice_options);
                if first {
                    first = false;
                    if with_tls_id && get_mid_value(m).is_some_and(|mid| speaks_for_itself(mid, id))
                    {
                        m.attributes.push(Attribute::new(
                            ATTR_KEY_TLS_ID.to_owned(),
                            Some(tls_id.clone()),
                        ));
                    }
                    let taken = std::mem::take(m);
                    *m = match add_candidates_to_media_descriptions(
                        &candidates,
                        taken.clone(),
                        ice.ice_gathering_state,
                    ) {
                        Ok(with) => with,
                        Err(_) => taken,
                    };
                }
            }
        }
    }

    /// Where a local or remote candidate goes: the transport of the section its `sdpMid` (or
    /// `sdpMLineIndex`, in `desc`) names; the default one without either.
    pub(crate) fn transport_of_candidate(
        &self,
        sdp_mid: Option<&str>,
        sdp_mline_index: Option<u16>,
        desc: Option<&SessionDescription>,
    ) -> TransportId {
        let transports = &self.pipeline_context.transports;
        let mid = sdp_mid.map(str::to_owned).or_else(|| {
            let index = usize::from(sdp_mline_index?);
            desc?
                .media_descriptions
                .get(index)
                .and_then(get_mid_value)
                .cloned()
        });
        mid.map_or(transports.default_id(), |mid| {
            transports.transport_id_for(&mid)
        })
    }

    /// The local description's first section on each transport other than the default one:
    /// the `sdpMid` / `sdpMLineIndex` its candidates name (W3C 5.6), recorded on the
    /// transport when a local description is set. Such a transport starts gathering its
    /// generation then, with its events (W3C 5.6 "gathering begins").
    pub(crate) fn describe_other_transports(&mut self, local: &SessionDescription) {
        let default = self.pipeline_context.transports.default_id();
        for id in self.pipeline_context.transports.ids() {
            if id == default {
                continue;
            }
            let section = local
                .media_descriptions
                .iter()
                .enumerate()
                .find_map(|(index, m)| {
                    let mid = get_mid_value(m)?;
                    (self.pipeline_context.transports.transport_id_for(mid) == id)
                        .then(|| (mid.clone(), u16::try_from(index).unwrap_or(u16::MAX)))
                });
            self.with_transport(id, |pc| {
                if section.is_some() {
                    pc.ice_transport_mut().local_media_section = section;
                }
                pc.begin_gathering_generation();
            });
        }
    }

    /// The local candidates of every transport other than the default one, in the local
    /// description as it is read (`populate_local_candidates`).
    pub(crate) fn populate_other_transports_candidates(&self, d: &mut SessionDescription) {
        self.write_transport_attributes(d, None);
    }

    /// The connection's mDNS mode (`SettingEngineBuilder::with_multicast_dns_mode`): with
    /// `QueryAndGather` its host candidates go out under `.local` names, which an application
    /// with sockets of its own needs mDNS sockets for (see
    /// [`set_multicast_dns_publishing`](Self::set_multicast_dns_publishing)).
    pub fn multicast_dns_mode(&self) -> ice::mdns::MulticastDnsMode {
        self.setting_engine.multicast_dns.mode
    }

    /// Tells the connection for which address families the application can send mDNS: an
    /// mDNS socket (port 5353, joined to 224.0.0.251 or ff02::fb) is open for it. Both, until
    /// this is called. With `QueryAndGather` the host candidates added afterwards on an
    /// address of a family it cannot send on get no published name
    /// (draft-ietf-mmusic-mdns-ice-candidates section 3.1.1 step 4 fails): they go out under a
    /// `.local` name that is not published, or, with
    /// [`with_multicast_dns_fail_closed`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_multicast_dns_fail_closed),
    /// not at all. Call it before adding the host candidates; it holds for every transport,
    /// those made later included, and names registered before stay.
    pub fn set_multicast_dns_publishing(&mut self, publishing: ice::mdns::MulticastDnsPublishing) {
        self.mdns_publishing = publishing;
        for bundle in self.pipeline_context.transports.iter_mut() {
            bundle
                .ice_handler_context
                .ice_transport
                .agent
                .set_multicast_dns_publishing(publishing);
        }
    }

    /// Declares, for every transport (those made later included), whether the application
    /// hands each mDNS datagram to `handle_read` with its destination address in `local_addr`
    /// (as `SettingEngineBuilder::with_multicast_dns_destination_reported`, for a driver that
    /// knows it): the mDNS group's for one that arrived by multicast, which RFC 6762 section 11
    /// deems on the link whatever its source, the host's own for a unicast one, the unspecified
    /// address when it does not know. `rtci-stream-driver`'s `PeerDriver` declares it.
    pub fn set_multicast_dns_destination_reported(&mut self, reported: bool) {
        self.mdns_destination_reported = Some(reported);
        for bundle in self.pipeline_context.transports.iter_mut() {
            bundle
                .ice_handler_context
                .ice_transport
                .agent
                .set_multicast_dns_destination_reported(reported);
        }
    }

    /// Marks which local addresses are RFC 4941 temporary IPv6 addresses (replacing what was
    /// marked before); only the operating system knows, the engine cannot tell from the
    /// bits. With
    /// [`with_multicast_dns_expose_temporary_ipv6_addresses`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_multicast_dns_expose_temporary_ipv6_addresses)
    /// and `QueryAndGather`, the host candidates added afterwards on a marked global unicast
    /// address keep their address (draft-ietf-mmusic-mdns-ice-candidates section 3.1.2.3);
    /// otherwise it changes nothing. Call it before adding the host candidates; it holds for
    /// every transport, those made later included. `rtci-stream-driver`'s `PeerDriver` calls
    /// it from the interface list where the operating system reports the flag.
    pub fn set_temporary_ipv6_addresses(&mut self, addresses: Vec<std::net::Ipv6Addr>) {
        for bundle in self.pipeline_context.transports.iter_mut() {
            bundle
                .ice_handler_context
                .ice_transport
                .agent
                .set_temporary_ipv6_addresses(addresses.clone());
        }
        self.temporary_ipv6_addresses = addresses;
    }

    /// The connection's transports: for each, the mid and m= line index of its first section,
    /// the one whose `sdpMid` / `sdpMLineIndex` its candidates carry, the default transport
    /// first. The sections are those of the local description, or of the remote offer before
    /// it is answered. While every section is bundled there is one entry; before any
    /// description, none.
    ///
    /// RFC 9429 section 5.2.1 gives each transport candidates of its own: the application
    /// gathers for every entry, on local addresses no other transport uses, and passes each
    /// candidate to [`add_local_candidate`](Self::add_local_candidate) with that `sdp_mid`.
    pub fn ice_transport_sections(&self) -> Vec<(String, u16)> {
        let desc = self
            .pending_local_description
            .as_ref()
            .or(self.current_local_description.as_ref())
            .or(self.pending_remote_description.as_ref())
            .or(self.current_remote_description.as_ref())
            .and_then(|d| d.parsed.as_ref());
        let Some(desc) = desc else {
            return vec![];
        };
        let transports = &self.pipeline_context.transports;
        let mut seen: Vec<TransportId> = vec![];
        let mut sections: Vec<(TransportId, String, u16)> = vec![];
        for (index, m) in desc.media_descriptions.iter().enumerate() {
            if is_rejected_media(m) {
                continue;
            }
            let Some(mid) = get_mid_value(m) else {
                continue;
            };
            let id = transports.transport_id_for(mid);
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            sections.push((id, mid.clone(), u16::try_from(index).unwrap_or(u16::MAX)));
        }
        let default = transports.default_id();
        sections.sort_by_key(|(id, _, _)| *id != default);
        sections
            .into_iter()
            .map(|(_, mid, index)| (mid, index))
            .collect()
    }

    /// The connection's DTLS transports, one per transport, the default one first: the
    /// objects the senders', receivers' and SCTP transport's `transport()` return (W3C
    /// webrtc-pc 5.2 `RTCRtpSender.transport`, 6.1 `RTCSctpTransport.transport`). One while
    /// every section is bundled.
    pub fn dtls_transports(&self) -> Vec<RTCDtlsTransport<'_>> {
        let transports = &self.pipeline_context.transports;
        let default = transports.default_id();
        let mut ids = transports.ids();
        ids.sort_by_key(|id| *id != default);
        ids.into_iter()
            .map(|transport| RTCDtlsTransport {
                peer_connection: self,
                transport,
            })
            .collect()
    }

    /// The DTLS transport whose id, or whose ICE transport's id, is `id` (an
    /// [`RTCTransportEvent`](crate::peer_connection::event::RTCTransportEvent) names both);
    /// `None` for a transport the connection does not have (any more).
    pub fn dtls_transport_by_id(&self, id: RTCTransportId) -> Option<RTCDtlsTransport<'_>> {
        let transports = &self.pipeline_context.transports;
        transports
            .ids()
            .into_iter()
            .find(|transport| {
                transports.transport(*transport).is_some_and(|bundle| {
                    bundle.dtls_handler_context.dtls_transport.id == id
                        || bundle.ice_handler_context.ice_transport.id == id
                })
            })
            .map(|transport| RTCDtlsTransport {
                peer_connection: self,
                transport,
            })
    }

    /// The mids of the transceivers whose section is on the active transport; `None` while
    /// the connection has one transport.
    ///
    /// While a local offer is pending they include the sections that offer lists in a BUNDLE
    /// group with one of them, although the offer stages such a section on a transport of
    /// its own: RFC 9143 section 7.2, "When the offerer assigns unique addresses:ports to
    /// multiple bundled 'm=' sections, the offerer needs to be prepared to receive bundled
    /// media on each unique address:port until it receives the associated answer". An
    /// answerer that bundles the section sends its media on the group's transport before the
    /// offerer has seen the answer that says so.
    pub(crate) fn active_transport_mids(&self) -> Option<Vec<String>> {
        let transports = &self.pipeline_context.transports;
        if transports.len() == 1 {
            return None;
        }
        let active = transports.active_id();
        let mut mids: Vec<String> = self
            .rtp_transceivers
            .iter()
            .filter_map(|t| t.mid().clone())
            .filter(|mid| transports.transport_id_for(mid) == active)
            .collect();
        if let Some(offer) = self
            .pending_local_description
            .as_ref()
            .filter(|description| description.sdp_type == RTCSdpType::Offer)
            .and_then(|description| description.parsed.as_ref())
        {
            for group in bundle_groups(offer) {
                if group.iter().any(|mid| mids.iter().any(|on| on == mid)) {
                    for mid in group {
                        if !mids.iter().any(|on| on == mid) {
                            mids.push(mid.to_owned());
                        }
                    }
                }
            }
        }
        Some(mids)
    }
}
