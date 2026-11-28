//! An ICE restart that can be taken back: the local offer that asked for it was rolled back
//! (RFC 9429 section 5.7).

use super::*;

/// What [`Agent::apply_restart`] replaced, kept by [`Agent::apply_restart_revertible`] until
/// the restart is committed ([`Agent::commit_restart`]) or taken back
/// ([`Agent::revert_restart`]).
#[derive(Clone)]
pub(crate) struct RestartUndo {
    connection_state: ConnectionState,
    local_credentials: Credentials,
    remote_credentials: Option<Credentials>,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
    candidate_pairs: Vec<CandidatePair>,
    nominated_pair: Option<usize>,
    selected_pair: Option<usize>,
    previous_media_path: Option<MediaPath>,
    previous_generation: Option<PreviousGeneration>,
    pending_binding_requests: Vec<BindingRequest>,
    early_requests: Vec<EarlyRequest>,
    triggered_queue: VecDeque<(usize, usize)>,
    remote_end_of_candidates: bool,
    local_gathering_complete: bool,
    lite_update_raised: bool,
    lite_update_taken: bool,
    next_check_at: Instant,
    next_consent_at: Option<Instant>,
    consent_unanswered_since: Option<Instant>,
    checking_duration: Instant,
    last_checking_time: Instant,
    tie_breaker: u64,
    ice_generation: u64,
    mdns_known_public: KnownPublicAddresses,
}

impl Agent {
    /// [`Agent::apply_restart`], remembering the session it replaces so that
    /// [`Agent::revert_restart`] can bring it back: the restart belongs to a local offer that
    /// may still be rolled back (RFC 9429 section 5.7: "any resources allocated by the
    /// abandoned local description are discarded"). A second restart before the first is
    /// committed keeps the session the first one replaced.
    pub fn apply_restart_revertible(
        &mut self,
        now: Instant,
        keep_local_candidates: bool,
    ) -> Result<()> {
        let undo = match self.restart_undo.take() {
            Some(undo) => undo,
            None => Box::new(RestartUndo {
                connection_state: self.connection_state,
                local_credentials: self.ufrag_pwd.local_credentials.clone(),
                remote_credentials: self.ufrag_pwd.remote_credentials.clone(),
                local_candidates: self.local_candidates.clone(),
                remote_candidates: self.remote_candidates.clone(),
                candidate_pairs: self.candidate_pairs.clone(),
                nominated_pair: self.nominated_pair,
                selected_pair: self.selected_pair,
                previous_media_path: self.previous_media_path,
                previous_generation: self.previous_generation.clone(),
                pending_binding_requests: self.pending_binding_requests.clone(),
                early_requests: self.early_requests.clone(),
                triggered_queue: self.triggered_queue.clone(),
                remote_end_of_candidates: self.remote_end_of_candidates,
                local_gathering_complete: self.local_gathering_complete,
                lite_update_raised: self.lite_update_raised,
                lite_update_taken: self.lite_update_taken,
                next_check_at: self.next_check_at,
                next_consent_at: self.next_consent_at,
                consent_unanswered_since: self.consent_unanswered_since,
                checking_duration: self.checking_duration,
                last_checking_time: self.last_checking_time,
                tie_breaker: self.tie_breaker,
                ice_generation: self.ice_generation,
                mdns_known_public: self.mdns_known_public.clone(),
            }),
        };
        self.apply_restart(now, keep_local_candidates)?;
        self.restart_undo = Some(undo);
        Ok(())
    }

    /// Whether a restart applied by [`Agent::apply_restart_revertible`] can still be taken
    /// back.
    pub fn has_revertible_restart(&self) -> bool {
        self.restart_undo.is_some()
    }

    /// Keeps the restart [`Agent::apply_restart_revertible`] applied: the answer to its offer
    /// arrived. A no-op without one.
    pub fn commit_restart(&mut self) {
        self.restart_undo = None;
    }

    /// Takes back the restart [`Agent::apply_restart_revertible`] applied: the local offer was
    /// rolled back, so the agent goes on with the session it had (RFC 9429 section 5.7),
    /// its credentials, candidates, pairs and selected pair, and what the new generation
    /// gathered or learned is dropped. Consent on the selected pair carries over what the
    /// previous-generation checks of the meantime established (RFC 7675). Returns whether there
    /// was a restart to take back; a closed agent stays closed.
    pub fn revert_restart(&mut self, now: Instant) -> bool {
        let Some(undo) = self.restart_undo.take() else {
            return false;
        };
        if self.connection_state == ConnectionState::Closed {
            return false;
        }
        let undo = *undo;
        // The consent the old path kept in the meantime.
        let kept_consent = self
            .previous_generation
            .as_ref()
            .map(|previous| (previous.last_consent, previous.next_consent_at));

        self.announce_all_pairs_removed();
        self.ufrag_pwd.local_credentials = undo.local_credentials;
        self.ufrag_pwd.remote_credentials = undo.remote_credentials;
        self.ufrag_pwd.pending_local_credentials = None;
        self.local_candidates = undo.local_candidates;
        // The snapshot was taken while the restart was staged: what was gathered for it
        // belongs to no generation now.
        for c in &mut self.local_candidates {
            c.restart_generation = false;
        }
        self.remote_candidates = undo.remote_candidates;
        self.candidate_pairs = undo.candidate_pairs;
        self.nominated_pair = undo.nominated_pair;
        self.selected_pair = undo.selected_pair;
        self.previous_media_path = undo.previous_media_path;
        self.previous_generation = undo.previous_generation;
        self.pending_binding_requests = undo.pending_binding_requests;
        self.early_requests = undo.early_requests;
        self.triggered_queue = undo.triggered_queue;
        self.remote_end_of_candidates = undo.remote_end_of_candidates;
        // The generation taken back is gone: what its gathering showed public with it.
        self.ice_generation = undo.ice_generation;
        self.mdns_known_public = undo.mdns_known_public;
        self.local_gathering_complete = undo.local_gathering_complete;
        self.lite_update_raised = undo.lite_update_raised;
        self.lite_update_taken = undo.lite_update_taken;
        self.next_check_at = undo.next_check_at.max(now);
        self.next_consent_at = undo.next_consent_at;
        self.consent_unanswered_since = undo.consent_unanswered_since;
        self.checking_duration = undo.checking_duration;
        self.last_checking_time = undo.last_checking_time;
        self.tie_breaker = undo.tie_breaker;

        if let (Some(pair_index), Some((last_consent, next_consent_at))) =
            (self.selected_pair, kept_consent)
        {
            let remote_index = self.candidate_pairs[pair_index].remote_index;
            let remote = &mut self.remote_candidates[remote_index];
            if self.lite {
                if remote.last_authenticated.is_none_or(|t| t < last_consent) {
                    remote.last_authenticated = Some(last_consent);
                }
            } else {
                if remote.last_consent.is_none_or(|t| t < last_consent) {
                    remote.last_consent = Some(last_consent);
                }
                let pair = &mut self.candidate_pairs[pair_index];
                if pair.last_consent.is_none_or(|t| t < last_consent) {
                    pair.last_consent = Some(last_consent);
                }
            }
            self.next_consent_at = Some(next_consent_at);
        }

        for index in 0..self.candidate_pairs.len() {
            self.announce_pair(index, true);
        }
        if let Some(pair_index) = self.selected_pair {
            let pair = self.candidate_pairs[pair_index];
            self.event_outs.push_back(TaggedEvent {
                now,
                event: Event::SelectedCandidatePairChange(
                    Box::new(self.local_candidates[pair.local_index].clone()),
                    Box::new(self.remote_candidates[pair.remote_index].clone()),
                ),
            });
        }
        self.update_connection_state(Some(now), undo.connection_state);
        true
    }
}
