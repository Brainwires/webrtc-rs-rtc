use std::str::FromStr;
use std::time::Instant;
use stun::message::*;
use stun::textattrs::Username;

use super::*;
use crate::attributes::{
    control::AttrControlled, control::AttrControlling, priority::PriorityAttr,
    use_candidate::UseCandidateAttr,
};
use crate::candidate::candidate_host::*;
use crate::candidate::candidate_peer_reflexive::*;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::*;
use crate::candidate::*;

/// Explicit provider for tests. The default-resolving STUN constructors were removed before 1.0,
/// so every `MessageIntegrity` now names its provider.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

#[test]
fn test_pair_search() -> Result<()> {
    let config = Arc::new(AgentConfig::default());
    let mut a = Agent::new(Instant::now(), config, test_crypto_provider())?;

    assert!(
        a.candidate_pairs.is_empty(),
        "TestPairSearch is only a valid test if a.validPairs is empty on construction"
    );

    let cp = a.get_best_available_pair();
    assert!(cp.is_none(), "No Candidate pairs should exist");

    a.close()?;

    Ok(())
}

#[test]
fn test_pair_priority() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let host_local = host_config.new_candidate_host()?;
    a.local_candidates.push(host_local);

    let relay_config = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    };

    let relay_remote = relay_config.new_candidate_relay()?;

    let srflx_config = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19218,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43212,
        ..Default::default()
    };

    let srflx_remote = srflx_config.new_candidate_server_reflexive()?;

    let prflx_config = CandidatePeerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.10.10.2".to_owned(),
            port: 19217,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43211,
    };

    let prflx_remote = prflx_config.new_candidate_peer_reflexive()?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.5".to_owned(),
            port: 12350,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let host_remote = host_config.new_candidate_host()?;

    let remotes: Vec<Candidate> = vec![relay_remote, srflx_remote, prflx_remote, host_remote];
    for remote in remotes {
        a.remote_candidates.push(remote);
    }

    {
        let local = 0;
        for remote in 0..a.remote_candidates.len() {
            if a.find_pair(local, remote).is_none() {
                a.add_pair(local, remote);
            }

            if let Some(p) = a.find_pair(local, remote) {
                a.candidate_pairs[p].state = CandidatePairState::Succeeded;
            }

            if let Some(best_pair) = a.get_best_available_pair() {
                assert_eq!(
                    a.candidate_pairs[best_pair].to_string(),
                    CandidatePair::new(
                        local,
                        remote,
                        a.local_candidates[local].priority(),
                        a.remote_candidates[remote].priority(),
                        a.is_controlling,
                    )
                    .to_string(),
                    "Unexpected bestPair {best_pair} (expected remote: {remote})",
                );
            } else {
                panic!("expected Some, but got None");
            }
        }
    }

    a.close()?;
    Ok(())
}

#[test]
fn test_on_selected_candidate_pair_change() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let host_local = host_config.new_candidate_host()?;
    a.add_local_candidate(host_local)?;

    let relay_config = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    };
    let relay_remote = relay_config.new_candidate_relay()?;
    a.add_remote_candidate(relay_remote)?;

    // select the pair
    let (local, remote) = (0, 0);
    a.add_pair(local, remote);
    a.set_selected_pair(Some(Instant::now()), Some(0));

    // ensure that the callback fired on setting the pair
    let mut is_selected_candidate_pair_change_event_fired = false;
    while let Some(event) = a.poll_event() {
        if let Event::SelectedCandidatePairChange(_, _) = event.event {
            is_selected_candidate_pair_change_event_fired = true;
        }
    }

    assert!(is_selected_candidate_pair_change_event_fired);

    a.close()?;
    Ok(())
}

#[test]
fn test_handle_peer_reflexive_udp_pflx_candidate() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };

    let local_candidate = host_config.new_candidate_host()?;
    let local = 0;
    let local_priority = local_candidate.priority();
    let local_network_type = local_candidate.network_type();
    a.add_local_candidate(local_candidate)?;

    let remote_addr = SocketAddr::from_str("172.17.0.3:999")?;

    let (username, local_pwd, tie_breaker) = {
        a.ufrag_pwd.remote_credentials = Some(Credentials {
            ufrag: "".to_string(),
            pwd: "".to_string(),
        });
        (
            a.ufrag_pwd.local_credentials.ufrag.to_owned() + ":",
            a.ufrag_pwd.local_credentials.pwd.clone(),
            a.tie_breaker,
        )
    };

    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(UseCandidateAttr::new()),
        Box::new(AttrControlling(tie_breaker)),
        Box::new(PriorityAttr(local_priority)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    {
        a.handle_inbound(Instant::now(), &mut msg, local, remote_addr)?;

        // length of remote candidate list must be one now
        assert_eq!(
            a.remote_candidates.len(),
            1,
            "failed to add a network type to the remote candidate list"
        );

        // length of remote candidate list for a network type must be 1
        if let Some(remote_index) = a.find_remote_candidate(remote_addr) {
            let c = &a.remote_candidates[remote_index];

            assert_eq!(
                c.candidate_type(),
                CandidateType::PeerReflexive,
                "candidate type must be prflx"
            );

            assert_eq!(c.address(), "172.17.0.3", "IP address mismatch");

            assert_eq!(c.port(), 999, "Port number mismatch");
        } else {
            panic!(
                "expected non-empty remote candidate for network type {}",
                local_network_type,
            );
        }
    }

    a.close()?;
    Ok(())
}

#[test]
fn test_handle_peer_reflexive_unknown_remote() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let mut tid = TransactionId::default();
    tid.0[..3].copy_from_slice("ABC".as_bytes());

    let remote_pwd = {
        a.pending_binding_requests = vec![BindingRequest::sent_once(
            Instant::now(),
            tid,
            SocketAddr::from_str("0.0.0.0:0")?,
            Duration::from_secs(4),
        )];
        a.ufrag_pwd.remote_credentials = Some(Credentials {
            ufrag: "".to_string(),
            pwd: "".to_string(),
        });
        "".to_string()
    };

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };

    let local = host_config.new_candidate_host()?;
    let local_index = 0;
    a.add_local_candidate(local)?;
    let remote_addr = SocketAddr::from_str("172.17.0.3:999")?;

    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_SUCCESS),
        Box::new(tid),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            remote_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    let result = a.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr);
    assert!(result.is_err());

    assert_eq!(
        a.remote_candidates.len(),
        0,
        "unknown remote was able to create a candidate"
    );

    a.close()?;
    Ok(())
}

#[test]
fn test_zero_failed_timeout_keeps_checking_agent_recoverable() -> Result<()> {
    let base = Instant::now();
    let mut agent = Agent::new(
        base,
        Arc::new(AgentConfig {
            disconnected_timeout: Some(Duration::from_secs(5)),
            failed_timeout: Some(Duration::ZERO),
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;

    agent.connection_state = ConnectionState::Checking;
    agent.last_connection_state = ConnectionState::Checking;
    agent.checking_duration = base;
    agent.contact(base + Duration::from_secs(3600));

    assert_eq!(
        agent.connection_state,
        ConnectionState::Checking,
        "a zero failed timeout is documented to disable the terminal transition"
    );
    Ok(())
}

/// Test role conflict when both agents are controlling
/// RFC 8445 Section 7.3.1.1 - Agent with smaller tiebreaker should switch to controlled
#[test]
fn test_role_conflict_both_controlling_smaller_tiebreaker_switches() -> Result<()> {
    // Create agent with controlling role
    let config = AgentConfig {
        is_controlling: true,
        ..Default::default()
    };
    let mut agent = Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())?;

    // Set a specific tiebreaker value
    agent.tie_breaker = 100;

    // Add local candidate
    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let local_candidate = host_config.new_candidate_host()?;
    let local_index = 0;
    agent.add_local_candidate(local_candidate)?;

    // Add remote candidate
    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let remote_candidate = remote_host_config.new_candidate_host()?;
    agent.add_remote_candidate(remote_candidate)?;

    // Set remote credentials
    agent.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    let username = agent.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = agent.ufrag_pwd.local_credentials.pwd.clone();

    // Create STUN binding request from remote agent (also controlling, with larger tiebreaker)
    let remote_tiebreaker = 200; // Larger than ours (100)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(remote_tiebreaker)), // Remote is also controlling
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    // Agent should be controlling before handling the message
    assert!(
        agent.is_controlling,
        "Agent should be controlling before role conflict"
    );

    // Store initial pair count and priorities
    let initial_pair_count = agent.candidate_pairs.len();
    let initial_priorities: Vec<u64> = agent.candidate_pairs.iter().map(|p| p.priority()).collect();

    // Handle the inbound message - should detect role conflict
    let result = agent.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr);

    // The message should be processed (role conflict handling doesn't stop processing)
    // It may return an error for other reasons, but not for role conflict itself
    let _ = result; // We don't care about the exact error, just that role switching happened

    // Agent should have switched to controlled (because our tiebreaker 100 < 200)
    assert!(
        !agent.is_controlling,
        "Agent should have switched to controlled role (smaller tiebreaker)"
    );

    // Verify that candidate pair priorities were recomputed
    if !agent.candidate_pairs.is_empty() {
        // Check that ice_role_controlling was updated in pairs
        for pair in &agent.candidate_pairs {
            assert!(
                !pair.ice_role_controlling,
                "Candidate pair should have controlling role set to false"
            );
        }

        // Priorities should change when role changes (unless there were no pairs initially)
        if initial_pair_count > 0 && !initial_priorities.is_empty() {
            // At least verify the role was updated in pairs
            assert_eq!(
                agent.candidate_pairs.len(),
                initial_pair_count,
                "Number of pairs should remain the same"
            );
        }
    }

    // Verify nominated pair was cleared
    assert!(
        agent.nominated_pair.is_none(),
        "Nominated pair should be cleared after role switch"
    );

    agent.close()?;
    Ok(())
}

/// Test role conflict when both agents are controlling
/// RFC 8445 Section 7.3.1.1 - Agent with larger tiebreaker should keep controlling role
#[test]
fn test_role_conflict_both_controlling_larger_tiebreaker_stays() -> Result<()> {
    // Create agent with controlling role
    let config = AgentConfig {
        is_controlling: true,
        ..Default::default()
    };
    let mut agent = Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())?;

    // Set a larger tiebreaker value
    agent.tie_breaker = 500;

    // Add local candidate
    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let local_candidate = host_config.new_candidate_host()?;
    let local_index = 0;
    agent.add_local_candidate(local_candidate)?;

    // Add remote candidate
    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let remote_candidate = remote_host_config.new_candidate_host()?;
    agent.add_remote_candidate(remote_candidate)?;

    // Set remote credentials
    agent.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    let username = agent.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = agent.ufrag_pwd.local_credentials.pwd.clone();

    // Create STUN binding request from remote agent (also controlling, with smaller tiebreaker)
    let remote_tiebreaker = 100; // Smaller than ours (500)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(remote_tiebreaker)), // Remote is also controlling
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    // Agent should be controlling before handling the message
    assert!(
        agent.is_controlling,
        "Agent should be controlling before role conflict"
    );

    // Handle the inbound message - should detect role conflict but NOT switch
    let _ = agent.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr);

    // Agent should remain controlling (because our tiebreaker 500 > 100)
    assert!(
        agent.is_controlling,
        "Agent should remain controlling (larger tiebreaker)"
    );

    // Verify candidate pairs still have controlling role
    for pair in &agent.candidate_pairs {
        assert!(
            pair.ice_role_controlling,
            "Candidate pair should still have controlling role set to true"
        );
    }

    agent.close()?;
    Ok(())
}

/// A controlling agent must answer a Binding request that carries USE-CANDIDATE but no
/// ICE-CONTROLLING, and ignore the USE-CANDIDATE (RFC 8445 7.3.1.5). Peers that always act as
/// controlling send checks in this shape.
#[test]
fn test_controlling_agent_answers_use_candidate_without_ice_controlling() -> Result<()> {
    let config = AgentConfig {
        is_controlling: true,
        ..Default::default()
    };
    let mut agent = Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())?;

    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    agent.add_local_candidate(host_config.new_candidate_host()?)?;
    let local_index = 0;

    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    agent.add_remote_candidate(remote_host_config.new_candidate_host()?)?;

    agent.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    let username = agent.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = agent.ufrag_pwd.local_credentials.pwd.clone();

    // USE-CANDIDATE without ICE-CONTROLLING.
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(UseCandidateAttr::new()),
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;
    let request_id = msg.transaction_id;

    agent.write_outs.clear();
    agent.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr)?;

    let transmit = agent
        .write_outs
        .pop_front()
        .expect("controlling agent must answer the check");
    let mut response = Message::new();
    response.unmarshal_binary(&transmit.message)?;
    assert_eq!(response.typ, BINDING_SUCCESS);
    assert_eq!(response.transaction_id, request_id);

    // USE-CANDIDATE is ignored: no role switch and no nomination.
    assert!(agent.is_controlling);
    assert!(agent.nominated_pair.is_none());
    assert!(agent.get_selected_pair().is_none());

    agent.close()?;
    Ok(())
}

/// Test role conflict when both agents are controlled
/// RFC 8445 Section 7.3.1.1 - Agent with larger tiebreaker should switch to controlling
#[test]
fn test_role_conflict_both_controlled_larger_tiebreaker_switches() -> Result<()> {
    use crate::attributes::control::AttrControlled;

    // Create agent with controlled role
    let config = AgentConfig {
        is_controlling: false, // Controlled
        ..Default::default()
    };
    let mut agent = Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())?;

    // Set a larger tiebreaker value
    agent.tie_breaker = 500;

    // Add local candidate
    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let local_candidate = host_config.new_candidate_host()?;
    let local_index = 0;
    agent.add_local_candidate(local_candidate)?;

    // Add remote candidate
    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let remote_candidate = remote_host_config.new_candidate_host()?;
    agent.add_remote_candidate(remote_candidate)?;

    // Set remote credentials
    agent.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    let username = agent.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = agent.ufrag_pwd.local_credentials.pwd.clone();

    // Create STUN binding request from remote agent (also controlled, with smaller tiebreaker)
    let remote_tiebreaker = 100; // Smaller than ours (500)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlled(remote_tiebreaker)), // Remote is also controlled
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    // Agent should be controlled before handling the message
    assert!(
        !agent.is_controlling,
        "Agent should be controlled before role conflict"
    );

    // Handle the inbound message - should detect role conflict
    let _ = agent.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr);

    // Agent should have switched to controlling (because our tiebreaker 500 > 100)
    assert!(
        agent.is_controlling,
        "Agent should have switched to controlling role (larger tiebreaker)"
    );

    // Verify that candidate pair priorities were recomputed
    for pair in &agent.candidate_pairs {
        assert!(
            pair.ice_role_controlling,
            "Candidate pair should have controlling role set to true"
        );
    }

    // Verify nominated pair was cleared
    assert!(
        agent.nominated_pair.is_none(),
        "Nominated pair should be cleared after role switch"
    );

    agent.close()?;
    Ok(())
}

/// Test role conflict when both agents are controlled
/// RFC 8445 Section 7.3.1.1 - Agent with smaller tiebreaker should stay controlled
#[test]
fn test_role_conflict_both_controlled_smaller_tiebreaker_stays() -> Result<()> {
    use crate::attributes::control::AttrControlled;

    // Create agent with controlled role
    let config = AgentConfig {
        is_controlling: false, // Controlled
        ..Default::default()
    };
    let mut agent = Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())?;

    // Set a smaller tiebreaker value
    agent.tie_breaker = 100;

    // Add local candidate
    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let local_candidate = host_config.new_candidate_host()?;
    let local_index = 0;
    agent.add_local_candidate(local_candidate)?;

    // Add remote candidate
    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let remote_candidate = remote_host_config.new_candidate_host()?;
    agent.add_remote_candidate(remote_candidate)?;

    // Set remote credentials
    agent.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    let username = agent.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = agent.ufrag_pwd.local_credentials.pwd.clone();

    // Create STUN binding request from remote agent (also controlled, with larger tiebreaker)
    let remote_tiebreaker = 500; // Larger than ours (100)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlled(remote_tiebreaker)), // Remote is also controlled
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    // Agent should be controlled before handling the message
    assert!(
        !agent.is_controlling,
        "Agent should be controlled before role conflict"
    );

    // Handle the inbound message - should detect role conflict but NOT switch
    let _ = agent.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr);

    // Agent should remain controlled (because our tiebreaker 100 < 500)
    assert!(
        !agent.is_controlling,
        "Agent should remain controlled (smaller tiebreaker)"
    );

    // Verify candidate pairs still have controlled role
    for pair in &agent.candidate_pairs {
        assert!(
            !pair.ice_role_controlling,
            "Candidate pair should still have controlling role set to false"
        );
    }

    agent.close()?;
    Ok(())
}

#[test]
fn test_candidate_type_filtering() -> Result<()> {
    // Create an agent with only Relay candidate type allowed (simulates RTCIceTransportPolicy::Relay)
    let config = Arc::new(AgentConfig {
        candidate_types: vec![CandidateType::Relay],
        ..Default::default()
    });
    let mut agent = Agent::new(Instant::now(), config, test_crypto_provider())?;

    // Host local candidate should be rejected
    let host_local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    assert!(
        !agent.add_local_candidate(host_local)?,
        "Host local candidate should be filtered out"
    );

    // Remote candidates of any type should still be accepted (relay policy only filters local)
    let host_remote = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.3".to_owned(),
            port: 5003,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    assert!(
        agent.add_remote_candidate(host_remote)?,
        "Remote candidates should be accepted regardless of candidate_types"
    );

    // Relay local candidate should be accepted
    let relay_local = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 5004,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 5005,
        ..Default::default()
    }
    .new_candidate_relay()?;
    assert!(
        agent.add_local_candidate(relay_local)?,
        "Relay local candidate should be accepted"
    );

    assert_eq!(
        agent.local_candidates.len(),
        1,
        "Only the relay candidate should be stored"
    );
    assert_eq!(
        agent.remote_candidates.len(),
        1,
        "Remote host candidate should be stored"
    );

    agent.close()?;
    Ok(())
}

// Verify that check_keepalive sends a STUN ping even when media traffic has
// recently updated the candidate timestamps (RFC 7675).
#[test]
fn test_keepalive_sent_during_media_flow() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    // Set up a selected pair
    let host_local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 19216,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(host_local)?;

    let relay_remote = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    }
    .new_candidate_relay()?;
    a.add_remote_candidate(relay_remote)?;

    a.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remoteufrag".to_string(),
        pwd: "remotepwd".to_string(),
    });
    a.is_controlling = true;

    a.add_pair(0, 0);
    a.set_selected_pair(Some(Instant::now()), Some(0));

    // Simulate recent media activity on both candidates
    a.local_candidates[0].seen(Instant::now(), true);
    a.remote_candidates[0].seen(Instant::now(), false);

    // Virtual time: the agent is told the instant, so nothing here sleeps or samples a clock.
    let base = Instant::now();

    // The consent interval has run out.
    a.next_consent_at = Some(base);

    // Drain any events/writes from setup
    a.write_outs.clear();

    // First call should send a consent ping immediately
    a.check_keepalive(base);
    assert!(
        !a.write_outs.is_empty(),
        "check_keepalive must send a STUN ping even when media timestamps are fresh"
    );

    // Drain and call again at the *same* instant; the interval has not elapsed, so no second ping.
    // Before clock injection this relied on the wall clock not advancing between two calls.
    a.write_outs.clear();
    a.check_keepalive(base);
    assert!(
        a.write_outs.is_empty(),
        "check_keepalive must not send again before the consent interval elapses"
    );
    // RFC 7675 Section 5.1: never less than 4 seconds between two checks.
    a.check_keepalive(base + Duration::from_millis(3999));
    assert!(a.write_outs.is_empty());

    // Advance virtual time past the longest interval (1.2 times 5 seconds): the next ping goes
    // out, instantly and reproducibly.
    a.check_keepalive(base + Duration::from_millis(6001));
    assert!(
        !a.write_outs.is_empty(),
        "check_keepalive must send again once the consent interval has elapsed"
    );

    a.close()?;
    Ok(())
}

#[test]
fn test_pair_network_type_mismatch() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    // UDP: IPv4 local should not pair with IPv6 remote.
    let local_v4 = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.1".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(local_v4)?;

    let remote_v6 = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "2001:db8::1".to_owned(),
            port: 8888,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote_v6)?;

    assert!(
        a.candidate_pairs.is_empty(),
        "IPv4 local and IPv6 remote candidates should not be paired"
    );

    // UDP: matching IPv4 should pair.
    let remote_v4 = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.1.2".to_owned(),
            port: 8888,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote_v4)?;

    assert_eq!(
        a.candidate_pairs.len(),
        1,
        "IPv4 local and IPv4 remote candidates should form exactly one pair"
    );

    // TCP: IPv4 active local should not pair with IPv6 passive remote.
    let local_tcp4_active = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "192.168.1.3".to_owned(),
            port: 7778,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Active,
    }
    .new_candidate_host()?;
    a.add_local_candidate(local_tcp4_active)?;

    let remote_tcp6_passive = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "2001:db8::2".to_owned(),
            port: 8889,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Passive,
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote_tcp6_passive)?;

    assert_eq!(
        a.candidate_pairs.len(),
        1,
        "TCP4 active local and TCP6 passive remote should not create an additional pair"
    );

    // TCP: matching IPv4 active/passive should pair.
    let remote_tcp4_passive = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "192.168.1.4".to_owned(),
            port: 8890,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Passive,
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote_tcp4_passive)?;

    assert_eq!(
        a.candidate_pairs.len(),
        2,
        "TCP4 active local and TCP4 passive remote should form exactly one pair"
    );

    a.close()?;
    Ok(())
}

// Regression test for https://github.com/webrtc-rs/rtc/issues/88 (Issue 1).
//
// When the agent transitions to `Failed` it calls `delete_all_candidates`, which
// empties `local_candidates`/`remote_candidates`. Previously the candidate pairs -
// and the `selected_pair`/`nominated_pair` indices into them - were left behind, so
// they referenced candidates that no longer existed. Any later access through a pair,
// e.g. `get_best_available_candidate_pair`, then indexed out of bounds and panicked:
//
//     thread '...' panicked at 'index out of bounds: the len is 0 but the index is 0'
#[test]
fn test_transition_to_failed_clears_stale_candidate_pairs() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(local)?;

    let remote = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote)?;

    // A single local/remote pair now exists; mark it selected and nominated so that
    // both index-into-pairs fields are populated.
    assert_eq!(a.candidate_pairs.len(), 1);
    a.set_selected_pair(Some(Instant::now()), Some(0));
    a.nominated_pair = Some(0);

    // Transition to Failed: this deletes all candidates.
    a.update_connection_state(Some(Instant::now()), ConnectionState::Failed);

    // The pairs and the indices into them must be gone, otherwise they dangle.
    assert!(
        a.candidate_pairs.is_empty(),
        "candidate pairs must be cleared when candidates are deleted"
    );
    assert!(a.selected_pair.is_none(), "selected_pair must be reset");
    assert!(a.nominated_pair.is_none(), "nominated_pair must be reset");
    assert!(a.local_candidates.is_empty());
    assert!(a.remote_candidates.is_empty());

    // Before the fix these accessors dereferenced stale pair indices into the emptied
    // candidate vectors and panicked; now they must simply return `None`.
    assert!(a.get_selected_candidate_pair().is_none());
    assert!(a.get_best_available_candidate_pair().is_none());

    a.close()?;
    Ok(())
}

// Regression test for https://github.com/webrtc-rs/rtc/issues/88 (Issue 2).
//
// Handling an inbound binding request from an unknown address adds a peer-reflexive
// remote candidate. Previously `add_remote_candidate` ran the connectivity check
// inline, which could advance the state to `Failed` and clear `remote_candidates`
// mid-call. The caller then computed `remote_candidates.len() - 1` on an empty vector
// and panicked ('attempt to subtract with overflow' in debug builds). Deferring the
// check to `handle_timeout` keeps candidate mutation free of surprising re-entrant
// state changes.
#[test]
fn test_handle_inbound_request_defers_failing_connectivity_check() -> Result<()> {
    use sansio::Protocol as _;

    let cfg = AgentConfig {
        disconnected_timeout: Some(Duration::from_secs(1)),
        failed_timeout: Some(Duration::from_secs(1)),
        ..Default::default()
    };
    let mut a = Agent::new(Instant::now(), Arc::new(cfg), test_crypto_provider())?;

    let local_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let local_index = 0;
    let local_priority = local_candidate.priority();
    a.add_local_candidate(local_candidate)?;

    a.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "".to_string(),
        pwd: "".to_string(),
    });
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":";
    let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
    let tie_breaker = a.tie_breaker;

    // Put the agent in a state where running a connectivity check now would time out
    // and transition to `Failed` (which deletes all candidates).
    a.connection_state = ConnectionState::Checking;
    a.last_connection_state = ConnectionState::Checking;
    a.checking_duration = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .unwrap_or(a.start_time);

    let remote_addr = SocketAddr::from_str("172.17.0.3:999")?;
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(UseCandidateAttr::new()),
        Box::new(AttrControlling(tie_breaker)),
        Box::new(PriorityAttr(local_priority)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    // Before the fix this call panicked while adding the peer-reflexive candidate.
    a.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr)?;

    // The candidate was added and no re-entrant state change happened during the call.
    assert_eq!(
        a.remote_candidates.len(),
        1,
        "peer-reflexive remote candidate should have been added"
    );
    assert_eq!(
        a.connection_state,
        ConnectionState::Checking,
        "connection state must not change while handling the inbound request"
    );
    assert!(
        a.force_candidate_contact,
        "a connectivity check should have been deferred to the timeout handler"
    );

    // The deferred check now runs via the timeout handler. Past its timeouts the agent does
    // not fail while the pair the request created is being checked (RFC 8445 Section 8.1.2:
    // the checklist fails when every pair has failed): the triggered check goes out.
    let now = Instant::now();
    a.handle_timeout(now)?;
    assert_eq!(a.connection_state, ConnectionState::Checking);
    let mut checks = 0;
    while let Some(out) = a.poll_write() {
        let mut m = Message::new();
        m.raw = out.message.to_vec();
        if m.decode().is_ok() && m.typ == BINDING_REQUEST {
            checks += 1;
        }
    }
    assert!(checks >= 1, "the triggered check was sent");

    // When it fails, it cleans up fully.
    a.update_connection_state(Some(now), ConnectionState::Failed);
    assert_eq!(a.connection_state, ConnectionState::Failed);
    assert!(a.candidate_pairs.is_empty());
    assert!(a.local_candidates.is_empty());
    assert!(a.remote_candidates.is_empty());
    assert!(a.selected_pair.is_none());
    assert!(a.nominated_pair.is_none());

    a.close()?;
    Ok(())
}

// Safari (and Chrome) expose ICE host candidates behind an mDNS "<uuid>.local"
// hostname by default. A QueryOnly agent (the default) must RESOLVE such a
// candidate -- i.e. issue an mDNS query, which surfaces as an outbound packet to
// MDNS_PORT -- whereas a Disabled agent silently drops it. This guards the
// behavioral consequence of defaulting the SettingEngine mDNS mode to QueryOnly.
//
// `add_remote_candidate` takes no instant, so it only *schedules* the query; the
// packet is stamped and emitted by the next `handle_timeout`, which does have one.
// `poll_timeout` reports an already-due deadline so the driver comes back at once.
#[test]
fn test_query_only_agent_queries_mdns_remote_candidate() -> Result<()> {
    // A .local host candidate in Safari's exact format.
    let cand_line =
        "1114572465 1 udp 2113939711 61b445d2-6503-41ac-96ce-ee3edac00e9f.local 61163 typ host";

    let base = Instant::now();

    // QueryOnly: adding the candidate issues an mDNS query (not a drop).
    let mut agent = Agent::new(
        base,
        Arc::new(AgentConfig {
            multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryOnly,
            // The RFC 6762 section 5.2 first-query delay has its own test
            // (`agent_open_rows_test.rs`); this one asks at once.
            multicast_dns_first_query_delay: Some(false),
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;
    let added = agent.add_remote_candidate(unmarshal_candidate(cand_line)?)?;
    assert!(
        !added,
        "an mDNS candidate is not immediately usable; resolution is async"
    );
    let deadline = agent
        .poll_timeout()
        .expect("a scheduled mDNS query must ask the driver for a timeout");
    assert!(
        deadline <= base,
        "the scheduled query is already due, so the driver runs it immediately"
    );
    agent.handle_timeout(deadline)?;
    let pkt = agent
        .poll_write()
        .expect("QueryOnly must emit an mDNS query for a .local remote candidate");
    assert_eq!(
        pkt.transport.peer_addr.port(),
        mdns::MDNS_PORT,
        "the emitted packet must be an mDNS query"
    );
    assert_eq!(
        pkt.now, deadline,
        "the query is stamped with the instant the driver supplied, not an ambient one"
    );

    // Disabled: the same candidate is silently dropped -- no mDNS query.
    let mut agent = Agent::new(
        base,
        Arc::new(AgentConfig {
            multicast_dns_mode: crate::mdns::MulticastDnsMode::Disabled,
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;
    agent.add_remote_candidate(unmarshal_candidate(cand_line)?)?;
    assert!(
        agent.poll_write().is_none(),
        "Disabled must not emit an mDNS query for a .local remote candidate"
    );

    Ok(())
}

/// A terminal ICE agent must not keep advertising its last connectivity-check deadline.
///
/// `contact` intentionally returns without updating `last_checking_time` after the agent fails.
/// If `poll_timeout` continues to derive a deadline from that value, every call after failure
/// returns the same instant in the past and a Sans-I/O driver can spin indefinitely.
#[test]
fn test_failed_agent_stops_and_restart_resumes_connectivity_check_timer() -> Result<()> {
    let base = Instant::now();
    let mut agent = Agent::new(
        base,
        Arc::new(AgentConfig {
            multicast_dns_mode: crate::mdns::MulticastDnsMode::Disabled,
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;

    agent.start_connectivity_checks(
        base,
        true,
        "remote-ufrag".to_owned(),
        "remote-password".to_owned(),
    )?;
    agent.update_connection_state(
        Some(base + Duration::from_secs(190)),
        ConnectionState::Failed,
    );

    assert_eq!(
        agent.poll_timeout(),
        None,
        "a failed agent has no more connectivity checks to schedule"
    );
    agent.handle_timeout(base + Duration::from_secs(191))?;
    assert_eq!(
        agent.poll_timeout(),
        None,
        "handling time after failure must not recreate the stale deadline"
    );

    let restart_time = base + Duration::from_secs(200);
    agent.apply_restart(restart_time, true)?;
    agent.start_connectivity_checks(
        restart_time,
        true,
        "new-remote-ufrag".to_owned(),
        "new-remote-password".to_owned(),
    )?;

    assert!(
        agent.poll_timeout().is_some(),
        "an ICE restart must resume connectivity-check scheduling"
    );

    agent.close()?;
    assert_eq!(
        agent.poll_timeout(),
        None,
        "a closed agent has no more connectivity checks to schedule"
    );

    Ok(())
}

/// Regression test: connectivity checks for a server-reflexive local candidate
/// must be tagged with the candidate's base (the bound host socket), not the
/// NAT-mapped srflx address (RFC 8445 §6.1.2). Drivers that route outbound
/// transmits by `transport.local_addr` otherwise have no socket to send from
/// and drop the packet.
#[test]
fn test_send_stun_from_srflx_uses_base_addr() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let srflx_local = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.12.1".to_owned(), // NAT mapping; no local socket here
            port: 60823,
            component: 1,
            ..Default::default()
        },
        rel_addr: "192.168.0.2".to_owned(), // base: bound host socket
        rel_port: 5000,
        ..Default::default()
    }
    .new_candidate_server_reflexive()?;
    a.add_local_candidate(srflx_local)?;

    let host_remote = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.79.11.1".to_owned(),
            port: 37983,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(host_remote)?;

    a.write_outs.clear();

    let msg = Message::new();
    a.send_stun(Instant::now(), &msg, 0, 0);

    let transmit = a.write_outs.pop_front().expect("send_stun must emit");
    assert_eq!(
        transmit.transport.local_addr,
        "192.168.0.2:5000".parse().unwrap(),
        "srflx checks must be sent from the candidate's base, not the mapped address"
    );
    assert_eq!(
        transmit.transport.peer_addr,
        "10.79.11.1:37983".parse().unwrap()
    );

    a.close()?;
    Ok(())
}

/// Staging an ICE restart must not disturb the live session.
///
/// JSEP requires `createOffer` to be free of side effects, so the credentials an ICE-restart offer
/// advertises are generated but *not* installed until the local description is applied. If they
/// were installed at offer time, inbound STUN would immediately start failing its USERNAME and
/// MESSAGE-INTEGRITY checks against the new pair — and permanently so if the offer were discarded,
/// which JSEP explicitly permits.
#[test]
fn test_staged_ice_restart_keeps_live_session_authenticating() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let local_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    let local_priority = local_candidate.priority();
    a.add_local_candidate(local_candidate)?;

    a.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: String::new(),
        pwd: String::new(),
    });

    let original = a.ufrag_pwd.local_credentials.clone();
    let remote_addr = SocketAddr::from_str("172.17.0.3:999")?;

    // Builds a binding request authenticated with `pwd`, as the remote peer would send it.
    let inbound = |ufrag: &str, pwd: String, tie_breaker: u64| -> Result<Message> {
        let mut msg = Message::new();
        msg.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, format!("{ufrag}:"))),
            Box::new(AttrControlling(tie_breaker)),
            Box::new(PriorityAttr(local_priority)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                pwd,
                test_crypto_provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        Ok(msg)
    };

    // Baseline: the peer's checks are accepted.
    let mut msg = inbound(&original.ufrag, original.pwd.clone(), a.tie_breaker)?;
    a.handle_inbound(Instant::now(), &mut msg, 0, remote_addr)?;

    // What `create_offer` does for an ICE restart: generate credentials for the offer to carry.
    a.generate_restart_credentials(String::new(), String::new())?;

    // The offer advertises the new pair...
    let advertised = a.get_local_credentials().clone();
    assert_ne!(
        advertised.ufrag, original.ufrag,
        "staging a restart must generate a fresh ufrag for the offer"
    );
    assert_ne!(advertised.pwd, original.pwd);

    // ...while the live session still authenticates with the old one.
    // (`Credentials` deliberately implements neither `Debug` nor `PartialEq`: `pwd` is the
    // MESSAGE-INTEGRITY key and must not reach a log line, so compare the fields directly.)
    assert_eq!(
        a.ufrag_pwd.local_credentials.ufrag, original.ufrag,
        "staging must not install the new ufrag into the live session"
    );
    assert_eq!(
        a.ufrag_pwd.local_credentials.pwd, original.pwd,
        "staging must not install the new pwd into the live session"
    );

    // The guarantee: the peer is still sending checks keyed on the original credentials, and they
    // must keep being accepted while the offer is in flight.
    let mut msg = inbound(&original.ufrag, original.pwd.clone(), a.tie_breaker)?;
    a.handle_inbound(Instant::now(), &mut msg, 0, remote_addr)
        .expect("inbound STUN keyed on the pre-restart credentials must still validate");

    // The application discards the offer and never sets a local description. The connection must
    // be exactly as it was.
    assert!(a.has_pending_restart());
    let mut msg = inbound(&original.ufrag, original.pwd.clone(), a.tie_breaker)?;
    a.handle_inbound(Instant::now(), &mut msg, 0, remote_addr)
        .expect("a discarded ICE-restart offer must leave the session working");

    // Applying it — what `set_local_description` does — installs the staged pair.
    a.apply_restart(Instant::now(), true)?;
    assert!(!a.has_pending_restart());
    assert_eq!(
        a.ufrag_pwd.local_credentials.ufrag, advertised.ufrag,
        "apply_restart must install exactly the ufrag the offer advertised"
    );
    assert_eq!(
        a.ufrag_pwd.local_credentials.pwd, advertised.pwd,
        "apply_restart must install exactly the pwd the offer advertised"
    );

    a.close()?;
    Ok(())
}

/// Agent events carry the instant their condition was observed at, so a consumer draining
/// `poll_event` is *told* the time rather than having to retain one and guess. `close` has no
/// caller-supplied instant, so it stamps with the newest one the agent was given.
#[test]
fn test_agent_events_carry_the_instant_they_were_observed_at() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let mut a = Agent::new(
        t(0),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let host_local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 1000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(host_local)?;

    let relay_remote = CandidateRelayConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "1.2.3.4".to_owned(),
            port: 12340,
            component: 1,
            ..Default::default()
        },
        rel_addr: "4.3.2.1".to_owned(),
        rel_port: 43210,
        ..Default::default()
    }
    .new_candidate_relay()?;
    a.add_remote_candidate(relay_remote)?;

    a.add_pair(0, 0);
    a.set_selected_pair(Some(t(5)), Some(0));

    // Selecting a pair emits Connected *and* SelectedCandidatePairChange; both are stamped
    // with the instant that caused them, not with a reading taken at drain time.
    // (The pair itself was announced when it was formed, at the agent's clock then.)
    let stamped: Vec<_> = std::iter::from_fn(|| a.poll_event())
        .filter(|e| !matches!(e.event, Event::CandidatePairAdded(..)))
        .collect();
    assert!(!stamped.is_empty(), "selecting a pair emits events");
    for e in &stamped {
        assert_eq!(
            e.now,
            t(5),
            "event {:?} must carry the instant its condition was observed at",
            std::mem::discriminant(&e.event)
        );
    }

    a.handle_timeout(t(30))?;
    while a.poll_event().is_some() {}

    // `close` is a drain with no caller-supplied instant, and the agent retains none, so the
    // Closed transition is applied to `connection_state` but emits no event — there is no
    // honest instant to stamp one with. A consumer that needs to observe the close should read
    // the state rather than wait for an event.
    a.close()?;
    assert_eq!(a.connection_state, ConnectionState::Closed);
    assert!(
        a.poll_event().is_none(),
        "close emits no event, having no instant to stamp one with"
    );

    Ok(())
}

/// A `getStats` snapshot reports the instant the caller asked at, throughout — including the
/// fields that default rather than being populated from live state. Mixing virtual protocol time
/// with wall-clock timestamps in one report is worse than no report: the reader cannot tell which
/// numbers are comparable.
#[test]
fn test_stats_snapshot_reports_the_callers_instant_throughout() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let mut a = Agent::new(
        t(0),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;

    let host_local = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 1000,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(host_local)?;

    let host_remote = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.3".to_owned(),
            port: 1001,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(host_remote)?;

    // Take the snapshot at an instant far from "now", so a stray wall-clock read is obvious.
    let pairs = a.get_candidate_pairs_stats(t(600));
    assert!(!pairs.is_empty(), "adding a remote candidate forms a pair");
    for p in &pairs {
        for (field, stamp) in [
            ("timestamp", p.timestamp),
            ("last_packet_sent_timestamp", p.last_packet_sent_timestamp),
            (
                "last_packet_received_timestamp",
                p.last_packet_received_timestamp,
            ),
            ("first_request_timestamp", p.first_request_timestamp),
            ("last_request_timestamp", p.last_request_timestamp),
            ("last_response_timestamp", p.last_response_timestamp),
            ("consent_expired_timestamp", p.consent_expired_timestamp),
        ] {
            assert_eq!(stamp, t(600), "{field} must report the caller's instant");
        }
    }

    let locals = a.get_local_candidates_stats(t(600));
    assert_eq!(locals.len(), 1);
    assert_eq!(locals[0].timestamp, t(600));

    let remotes = a.get_remote_candidates_stats(t(600));
    assert_eq!(remotes.len(), 1);
    assert_eq!(remotes[0].timestamp, t(600));

    // A second snapshot at a different instant reports that one, with no wall-clock time having
    // passed between the two calls.
    assert_eq!(a.get_candidate_pairs_stats(t(900))[0].timestamp, t(900));

    Ok(())
}

/// RFC 8445 §7.3.1.4: when the controlling agent receives a Binding request on a pair it had
/// already marked Failed, it must answer and also send a triggered check on that pair, so a
/// path that opened late (e.g. after a NAT binding appeared) is checked again.
#[test]
fn test_controlling_rechecks_failed_pair_on_inbound_binding_request() -> Result<()> {
    use crate::attributes::control::AttrControlled;

    let now = Instant::now();
    let config = AgentConfig {
        is_controlling: true,
        ..Default::default()
    };
    let mut a = Agent::new(now, Arc::new(config), test_crypto_provider())?;

    let local_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(local_candidate)?;

    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote_candidate)?;

    a.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    assert_eq!(a.candidate_pairs.len(), 1);
    // The pair's check timed out and the pair failed.
    a.candidate_pairs[0].state = CandidatePairState::Failed;
    a.write_outs.clear();
    a.pending_binding_requests.clear();

    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlled(1)),
        Box::new(PriorityAttr(1000)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd,
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    a.process_binding_request(now, &msg, 0, remote_addr, true)?;

    // RFC 8445 Section 7.3.1.4: the pair is Waiting and on the triggered-check queue, and the
    // request has been answered.
    assert_eq!(
        a.candidate_pairs[0].state,
        CandidatePairState::Waiting,
        "a Binding request on a Failed pair must move it back to Waiting"
    );
    assert_eq!(a.triggered_queue.len(), 1);
    assert_eq!(a.write_outs.len(), 1, "the success response");
    // The triggered check goes out when Ta allows it: at once here.
    a.handle_timeout(now)?;
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::InProgress);
    assert_eq!(
        a.pending_binding_requests.len(),
        1,
        "a triggered check should be pending"
    );
    assert_eq!(a.pending_binding_requests[0].destination, remote_addr);

    assert_eq!(
        a.write_outs.len(),
        2,
        "expected a success response and a check"
    );
    let mut types = vec![];
    for out in &a.write_outs {
        assert_eq!(out.transport.peer_addr, remote_addr);
        let mut m = Message::new();
        m.raw = out.message.to_vec();
        m.decode()?;
        types.push(m.typ);
    }
    assert_eq!(types, vec![BINDING_SUCCESS, BINDING_REQUEST]);

    // The pair is being checked again: it stays In-Progress while its transaction runs (it
    // is retransmitted, not failed again at once).
    a.handle_timeout(now + Duration::from_millis(600))?;
    assert_eq!(a.candidate_pairs[0].state, CandidatePairState::InProgress);
    assert_eq!(a.pending_binding_requests[0].transmissions, 2);

    a.close()?;
    Ok(())
}

/// Every authenticated Binding request on a pair that has not succeeded triggers a check, which
/// cancels the transaction in progress (kept until its timeout, in case its response comes)
/// and opens a new one. The pending list stays bounded however many requests arrive, keeps the
/// newest transactions, and still matches their responses.
#[test]
fn test_pending_binding_requests_are_bounded() -> Result<()> {
    let now = Instant::now();
    let config = AgentConfig {
        is_controlling: true,
        ..Default::default()
    };
    let mut a = Agent::new(now, Arc::new(config), test_crypto_provider())?;

    let local_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_local_candidate(local_candidate)?;
    let remote_candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    a.add_remote_candidate(remote_candidate)?;
    a.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });
    assert_eq!(a.candidate_pairs.len(), 1);
    a.pending_binding_requests.clear();

    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = a.ufrag_pwd.local_credentials.pwd.clone();
    let mut tick = now;
    for _ in 0..(MAX_PENDING_BINDING_REQUESTS * 20) {
        let mut msg = Message::new();
        msg.build(&[
            Box::new(BINDING_REQUEST),
            Box::new(TransactionId::new()),
            Box::new(Username::new(ATTR_USERNAME, username.clone())),
            Box::new(AttrControlled(1)),
            Box::new(PriorityAttr(1000)),
            Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
                local_pwd.clone(),
                test_crypto_provider().crypto(),
            )),
            Box::new(FINGERPRINT),
        ])?;
        a.handle_binding_request(tick, &msg, 0, 0);
        // The triggered check goes out one Ta later.
        tick += a.ta;
        a.handle_timeout(tick)?;
        assert!(
            a.pending_binding_requests.len() <= MAX_PENDING_BINDING_REQUESTS + 1,
            "{} pending binding requests",
            a.pending_binding_requests.len()
        );
        a.write_outs.clear();
    }
    assert_eq!(
        a.pending_binding_requests.len(),
        MAX_PENDING_BINDING_REQUESTS + 1,
        "every request triggered a check: the one in progress and the cancelled ones kept"
    );
    assert_eq!(
        a.pending_binding_requests
            .iter()
            .filter(|r| !r.cancelled)
            .count(),
        1
    );
    let now = tick;

    // The newest transaction is still tracked and its response matches once.
    let newest = a
        .pending_binding_requests
        .last()
        .expect("a pending request")
        .transaction_id;
    assert!(a.handle_inbound_binding_success(now, newest).is_some());
    assert!(a.handle_inbound_binding_success(now, newest).is_none());

    // Pending requests still expire.
    let later = now + Duration::from_secs(60);
    a.run_transactions(later);
    assert!(a.pending_binding_requests.is_empty());

    a.close()?;
    Ok(())
}

/// A role conflict is acted on only for an authenticated request: a forged Binding request
/// carrying ICE-CONTROLLING with a larger tiebreaker must not make us switch roles.
#[test]
fn test_role_conflict_needs_message_integrity() -> Result<()> {
    // Create agent with controlling role
    let config = AgentConfig {
        is_controlling: true,
        ..Default::default()
    };
    let mut agent = Agent::new(Instant::now(), Arc::new(config), test_crypto_provider())?;

    // Set a specific tiebreaker value
    agent.tie_breaker = 100;

    // Add local candidate
    let host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "192.168.0.2".to_owned(),
            port: 7777,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let local_candidate = host_config.new_candidate_host()?;
    let local_index = 0;
    agent.add_local_candidate(local_candidate)?;

    // Add remote candidate
    let remote_addr = SocketAddr::from_str("172.17.0.3:9999")?;
    let remote_host_config = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "172.17.0.3".to_owned(),
            port: 9999,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let remote_candidate = remote_host_config.new_candidate_host()?;
    agent.add_remote_candidate(remote_candidate)?;

    // Set remote credentials
    agent.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote_ufrag".to_string(),
        pwd: "remote_pwd".to_string(),
    });

    let username = agent.ufrag_pwd.local_credentials.ufrag.clone() + ":remote_ufrag";
    let local_pwd = agent.ufrag_pwd.local_credentials.pwd.clone();

    // Create STUN binding request from remote agent (also controlling, with larger tiebreaker)
    let remote_tiebreaker = 200; // Larger than ours (100)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlling(remote_tiebreaker)), // Remote is also controlling
        Box::new(PriorityAttr(1000)),
        // Signed with the wrong password: the request does not authenticate.
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            local_pwd + "-forged",
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;

    // Agent should be controlling before handling the message
    assert!(
        agent.is_controlling,
        "Agent should be controlling before role conflict"
    );

    // Handle the inbound message - should detect role conflict
    let result = agent.handle_inbound(Instant::now(), &mut msg, local_index, remote_addr);

    assert!(
        result.is_err(),
        "an unauthenticated request must be rejected"
    );
    assert!(
        agent.is_controlling,
        "an unauthenticated request must not flip the ICE role"
    );
    assert!(
        agent
            .candidate_pairs
            .iter()
            .all(|pair| pair.ice_role_controlling),
        "pair roles must be unchanged"
    );

    agent.close()?;
    Ok(())
}

/// Consent freshness (RFC 7675) is kept only by authenticated STUN. Non-STUN datagrams from
/// the remote's address (which anyone can spoof) must not keep a pair whose peer stopped
/// answering consent checks from failing.
#[test]
fn test_unauthenticated_traffic_does_not_refresh_consent() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let mut a = Agent::new(
        t(0),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;
    let local_addr = SocketAddr::from_str("192.168.0.2:1000")?;
    let remote_addr = SocketAddr::from_str("1.2.3.4:12340")?;
    a.add_local_candidate(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: local_addr.ip().to_string(),
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    )?;
    a.add_remote_candidate(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: remote_addr.ip().to_string(),
                port: remote_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    )?;
    a.add_pair(0, 0);
    a.set_selected_pair(Some(t(1)), Some(0));

    let transport = TransportContext {
        local_addr,
        peer_addr: remote_addr,
        ecn: None,
        transport_protocol: TransportProtocol::UDP,
    };
    for secs in 2..60 {
        // A spoofed media/DTLS datagram every second, and nothing authenticated.
        // (Once the pair fails the agent forgets its candidates, so the traffic is refused.)
        let _ = a.is_valid_non_stun_traffic(t(secs), transport);
        a.validate_selected_pair(t(secs));
    }
    // Consent expired: the pair is no longer used (`Failed`, or `Disconnected` while the end
    // of the candidates or the PAC timer is awaited, W3C webrtc-pc 5.6.4).
    assert!(
        a.get_selected_candidate_pair().is_none() && a.media_path().is_none(),
        "unauthenticated traffic kept consent alive"
    );
    Ok(())
}

/// The remote candidate list is bounded.
#[test]
fn test_remote_candidates_are_capped() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;
    for i in 0..(MAX_REMOTE_CANDIDATES as u16 + 50) {
        let c = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "10.0.0.1".to_owned(),
                port: 1000 + i,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        let _ = a.add_remote_candidate(c);
    }
    assert_eq!(a.remote_candidates.len(), MAX_REMOTE_CANDIDATES);
    Ok(())
}

/// The `.local` name of the candidate the mDNS tests resolve.
const MDNS_TEST_NAME: &str = "61b445d2-6503-41ac-96ce-ee3edac00e9f.local";

/// A QueryOnly agent that has issued the query for `MDNS_TEST_NAME`, and the answer a responder
/// for that name (at 10.0.0.9) sends to it.
fn agent_with_answered_mdns_query(base: Instant) -> Result<(Agent, TaggedBytesMut)> {
    let mut agent = Agent::new(
        base,
        Arc::new(AgentConfig {
            multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryOnly,
            // The RFC 6762 section 5.2 first-query delay has its own test
            // (`agent_open_rows_test.rs`); this one asks at once.
            multicast_dns_first_query_delay: Some(false),
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;
    agent.add_remote_candidate(unmarshal_candidate(&format!(
        "1 1 udp 2113939711 {MDNS_TEST_NAME} 61163 typ host"
    ))?)?;
    agent.handle_timeout(base)?;
    let query = agent.poll_write().expect("the agent queries the name");

    let mut responder = mdns::Mdns::new(
        base,
        mdns::MdnsConfig::default()
            .with_local_names(vec![MDNS_TEST_NAME.to_owned()])
            .with_local_ip("10.0.0.9".parse().unwrap()),
    );
    sansio::Protocol::handle_read(
        &mut responder,
        TaggedBytesMut {
            now: base,
            transport: TransportContext {
                local_addr: "0.0.0.0:5353".parse().unwrap(),
                peer_addr: "192.168.1.2:5353".parse().unwrap(),
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: query.message,
        },
    )?;
    let answer = sansio::Protocol::poll_write(&mut responder).expect("the responder answers");
    Ok((agent, answer))
}

/// mDNS answers are taken only from the mDNS socket. One sent from port 5353 to an ICE socket
/// used to be parsed as an answer too, letting anyone who learned the peer's `.local` name
/// point its candidate at an address of their choosing.
#[test]
fn test_mdns_answer_is_taken_only_from_the_mdns_socket() -> Result<()> {
    let base = Instant::now();
    let deliver = |agent: &mut Agent, answer: &TaggedBytesMut, local: &str| {
        let _ = agent.handle_read(TaggedBytesMut {
            now: base,
            transport: TransportContext {
                local_addr: local.parse().unwrap(),
                peer_addr: "10.0.0.9:5353".parse().unwrap(),
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: answer.message.clone(),
        });
    };

    let (mut agent, answer) = agent_with_answered_mdns_query(base)?;
    deliver(&mut agent, &answer, "192.168.1.2:50000");
    assert!(
        agent.remote_candidates.is_empty(),
        "an answer that reached an ICE socket resolved a candidate"
    );
    assert_eq!(agent.mdns_queries.len(), 1, "the query is still pending");

    deliver(&mut agent, &answer, "0.0.0.0:5353");
    assert_eq!(agent.remote_candidates.len(), 1);
    assert_eq!(
        agent.remote_candidates[0].addr().ip(),
        "10.0.0.9".parse::<IpAddr>().unwrap()
    );
    Ok(())
}

/// draft-ietf-mmusic-mdns-ice-candidates section 3.2.1 step 5: a `.local` candidate whose
/// name does not resolve is ignored. The query of an agent with no timeout configured ends
/// after `rtci-mdns`'s 30 s; the name then leaves nothing behind: no remote candidate, no
/// pending query, and an answer that comes after it resolves nothing.
#[test]
fn test_an_mdns_name_that_does_not_resolve_in_time_leaves_no_candidate() -> Result<()> {
    let base = Instant::now();
    let (mut agent, late_answer) = agent_with_answered_mdns_query(base)?;
    assert_eq!(agent.mdns_queries.len(), 1);
    let until = base + Duration::from_secs(31);
    let mut now = base;
    while now < until {
        now = agent
            .poll_timeout()
            .filter(|t| *t > now && *t <= until)
            .unwrap_or(until);
        agent.handle_timeout(now)?;
        while agent.poll_write().is_some() {}
    }
    assert!(agent.mdns_queries.is_empty(), "the query ended");
    assert!(agent.remote_candidates.is_empty(), "no candidate");

    let _ = agent.handle_read(TaggedBytesMut {
        now,
        transport: TransportContext {
            local_addr: "0.0.0.0:5353".parse().unwrap(),
            peer_addr: "10.0.0.9:5353".parse().unwrap(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: late_answer.message,
    });
    assert!(
        agent.remote_candidates.is_empty(),
        "an answer after the query ended resolved a candidate"
    );
    Ok(())
}

/// A browser's `<uuid>.local` host candidate that does not resolve is the normal case on many
/// networks (draft-ietf-mmusic-mdns-ice-candidates Section 3.2.1 step 5: "Otherwise, ignore
/// the candidate"), so it is dropped quietly: with the default mode (`QueryOnly`, which
/// resolves: step 3), the query ends, no pair is formed, no error comes back from the agent's
/// calls and no state change reaches the application, and the agent goes on pairing the
/// candidates that follow. (The timeout's log line is at debug; the crates have no log
/// capture for tests, so the level is not pinned here.)
#[test]
fn test_an_unresolved_remote_mdns_name_is_dropped_quietly_and_the_agent_goes_on() -> Result<()> {
    let base = Instant::now();
    assert_eq!(
        AgentConfig::default().multicast_dns_mode,
        crate::mdns::MulticastDnsMode::QueryOnly,
        "the default resolves remote names"
    );
    let mut agent = Agent::new(
        base,
        Arc::new(AgentConfig {
            // A short timeout keeps the test inside the checking timeouts; the mode is the
            // default.
            multicast_dns_query_timeout: Some(Duration::from_secs(2)),
            multicast_dns_first_query_delay: Some(false),
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;
    agent.add_local_candidate(
        CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.168.1.2".to_owned(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?,
    )?;
    agent.start_connectivity_checks(
        base,
        true,
        "remote-ufrag".to_owned(),
        "remote-password".to_owned(),
    )?;
    assert!(
        !agent.add_remote_candidate(unmarshal_candidate(&format!(
            "1 1 udp 2113939711 {MDNS_TEST_NAME} 61163 typ host"
        ))?)?,
        "an mDNS candidate waits for its name"
    );
    assert_eq!(agent.mdns_queries.len(), 1, "the default mode queries");

    // The driver runs the agent at once (`add_remote_candidate` only schedules the query; the
    // query starts, and its timeout runs, from this `handle_timeout`), then at each deadline.
    let mut events = vec![];
    let mut queried = false;
    let until = base + Duration::from_secs(3);
    let mut now = base;
    loop {
        agent.handle_timeout(now)?;
        while let Some(t) = agent.poll_write() {
            queried |= t.transport.peer_addr.port() == mdns::MDNS_PORT;
        }
        while let Some(e) = agent.poll_event() {
            events.push(e.event);
        }
        if now >= until {
            break;
        }
        now = agent
            .poll_timeout()
            .filter(|t| *t > now && *t <= until)
            .unwrap_or(until);
    }
    assert!(queried, "the query went out");
    assert!(agent.mdns_queries.is_empty(), "the query ended");
    assert!(agent.remote_candidates.is_empty(), "no remote candidate");
    assert!(agent.candidate_pairs.is_empty(), "no pair");
    assert!(
        !events.iter().any(|e| matches!(
            e,
            Event::CandidatePairAdded(..) | Event::ConnectionStateChange(ConnectionState::Failed)
        )),
        "nothing reaches the application"
    );
    assert_eq!(agent.state(), ConnectionState::Checking);

    // The agent goes on: the next candidate is paired.
    assert!(agent.add_remote_candidate(unmarshal_candidate(
        "2 1 udp 2113939711 192.168.1.3 6000 typ host"
    )?)?);
    assert_eq!(
        agent.candidate_pairs.len(),
        1,
        "the next candidate is paired"
    );
    let peer: SocketAddr = "192.168.1.3:6000".parse().unwrap();
    let until = now + Duration::from_secs(1);
    let mut checked = false;
    while !checked && now < until {
        agent.handle_timeout(now)?;
        checked = std::iter::from_fn(|| agent.poll_write()).any(|t| t.transport.peer_addr == peer);
        now = agent
            .poll_timeout()
            .filter(|t| *t > now && *t <= until)
            .unwrap_or(until);
    }
    assert!(checked, "and checked");
    Ok(())
}

/// mDNS-resolved candidates count against `MAX_REMOTE_CANDIDATES` like any other: they used to
/// be added past it.
#[test]
fn test_mdns_resolved_candidates_respect_the_remote_candidate_cap() -> Result<()> {
    let base = Instant::now();
    let (mut agent, answer) = agent_with_answered_mdns_query(base)?;
    for i in 0..MAX_REMOTE_CANDIDATES {
        let port = 10_000 + i;
        assert!(agent.add_remote_candidate(unmarshal_candidate(&format!(
            "1 1 udp 2113939711 10.1.0.1 {port} typ host"
        ))?)?);
    }
    agent.handle_read(TaggedBytesMut {
        now: base,
        transport: TransportContext {
            local_addr: "0.0.0.0:5353".parse().unwrap(),
            peer_addr: "10.0.0.9:5353".parse().unwrap(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: answer.message,
    })?;
    assert_eq!(agent.remote_candidates.len(), MAX_REMOTE_CANDIDATES);
    Ok(())
}

/// A Binding request that passes `handle_inbound`'s username and MESSAGE-INTEGRITY checks, as
/// the controlled peer sends it.
fn authenticated_check_from_controlled(a: &mut Agent) -> Result<Message> {
    a.ufrag_pwd.remote_credentials = Some(Credentials {
        ufrag: "remote".to_string(),
        pwd: "remotepasswordremotepassword".to_string(),
    });
    let username = a.ufrag_pwd.local_credentials.ufrag.clone() + ":remote";
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId::new()),
        Box::new(Username::new(ATTR_USERNAME, username)),
        Box::new(AttrControlled(a.tie_breaker.wrapping_add(1))),
        Box::new(PriorityAttr(1)),
        Box::new(MessageIntegrity::new_short_term_integrity_with_provider(
            a.ufrag_pwd.local_credentials.pwd.clone(),
            test_crypto_provider().crypto(),
        )),
        Box::new(FINGERPRINT),
    ])?;
    Ok(msg)
}

// A browser offering ICE-TCP as the controlled side connects from an active candidate (port 9 in
// its SDP) to our passive one. Its checks arrive from the connection's ephemeral port and create
// a peer-reflexive candidate. That candidate must be active, so it pairs with the passive one
// (RFC 6544): left without a TCP type it paired with nothing, and a controlling agent, which only
// checks and nominates pairs it has, never connected.
#[test]
fn test_tcp_peer_reflexive_candidate_pairs_with_passive_local() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            network_types: vec![NetworkType::Tcp4],
            ..Default::default()
        }),
        test_crypto_provider(),
    )?;
    a.set_role(true);

    let passive = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "192.168.1.3".to_owned(),
            port: 5000,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Passive,
    }
    .new_candidate_host()?;
    a.add_local_candidate(passive)?;

    let remote_addr = SocketAddr::from_str("192.168.1.4:45678")?;
    let mut msg = authenticated_check_from_controlled(&mut a)?;
    a.handle_inbound(Instant::now(), &mut msg, 0, remote_addr)?;

    let remote_index = a
        .find_remote_candidate(remote_addr)
        .expect("the check's source becomes a peer-reflexive candidate");
    let remote = &a.remote_candidates[remote_index];
    assert_eq!(remote.candidate_type(), CandidateType::PeerReflexive);
    assert_eq!(remote.network_type(), NetworkType::Tcp4);
    assert_eq!(remote.tcp_type(), TcpType::Active);
    assert!(
        a.find_pair(0, remote_index).is_some(),
        "the peer-reflexive active candidate pairs with the passive local one"
    );

    a.close()?;
    Ok(())
}

// A signalled active candidate still forms no pair of its own: it has no port to connect to.
#[test]
fn test_signalled_tcp_active_remote_candidate_is_not_added() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;
    let active = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "tcp".to_owned(),
            address: "192.168.1.4".to_owned(),
            port: 9,
            component: 1,
            ..Default::default()
        },
        tcp_type: TcpType::Active,
    }
    .new_candidate_host()?;
    assert!(!a.add_remote_candidate(active)?);
    assert!(a.remote_candidates.is_empty());
    a.close()?;
    Ok(())
}

// A connection accepted on a passive candidate arrives on that candidate's exact address. An
// active candidate on the same IP, listed first, used to claim it by its IP-only match.
#[test]
fn test_find_local_candidate_prefers_exact_tcp_address() -> Result<()> {
    let mut a = Agent::new(
        Instant::now(),
        Arc::new(AgentConfig::default()),
        test_crypto_provider(),
    )?;
    for (port, tcp_type) in [(9, TcpType::Active), (5000, TcpType::Passive)] {
        let c = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "tcp".to_owned(),
                address: "192.168.1.3".to_owned(),
                port,
                component: 1,
                ..Default::default()
            },
            tcp_type,
        }
        .new_candidate_host()?;
        a.add_local_candidate(c)?;
    }
    assert_eq!(
        a.find_local_candidate(
            SocketAddr::from_str("192.168.1.3:5000")?,
            TransportProtocol::TCP
        ),
        Some(1),
        "the passive candidate's own address"
    );
    assert_eq!(
        a.find_local_candidate(
            SocketAddr::from_str("192.168.1.3:40000")?,
            TransportProtocol::TCP
        ),
        Some(0),
        "an outbound connection's ephemeral port is the active candidate's"
    );
    assert_eq!(
        a.find_local_candidate(
            SocketAddr::from_str("192.168.1.3:5000")?,
            TransportProtocol::UDP
        ),
        None
    );
    a.close()?;
    Ok(())
}

fn host(network: &str, address: &str, port: u16, tcp_type: TcpType) -> Result<Candidate> {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: network.to_owned(),
            address: address.to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        tcp_type,
    }
    .new_candidate_host()
}

fn mdns_agent(mode: crate::mdns::MulticastDnsMode, local_ip: Option<IpAddr>) -> Result<Agent> {
    Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            multicast_dns_mode: mode,
            multicast_dns_local_ip: local_ip,
            // The RFC 6762 section 5.2 first-query delay has its own test
            // (`agent_open_rows_test.rs`); these ask at once.
            multicast_dns_first_query_delay: Some(false),
            ..Default::default()
        }),
        test_crypto_provider(),
    )
}

/// Moves every mDNS packet `from` (at `from_ip`) wrote to `to`'s mDNS socket; returns how many.
fn carry_mdns(from: &mut Agent, from_ip: &str, to: &mut Agent, now: Instant) -> Result<usize> {
    let mut n = 0;
    while let Some(packet) = from.poll_write() {
        if packet.transport.peer_addr.port() != mdns::MDNS_PORT {
            continue;
        }
        to.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: "0.0.0.0:5353".parse().unwrap(),
                peer_addr: format!("{from_ip}:5353").parse().unwrap(),
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: packet.message,
        })?;
        n += 1;
    }
    Ok(n)
}

// Browsers publish every host candidate under an mDNS name, one per address. `QueryAndGather`
// without a fixed IP used to hide nothing (its one name pointed at 127.0.0.1), so every local
// address went out in the SDP.
#[test]
fn test_query_and_gather_hides_every_local_address() -> Result<()> {
    let mut a = mdns_agent(crate::mdns::MulticastDnsMode::QueryAndGather, None)?;
    a.add_local_candidate(host("udp", "192.168.1.3", 5000, TcpType::Unspecified)?)?;
    a.add_local_candidate(host("tcp", "192.168.1.3", 5001, TcpType::Passive)?)?;
    a.add_local_candidate(host("udp", "192.168.7.3", 5000, TcpType::Unspecified)?)?;
    a.add_local_candidate(host("udp", "2001:db8::3", 5000, TcpType::Unspecified)?)?;

    let names: Vec<String> = a
        .local_candidates
        .iter()
        .map(|c| c.address().to_owned())
        .collect();
    for name in &names {
        assert!(
            name.ends_with(".local") && name.len() == 36 + ".local".len(),
            "{name} is a <uuid>.local name"
        );
    }
    assert_eq!(
        names[0], names[1],
        "one name per address, UDP and TCP alike"
    );
    assert_ne!(names[0], names[2]);
    assert_ne!(names[0], names[3]);
    assert_ne!(names[2], names[3]);
    // The candidates still know where they are bound.
    assert_eq!(
        a.local_candidates[3].addr(),
        "[2001:db8::3]:5000".parse::<SocketAddr>()?
    );
    a.close()?;
    Ok(())
}

// The original fixed-IP form hides that one IPv4 address, now on TCP candidates too (they used
// to keep the literal address the UDP candidate's name hid).
#[test]
fn test_query_and_gather_with_fixed_ip_hides_its_tcp_candidates_too() -> Result<()> {
    let ip: IpAddr = "192.168.1.3".parse()?;
    let mut a = mdns_agent(crate::mdns::MulticastDnsMode::QueryAndGather, Some(ip))?;
    a.add_local_candidate(host("udp", "192.168.1.3", 5000, TcpType::Unspecified)?)?;
    a.add_local_candidate(host("tcp", "192.168.1.3", 5001, TcpType::Passive)?)?;
    a.add_local_candidate(host("udp", "192.168.9.9", 5000, TcpType::Unspecified)?)?;
    assert_eq!(a.local_candidates[0].address(), a.mdns_local_name);
    assert_eq!(a.local_candidates[1].address(), a.mdns_local_name);
    assert_eq!(a.local_candidates[2].address(), "192.168.9.9");
    a.close()?;
    Ok(())
}

// End to end, sans-I/O: B resolves the names A publishes, IPv4 and IPv6, and gets A's real
// addresses as remote candidates.
#[test]
fn test_published_mdns_host_candidates_resolve_at_the_peer() -> Result<()> {
    let now = Instant::now();
    let mut a = mdns_agent(crate::mdns::MulticastDnsMode::QueryAndGather, None)?;
    let mut b = mdns_agent(crate::mdns::MulticastDnsMode::QueryOnly, None)?;
    a.add_local_candidate(host("udp", "192.168.1.3", 5000, TcpType::Unspecified)?)?;
    a.add_local_candidate(host("udp", "2001:db8::3", 5002, TcpType::Unspecified)?)?;
    for c in a.local_candidates.clone() {
        let line = c.marshal();
        assert!(!line.contains("192.168.1.3") && !line.contains("2001:db8::3"));
        assert!(!b.add_remote_candidate(unmarshal_candidate(&line)?)?);
    }
    assert_eq!(b.mdns_queries.len(), 2);

    b.handle_timeout(now)?;
    assert_eq!(carry_mdns(&mut b, "192.168.1.4", &mut a, now)?, 2);
    // Each query asks two questions (A and AAAA): the answers wait 20 to 120 ms (RFC 6762
    // section 6.3).
    assert_eq!(carry_mdns(&mut a, "192.168.1.3", &mut b, now)?, 0);
    let later = now + Duration::from_millis(120);
    a.handle_timeout(later)?;
    assert_eq!(carry_mdns(&mut a, "192.168.1.3", &mut b, later)?, 2);
    b.handle_timeout(later)?;

    let mut resolved: Vec<SocketAddr> = b.remote_candidates.iter().map(|c| c.addr()).collect();
    resolved.sort();
    assert_eq!(
        resolved,
        vec![
            "192.168.1.3:5000".parse::<SocketAddr>()?,
            "[2001:db8::3]:5002".parse::<SocketAddr>()?
        ]
    );
    assert!(b.mdns_queries.is_empty());
    a.close()?;
    b.close()?;
    Ok(())
}

// draft-ietf-mmusic-mdns-ice-candidates section 3.1.1: "the ICE agent SHOULD still provide
// mDNS candidates in step 6 even if [...] mDNS registration fails in step 4". Past the cap
// of published names a host candidate is still provided, under a `.local` name that is not
// published: its address does not show.
#[test]
fn test_host_candidate_past_the_name_cap_is_provided_under_an_unpublished_name() -> Result<()> {
    let mut a = mdns_agent(crate::mdns::MulticastDnsMode::QueryAndGather, None)?;
    let cap = mdns::MAX_LOCAL_NAMES;
    for i in 0..=cap {
        let address = format!("10.0.{}.{}", i / 200, 1 + i % 200);
        assert!(
            a.add_local_candidate(host("udp", &address, 5000, TcpType::Unspecified)?)?,
            "candidate {i} is provided"
        );
    }
    let last = &a.local_candidates[cap];
    assert!(
        crate::mdns::is_ice_mdns_name(last.address()),
        "{}",
        last.address()
    );
    assert!(!last.marshal().contains("10.0."), "{}", last.marshal());
    assert_eq!(
        a.mdns_local_names.len(),
        cap,
        "the cap is kept: it is not published"
    );
    a.close()?;
    Ok(())
}

fn fail_closed_mdns_agent(publishing: crate::mdns::MulticastDnsPublishing) -> Result<Agent> {
    Agent::new(
        Instant::now(),
        Arc::new(AgentConfig {
            multicast_dns_mode: crate::mdns::MulticastDnsMode::QueryAndGather,
            multicast_dns_fail_closed: true,
            multicast_dns_publishing: publishing,
            multicast_dns_first_query_delay: Some(false),
            ..Default::default()
        }),
        test_crypto_provider(),
    )
}

/// The mDNS datagrams the agent writes within a few seconds.
fn mdns_writes(a: &mut Agent) -> Result<usize> {
    let mut now = Instant::now();
    let mut n = 0;
    for _ in 0..40 {
        a.handle_timeout(now)?;
        while let Some(packet) = a.poll_write() {
            if packet.transport.peer_addr.port() == mdns::MDNS_PORT {
                n += 1;
            }
        }
        now += Duration::from_millis(100);
    }
    Ok(n)
}

// draft-ietf-mmusic-mdns-ice-candidates section 3.1.1 step 4 fails because the application can
// send no mDNS for the address's family (`set_multicast_dns_publishing`). By default the draft's
// form: "the ICE agent SHOULD still provide mDNS candidates in step 6 even if the local network
// does not support mDNS": the candidate goes out under a `.local` name that is neither
// registered nor announced, one name for the address (its UDP and TCP candidates share it).
#[test]
fn test_host_candidate_without_mdns_for_its_family_goes_out_under_an_unpublished_name() -> Result<()>
{
    let mut a = mdns_agent(crate::mdns::MulticastDnsMode::QueryAndGather, None)?;
    a.set_multicast_dns_publishing(crate::mdns::MulticastDnsPublishing {
        ipv4: false,
        ipv6: true,
    });
    assert!(a.add_local_candidate(host("udp", "10.0.7.5", 5000, TcpType::Unspecified)?)?);
    assert!(a.add_local_candidate(host("tcp", "10.0.7.5", 5001, TcpType::Passive)?)?);
    let names: Vec<&str> = a.local_candidates.iter().map(|c| c.address()).collect();
    assert_eq!(names.len(), 2);
    assert!(crate::mdns::is_ice_mdns_name(names[0]), "{names:?}");
    assert_eq!(names[0], names[1], "one name for the address");
    for c in &a.local_candidates {
        assert!(!c.marshal().contains("10.0.7.5"), "{}", c.marshal());
    }
    assert!(a.mdns_local_names.is_empty(), "the name is not registered");
    assert!(!a.multicast_dns_withholds("10.0.7.5".parse()?));
    assert_eq!(mdns_writes(&mut a)?, 0, "nothing announces it");
    // IPv6 can be published: its name is registered and announced.
    assert!(a.add_local_candidate(host("udp", "fd00::7", 5000, TcpType::Unspecified)?)?);
    assert_eq!(a.mdns_local_names.len(), 1);
    assert!(mdns_writes(&mut a)? > 0, "the IPv6 name is announced");
    a.close()?;
    Ok(())
}

// `multicast_dns_fail_closed`: a host candidate whose name cannot be registered (no mDNS for its
// family) is not provided at all, UDP or TCP: it is not held, not paired, and no datagram
// announces it. An address whose family can publish is hidden as usual.
#[test]
fn test_fail_closed_agent_withholds_a_host_candidate_whose_name_cannot_be_registered() -> Result<()>
{
    let mut a = fail_closed_mdns_agent(crate::mdns::MulticastDnsPublishing {
        ipv4: false,
        ipv6: true,
    })?;
    let remote = host("udp", "10.0.7.9", 6000, TcpType::Unspecified)?;
    a.add_remote_candidate(remote)?;
    assert!(!a.add_local_candidate(host("udp", "10.0.7.5", 5000, TcpType::Unspecified)?)?);
    assert!(!a.add_local_candidate(host("tcp", "10.0.7.5", 5001, TcpType::Passive)?)?);
    assert!(a.local_candidates.is_empty(), "nothing is held");
    assert!(a.candidate_pairs.is_empty(), "nothing is paired");
    assert!(a.multicast_dns_withholds("10.0.7.5".parse()?));
    assert_eq!(mdns_writes(&mut a)?, 0, "no name is announced");
    assert!(a.add_local_candidate(host("udp", "fd00::7", 5000, TcpType::Unspecified)?)?);
    assert!(crate::mdns::is_ice_mdns_name(
        a.local_candidates[0].address()
    ));
    a.close()?;
    Ok(())
}

// `multicast_dns_fail_closed` at the other failure of registration: past the cap of published
// names, the next address's host candidate is withheld instead of going out under an
// unpublished name.
#[test]
fn test_fail_closed_agent_withholds_a_host_candidate_past_the_name_cap() -> Result<()> {
    let mut a = fail_closed_mdns_agent(Default::default())?;
    let cap = mdns::MAX_LOCAL_NAMES;
    for i in 0..cap {
        let address = format!("10.0.{}.{}", i / 200, 1 + i % 200);
        assert!(a.add_local_candidate(host("udp", &address, 5000, TcpType::Unspecified)?)?);
    }
    assert!(!a.add_local_candidate(host("udp", "10.9.9.9", 5000, TcpType::Unspecified)?)?);
    assert_eq!(a.local_candidates.len(), cap);
    assert!(a.multicast_dns_withholds("10.9.9.9".parse()?));
    a.close()?;
    Ok(())
}
