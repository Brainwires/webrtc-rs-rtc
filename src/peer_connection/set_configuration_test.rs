//! `set_configuration` (W3C webrtc 4.4.1.6, "set the configuration").

use std::time::Instant;

use crate::peer_connection::RTCPeerConnectionBuilder;
use crate::peer_connection::configuration::{RTCConfigurationBuilder, RTCIceTransportPolicy};
use crate::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use shared::error::Result;

fn host_candidate(port: u16) -> Result<crate::peer_connection::transport::RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: "10.0.0.1".to_owned(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    RTCIceCandidate::from(&candidate).to_json()
}

fn policy(
    policy: RTCIceTransportPolicy,
) -> crate::peer_connection::configuration::RTCConfiguration {
    RTCConfigurationBuilder::new()
        .with_ice_transport_policy(policy)
        .build()
}

/// Step 8: a new `iceTransportPolicy` reaches the ICE agent. With `relay`, a host candidate
/// added afterwards is not used.
#[test]
fn a_relay_policy_set_later_reaches_the_agent() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(policy(RTCIceTransportPolicy::All))
        .build(Instant::now())?;
    pc.add_local_candidate(host_candidate(5000)?)?;
    assert_eq!(pc.ice_transport().agent.get_local_candidates().len(), 1);

    pc.set_configuration(policy(RTCIceTransportPolicy::Relay))?;
    assert_eq!(
        pc.get_configuration().ice_transport_policy,
        RTCIceTransportPolicy::Relay
    );
    pc.add_local_candidate(host_candidate(5001)?)?;
    assert_eq!(
        pc.ice_transport().agent.get_local_candidates().len(),
        1,
        "the host candidate added under `relay` is not used; the earlier one stays \
         (RFC 9429, Section 4.1.18: the new setting applies from the next gathering)"
    );
    Ok(())
}

/// And back: from `relay` to `all`, host candidates are used again.
#[test]
fn an_all_policy_set_later_lifts_relay() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(policy(RTCIceTransportPolicy::Relay))
        .build(Instant::now())?;
    pc.add_local_candidate(host_candidate(5000)?)?;
    assert!(pc.ice_transport().agent.get_local_candidates().is_empty());

    pc.set_configuration(policy(RTCIceTransportPolicy::All))?;
    pc.add_local_candidate(host_candidate(5001)?)?;
    assert_eq!(pc.ice_transport().agent.get_local_candidates().len(), 1);
    Ok(())
}

fn server(url: &str) -> crate::peer_connection::transport::RTCIceServer {
    crate::peer_connection::transport::RTCIceServer {
        urls: vec![url.to_owned()],
        username: "user".to_owned(),
        credential: "secret".to_owned(),
    }
}

fn with_servers(
    servers: Vec<crate::peer_connection::transport::RTCIceServer>,
) -> crate::peer_connection::configuration::RTCConfiguration {
    RTCConfigurationBuilder::new()
        .with_ice_servers(servers)
        .build()
}

/// W3C 4.4.1.5 (bug B6): every check runs before anything is stored. A configuration whose
/// ICE server is invalid changes nothing, not even the transport policy that came before it.
#[test]
fn a_refused_configuration_changes_nothing() -> Result<()> {
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let mut refused = with_servers(vec![server("stun:")]);
    refused.ice_transport_policy = RTCIceTransportPolicy::Relay;
    assert!(pc.set_configuration(refused).is_err());
    assert_ne!(
        pc.get_configuration().ice_transport_policy,
        RTCIceTransportPolicy::Relay,
        "the policy of a refused configuration is not stored"
    );
    Ok(())
}

/// W3C "validate an ICE server URL" and "set a configuration": the SyntaxError and
/// InvalidAccessError cases, in set_configuration and in the constructor.
#[test]
fn ice_server_urls_are_validated_as_the_spec_says() -> Result<()> {
    use shared::error::Error;
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let empty = crate::peer_connection::transport::RTCIceServer::default();
    for (servers, expected) in [
        (vec![empty], Error::ErrNoIceServerUrls),
        (vec![server("http:example.org")], Error::ErrSchemeType),
        (vec![server("stun:example.org#frag")], Error::ErrInvalidUrl),
        (vec![server("turn:user@example.org")], Error::ErrInvalidUrl),
        (vec![server("turn:example.org/path")], Error::ErrInvalidUrl),
        (
            vec![server("stun:example.org?transport=udp")],
            Error::ErrStunQuery,
        ),
        (
            vec![server("turn:example.org?transport=sctp")],
            Error::ErrInvalidQuery,
        ),
        (
            vec![crate::peer_connection::transport::RTCIceServer {
                username: "u".repeat(509),
                ..server("turn:example.org")
            }],
            Error::InvalidAccessError,
        ),
        // RFC 8265 section 4.1 (the OpaqueString profile of 4.2): a control character, or a
        // default-ignorable code point such as SOFT HYPHEN, in the credential; RFC 8489
        // section 14.3 has the username processed with the same profile.
        (
            vec![crate::peer_connection::transport::RTCIceServer {
                credential: "sec\u{7}ret".to_owned(),
                ..server("turn:example.org")
            }],
            Error::InvalidAccessError,
        ),
        (
            vec![crate::peer_connection::transport::RTCIceServer {
                credential: "The\u{ad}Matrix".to_owned(),
                ..server("turn:example.org")
            }],
            Error::InvalidAccessError,
        ),
        (
            vec![crate::peer_connection::transport::RTCIceServer {
                username: "us\u{0}er".to_owned(),
                ..server("turn:example.org")
            }],
            Error::InvalidAccessError,
        ),
        // "hostAndPortURL is failure": a host or a port that does not parse.
        (vec![server("turn:exa mple.org")], Error::ErrInvalidUrl),
        (vec![server("stun:example.org:99999")], Error::ErrInvalidUrl),
    ] {
        let refused = pc.set_configuration(with_servers(servers.clone()));
        assert_eq!(refused.as_ref().err(), Some(&expected), "{servers:?}");
        let built = RTCPeerConnectionBuilder::new()
            .with_configuration(with_servers(servers.clone()))
            .build(Instant::now());
        assert_eq!(built.err(), Some(expected), "constructor, {servers:?}");
    }
    pc.set_configuration(with_servers(vec![server("turn:example.org?transport=tcp")]))?;
    // Non-ASCII that is an OpaqueString is taken.
    pc.set_configuration(with_servers(vec![
        crate::peer_connection::transport::RTCIceServer {
            credential: "Jack of \u{2666}s".to_owned(),
            ..server("turn:example.org")
        },
    ]))?;
    Ok(())
}

/// W3C "validate an ICE server URL" lists the conditions under which it throws (a URL that
/// fails to parse, a scheme other than the four, no opaque path or one with "/" or "@", a
/// fragment, a query on stun / stuns, a scheme not implemented, a host-and-port part that
/// fails to parse or has a path, username or password, a turn / turns query other than
/// transport=udp / tcp, a turn / turns server without valid username and credential). A URL
/// none of them refuses is accepted, in set_configuration and in the constructor: among them
/// a `stuns:` URL whose host is an IP address, which RFC 8489 section 8.1 has the STUN client
/// reject when it would use it ("A 'stuns' URI containing an IP address MUST be rejected"),
/// not the configuration; and `turns:` with an IP address, which RFC 5928 section 3 step 1
/// takes ("If <host> is an IP address, then it indicates the specific IP address to be
/// used", for <secure> true as well).
#[test]
fn a_url_no_check_refuses_is_accepted() -> Result<()> {
    for url in [
        "stun:192.0.2.1",
        "stun:[2001:db8::1]:3478",
        "stuns:stun.example.org",
        "stuns:192.0.2.1:5349",
        "stuns:192.0.2.1",
        "stuns:[2001:db8::1]:5349",
        "turn:192.0.2.1?transport=udp",
        "turns:192.0.2.1:5349",
        "turns:[2001:db8::1]?transport=tcp",
    ] {
        let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
        pc.set_configuration(with_servers(vec![server(url)]))
            .unwrap_or_else(|e| panic!("set_configuration refused {url}: {e:?}"));
        RTCPeerConnectionBuilder::new()
            .with_configuration(with_servers(vec![server(url)]))
            .build(Instant::now())
            .unwrap_or_else(|e| panic!("the constructor refused {url}: {e:?}"));
    }
    Ok(())
}

/// W3C 4.2.1 / 4.4.1.5: ICE servers past the supported maximum (at least 32) are ignored, and
/// an empty list clears the servers.
#[test]
fn ice_servers_past_the_maximum_are_ignored_and_an_empty_list_clears_them() -> Result<()> {
    use crate::peer_connection::configuration::MAX_ICE_SERVERS;
    const { assert!(MAX_ICE_SERVERS >= 32) };
    let mut pc = RTCPeerConnectionBuilder::new().build(Instant::now())?;
    let many: Vec<_> = (0..MAX_ICE_SERVERS + 3)
        .map(|n| server(&format!("stun:stun{n}.example.org")))
        .collect();
    pc.set_configuration(with_servers(many))?;
    assert_eq!(pc.get_configuration().ice_servers.len(), MAX_ICE_SERVERS);
    pc.set_configuration(with_servers(vec![]))?;
    assert!(pc.get_configuration().ice_servers.is_empty());
    Ok(())
}

/// W3C 4.4.1.5 steps on certificates (bug B4): the configuration keeps the constructor's
/// certificates; passing them again is accepted, a different one or a different count is an
/// InvalidModificationError; getConfiguration reports them.
#[test]
fn the_certificates_cannot_change_and_are_reported() -> Result<()> {
    use crate::peer_connection::certificate::RTCCertificate;
    use shared::error::Error;
    let crypto = crypto::default_provider().expect("crypto provider");
    let generate = || {
        RTCCertificate::generate_certificate(
            crypto.crypto(),
            crypto::SignatureScheme::EcdsaP256Sha256,
            None,
            std::time::SystemTime::now(), // Exemption: usage in #test code
        )
    };
    let original = generate()?;
    let configuration = RTCConfigurationBuilder::new()
        .with_certificates(vec![original.clone()])
        .build();
    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(configuration.clone())
        .build(Instant::now())?;
    assert_eq!(
        pc.get_configuration().certificates(),
        std::slice::from_ref(&original)
    );
    pc.set_configuration(configuration)?;

    let other = RTCConfigurationBuilder::new()
        .with_certificates(vec![generate()?])
        .build();
    assert_eq!(
        pc.set_configuration(other),
        Err(Error::ErrModifyingCertificates)
    );
    assert_eq!(
        pc.set_configuration(RTCConfigurationBuilder::new().build()),
        Err(Error::ErrModifyingCertificates),
        "dropping the certificates is a change too"
    );
    Ok(())
}
