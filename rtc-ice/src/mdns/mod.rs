//#[cfg(test)]
//mod mdns_test;

use mdns::Mdns;
use mdns::MdnsConfig;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use uuid::Uuid;

use shared::error::Result;

/// Represents the different Multicast modes that ICE can run.
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
#[non_exhaustive]
pub enum MulticastDnsMode {
    /// Means remote mDNS candidates will be discarded, and local host candidates will use IPs.
    Disabled,

    /// Means remote mDNS candidates will be accepted, and local host candidates will use IPs.
    #[default]
    QueryOnly,

    /// Means remote mDNS candidates will be accepted, and local host candidates will use mDNS:
    /// with `multicast_dns_local_ip` set, the candidates on that IPv4 address are published
    /// under `multicast_dns_local_name`; without it, every local address (IPv4 and IPv6) under
    /// a `<uuid>.local` name of its own, as browsers do.
    QueryAndGather,
}

pub(crate) fn generate_multicast_dns_name() -> String {
    // https://tools.ietf.org/id/draft-ietf-rtcweb-mdns-ice-candidates-02.html#gathering
    // The unique name MUST consist of a version 4 UUID as defined in [RFC4122], followed by “.local”.
    // This is a short-lived privacy alias, not a credential. `Uuid::new_v4` obtains randomness
    // from the UUID crate's secure random source without forcing provider ownership into mDNS.
    let u = Uuid::new_v4();
    format!("{u}.local")
}

pub(crate) fn create_multicast_dns(
    now: Instant,
    mdns_mode: MulticastDnsMode,
    mdns_local_name: &str,
    mdns_local_ip: &Option<IpAddr>,
    mdns_query_timeout: &Option<Duration>,
) -> Result<Option<Mdns>> {
    if mdns_mode == MulticastDnsMode::Disabled {
        return Ok(None);
    }

    // With a fixed local IP, its one name answers with it. Without one, each local address is
    // published under a name of its own as its host candidates are added
    // (`Mdns::add_local_name`), so the responder starts with none.
    let mut config = match (mdns_mode, mdns_local_ip) {
        (MulticastDnsMode::QueryAndGather, Some(local_ip)) => {
            log::info!("mDNS is using {local_ip} as local ip");
            MdnsConfig::new()
                .with_local_names(vec![mdns_local_name.to_owned()])
                .with_local_ip(*local_ip)
        }
        _ => MdnsConfig::new(),
    };

    if let Some(query_timeout) = mdns_query_timeout {
        config = config.with_query_timeout(*query_timeout);
    }

    let mdns_server = Mdns::new(now, config);

    Ok(Some(mdns_server))
}
