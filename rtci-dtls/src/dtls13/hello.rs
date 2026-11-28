//! The hellos of DTLS 1.3: what a client offers, what a server makes of it, and the
//! HelloRetryRequest with its stateless cookie (RFC 8446 sections 4.1 and 4.2, RFC 9147
//! sections 5.1 and 5.3).

use super::codec::*;
use super::messages::*;
use super::psk::{
    OfferedPsk, PSK_DHE_KE, PSK_KE, placeholder_binders, pre_shared_key_data,
    psk_key_exchange_modes_data,
};
use super::suite::Suite13;
use super::{DTLS1_2_WIRE_VERSION, DTLS1_3_WIRE_VERSION};
use crate::cipher_suite::CipherSuiteId;
use crate::config::{DtlsVersion, HandshakeConfig};
use crate::crypto::Certificate;
use crate::curve::named_curve::{NamedCurve, NamedCurveKeypair};
use crate::extension::Extension;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::signature_hash_algorithm::SignatureHashAlgorithm;
use crypto::{HmacAlgorithm, RTCCryptoProvider};
use shared::error::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

/// How many of its groups a client sends a key share for: the first two it prefers, so that
/// a server which supports either answers without a HelloRetryRequest.
const KEY_SHARES_OFFERED: usize = 2;

/// What a client that offers DTLS 1.3 keeps from its ClientHello until the server answers.
pub(crate) struct ClientOffer {
    /// The key shares offered, in order of preference.
    pub(crate) key_shares: Vec<NamedCurveKeypair>,
    /// The connection id this client asks the server to put in its records, if it asks for
    /// connection ids at all (empty: it offers the extension and wants none itself).
    pub(crate) connection_id: Option<Vec<u8>>,
    /// The PSKs offered (RFC 8446 section 4.2.11), in the order of the identities: a ticket
    /// first, if the session store had one, then the external PSKs.
    pub(crate) psks: Vec<OfferedPsk>,
    /// The 0-RTT data sent with the ClientHello, if early_data is offered (RFC 8446 section
    /// 4.2.10): with the first PSK, a ticket that allows that much.
    pub(crate) early_data: Option<Vec<u8>>,
}

impl HandshakeConfig {
    /// The PSK key exchange modes this side offers or accepts (RFC 8446 section 4.2.9):
    /// `psk_dhe_ke`, and `psk_ke` only where the configuration allows it.
    pub(crate) fn psk_key_exchange_modes(&self) -> Vec<u8> {
        #[cfg(test)]
        if let Some(modes) = &self.psk_modes_for_test {
            return modes.clone();
        }
        let mut modes = vec![PSK_DHE_KE];
        if self.psk_without_key_exchange {
            modes.push(PSK_KE);
        }
        modes
    }

    /// Whether a client sends psk_key_exchange_modes: it can resume, or has PSKs to offer.
    /// Without the extension a server sends it no tickets (RFC 8446 section 4.2.9).
    pub(crate) fn uses_psks(&self) -> bool {
        self.session_store.is_some() || !self.external_psks.is_empty()
    }
}

impl ClientOffer {
    /// Makes the key shares of a ClientHello, and takes the PSKs it offers: one ticket from
    /// the session store for the server name, if it has one that is valid at `now` and of a
    /// hash this client's suites have, and the external PSKs.
    pub(crate) fn new(
        cfg: &HandshakeConfig,
        now: Option<Instant>,
        early_data: &[u8],
    ) -> Result<Self> {
        let mut key_shares = vec![];
        for curve in cfg.local_tls13_groups.iter().take(KEY_SHARES_OFFERED) {
            key_shares.push(curve.generate_keypair_with_crypto(cfg.provider().crypto())?);
        }
        if key_shares.is_empty() {
            return Err(Error::ErrNoSupportedEllipticCurves);
        }
        let mut psks = vec![];
        if let (Some(store), Some(now)) = (&cfg.session_store, now) {
            // A ticket is taken, and so used, once (RFC 8446 appendix C.4); an expired one,
            // or one of a hash none of this client's suites has, is dropped on the way.
            while let Some(session) = store.take(&cfg.server_name) {
                let usable = session.is_valid_at(now)
                    && Suite13::for_id(session.suite).is_some_and(|suite| {
                        cfg.local_tls13_cipher_suites
                            .iter()
                            .filter_map(|id| Suite13::for_id(*id))
                            .any(|own| own.hash() == suite.hash())
                    });
                if usable && let Some(psk) = OfferedPsk::from_session(session, now) {
                    psks.push(psk);
                    break;
                }
            }
        }
        for external in &cfg.external_psks {
            if let Some(psk) = OfferedPsk::from_external(external, &cfg.local_tls13_cipher_suites) {
                psks.push(psk);
            }
        }
        // RFC 8446 section 4.2.10: early data goes with the first PSK, and only a ticket
        // that says how much it allows (an external PSK has no single-use record at the
        // server, so no 0-RTT is offered with one).
        let early_data = psks
            .first()
            .filter(|psk| {
                !early_data.is_empty()
                    && !psk.external
                    && early_data.len() <= psk.max_early_data as usize
                    && early_data.len() <= super::record::MAX_PLAINTEXT
            })
            .map(|_| early_data.to_vec());
        Ok(Self {
            key_shares,
            connection_id: cfg.connection_id_offer(),
            psks,
            early_data,
        })
    }

    /// The extensions a DTLS 1.3 offer adds to the ClientHello: supported_versions,
    /// key_share and, if configured, connection_id.
    pub(crate) fn extensions(&self, cfg: &HandshakeConfig) -> Vec<Extension> {
        let mut versions = vec![];
        put_vec8(&mut versions, |list| {
            put_u16(list, DTLS1_3_WIRE_VERSION);
            if cfg.min_version == DtlsVersion::Dtls1_2 {
                put_u16(list, DTLS1_2_WIRE_VERSION);
            }
        });
        let shares: Vec<(u16, &[u8])> = self
            .key_shares
            .iter()
            .map(|keypair| (keypair.curve as u16, keypair.public_key.as_slice()))
            .collect();
        let mut extensions = vec![
            Extension::Unknown {
                extension_type: EXT_SUPPORTED_VERSIONS,
                data: versions,
            },
            Extension::Unknown {
                extension_type: EXT_KEY_SHARE,
                data: client_key_share_data(&shares),
            },
        ];
        if let Some(connection_id) = &self.connection_id {
            let mut data = vec![];
            put_vec8(&mut data, |out| out.extend_from_slice(connection_id));
            extensions.push(Extension::Unknown {
                extension_type: EXT_CONNECTION_ID,
                data,
            });
        }
        // RFC 8446 section 4.2.6: this client answers a CertificateRequest after the
        // handshake.
        if cfg.post_handshake_auth {
            extensions.push(Extension::Unknown {
                extension_type: EXT_POST_HANDSHAKE_AUTH,
                data: vec![],
            });
        }
        if cfg.uses_psks() {
            extensions.push(Extension::Unknown {
                extension_type: EXT_PSK_KEY_EXCHANGE_MODES,
                data: psk_key_exchange_modes_data(&cfg.psk_key_exchange_modes()),
            });
        }
        if self.early_data.is_some() {
            extensions.push(Extension::Unknown {
                extension_type: EXT_EARLY_DATA,
                data: vec![],
            });
        }
        // RFC 8446 section 4.2.11: the last extension of the ClientHello. Its binders are
        // written once the ClientHello they cover is ([`super::psk::bind`]).
        if !self.psks.is_empty() {
            extensions.push(Extension::Unknown {
                extension_type: EXT_PRE_SHARED_KEY,
                data: pre_shared_key_data(&self.psks, &placeholder_binders(&self.psks)),
            });
        }
        extensions
    }

    /// Writes the binders of the PSKs into `client_hello` (its body, which ends with the
    /// pre_shared_key extension), a first ClientHello: nothing comes before it in the
    /// transcript.
    pub(crate) fn bind(&self, cfg: &HandshakeConfig, client_hello: &mut [u8]) -> Result<()> {
        if self.psks.is_empty() {
            return Ok(());
        }
        super::psk::bind(
            cfg.provider().crypto(),
            &self.psks,
            &super::key_schedule::Transcript::default(),
            client_hello,
        )
    }
}

/// Rewrites a first ClientHello into the one that answers a HelloRetryRequest (RFC 8446
/// section 4.1.2): the same message, with the key_share replaced when the server named a
/// group, early_data removed, and the cookie added. `pre_shared_key` stays the last
/// extension, with `psk` as its data (placeholder binders), or goes when that is `None`.
pub(crate) fn second_client_hello(
    first: &ClientHello<'_>,
    key_share: Option<(u16, &[u8])>,
    cookie: Option<&[u8]>,
    psk: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);
    put_u16(&mut body, first.legacy_version);
    body.extend_from_slice(first.random);
    put_vec8(&mut body, |out| {
        out.extend_from_slice(first.legacy_session_id)
    });
    put_vec8(&mut body, |out| out.extend_from_slice(first.legacy_cookie));
    put_vec16(&mut body, |out| {
        for suite in &first.cipher_suites {
            put_u16(out, *suite);
        }
    });
    put_vec8(&mut body, |out| {
        out.extend_from_slice(first.legacy_compression_methods)
    });
    put_vec16(&mut body, |out| {
        for (extension_type, data) in &first.extensions {
            match *extension_type {
                EXT_EARLY_DATA | EXT_COOKIE | EXT_PRE_SHARED_KEY => {}
                EXT_KEY_SHARE => match key_share {
                    Some(share) => put_extension(out, EXT_KEY_SHARE, |data| {
                        data.extend_from_slice(&client_key_share_data(&[share]))
                    }),
                    None => put_extension(out, EXT_KEY_SHARE, |out| out.extend_from_slice(data)),
                },
                other => put_extension(out, other, |out| out.extend_from_slice(data)),
            }
        }
        if let Some(cookie) = cookie {
            put_extension(out, EXT_COOKIE, |data| {
                put_vec16(data, |out| out.extend_from_slice(cookie))
            });
        }
        if let Some(psk) = psk {
            put_extension(out, EXT_PRE_SHARED_KEY, |data| data.extend_from_slice(psk));
        }
    });
    body
}

/// What a server settles from a ClientHello.
pub(crate) struct Negotiated {
    pub(crate) suite: Suite13,
    pub(crate) group: NamedCurve,
    /// The client's key share for `group`; `None` when it sent none and has to be asked for
    /// one with a HelloRetryRequest.
    pub(crate) client_share: Option<Vec<u8>>,
    pub(crate) certificate: Certificate,
    pub(crate) signature_scheme: SignatureHashAlgorithm,
    pub(crate) srtp_profile: SrtpProtectionProfile,
    pub(crate) server_name: String,
    /// The connection id the client asks for in records sent to it, if it offered the
    /// extension.
    pub(crate) client_connection_id: Option<Vec<u8>>,
    /// The application protocol selected from the client's ALPN extension (RFC 7301
    /// section 3.2), when both sides use ALPN.
    pub(crate) application_protocol: Option<String>,
    /// The extension types the ClientHello carried: what EncryptedExtensions may answer.
    pub(crate) offered_extensions: Vec<u16>,
}

fn illegal(error: Error) -> Refusal {
    refuse(alert::ILLEGAL_PARAMETER, error)
}

/// Negotiates a DTLS 1.3 handshake from a ClientHello that offers it (RFC 8446 sections
/// 4.1.1, 4.1.2 and 4.2, RFC 9147 section 5.3).
///
/// # Errors
///
/// The alert RFC 8446 names for each way the ClientHello cannot be served.
pub(crate) fn negotiate(
    cfg: &HandshakeConfig,
    hello: &ClientHello<'_>,
) -> std::result::Result<Negotiated, Refusal> {
    // RFC 9147 section 5.3: a legacy_cookie in a DTLS 1.3 ClientHello is an
    // illegal_parameter. RFC 8446 section 4.1.2: so is any compression but null.
    if !hello.legacy_cookie.is_empty() {
        return Err(illegal(Error::ErrCookieMismatch));
    }
    if hello.legacy_compression_methods != [0] {
        return Err(illegal(Error::ErrNoNullCompressionMethod));
    }
    // RFC 8446 section 4.2.11: pre_shared_key is the last extension, and comes with
    // psk_key_exchange_modes. No PSK is accepted here; the handshake is a full one.
    if let Some(position) = hello
        .extensions
        .iter()
        .position(|(extension_type, _)| *extension_type == EXT_PRE_SHARED_KEY)
    {
        if position + 1 != hello.extensions.len() {
            return Err(illegal(Error::ErrInvalidExtensionType));
        }
        if hello.extension(EXT_PSK_KEY_EXCHANGE_MODES).is_none() {
            return Err(refuse(
                alert::MISSING_EXTENSION,
                Error::ErrInvalidExtensionType,
            ));
        }
    }

    // The first suite of the client's list that this server has.
    let shared_suites = || {
        hello
            .cipher_suites
            .iter()
            .map(|suite| CipherSuiteId::from(*suite))
            .filter(|suite| cfg.local_tls13_cipher_suites.contains(suite))
            .filter_map(Suite13::for_id)
    };
    let suite = shared_suites().next().ok_or_else(|| {
        refuse(
            alert::HANDSHAKE_FAILURE,
            Error::ErrCipherSuiteNoIntersection,
        )
    })?;
    // RFC 8446 section 4.2.11: an external PSK the client offers and this server holds
    // influences the suite, so that it can be used: the client's first of the PSK's hash.
    let suite = match external_psk_hash(cfg, hello) {
        Some(hash) if hash != suite.hash() => shared_suites()
            .find(|candidate| candidate.hash() == hash)
            .unwrap_or(suite),
        _ => suite,
    };

    // RFC 8446 section 9.2: a ClientHello for (EC)DHE without supported_groups, key_share
    // or signature_algorithms is answered with missing_extension.
    let missing = |error| refuse(alert::MISSING_EXTENSION, error);
    let groups = hello
        .extension(EXT_SUPPORTED_GROUPS)
        .ok_or_else(|| missing(Error::ErrNoSupportedEllipticCurves))?;
    let groups = parse_u16_list(groups).map_err(decode_error)?;
    let shares = hello
        .extension(EXT_KEY_SHARE)
        .ok_or_else(|| missing(Error::ErrNoSupportedEllipticCurves))?;
    let shares = parse_client_key_shares(shares).map_err(decode_error)?;
    let schemes = hello
        .extension(EXT_SIGNATURE_ALGORITHMS)
        .ok_or_else(|| missing(Error::ErrNoAvailableSignatureSchemes))?;
    let schemes = parse_u16_list(schemes).map_err(decode_error)?;

    // RFC 8446 section 4.2.8: each share is for a group of supported_groups, in the same
    // order, and no group has two.
    let mut share_positions = vec![];
    for (index, (group, _)) in shares.iter().enumerate() {
        let Some(position) = groups.iter().position(|listed| listed == group) else {
            return Err(illegal(Error::ErrInvalidNamedCurve));
        };
        if shares[..index].iter().any(|(earlier, _)| earlier == group)
            || share_positions.last().is_some_and(|last| position < *last)
        {
            return Err(illegal(Error::ErrInvalidNamedCurve));
        }
        share_positions.push(position);
    }
    // The group: the first of the client's that this server has and the client sent a share
    // for; failing that, the first this server has, which costs a HelloRetryRequest.
    let supported = |group: &u16| cfg.local_tls13_groups.contains(&NamedCurve::from(*group));
    let with_share = groups
        .iter()
        .filter(|group| supported(group))
        .find_map(|group| {
            shares
                .iter()
                .find(|(share_group, _)| share_group == group)
                .map(|(_, key)| (*group, Some(key.to_vec())))
        });
    let (group, client_share) = with_share
        .or_else(|| {
            groups
                .iter()
                .find(|group| supported(group))
                .map(|g| (*g, None))
        })
        .ok_or_else(|| {
            refuse(
                alert::HANDSHAKE_FAILURE,
                Error::ErrNoSupportedEllipticCurves,
            )
        })?;

    let server_name = match hello.extension(EXT_SERVER_NAME) {
        Some(data) => parse_server_name(data)
            .map_err(decode_error)?
            .unwrap_or_default(),
        None => String::new(),
    };

    // RFC 8446 section 4.4.3: a scheme the client lists, valid for TLS 1.3, that the
    // certificate's key can sign with. In this server's order of preference.
    let named = cfg
        .get_certificate(&server_name)
        .map_err(|error| refuse(alert::HANDSHAKE_FAILURE, error))?;
    let scheme_for = |certificate: &Certificate| {
        cfg.local_signature_schemes
            .iter()
            .find(|scheme| {
                scheme.is_tls13_signature()
                    && schemes.contains(&scheme.scheme_code())
                    && scheme.is_compatible(&certificate.private_key)
            })
            .copied()
    };
    // RFC 8446 section 4.4.2.2: the chain is one signed with algorithms the client lists,
    // if this server has one (the certificate for the name first, then its others); if it
    // has none, the handshake goes on with a chain whose key the client can verify with,
    // and the client decides.
    let client_pairs: Vec<SignatureHashAlgorithm> = schemes
        .iter()
        .map(|code| SignatureHashAlgorithm::from_scheme_code(*code))
        .collect();
    // RFC 8446 section 4.4.2.2: only a certificate whose key may sign is sent at all.
    let candidates = || {
        std::iter::once(&named)
            .chain(cfg.local_certificates.iter())
            .filter(|certificate| {
                certificate
                    .certificate
                    .first()
                    .is_some_and(|leaf| super::certificate_checks::allows_signing(leaf.as_ref()))
            })
    };
    let (certificate, signature_scheme) = candidates()
        .filter(|certificate| {
            crate::crypto::certificates_signed_within(&certificate.certificate, &client_pairs)
        })
        .chain(candidates())
        .find_map(|certificate| scheme_for(certificate).map(|scheme| (certificate.clone(), scheme)))
        .ok_or_else(|| {
            refuse(
                alert::HANDSHAKE_FAILURE,
                Error::ErrNoAvailableSignatureSchemes,
            )
        })?;

    // RFC 5764 section 4.1.1: a server that does not do DTLS-SRTP ignores the extension.
    let mut srtp_profile = SrtpProtectionProfile::Unsupported;
    if let Some(data) = hello.extension(EXT_USE_SRTP)
        && !cfg.local_srtp_protection_profiles.is_empty()
    {
        let (profiles, _mki) = parse_use_srtp(data).map_err(decode_error)?;
        match profiles
            .iter()
            .map(|profile| SrtpProtectionProfile::from(*profile))
            .find(|profile| cfg.local_srtp_protection_profiles.contains(profile))
        {
            Some(profile) => srtp_profile = profile,
            // As in DTLS 1.2: without a shared profile the association goes on without
            // SRTP unless the configuration requires it.
            None if cfg.use_srtp_required => {
                return Err(refuse(
                    alert::INSUFFICIENT_SECURITY,
                    Error::ErrServerNoMatchingSrtpProfile,
                ));
            }
            None => {}
        }
    }

    // RFC 7301 section 3.2: the first of this server's protocols the client offered; none in
    // common is a no_application_protocol alert. A server without ALPN ignores the extension.
    let application_protocol = match hello.extension(EXT_ALPN) {
        Some(data) => {
            let offered = crate::extension::parse_alpn(data).map_err(decode_error)?;
            match cfg.select_alpn(&offered) {
                Some(Ok(protocol)) => Some(protocol),
                Some(Err(error)) => return Err(refuse(alert::NO_APPLICATION_PROTOCOL, error)),
                None => None,
            }
        }
        None => None,
    };

    let client_connection_id = match hello.extension(EXT_CONNECTION_ID) {
        Some(data) => Some(parse_connection_id(data).map_err(decode_error)?.to_vec()),
        None => None,
    };

    Ok(Negotiated {
        suite,
        group: NamedCurve::from(group),
        client_share,
        certificate,
        signature_scheme,
        srtp_profile,
        server_name,
        client_connection_id,
        application_protocol,
        offered_extensions: hello.extensions.iter().map(|(t, _)| *t).collect(),
    })
}

/// The hash of the first external PSK of this server that `hello` offers, if any.
fn external_psk_hash(
    cfg: &HandshakeConfig,
    hello: &ClientHello<'_>,
) -> Option<crypto::HashAlgorithm> {
    if cfg.external_psks.is_empty() {
        return None;
    }
    let offered =
        super::psk::parse_client_pre_shared_key(hello.extension(EXT_PRE_SHARED_KEY)?).ok()?;
    offered.identities.iter().find_map(|(identity, _)| {
        cfg.external_psks
            .iter()
            .find(|psk| psk.identity == *identity)
            .map(|psk| super::psk::hash_of(psk.hash))
    })
}

/// What a HelloRetryRequest cookie carries, so that the server needs no state between the
/// two ClientHellos (RFC 9147 section 5.1): the hash of the first ClientHello, which the
/// transcript continues from, and what the HelloRetryRequest said, from which it is written
/// again byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetryCookie {
    pub(crate) suite: u16,
    /// The group of the HelloRetryRequest's key_share, or zero when it had none.
    pub(crate) group: u16,
    pub(crate) client_hello_hash: Vec<u8>,
}

const COOKIE_MAC_LENGTH: usize = 32;

/// The secrets an [`Endpoint`](crate::endpoint::Endpoint) makes its stateless
/// HelloRetryRequest cookies with, and the client address they are bound to, handed to an
/// association that runs the cookie exchange for a ClientHello the endpoint could not judge
/// on its own (one cut into fragments). Its cookies are then the endpoint's: whichever
/// association, or the endpoint itself, sees the second ClientHello can verify it, so an
/// association that goes before the second ClientHello arrives costs the client nothing.
pub(crate) struct RetryKeys {
    /// The current secret, which new cookies are made with, first.
    pub(crate) secrets: Vec<crypto::SecretVec>,
    pub(crate) remote: SocketAddr,
}

impl RetryCookie {
    /// The cookie's HMAC-SHA-256 under `secret`, on a stack that is overwritten afterwards
    /// (`crypto::on_erased_stack`): the HMAC leaves the keyed hash states of the secret in the
    /// provider's frames (tests/key_residue.rs).
    fn mac(
        provider: &dyn RTCCryptoProvider,
        secret: &[u8],
        remote: Option<SocketAddr>,
        content: &[u8],
    ) -> Result<[u8; COOKIE_MAC_LENGTH]> {
        crypto::on_erased_stack(|| Self::keyed_mac(provider, secret, remote, content))
    }

    fn keyed_mac(
        provider: &dyn RTCCryptoProvider,
        secret: &[u8],
        remote: Option<SocketAddr>,
        content: &[u8],
    ) -> Result<[u8; COOKIE_MAC_LENGTH]> {
        let (address, port) = match remote {
            Some(remote) => (
                match remote.ip() {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                },
                remote.port(),
            ),
            None => (vec![], 0),
        };
        let crypto_error = |error: crypto::CryptoError| Error::Crypto(error.to_string());
        let mut mac = provider
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, secret)
            .map_err(crypto_error)?;
        let mut tag = [0u8; COOKIE_MAC_LENGTH];
        mac.sign(
            &[
                b"dtls13 hrr cookie",
                &[address.len() as u8],
                &address,
                &port.to_be_bytes(),
                content,
            ],
            &mut tag,
        )
        .map_err(crypto_error)?;
        Ok(tag)
    }

    /// The cookie bytes: the contents and their HMAC-SHA-256 under `secret`, bound to the
    /// client's address when the server knows it.
    pub(crate) fn seal(
        &self,
        provider: &dyn RTCCryptoProvider,
        secret: &[u8],
        remote: Option<SocketAddr>,
    ) -> Result<Vec<u8>> {
        let mut cookie = Vec::with_capacity(5 + self.client_hello_hash.len() + COOKIE_MAC_LENGTH);
        put_u16(&mut cookie, self.suite);
        put_u16(&mut cookie, self.group);
        put_vec8(&mut cookie, |out| {
            out.extend_from_slice(&self.client_hello_hash)
        });
        let tag = Self::mac(provider, secret, remote, &cookie)?;
        cookie.extend_from_slice(&tag);
        Ok(cookie)
    }

    /// Reads a cookie this server made for `remote` under one of `secrets`. `None` for any
    /// other: the MAC is compared in constant time.
    pub(crate) fn open(
        provider: &dyn RTCCryptoProvider,
        secrets: &[&[u8]],
        remote: Option<SocketAddr>,
        cookie: &[u8],
    ) -> Result<Option<Self>> {
        if cookie.len() <= COOKIE_MAC_LENGTH {
            return Ok(None);
        }
        let (content, tag) = cookie.split_at(cookie.len() - COOKIE_MAC_LENGTH);
        let mut valid = false;
        for secret in secrets {
            let expected = Self::mac(provider, secret, remote, content)?;
            valid |= crypto::constant_time_eq(&expected, tag);
        }
        if !valid {
            return Ok(None);
        }
        let mut reader = Reader::new(content);
        let parsed = (|| -> Result<Self> {
            let suite = reader.u16()?;
            let group = reader.u16()?;
            let client_hello_hash = reader.vec8()?.to_vec();
            reader.finish()?;
            Ok(Self {
                suite,
                group,
                client_hello_hash,
            })
        })();
        Ok(parsed.ok())
    }

    /// The HelloRetryRequest this cookie stands for.
    pub(crate) fn hello_retry_request(&self, cookie: &[u8]) -> Vec<u8> {
        server_hello(&HELLO_RETRY_REQUEST_RANDOM, self.suite, |extensions| {
            if self.group != 0 {
                put_extension(extensions, EXT_KEY_SHARE, |data| put_u16(data, self.group));
            }
            put_extension(extensions, EXT_COOKIE, |data| {
                put_vec16(data, |out| out.extend_from_slice(cookie))
            });
        })
    }
}

/// The cookie of a ClientHello's cookie extension (RFC 8446 section 4.2.2).
pub(crate) fn parse_cookie(data: &[u8]) -> Result<&[u8]> {
    let mut reader = Reader::new(data);
    let cookie = reader.vec16()?;
    reader.finish()?;
    if cookie.is_empty() {
        return Err(Error::ErrLengthMismatch);
    }
    Ok(cookie)
}

/// The body of the ClientHello that is the whole of `datagram`'s first record, if the
/// datagram starts with one that is not fragmented, with its record sequence number and
/// message_seq. A server reads it before it keeps any state for the client.
pub(crate) fn whole_client_hello(datagram: &[u8]) -> Option<(&[u8], u64, u16)> {
    let header = datagram.get(..13)?;
    if header[0] != 22 || header[3..5] != [0, 0] {
        return None;
    }
    let mut sequence = [0u8; 8];
    sequence[2..].copy_from_slice(&header[5..11]);
    let length = usize::from(u16::from_be_bytes([header[11], header[12]]));
    let record = datagram.get(13..13 + length)?;
    let fragments = HandshakeFragment::parse_all(record).ok()?;
    let first = fragments.first()?;
    (first.handshake_type == CLIENT_HELLO
        && first.fragment_offset == 0
        && first.fragment.len() == first.length)
        .then_some((
            first.fragment,
            u64::from_be_bytes(sequence),
            first.message_seq,
        ))
}
