#[cfg(test)]
mod prf_test;

use crate::record_layer::record_layer_header::RecordLayerHeader;
use std::fmt;

use crypto::{Mac, RTCCrypto, SecretVec};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::cipher_suite::CipherSuiteHash;
use crate::content::ContentType;
use crate::curve::named_curve::*;
use crate::record_layer::record_layer_header::ProtocolVersion;
use shared::error::*;

pub(crate) const PRF_MASTER_SECRET_LABEL: &str = "master secret";
pub(crate) const PRF_EXTENDED_MASTER_SECRET_LABEL: &str = "extended master secret";
pub(crate) const PRF_KEY_EXPANSION_LABEL: &str = "key expansion";
pub(crate) const PRF_VERIFY_DATA_CLIENT_LABEL: &str = "client finished";
pub(crate) const PRF_VERIFY_DATA_SERVER_LABEL: &str = "server finished";

/// The key block of a DTLS 1.2 connection (RFC 5246 section 6.3), split into its keys.
///
/// Every field is key material: zeroized on drop, never printed.
#[derive(PartialEq, Zeroize, ZeroizeOnDrop)]
pub(crate) struct EncryptionKeys {
    pub(crate) client_mac_key: Vec<u8>,
    pub(crate) server_mac_key: Vec<u8>,
    pub(crate) client_write_key: Vec<u8>,
    pub(crate) server_write_key: Vec<u8>,
    pub(crate) client_write_iv: Vec<u8>,
    pub(crate) server_write_iv: Vec<u8>,
}

impl fmt::Debug for EncryptionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKeys")
            .field("mac_key_len", &self.client_mac_key.len())
            .field("write_key_len", &self.client_write_key.len())
            .field("write_iv_len", &self.client_write_iv.len())
            .finish_non_exhaustive()
    }
}

// The premaster secret is formed as follows: if the PSK is N octets
// long, concatenate a uint16 with the value N, N zero octets, a second
// uint16 with the value N, and the PSK itself.
//
// https://tools.ietf.org/html/rfc4279#section-2
pub(crate) fn prf_psk_pre_master_secret(psk: &[u8]) -> SecretVec {
    let psk_len = psk.len();
    let be = (psk_len as u16).to_be_bytes();

    // Sized up front: a buffer that grew would leave a copy behind.
    let mut out = vec![0u8; 2 + psk_len + 2 + psk_len];
    out[..2].copy_from_slice(&be);
    out[2 + psk_len..2 + psk_len + 2].copy_from_slice(&be);
    out[2 + psk_len + 2..].copy_from_slice(psk);

    SecretVec::new(out)
}

pub(crate) fn prf_pre_master_secret(
    public_key: &[u8],
    keypair: &mut NamedCurveKeypair,
    curve: NamedCurve,
) -> Result<SecretVec> {
    if keypair.curve != curve {
        return Err(Error::ErrNamedCurveAndPrivateKeyMismatch);
    }
    keypair.complete(public_key)
}

//  This PRF with the SHA-256 hash function is used for all cipher suites
//  defined in this document and in TLS documents published prior to this
//  document when TLS 1.2 is negotiated.  New cipher suites MUST explicitly
//  specify a PRF and, in general, SHOULD use the TLS PRF with SHA-256 or a
//  stronger standard hash function.
//
//     P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
//                            HMAC_hash(secret, A(2) + seed) +
//                            HMAC_hash(secret, A(3) + seed) + ...
//
//  A() is defined as:
//
//     A(0) = seed
//     A(i) = HMAC_hash(secret, A(i-1))
//
//  P_hash can be iterated as many times as necessary to produce the
//  required quantity of data.  For example, if P_SHA256 is being used to
//  create 80 bytes of data, it will have to be iterated three times
//  (through A(3)), creating 96 bytes of output data; the last 16 bytes
//  of the final iteration will then be discarded, leaving 80 bytes of
//  output data.
//
// https://tools.ietf.org/html/rfc4346w
//
// Everything P_hash computes is key material, or is derived from the secret: the output, each
// HMAC output, each A(i). It is all built in zeroizing buffers sized up front (a buffer that grew
// would leave a copy in the allocation it moved from), and the secret is keyed into the HMAC
// once.
//
// It runs on a stack that is overwritten afterwards (`crypto::on_erased_stack`): each HMAC
// leaves the keyed hash states of the secret, and its output, in the provider's frames (ring
// copies the keyed context onto the stack per MAC; measured by tests/key_residue.rs, where the
// master secret's HMAC states were the largest DTLS residue). That covers the master secret, the
// extended master secret, the key block, verify_data and the exporter.
pub(crate) fn prf_p_hash(
    crypto: &dyn RTCCrypto,
    secret: &[u8],
    seed: &[u8],
    requested_length: usize,
    h: CipherSuiteHash,
) -> Result<SecretVec> {
    crypto::on_erased_stack(|| p_hash(crypto, secret, seed, requested_length, h))
}

fn p_hash(
    crypto: &dyn RTCCrypto,
    secret: &[u8],
    seed: &[u8],
    requested_length: usize,
    h: CipherSuiteHash,
) -> Result<SecretVec> {
    let algorithm = h.hmac_algorithm();
    let digest_len = algorithm.output_len();
    let mut mac = crypto
        .new_hmac(algorithm, secret)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let mut sign = |input: &[&[u8]], output: &mut [u8]| {
        mac.sign(input, output)
            .map_err(|error| Error::Crypto(error.to_string()))
    };

    let iterations = requested_length.div_ceil(digest_len);
    let mut out = Zeroizing::new(vec![0u8; iterations * digest_len]);
    // A(i), and A(i-1) while A(i) is computed from it.
    let mut a = Zeroizing::new(vec![0u8; digest_len]);
    let mut previous = Zeroizing::new(vec![0u8; digest_len]);
    for (i, block) in out.chunks_exact_mut(digest_len).enumerate() {
        if i == 0 {
            // A(1) = HMAC_hash(secret, A(0)), A(0) = seed.
            sign(&[seed], &mut a)?;
        } else {
            previous.copy_from_slice(&a);
            sign(&[&previous], &mut a)?;
        }
        sign(&[&a, seed], block)?;
    }

    out.truncate(requested_length);
    Ok(SecretVec::new(std::mem::take(&mut *out)))
}

pub(crate) fn prf_extended_master_secret(
    crypto: &dyn RTCCrypto,
    pre_master_secret: &[u8],
    session_hash: &[u8],
    h: CipherSuiteHash,
) -> Result<SecretVec> {
    let mut seed = PRF_EXTENDED_MASTER_SECRET_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(session_hash);
    prf_p_hash(crypto, pre_master_secret, &seed, 48, h)
}

pub(crate) fn prf_master_secret(
    crypto: &dyn RTCCrypto,
    pre_master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    h: CipherSuiteHash,
) -> Result<SecretVec> {
    let mut seed = PRF_MASTER_SECRET_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf_p_hash(crypto, pre_master_secret, &seed, 48, h)
}

pub(crate) struct EncryptionKeyLengths {
    pub(crate) mac: usize,
    pub(crate) key: usize,
    pub(crate) iv: usize,
}

pub(crate) fn prf_encryption_keys(
    crypto: &dyn RTCCrypto,
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
    lengths: EncryptionKeyLengths,
    h: CipherSuiteHash,
) -> Result<EncryptionKeys> {
    let mut seed = PRF_KEY_EXPANSION_LABEL.as_bytes().to_vec();
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let material = prf_p_hash(
        crypto,
        master_secret,
        &seed,
        (2 * lengths.mac) + (2 * lengths.key) + (2 * lengths.iv),
        h,
    )?;
    let mut key_material = material.as_ref();

    // Each key is copied into an allocation of its own size, which never grows.
    let client_mac_key = key_material[..lengths.mac].to_vec();
    key_material = &key_material[lengths.mac..];

    let server_mac_key = key_material[..lengths.mac].to_vec();
    key_material = &key_material[lengths.mac..];

    let client_write_key = key_material[..lengths.key].to_vec();
    key_material = &key_material[lengths.key..];

    let server_write_key = key_material[..lengths.key].to_vec();
    key_material = &key_material[lengths.key..];

    let client_write_iv = key_material[..lengths.iv].to_vec();
    key_material = &key_material[lengths.iv..];

    let server_write_iv = key_material[..lengths.iv].to_vec();

    Ok(EncryptionKeys {
        client_mac_key,
        server_mac_key,
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

pub(crate) fn prf_verify_data(
    crypto: &dyn RTCCrypto,
    master_secret: &[u8],
    handshake_bodies: &[u8],
    label: &str,
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    let result = crypto
        .hash(h.hash_algorithm(), handshake_bodies)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let mut seed = label.as_bytes().to_vec();
    seed.extend_from_slice(&result);

    // verify_data is no secret: it is sent, in the Finished message.
    Ok(prf_p_hash(crypto, master_secret, &seed, 12, h)?.into_bytes())
}

pub(crate) fn prf_verify_data_client(
    crypto: &dyn RTCCrypto,
    master_secret: &[u8],
    handshake_bodies: &[u8],
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    prf_verify_data(
        crypto,
        master_secret,
        handshake_bodies,
        PRF_VERIFY_DATA_CLIENT_LABEL,
        h,
    )
}

pub(crate) fn prf_verify_data_server(
    crypto: &dyn RTCCrypto,
    master_secret: &[u8],
    handshake_bodies: &[u8],
    h: CipherSuiteHash,
) -> Result<Vec<u8>> {
    prf_verify_data(
        crypto,
        master_secret,
        handshake_bodies,
        PRF_VERIFY_DATA_SERVER_LABEL,
        h,
    )
}

// compute the MAC using HMAC-SHA1
/// Computes the TLS 1.2 record MAC (RFC 5246 section 6.2.3.1) with an already-keyed MAC.
///
/// Takes `&mut dyn Mac` rather than a crypto handle plus raw key bytes so the caller keys once
/// per epoch. Re-deriving the HMAC key schedule per record measured ~2x on the CBC record path.
pub(crate) fn prf_mac(
    mac: &mut dyn Mac,
    epoch: u16,
    sequence_number: u64,
    content_type: ContentType,
    protocol_version: ProtocolVersion,
    cid: Option<&[u8]>,
    payload: &[u8],
) -> Result<Vec<u8>> {
    // RFC 9146 section 5.1 for a `tls12_cid` record (its connection id given), RFC 5246
    // 6.2.3.1 otherwise.
    let msg = crate::crypto::record_additional_data(
        &RecordLayerHeader {
            content_type,
            protocol_version,
            epoch,
            sequence_number,
            content_len: 0,
        },
        payload.len(),
        cid,
    );

    let mut output = vec![0; mac.output_len()];
    mac.sign(&[&msg, payload], &mut output)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(output)
}
