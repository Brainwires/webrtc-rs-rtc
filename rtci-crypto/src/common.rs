use crate::{
    AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher, CryptoError,
    StreamCipher, StreamCipherAlgorithm,
};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, InnerIvInit, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use ccm::Ccm;
use ccm::aead::AeadInPlace;
use ccm::consts::{U8, U12, U16};
use ctr::CtrCore;
use ctr::cipher::StreamCipher as CtrStreamCipher;
use ctr::cipher::StreamCipherCoreWrapper;
use ctr::flavors::Ctr128BE;
use md5::{Digest, Md5};
use std::mem::ManuallyDrop;
use std::sync::atomic::{Ordering, compiler_fence};

const AES_BLOCK_LEN: usize = 16;
const CCM_NONCE_LEN: usize = 12;

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

/// Fills `output` from the thread-local CSPRNG shared by the built-in providers.
///
/// This is a ChaCha-based generator seeded from the operating system and periodically reseeded,
/// not a per-call OS read. `ring::rand::SystemRandom` and `aws_lc_rs::rand::SystemRandom` reach
/// the OS on every call — measured at ~829 ns and ~2196 ns for an 8-byte fill, against ~8 ns
/// here. DTLS generates a GCM explicit nonce and a CBC record IV *per record*, so the difference
/// showed up as a 3-8x regression on DTLS encryption; see `rtci-dtls/benches/README.md`.
///
/// This restores what the pre-provider code did (`rand::rng()`), and matches how BoringSSL and
/// OpenSSL buffer internally. A deployment that requires every byte of entropy to come from a
/// validated module supplies its own [`RTCRandom`](crate::RTCRandom) implementation; that is what
/// the trait is for.
pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    rand::fill(output);
    Ok(())
}

pub(crate) fn md5(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

/// SHA-224 for the ring provider, which has none of its own.
#[cfg(feature = "crypto-ring")]
pub(crate) fn sha224(data: &[u8]) -> Vec<u8> {
    sha2::Sha224::digest(data).to_vec()
}

pub(crate) fn block_encrypt(
    algorithm: BlockCipherAlgorithm,
    key: &[u8],
    block: &mut [u8],
) -> Result<(), CryptoError> {
    check_len(AES_BLOCK_LEN, block.len(), LengthKind::Output)?;
    match algorithm {
        BlockCipherAlgorithm::Aes128 => {
            check_key_len(16, key.len())?;
            Aes128::new_from_slice(key)
                .map_err(|_| invalid_key(16, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
        BlockCipherAlgorithm::Aes256 => {
            check_key_len(32, key.len())?;
            Aes256::new_from_slice(key)
                .map_err(|_| invalid_key(32, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
        BlockCipherAlgorithm::Aes192 => {
            check_key_len(24, key.len())?;
            Aes192::new_from_slice(key)
                .map_err(|_| invalid_key(24, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
    }
    Ok(())
}

pub(crate) fn new_stream_cipher(
    algorithm: StreamCipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn StreamCipher>, CryptoError> {
    match algorithm {
        StreamCipherAlgorithm::Aes128Ctr => check_key_len(16, key.len())?,
        StreamCipherAlgorithm::Aes256Ctr => check_key_len(32, key.len())?,
        StreamCipherAlgorithm::Aes192Ctr => check_key_len(24, key.len())?,
    }
    // The cipher object is built on the stack and moved into its box, bytes it never
    // initialised included (see `AesCtr`): those must not be what an earlier call left there.
    crate::scrub_stack();
    Ok(expanded_stream_cipher(algorithm, key))
}

/// Expands `key` (of the algorithm's length) and boxes the cipher. A frame of its own, so that
/// it and everything it calls lie in the stack [`new_stream_cipher`] has just overwritten.
#[inline(never)]
fn expanded_stream_cipher(algorithm: StreamCipherAlgorithm, key: &[u8]) -> Box<dyn StreamCipher> {
    match algorithm {
        StreamCipherAlgorithm::Aes128Ctr => {
            Box::new(AesCtr::new(Aes128::new(GenericArray::from_slice(key))))
        }
        StreamCipherAlgorithm::Aes256Ctr => {
            Box::new(AesCtr::new(Aes256::new(GenericArray::from_slice(key))))
        }
        StreamCipherAlgorithm::Aes192Ctr => {
            Box::new(AesCtr::new(Aes192::new(GenericArray::from_slice(key))))
        }
    }
}

pub(crate) fn new_cbc(
    algorithm: CbcAlgorithm,
    key: &[u8],
) -> Result<Box<dyn CbcCipher>, CryptoError> {
    match algorithm {
        CbcAlgorithm::Aes256Cbc => Ok(Box::new(AesCbc {
            key: ExpandedAesKey::new_256(key)?,
        })),
    }
}

pub(crate) fn new_ccm(
    algorithm: AeadAlgorithm,
    key: &[u8],
) -> Result<Box<dyn AeadCipher>, CryptoError> {
    check_key_len(16, key.len())?;
    let cipher = match algorithm {
        AeadAlgorithm::Aes128Ccm => {
            CommonCcm::Full(Aes128Ccm::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?)
        }
        AeadAlgorithm::Aes128Ccm8 => CommonCcm::Short(
            Aes128Ccm8::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?,
        ),
        _ => {
            return Err(CryptoError::UnsupportedAlgorithm(
                crate::CryptoAlgorithm::Aead(algorithm),
            ));
        }
    };
    Ok(Box::new(cipher))
}

// Stores an expanded key inside an already boxed cipher object, avoiding another allocation in
// every constructed state object. Only AES-256 is needed: `CbcAlgorithm` has a single variant,
// and CTR now goes through the `ctr` crate.
#[allow(clippy::large_enum_variant)]
enum ExpandedAesKey {
    Aes256(Aes256),
}

impl ExpandedAesKey {
    fn new_256(key: &[u8]) -> Result<Self, CryptoError> {
        check_key_len(32, key.len())?;
        Ok(Self::Aes256(
            Aes256::new_from_slice(key).map_err(|_| invalid_key(32, key.len()))?,
        ))
    }

    fn encrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(block)),
        }
    }

    fn decrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.decrypt_block(GenericArray::from_mut_slice(block)),
        }
    }
}

/// One record's work with RustCrypto's AES (AES-CTR, AES-CBC, AES-CCM). In an unoptimised build
/// it runs in a frame of its own and the stack below the caller is overwritten afterwards
/// ([`crate::secret::scrub_record_stack`]: the unoptimised AES-NI code leaves round keys in
/// stack temporaries); in an optimised build it is `work()`, inlined, and adds nothing.
#[inline(always)]
fn record_work<R>(work: impl FnOnce() -> R) -> R {
    #[cfg(debug_assertions)]
    {
        #[inline(never)]
        fn own_frame<R>(work: impl FnOnce() -> R) -> R {
            work()
        }
        let value = own_frame(work);
        crate::secret::scrub_record_stack();
        value
    }
    #[cfg(not(debug_assertions))]
    {
        work()
    }
}

/// AES counter mode over a key schedule expanded once.
///
/// Delegates to the `ctr` crate rather than driving `encrypt_block` once per 16-byte block, which
/// defeats the batching that lets AES-NI / ARMv8 crypto instructions pipeline. Measured ~9-10%
/// faster on a 1200-byte SRTP payload. See `rtci-srtp/benches/README.md`.
///
/// The schedule lives here, in the boxed cipher object, and a call runs `ctr` over a
/// reference to it: nothing key-dependent but the keystream is built per call. Until 0.2 the
/// object kept the key and each call expanded it into a cipher on its stack: both AES
/// schedules of the session key were then left in a dead stack frame by every packet (RFC
/// 7714 section 13.1; found by `rtci-srtp/tests/key_residue.rs`).
///
/// Erasure. `aes` zeroizes the schedule it used when the cipher is dropped, but its cipher
/// types are unions of a hardware and a (larger) portable schedule, and the bytes of the
/// variant not in use are never written by it: they are whatever the stack held where the
/// value was built, carried into the box by the move. So this type drops the cipher in place
/// and then overwrites every byte of it, used or not, and [`new_stream_cipher`] builds it over
/// stack it has just overwritten.
struct AesCtr<C> {
    cipher: ManuallyDrop<C>,
}

impl<C> AesCtr<C> {
    fn new(cipher: C) -> Self {
        Self {
            cipher: ManuallyDrop::new(cipher),
        }
    }
}

impl<C> Drop for AesCtr<C> {
    fn drop(&mut self) {
        // SAFETY: the cipher is dropped once, here, and never used again (`ManuallyDrop` keeps
        // the drop glue from touching it afterwards). Its bytes are then overwritten through a
        // raw byte pointer: after the drop in place the field holds no value, only memory this
        // value owns, so the writes do not depend on the cipher's layout.
        unsafe {
            ManuallyDrop::drop(&mut self.cipher);
            let bytes = (&raw mut self.cipher).cast::<u8>();
            for offset in 0..size_of::<C>() {
                std::ptr::write_volatile(bytes.add(offset), 0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<C> StreamCipher for AesCtr<C>
where
    C: Send,
    for<'a> &'a C: BlockEncrypt + BlockCipher + BlockSizeUser<BlockSize = U16>,
{
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
        record_work(|| {
            check_nonce_len(AES_BLOCK_LEN, iv.len())?;
            // SRTP counter mode (RFC 3711 section 4.1.1) is AES-CTR with a big-endian 128-bit
            // counter.
            let mut stream = StreamCipherCoreWrapper::from_core(
                CtrCore::<&C, Ctr128BE>::inner_iv_init(&*self.cipher, GenericArray::from_slice(iv)),
            );
            stream.apply_keystream(data);
            Ok(())
        })
    }
}

struct AesCbc {
    key: ExpandedAesKey,
}

impl CbcCipher for AesCbc {
    fn block_len(&self) -> usize {
        AES_BLOCK_LEN
    }

    fn encrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        record_work(|| {
            check_nonce_len(AES_BLOCK_LEN, iv.len())?;
            check_blocks(blocks)?;
            let mut previous: [u8; AES_BLOCK_LEN] = iv
                .try_into()
                .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

            // `check_blocks` has already rejected a length that is not a whole number of blocks,
            // so the remainder this returns is empty and the array chunks are the whole input.
            for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
                for (byte, prior) in block.iter_mut().zip(previous) {
                    *byte ^= prior;
                }
                self.key.encrypt(block);
                previous = *block;
            }
            Ok(())
        })
    }

    fn decrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        record_work(|| {
            check_nonce_len(AES_BLOCK_LEN, iv.len())?;
            check_blocks(blocks)?;
            let mut previous: [u8; AES_BLOCK_LEN] = iv
                .try_into()
                .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

            for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
                // The ciphertext masks the *next* block, so it has to be kept before decryption
                // overwrites it in place.
                let ciphertext = *block;
                self.key.decrypt(block);
                for (byte, prior) in block.iter_mut().zip(previous) {
                    *byte ^= prior;
                }
                previous = ciphertext;
            }
            Ok(())
        })
    }
}

enum CommonCcm {
    Full(Aes128Ccm),
    Short(Aes128Ccm8),
}

impl AeadCipher for CommonCcm {
    fn tag_len(&self) -> usize {
        match self {
            Self::Full(_) => 16,
            Self::Short(_) => 8,
        }
    }

    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        record_work(|| {
            check_nonce_len(CCM_NONCE_LEN, nonce.len())?;
            check_tag_len(self.tag_len(), tag_out.len())?;
            match self {
                Self::Full(cipher) => {
                    let tag = cipher
                        .encrypt_in_place_detached(
                            GenericArray::from_slice(nonce),
                            aad,
                            plaintext_and_ciphertext,
                        )
                        .map_err(|_| CryptoError::AuthenticationFailed)?;
                    tag_out.copy_from_slice(&tag);
                }
                Self::Short(cipher) => {
                    let tag = cipher
                        .encrypt_in_place_detached(
                            GenericArray::from_slice(nonce),
                            aad,
                            plaintext_and_ciphertext,
                        )
                        .map_err(|_| CryptoError::AuthenticationFailed)?;
                    tag_out.copy_from_slice(&tag);
                }
            }
            Ok(())
        })
    }

    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        record_work(|| {
            check_nonce_len(CCM_NONCE_LEN, nonce.len())?;
            check_tag_len(self.tag_len(), tag.len())?;
            match self {
                Self::Full(cipher) => cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        ciphertext_and_plaintext,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed),
                Self::Short(cipher) => cipher
                    .decrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        ciphertext_and_plaintext,
                        GenericArray::from_slice(tag),
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed),
            }
        })
    }
}

fn check_blocks(blocks: &[u8]) -> Result<(), CryptoError> {
    if blocks.is_empty() || !blocks.len().is_multiple_of(AES_BLOCK_LEN) {
        return Err(CryptoError::OutputTooSmall {
            required: blocks
                .len()
                .next_multiple_of(AES_BLOCK_LEN)
                .max(AES_BLOCK_LEN),
            actual: blocks.len(),
        });
    }
    Ok(())
}

enum LengthKind {
    Output,
}

fn check_len(expected: usize, actual: usize, kind: LengthKind) -> Result<(), CryptoError> {
    if expected == actual {
        return Ok(());
    }
    match kind {
        LengthKind::Output => Err(CryptoError::OutputTooSmall {
            required: expected,
            actual,
        }),
    }
}

pub(crate) fn check_key_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_key(expected, actual))
    }
}

pub(crate) fn check_nonce_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_nonce(expected, actual))
    }
}

pub(crate) fn check_tag_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CryptoError::InvalidTagLength { expected, actual })
    }
}

fn invalid_key(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidKeyLength { expected, actual }
}

fn invalid_nonce(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidNonceLength { expected, actual }
}
