use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An owned byte vector that zeroizes its allocation when dropped.
///
/// The whole allocation is overwritten, spare capacity included. A `SecretVec` never grows: a
/// buffer that does (`Vec::extend`, `push`) moves to a new allocation and leaves the old one
/// behind unerased, so build key material in a buffer sized up front and wrap it here.
pub struct SecretVec(Zeroizing<Vec<u8>>);

impl Zeroize for SecretVec {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SecretVec {}

impl SecretVec {
    /// Wraps secret bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the number of secret bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Explicitly unwraps the secret bytes. The returned vector is no longer automatically zeroized.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.0)
    }
}

impl AsRef<[u8]> for SecretVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for SecretVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl Clone for SecretVec {
    fn clone(&self) -> Self {
        Self::new(self.as_ref().to_vec())
    }
}

impl fmt::Debug for SecretVec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretVec")
            .field("len", &self.len())
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl From<Vec<u8>> for SecretVec {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

/// How much stack [`scrub_stack`] overwrites: 32 KiB in an optimised build, 128 KiB in an
/// unoptimised one (`debug_assertions`, which Cargo's `dev` and `test` profiles turn on with
/// opt-level 0).
///
/// The depth has to cover the stack the work before it used. Building an SRTP context uses
/// about 3 KiB in an optimised build and 42 to 47 KiB in an unoptimised one, where every
/// temporary has a stack slot of its own (`rtci-srtp/tests/key_residue.rs`, measured with a
/// 32 KiB overwrite): the AES key schedules built for the key derivation are the deepest
/// part, below frames such as
/// `common::block_encrypt`'s, which holds a cipher object of every AES key length. With rustc
/// 1.99.1 (x86-64 Linux) the master key and its round keys were left 37.7 to 42.2 KB below the
/// point the measurement starts from, more than 32 KiB below the context's `on_erased_stack`
/// frame (which lies less than 4.9 KB below that point), out of a 32 KiB overwrite's reach.
/// 128 KiB is the deepest unoptimised use measured (47 KiB) times 2.7, for other compilers and
/// profiles. The optimised depth is unchanged, and so is an optimised build's cost.
const SCRUB_STACK_BYTES: usize = if cfg!(debug_assertions) {
    128 * 1024
} else {
    32 * 1024
};

/// Overwrites the stack below the caller's frame (32 KiB of it in an optimised build, 128 KiB in
/// an unoptimised one).
///
/// Building a keyed object leaves copies of the key and its schedule in the stack frames of
/// the functions that built it: a value moved out of a frame is not dropped there, so its
/// zeroize-on-drop never runs on the copy left behind, and a provider's own temporaries are
/// not erased at all. Those dead frames are reused by later calls, and a value later built
/// there and moved into the heap (into a `Box`, a `Vec`) carries whatever was in its padding
/// or in the unused part of an enum or union along: the key ends up in memory the heap frees
/// without erasure. Calling this right after a key schedule is built and moved to where it
/// lives, from the frame that called the provider, overwrites what the deeper frames left.
///
/// What it does: one bulk zero fill (`ptr::write_bytes`, a `memset`) of a buffer of that size
/// in its own frame, which is never inlined, so the buffer lies in the stack just below the
/// caller's frame, where the frames of the calls the caller made before lay. The buffer is
/// then handed to [`std::hint::black_box`] and followed by a compiler fence, so the compiler
/// cannot treat the fill as a dead store and drop it. The calling thread needs that much stack
/// free below the caller.
///
/// What it does not do: it cannot reach registers, the caller's own frame or any frame above
/// it, other threads' stacks, or anything deeper than that size below the caller (a build
/// profile with opt-level 0 and `debug-assertions = false` gets the optimised depth); and
/// copies the compiler or a provider leaves that no test can see are not observed, so their
/// absence is not guaranteed. The tests show only that copies carried from dead frames into heap padding
/// are gone (`tests/dtls_secret_erasure.rs`; docs/key-erasure.md).
#[inline(never)]
pub fn scrub_stack() {
    let mut area = std::mem::MaybeUninit::<[u8; SCRUB_STACK_BYTES]>::uninit();
    // SAFETY: the pointer is to a local buffer of exactly `SCRUB_STACK_BYTES` bytes, written
    // as bytes (any value is valid for `u8`) and never read as anything else.
    unsafe { std::ptr::write_bytes(area.as_mut_ptr().cast::<u8>(), 0, SCRUB_STACK_BYTES) };
    // The buffer is never read: without this the fill is a dead store the optimiser may remove.
    std::hint::black_box(&mut area);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// How much stack [`scrub_record_stack`] overwrites: 48 KiB, in an unoptimised build only.
///
/// The deepest record-key form measured in an unoptimised build lay 31,288 bytes below the
/// DTLS key residue measurement's floor (rustc 1.89, the AES-CCM records step,
/// `rtci-dtls/tests/key_residue.rs`, run 46015302538). Every record call's own frame lies below
/// that floor, so what the record work leaves lies less than that below the call. 48 KiB is
/// that depth times 1.5, for other compilers and call paths; it is paid in unoptimised builds
/// only.
#[cfg(debug_assertions)]
const SCRUB_RECORD_STACK_BYTES: usize = 48 * 1024;

/// Overwrites the stack below the caller's frame after one record's work with RustCrypto's AES,
/// in an unoptimised build (`debug_assertions`); in an optimised build it is not compiled.
///
/// At opt-level 0 the AES-NI intrinsics of the `aes` crate are calls whose vector arguments go
/// through stack copies, so every block encrypted or decrypted leaves round keys (round key 0
/// is the key) and AES states in stack temporaries; an optimised build keeps them in registers.
/// Measured: on Windows a DTLS 1.2 AES-CCM write key left there was carried into a freed heap
/// block by the unwritten bytes of a handshake message moved into a map (docs/key-erasure.md);
/// with the `aes` and `ccm` crates optimised, with the portable AES, in an optimised build, or
/// with an overwrite after each AES-CCM call, it was not (runs 46026969169, 46026978042).
#[cfg(debug_assertions)]
#[inline(never)]
pub(crate) fn scrub_record_stack() {
    let mut area = std::mem::MaybeUninit::<[u8; SCRUB_RECORD_STACK_BYTES]>::uninit();
    // SAFETY: the pointer is to a local buffer of exactly `SCRUB_RECORD_STACK_BYTES` bytes,
    // written as bytes and never read as anything else.
    unsafe { std::ptr::write_bytes(area.as_mut_ptr().cast::<u8>(), 0, SCRUB_RECORD_STACK_BYTES) };
    std::hint::black_box(&mut area);
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
