//! Key handling on a stack that is overwritten afterwards.
//!
//! Building a keyed object leaves copies of the key in the stack frames of the functions that
//! built it: a key schedule expanded in a local and moved to where it lives, a provider's own
//! temporaries, the state of a MAC keyed on the stack before it is boxed. A value moved out of
//! a frame is not dropped there, so no zeroize-on-drop reaches the copy left behind, and the
//! frames belong to code this crate does not control (the compiler's moves, the provider).
//! Measured with every SRTP profile (`rtci-srtp/tests/key_residue.rs`): after building a
//! context the master key with both of its AES schedules, session round keys, GHASH keys and
//! HMAC states are in the dead frames of the thread that built it.
//!
//! [`on_erased_stack`] does not chase those copies one by one. It runs the work in a frame of
//! its own and overwrites the stack below the caller's frame when the work has returned.

/// Runs `work` and overwrites the stack it ran on.
///
/// `work` runs in a frame of its own on the caller's stack, and
/// [`scrub_stack`](crate::scrub_stack) then overwrites the stack below this function's frame,
/// 32 KiB of it in an optimised build and 128 KiB in an unoptimised one: what `work` and its
/// callees left in their frames within that reach is gone. Building an SRTP context uses about
/// 3 KiB of stack in an optimised build and 42 to 47 KiB in an unoptimised one, depending on
/// the compiler (`rtci-srtp/tests/key_residue.rs` measured it, and asserts that nothing is left
/// after it in either build, on x86-64 Linux and AArch64 macOS); a provider that goes deeper
/// than the overwrite leaves what lies below.
/// What it does not cover: the value `work` returns (return pointers to key material, not key
/// material), registers, and what `work` wrote elsewhere (the heap: use
/// [`SecretVec`](crate::SecretVec) and zeroizing types there).
#[inline(never)]
pub fn on_erased_stack<R>(work: impl FnOnce() -> R) -> R {
    #[inline(never)]
    fn own_frame<R>(work: impl FnOnce() -> R) -> R {
        work()
    }
    let value = own_frame(work);
    crate::scrub_stack();
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_of_the_work_is_returned() {
        let secret = [1u8, 2, 3];
        assert_eq!(6u8, on_erased_stack(|| secret.iter().sum()));
        assert_eq!(3, on_erased_stack(move || secret.len()));
    }
}
