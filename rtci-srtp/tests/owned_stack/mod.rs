//! A thread that runs on a stack the test owns, so that what code leaves in dead stack frames
//! can be read byte for byte: the measurement of `key_residue.rs`.
//!
//! Why not an ordinary thread. The stack of a thread the C library made is the C library's,
//! and what a search of it sees after the thread has ended is decided there. Measured
//! (`investigate_how_the_c_library_treats_thread_stacks`, runs 45873633642 and 45873641664):
//!
//! * glibc 2.39 and 2.43 both give an ended thread's stack back to the kernel except for a
//!   few pages near its top: of 256 marks written down the first mebibyte, 4 are left (about
//!   10 to 22 KiB below the top) and 506 of 512 pages read as zeros. Residue deeper than that
//!   is gone, whatever the code under test did.
//! * With glibc 2.39 a thread's guard is a mapping of its own, so each stack is one line of
//!   `/proc/self/maps`. With glibc 2.43 (kernel 7.0) it is not: a worker's stack and the stack
//!   of the thread that started it are one mapping (4104 KiB), and reading it through
//!   `/proc/self/mem` in 1 MiB pieces fails for the pieces holding a guard page (2 of 5). A
//!   search that leaves out "the mapping holding my own stack", or drops a piece it cannot
//!   read, never looks at the worker's stack there. That is why the search this replaced
//!   found key residue in 20 of 20 runs in one environment and in 0 of 40 in the other.
//! * glibc leaves a stack the caller supplied alone when its thread ends (all marks left, no
//!   page zeroed).
//!
//! Here instead:
//!
//! * the stack is a mapping the test makes ([`OwnedStack`]: `mmap`, a guard on each side),
//!   filled with [`FILL`] before the thread starts, so every byte that differs afterwards was
//!   written by the thread, and the lowest of them tells how deep it went;
//! * the thread is made with `pthread_attr_setstack`, runs the work, and then WAITS: it is
//!   searched while it is alive and parked, so nothing has freed, unmapped or reused its stack;
//! * the work is called through [`with_moat`], a frame holding [`MOAT`] bytes: everything the
//!   work and its callees write lies below the moat's lowest address (the `floor`), and what
//!   the thread does afterwards (handing over the result, waiting) lies above it, inside the
//!   moat. The bytes below the floor are therefore exactly the dead frames of the work, and
//!   nothing touches them while they are read. [`Parked::verify`] checks that the waiting
//!   never reached the floor and that the work never came near the low end of the stack.
//!
//! Unix only (`pthread_attr_setstack`).

#![allow(dead_code)]

use std::ffi::c_void;
use std::ops::Range;
use std::sync::mpsc;

/// The size of a worker's stack.
pub const STACK_SIZE: usize = 1 << 20;
/// What the stack is filled with before the worker starts.
pub const FILL: u8 = 0xa5;
/// The guard on each side of the stack: a multiple of every page size in use (4, 16, 64 KiB).
const GUARD: usize = 64 * 1024;
/// The frame between the worker's own frame and the work.
pub const MOAT: usize = 16 * 1024;
const MOAT_FILL: u8 = 0x5c;
/// How much of the moat, from the floor up, must still hold [`MOAT_FILL`] after the work:
/// the waiting never came this close to the dead frames.
const MOAT_INTACT: usize = MOAT / 2;
/// How much of the stack, from its low end up, must still hold [`FILL`]: the work never came
/// this close to running off the stack.
const UNUSED: usize = 128 * 1024;

/// A stack the test maps: `STACK_SIZE` readable and writable bytes filled with [`FILL`],
/// between two inaccessible guards.
pub struct OwnedStack {
    mapping: *mut u8,
}

// SAFETY: the mapping is plain memory owned by this value; it is handed to one thread as its
// stack and read by another only as `Parked` describes.
unsafe impl Send for OwnedStack {}

impl OwnedStack {
    pub fn new() -> Self {
        let len = STACK_SIZE + 2 * GUARD;
        // SAFETY: an anonymous private mapping of `len` bytes at an address the kernel picks.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED, "mmap of a worker stack");
        let mapping = mapping.cast::<u8>();
        // SAFETY: the stack and both guards lie inside the mapping just made; nothing else
        // uses it yet.
        unsafe {
            std::ptr::write_bytes(mapping.add(GUARD), FILL, STACK_SIZE);
            for guard in [mapping, mapping.add(GUARD + STACK_SIZE)] {
                assert_eq!(
                    0,
                    libc::mprotect(guard.cast::<c_void>(), GUARD, libc::PROT_NONE),
                    "mprotect of a worker stack's guard"
                );
            }
        }
        Self { mapping }
    }

    /// The addresses of the stack (without the guards).
    pub fn range(&self) -> Range<usize> {
        let low = self.mapping as usize + GUARD;
        low..low + STACK_SIZE
    }
}

impl Drop for OwnedStack {
    fn drop(&mut self) {
        // SAFETY: no thread runs on the stack any more (`Parked` joins its thread before the
        // stack is dropped); the whole mapping is this value's.
        unsafe {
            std::ptr::write_bytes(self.mapping.add(GUARD), 0, STACK_SIZE);
            libc::munmap(self.mapping.cast::<c_void>(), STACK_SIZE + 2 * GUARD);
        }
    }
}

/// Calls `work` from a frame that holds [`MOAT`] bytes of [`MOAT_FILL`], and returns the
/// moat's lowest address: every frame of `work` and of what it calls lies below it.
#[inline(never)]
fn with_moat(work: &mut dyn FnMut()) -> usize {
    let mut moat = [MOAT_FILL; MOAT];
    let floor = std::hint::black_box(moat.as_mut_ptr()) as usize;
    work();
    std::hint::black_box(&mut moat);
    floor
}

unsafe extern "C" {
    /// POSIX `pthread_attr_setstack`: the `libc` crate does not declare it for every Unix
    /// (not for Apple's), and the declaration is the same on all of them.
    fn pthread_attr_setstack(
        attributes: *mut libc::pthread_attr_t,
        lowest_address: *mut c_void,
        size: usize,
    ) -> std::ffi::c_int;
}

type Body = Box<dyn FnOnce() + Send>;

extern "C" fn start(argument: *mut c_void) -> *mut c_void {
    // SAFETY: `spawn_on` passes a `Box<Body>` made with `Box::into_raw`, once.
    let body = unsafe { Box::from_raw(argument.cast::<Body>()) };
    // A panic must not unwind into the C library's thread start. The body's channel is dropped
    // by the unwinding, which is how the test thread learns of it.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || (*body)()));
    std::ptr::null_mut()
}

fn spawn_on(stack: &OwnedStack, body: Body) -> libc::pthread_t {
    let argument = Box::into_raw(Box::new(body)).cast::<c_void>();
    let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
    // SAFETY: the attribute object is initialised before use and destroyed after; the stack
    // range is a live mapping of `STACK_SIZE` bytes that outlives the thread (`Parked` joins
    // the thread before dropping the stack); `start` takes ownership of `argument`.
    unsafe {
        let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
        assert_eq!(0, libc::pthread_attr_init(attributes.as_mut_ptr()));
        assert_eq!(
            0,
            pthread_attr_setstack(
                attributes.as_mut_ptr(),
                stack.range().start as *mut c_void,
                STACK_SIZE,
            ),
            "pthread_attr_setstack"
        );
        let made = libc::pthread_create(thread.as_mut_ptr(), attributes.as_ptr(), start, argument);
        libc::pthread_attr_destroy(attributes.as_mut_ptr());
        assert_eq!(0, made, "pthread_create on a stack of the test's own");
        thread.assume_init()
    }
}

/// Runs `body` on a new thread on `stack` and joins it: the thread has ENDED when this
/// returns. Only for looking at what the C library does to a stack it did not make when its
/// thread ends; the measurements use [`run_parked`].
pub fn run_to_exit(stack: &OwnedStack, body: impl FnOnce() + Send + 'static) {
    let thread = spawn_on(stack, Box::new(body));
    // SAFETY: the thread was made joinable just above and is joined once.
    unsafe { libc::pthread_join(thread, std::ptr::null_mut()) };
}

/// A worker that has run its work and waits, alive, on a stack the test owns.
pub struct Parked<T> {
    /// What the search calls this worker ("build", "packets", ...).
    pub name: &'static str,
    value: Option<T>,
    stack: OwnedStack,
    floor: usize,
    release: Option<mpsc::Sender<()>>,
    thread: Option<libc::pthread_t>,
}

/// Runs `work` on a new thread whose stack the test owns and returns once the work has
/// returned; the thread then waits until the [`Parked`] is finished or dropped.
///
/// `T` is handed to the test thread through the worker's own frame, above the moat: it must
/// hold no key bytes inline (a `Box`, a `SecretVec` and `()` do not).
pub fn run_parked<T: Send + 'static>(
    name: &'static str,
    work: impl FnOnce() -> T + Send + 'static,
) -> Parked<T> {
    let stack = OwnedStack::new();
    let (done_tx, done_rx) = mpsc::channel::<(T, usize)>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let body: Body = Box::new(move || {
        let mut work = Some(work);
        let mut value = None;
        let floor = with_moat(&mut || {
            value = Some((work.take().expect("the work runs once"))());
        });
        let _ = done_tx.send((value.expect("the work ran"), floor));
        let _ = release_rx.recv();
    });
    let thread = spawn_on(&stack, body);
    let Ok((value, floor)) = done_rx.recv() else {
        // SAFETY: the thread was made joinable just above and is joined once.
        unsafe { libc::pthread_join(thread, std::ptr::null_mut()) };
        panic!("the worker `{name}` panicked (its message is above)");
    };
    Parked {
        name,
        value: Some(value),
        stack,
        floor,
        release: Some(release_tx),
        thread: Some(thread),
    }
}

/// Runs `work` on a worker of its own and returns its value once the worker has ended and its
/// stack has been overwritten and unmapped. For what must leave nothing behind on the calling
/// thread's stack: the test computes the keys it looks for here, so that no frame of a test
/// thread ever holds one in the clear (a value later built in such a frame and moved to the
/// heap carries what its padding lies on: the search would find the test's own arithmetic).
pub fn on_scratch_stack<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let mut worker = run_parked("scratch", work);
    let value = worker.take();
    worker.finish();
    value
}

impl<T> Parked<T> {
    /// What the work returned. Once.
    pub fn take(&mut self) -> T {
        self.value.take().expect("the work's value is taken once")
    }

    /// The addresses of the worker's stack.
    pub fn stack(&self) -> Range<usize> {
        self.stack.range()
    }

    /// The lowest address of the moat: the dead frames of the work lie below it.
    pub fn floor(&self) -> usize {
        self.floor
    }

    /// The addresses of the dead frames: the stack below the floor.
    pub fn dead_range(&self) -> Range<usize> {
        self.stack.range().start..self.floor
    }

    /// The stack below the floor: the dead frames of the work, down to the stack's low end.
    pub fn dead(&self) -> &[u8] {
        let range = self.dead_range();
        // SAFETY: the range lies inside the stack mapping, which lives as long as `self`. The
        // worker is alive but waits in a frame above the floor and writes nothing below it
        // (`verify` checks the moat between them is intact), so nothing writes these bytes
        // while they are borrowed.
        unsafe { std::slice::from_raw_parts(range.start as *const u8, range.len()) }
    }

    /// How deep the work went: the bytes between the lowest one it wrote and the floor.
    pub fn used(&self) -> usize {
        let dead = self.dead();
        dead.len() - dead.iter().position(|&b| b != FILL).unwrap_or(dead.len())
    }

    /// The measurement is what the module says it is: the floor lies in the stack, the work
    /// wrote below it, never came near the stack's low end, and the waiting stayed inside the
    /// upper half of the moat.
    pub fn verify(&self) {
        let stack = self.stack();
        assert!(
            stack.contains(&self.floor) && self.floor - stack.start > UNUSED + MOAT,
            "worker `{}`: its floor {:#x} is not well inside its stack {stack:#x?}",
            self.name,
            self.floor
        );
        let used = self.used();
        assert!(
            used > 0,
            "worker `{}` wrote nothing below its floor: it did not run on this stack",
            self.name
        );
        assert!(
            self.dead()[..UNUSED].iter().all(|&b| b == FILL),
            "worker `{}` used {used} bytes of stack and reached its last {UNUSED}",
            self.name
        );
        // SAFETY: the lower half of the moat lies inside the stack mapping; the worker waits
        // above it. If it does not, the bytes read here differ and the assertion fails, which
        // is what this is for.
        let moat = unsafe { std::slice::from_raw_parts(self.floor as *const u8, MOAT_INTACT) };
        assert!(
            moat.iter().all(|&b| b == MOAT_FILL),
            "worker `{}`: what it did after the work reached the lower half of the moat",
            self.name
        );
    }

    /// Checks the measurement ([`Self::verify`]), lets the worker end and joins it.
    pub fn finish(mut self) {
        self.verify();
        self.end();
    }

    fn end(&mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            // SAFETY: the thread was made joinable and is joined once.
            unsafe { libc::pthread_join(thread, std::ptr::null_mut()) };
        }
    }
}

impl<T> Drop for Parked<T> {
    fn drop(&mut self) {
        self.end();
    }
}
