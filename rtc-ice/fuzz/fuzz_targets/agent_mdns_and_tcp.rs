#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_ice::fuzzing::agent_mdns_and_tcp;
use std::sync::OnceLock;
use std::time::Instant;

// One base instant for the whole process: the harness only ever adds input-chosen offsets to it,
// so an input replays identically.
static START: OnceLock<Instant> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    agent_mdns_and_tcp(data, *START.get_or_init(Instant::now));
});
