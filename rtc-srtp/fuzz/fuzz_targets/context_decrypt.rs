#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_srtp::fuzzing::context_decrypt;

fuzz_target!(|data: &[u8]| {
    context_decrypt(data);
});
