#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtp::fuzzing::depacketize_sequence;

fuzz_target!(|data: &[u8]| {
    depacketize_sequence(data);
});
