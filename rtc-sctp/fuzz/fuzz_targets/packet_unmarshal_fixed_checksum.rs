#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::packet_unmarshal_fixed_checksum;

fuzz_target!(|data: &[u8]| {
    let _ = packet_unmarshal_fixed_checksum(data);
});
