#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::state::State;

fuzz_target!(|data: &[u8]| {
    let Ok(provider) = rtc_dtls::crypto_provider::default_provider() else {
        return;
    };
    let mut state = State::new(provider, false);
    let _ = state.unmarshal_binary(data);
});
