//! A data-plane configuration, as parsed and checked before anything starts.
#![no_main]
use cypherpunk_vpn::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = serde_json::from_slice::<Config>(data) {
        let _ = c.validate();
    }
});
