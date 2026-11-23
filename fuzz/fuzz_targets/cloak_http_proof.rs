//! The cloak parses the HTTP request a would-be client sends on port 443.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    cypherpunk_vpn::fuzzing::cloak_http_proof(data);
});
