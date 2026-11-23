//! A hop verifies the leaf certificate a client presents (hardware-bound sessions).
#![no_main]
use cypherpunk_vpn::config::PeerDevice;
use cypherpunk_vpn::session_auth::verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let es256 = PeerDevice {
        alg: "es256".into(),
        public_hex: format!("04{}", "ab".repeat(64)),
    };
    let eddsa = PeerDevice {
        alg: "eddsa".into(),
        public_hex: "cd".repeat(32),
    };
    for device in [&es256, &eddsa] {
        let _ = verify(device, data, 1_795_000_000);
    }
});
