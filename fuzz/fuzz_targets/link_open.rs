//! A paced link's receiving end opens whatever arrives on its UDP socket.
#![no_main]
use cypherpunk_vpn::link::{Dir, Opener};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut opener = Opener::new(vec![[7u8; 32], [9u8; 32]], Dir::Forward);
    for cell in [data.len(), 1214, 64] {
        let _ = opener.open(data, cell);
    }
});
