//! DC-net: a group sum and a member's frame, both built from network bytes.
#![no_main]
use cypherpunk_vpn::dcnet::{BODY_LEN, DcEvent, FRAME_LEN, Frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= BODY_LEN {
        let slot: [u8; BODY_LEN] = data[..BODY_LEN].try_into().unwrap();
        let _ = DcEvent::decode(&slot);
    }
    if data.len() >= FRAME_LEN {
        let frame = Frame {
            bytes: data[..FRAME_LEN].try_into().unwrap(),
        };
        let _ = (frame.magic(), frame.cell_id(), frame.round(), frame.body());
        let _ = frame.verify(&[3u8; 32]);
    }
});
