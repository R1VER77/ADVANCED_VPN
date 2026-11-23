//! cypherpunk_vpn laboratory host; not part of upstream Solo 2.
//!
//! Serves Solo 2's unmodified `fido-authenticator`, configured as `runners/lpc55` configures
//! it (`components/solo-apps` `fido_config`), over CTAPHID on loopback UDP: 64-byte frames
//! from 127.0.0.1:7112 to 127.0.0.1:8111, the transport the laboratory's Solo 1 and CanoKey
//! backends use (`tools/device_compatibility_lab.py`). `CPVPN_CTAPHID_PORTS=HOST,PEER` moves
//! it to other loopback ports, so the lab can present a second, separate key. Upstream's PC runner serves no
//! CTAPHID, so this file supplies only the framing that `usbd-ctaphid` does on the device;
//! every message goes to the authenticator through the same `ctaphid_app::App::call` entry.
//!
//! Built inside `runners/pc`'s test crate to reuse its in-process Trussed runtime
//! (`tests/support/sim.rs`, whose RNG is seeded with zeros). User presence is granted to
//! every request (`buttons::approve_sticky`), like a touch that is always held.

#[path = "support/sim.rs"]
mod sim;

use ctaphid_dispatch::app::{App, Command, Error};
use fido_authenticator::{credential::CredentialIdVersion, Authenticator, Config, Conforming};
use std::net::UdpSocket;

const BROADCAST: u32 = 0xffff_ffff;
const MAX_MESSAGE: usize = ctaphid_dispatch::DEFAULT_MESSAGE_SIZE;

const PING: u8 = 0x81;
const MSG: u8 = 0x83;
const INIT: u8 = 0x86;
const WINK: u8 = 0x88;
const CBOR: u8 = 0x90;
const CANCEL: u8 = 0x91;
const ERROR: u8 = 0xbf;

const ERR_INVALID_CMD: u8 = 0x01;
const ERR_INVALID_LEN: u8 = 0x03;
const ERR_INVALID_SEQ: u8 = 0x04;
const ERR_INVALID_CHANNEL: u8 = 0x0b;

/// `solo_apps::config::fido_config(0, 100)`, the lpc55 configuration, with firmware version 0.
fn production_config() -> Config {
    Config {
        max_msg_size: MAX_MESSAGE,
        skip_up_timeout: None,
        max_resident_credential_count: Some(100),
        large_blobs: Some(fido_authenticator::LargeBlobsConfig {
            location: trussed_core::types::Location::External,
            max_size: 1024,
        }),
        nfc_transport: true,
        ccid_transport: false,
        firmware_version: Some(fido_authenticator::FirmwareVersion {
            default: 0,
            credential_id_v1: None,
            credential_id_v2: None,
        }),
        credential_id_version: Some(CredentialIdVersion::V2),
        long_touch_for_reset: true,
        fido2_up_timeout: None,
    }
}

/// (this host's address, the client's address) on loopback.
fn addresses() -> (String, String) {
    let ports = std::env::var("CPVPN_CTAPHID_PORTS").unwrap_or_else(|_| "8111,7112".into());
    let (me, peer) = ports.split_once(',').expect("CPVPN_CTAPHID_PORTS=HOST,PEER");
    let port = |p: &str| p.parse::<u16>().expect("a port number");
    (format!("127.0.0.1:{}", port(me)), format!("127.0.0.1:{}", port(peer)))
}

fn send_frames(sock: &UdpSocket, peer: &str, cid: u32, cmd: u8, data: &[u8]) {
    let mut frame = [0u8; 64];
    frame[..4].copy_from_slice(&cid.to_be_bytes());
    frame[4] = cmd;
    frame[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let mut sent = data.len().min(57);
    frame[7..7 + sent].copy_from_slice(&data[..sent]);
    sock.send_to(&frame, peer).expect("send");
    let mut seq = 0u8;
    while sent < data.len() {
        let mut frame = [0u8; 64];
        frame[..4].copy_from_slice(&cid.to_be_bytes());
        frame[4] = seq;
        let n = (data.len() - sent).min(59);
        frame[5..5 + n].copy_from_slice(&data[sent..sent + n]);
        sock.send_to(&frame, peer).expect("send");
        sent += n;
        seq += 1;
    }
}

struct Message {
    cid: u32,
    cmd: u8,
    len: usize,
    data: Vec<u8>,
    seq: u8,
}

fn serve<'i>(app: &mut dyn App<'i>) {
    let (me, peer) = addresses();
    let sock = UdpSocket::bind(&me).expect("bind the host's loopback port");
    let send = |cid: u32, cmd: u8, data: &[u8]| send_frames(&sock, &peer, cid, cmd, data);
    let mut next_cid: u32 = 0;
    let mut pending: Option<Message> = None;
    let mut frame = [0u8; 65];
    loop {
        let (n, from) = sock.recv_from(&mut frame).expect("recv");
        if n != 64 || from.to_string() != peer {
            continue;
        }
        let cid = u32::from_be_bytes(frame[..4].try_into().unwrap());
        if frame[4] & 0x80 != 0 {
            let (cmd, len) = (frame[4], u16::from_be_bytes([frame[5], frame[6]]) as usize);
            if cmd == INIT {
                if len != 8 {
                    send(cid, ERROR, &[ERR_INVALID_LEN]);
                    continue;
                }
                let assigned = if cid == BROADCAST {
                    next_cid += 1;
                    next_cid
                } else {
                    cid
                };
                if pending.as_ref().is_some_and(|m| m.cid == cid) {
                    pending = None;
                }
                let mut reply = frame[7..15].to_vec(); // the client's nonce
                reply.extend_from_slice(&assigned.to_be_bytes());
                reply.extend_from_slice(&[2, 0, 0, 0, 0x01 | 0x04]); // protocol 2; WINK and CBOR; MSG offered
                send(cid, INIT, &reply);
                continue;
            }
            if cid == BROADCAST || cid == 0 || cid > next_cid {
                send(cid, ERROR, &[ERR_INVALID_CHANNEL]);
                continue;
            }
            if len > MAX_MESSAGE {
                send(cid, ERROR, &[ERR_INVALID_LEN]);
                continue;
            }
            pending = Some(Message { cid, cmd, len, data: frame[7..7 + len.min(57)].to_vec(), seq: 0 });
        } else {
            let Some(message) = pending.as_mut() else { continue };
            if message.cid != cid {
                continue; // a continuation for another channel is ignored, as the spec allows
            }
            if frame[4] != message.seq {
                send(cid, ERROR, &[ERR_INVALID_SEQ]);
                pending = None;
                continue;
            }
            let take = (message.len - message.data.len()).min(59);
            message.data.extend_from_slice(&frame[5..5 + take]);
            message.seq += 1;
        }
        if pending.as_ref().is_some_and(|m| m.data.len() == m.len) {
            let message = pending.take().unwrap();
            let command = match message.cmd {
                PING => {
                    send(message.cid, PING, &message.data);
                    continue;
                }
                WINK => {
                    send(message.cid, WINK, &[]);
                    continue;
                }
                CANCEL => continue,
                MSG => Command::Msg,
                CBOR => Command::Cbor,
                _ => {
                    send(message.cid, ERROR, &[ERR_INVALID_CMD]);
                    continue;
                }
            };
            let mut response = ctap_types::Bytes::<MAX_MESSAGE>::new();
            match app.call(command, &message.data, response.as_mut_view()) {
                Ok(()) => send(message.cid, message.cmd, &response),
                Err(Error::InvalidLength) => send(message.cid, ERROR, &[ERR_INVALID_LEN]),
                Err(Error::InvalidCommand) => send(message.cid, ERROR, &[ERR_INVALID_CMD]),
                Err(Error::NoResponse) => {}
            }
        }
    }
}

#[test]
#[ignore = "laboratory host: serves until its process is stopped"]
fn serve_ctaphid_over_udp() {
    solo_pc::buttons::approve_sticky();
    std::thread::Builder::new()
        .name("cpvpn-ctaphid-host".into())
        .stack_size(16 << 20)
        .spawn(|| {
            sim::with_client(|client| {
                let mut authenticator = Authenticator::new(client, Conforming {}, production_config());
                serve(&mut authenticator);
            })
        })
        .unwrap()
        .join()
        .unwrap();
}
