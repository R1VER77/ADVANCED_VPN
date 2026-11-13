//! Dump full-cell protocol vectors (byte-identity oracle for the audited
//! production crate). Run against the REFERENCE crate:
//!
//! ```bash
//! cargo run --example dump_cells --release > cells.txt
//! ```
//!
//! Format: `name|field|hex`, one record per line, same convention as
//! vectors.txt. Deterministic: every randomness source is a seeded DetRng,
//! and the seeds themselves are recorded in the output so the consuming test
//! can replay the exact same stream.

use avpn_pq_sphinx::sphinx::{
    build_cell, build_surb, mix_keypair, open_payload, open_surb_reply, process_cell,
    surb_reply_cell, Action, DetRng, MixKeys, SphinxRng,
};
use std::io::Write;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fill32(rng: &mut dyn SphinxRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    b
}

struct Rec {
    name: String,
    field: String,
    hex: String,
}

impl Rec {
    fn new(name: &str, field: &str, data: &[u8]) -> Self {
        Rec {
            name: name.into(),
            field: field.into(),
            hex: hex(data),
        }
    }
}

/// Generate v mixes with a seeded RNG; dump their seeds AND derived keys so
/// the consumer cross-checks keygen determinism, then build a cell and dump
/// every per-hop post-processing state.
fn scenario_cell(out: &mut Vec<Rec>, v: usize, tag: &str, seed: u64) {
    let name = format!("cell_{tag}");
    let mut krng = DetRng(seed);
    let mut mixes = Vec::new();
    for i in 0..v {
        let id = [0xA0 + i as u8; 16];
        let d = fill32(&mut krng);
        let z = fill32(&mut krng);
        let xsk = fill32(&mut krng);
        out.push(Rec::new(&name, &format!("k{i}_d"), &d));
        out.push(Rec::new(&name, &format!("k{i}_z"), &z));
        out.push(Rec::new(&name, &format!("k{i}_xsk"), &xsk));
        out.push(Rec::new(&name, &format!("k{i}_id"), &id));
        let (k, s) = mix_keypair(&d, &z, xsk, id);
        out.push(Rec::new(&name, &format!("k{i}_ek"), &k.mlkem_ek));
        out.push(Rec::new(&name, &format!("k{i}_xpk"), &k.x25519_pk));
        out.push(Rec::new(&name, &format!("k{i}_dk"), &s.mlkem_dk));
        out.push(Rec::new(&name, &format!("k{i}_xsk_out"), &s.x25519_sk));
        mixes.push((k, s));
    }
    let path: Vec<MixKeys> = mixes.iter().map(|(k, _)| k.clone()).collect();

    let mailbox = [0xEE; 16];
    let msg = format!("mix lane vector {tag}: async control event payload").into_bytes();
    out.push(Rec::new(&name, "mailbox", &mailbox));
    out.push(Rec::new(&name, "msg", &msg));

    let built = build_cell(&path, &mailbox, &msg, &mut DetRng(seed ^ 0x5EED)).unwrap();
    out.push(Rec::new(&name, "cell", &built.cell));
    out.push(Rec::new(&name, "pkey", &built.payload_key));
    for (i, s) in built.hop_secrets.iter().enumerate() {
        out.push(Rec::new(&name, &format!("hsec{}", i + 1), s));
    }

    let mut cell = built.cell.clone();
    for (i, (_, sec)) in mixes.iter().enumerate() {
        match process_cell(&mut cell, sec).unwrap() {
            Action::Forward { .. } | Action::Deliver { .. } => {}
        }
        out.push(Rec::new(&name, &format!("post{}", i + 1), &cell));
    }
    let opened = open_payload(&cell, &built.payload_key).unwrap();
    assert_eq!(opened, msg, "oracle self-check failed for {name}");
    out.push(Rec::new(&name, "opened", &opened));
}

/// SURB round-trip vector: path keys, SURB bytes, reply secret, reply cell,
/// and per-hop post-processing states of the reply.
fn scenario_surb(out: &mut Vec<Rec>, v: usize, seed: u64) {
    let name = format!("surb_v{v}");
    let mut krng = DetRng(seed);
    let mut mixes = Vec::new();
    for i in 0..v {
        let id = [0xB0 + i as u8; 16];
        let d = fill32(&mut krng);
        let z = fill32(&mut krng);
        let xsk = fill32(&mut krng);
        out.push(Rec::new(&name, &format!("k{i}_d"), &d));
        out.push(Rec::new(&name, &format!("k{i}_z"), &z));
        out.push(Rec::new(&name, &format!("k{i}_xsk"), &xsk));
        out.push(Rec::new(&name, &format!("k{i}_id"), &id));
        let (k, s) = mix_keypair(&d, &z, xsk, id);
        out.push(Rec::new(&name, &format!("k{i}_ek"), &k.mlkem_ek));
        out.push(Rec::new(&name, &format!("k{i}_xpk"), &k.x25519_pk));
        out.push(Rec::new(&name, &format!("k{i}_dk"), &s.mlkem_dk));
        out.push(Rec::new(&name, &format!("k{i}_xsk_out"), &s.x25519_sk));
        mixes.push((k, s));
    }
    let path: Vec<MixKeys> = mixes.iter().map(|(k, _)| k.clone()).collect();

    let mailbox = [0xAA; 16];
    out.push(Rec::new(&name, "mailbox", &mailbox));
    let surb = build_surb(&path, &mailbox, &mut DetRng(seed ^ 0x5EED)).unwrap();
    out.push(Rec::new(&name, "surb", &surb.bytes));
    out.push(Rec::new(&name, "reply_secret", &surb.reply_secret));

    let reply_msg = b"reply over the mix lane (vector)".to_vec();
    out.push(Rec::new(&name, "reply_msg", &reply_msg));
    let cell = surb_reply_cell(&surb.bytes, &reply_msg, &mut DetRng(seed ^ 0x1234)).unwrap();
    out.push(Rec::new(&name, "reply_cell", &cell));

    let mut cell = cell;
    for (i, (_, sec)) in mixes.iter().enumerate() {
        process_cell(&mut cell, sec).unwrap();
        out.push(Rec::new(&name, &format!("post{}", i + 1), &cell));
    }
    let opened = open_surb_reply(&surb.reply_secret, &surb.path_secrets, &cell).unwrap();
    assert_eq!(opened, reply_msg, "oracle self-check failed for {name}");
    out.push(Rec::new(&name, "opened", &opened));
}

fn main() {
    let mut out = Vec::new();
    for v in 2..=5 {
        scenario_cell(&mut out, v, &format!("v{v}"), 1000 + v as u64);
    }
    // Repeated mix on the path (A, B, A): exercises position-hiding for a
    // mix that legitimately owns two slots.
    scenario_cell(&mut out, 3, "loop", 77);
    for v in 2..=4 {
        scenario_surb(&mut out, v, 2000 + v as u64);
    }

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    for r in &out {
        writeln!(lock, "{}|{}|{}", r.name, r.field, r.hex).unwrap();
    }
    eprintln!("wrote {} records", out.len());
}
