//! Prototype measurement: anonymous membership + forward-private nullifier as a RISC Zero
//! STARK (guest statement in methods/guest/src/main.rs).
//!
//! Builds a Merkle tree of 2^DEPTH member commitments, proves membership of one member
//! with a succinct (single-STARK, hash-based) receipt, verifies it, and checks the
//! properties the design needs. Prints one JSON object. Never runs in dev mode.
use methods::{MEMBER_ELF, MEMBER_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use sha2::{Digest, Sha256};
use std::time::Instant;

type Path = Vec<([u8; 32], bool)>;
type Journal = ([u8; 32], u64, u64, u64, [u8; 32], [u8; 32], [u8; 32]);

/// Epochs a tree lives (one a day: a year), and its start epoch.
const LIFETIME: u64 = 365;
const START: u64 = 20400;
/// The request a proof authorizes (here a fixed example), bound into the journal.
const ACTION: [u8; 32] = [0x5a; 32];

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut s = Sha256::new();
    for p in parts {
        s.update(p);
    }
    s.finalize().into()
}

fn step(x: &[u8; 32]) -> [u8; 32] {
    h(&[b"avpn/fp-step/v1", x])
}

fn walk(x: &[u8; 32], n: u64) -> [u8; 32] {
    let mut y = *x;
    for _ in 0..n {
        y = step(&y);
    }
    y
}

/// The member's epoch secret for `epoch`: H^(epoch - START)(s0).
fn epoch_secret(s0: &[u8; 32], epoch: u64) -> [u8; 32] {
    walk(s0, epoch - START)
}

fn leaf(s0: &[u8; 32]) -> [u8; 32] {
    h(&[b"avpn/member/v2", &walk(s0, LIFETIME)])
}

/// The tree's levels, leaves first.
fn build(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaves];
    while levels.last().unwrap().len() > 1 {
        let up = levels
            .last()
            .unwrap()
            .chunks(2)
            .map(|p| h(&[b"avpn/node/v1", &p[0], &p[1]]))
            .collect();
        levels.push(up);
    }
    levels
}

fn path(levels: &[Vec<[u8; 32]>], mut index: usize) -> Path {
    let mut out = Vec::new();
    for level in &levels[..levels.len() - 1] {
        let right = index % 2 == 0; // our node is on the left: the sibling is on the right
        out.push((level[index ^ 1], right));
        index /= 2;
    }
    out
}

fn prove(x: [u8; 32], p: &Path, epoch: u64, scope: [u8; 32]) -> (Receipt, f64) {
    let env = ExecutorEnv::builder()
        .write(&x)
        .unwrap()
        .write(p)
        .unwrap()
        .write(&LIFETIME)
        .unwrap()
        .write(&START)
        .unwrap()
        .write(&epoch)
        .unwrap()
        .write(&scope)
        .unwrap()
        .write(&ACTION)
        .unwrap()
        .build()
        .unwrap();
    let t = Instant::now();
    let info = default_prover()
        .prove_with_opts(env, MEMBER_ELF, &ProverOpts::succinct())
        .unwrap();
    (info.receipt, t.elapsed().as_secs_f64())
}

fn journal(r: &Receipt) -> Journal {
    r.journal.decode().unwrap()
}

fn main() {
    assert!(
        std::env::var("RISC0_DEV_MODE").map(|v| v.is_empty() || v == "0").unwrap_or(true),
        "dev mode fakes proofs: refusing"
    );
    let depth: u32 = std::env::args().nth(1).map(|d| d.parse().unwrap()).unwrap_or(20);
    let n = 1usize << depth;
    let mut secrets: Vec<[u8; 32]> = (0..n).map(|_| rand_bytes()).collect();
    let me = n / 3;
    let t = Instant::now();
    let levels = build(secrets.iter().map(leaf).collect());
    let tree_s = t.elapsed().as_secs_f64();
    let root = levels.last().unwrap()[0];
    let scope = h(&[b"avpn/scope/mesh-credit"]);
    let (epoch, next) = (20405u64, 20406u64);

    // 1. A member proves; the verifier checks the receipt and the public values.
    let my_path = path(&levels, me);
    let x_now = epoch_secret(&secrets[me], epoch);
    let (receipt, prove_s) = prove(x_now, &my_path, epoch, scope);
    assert!(
        matches!(receipt.inner, InnerReceipt::Succinct(_)),
        "not a succinct STARK receipt"
    );
    let t = Instant::now();
    receipt.verify(MEMBER_ID).expect("verifies");
    let verify_s = t.elapsed().as_secs_f64();
    let (r, life, st, e, sc, null, act) = journal(&receipt);
    assert_eq!((r, life, st, e, sc, act), (root, LIFETIME, START, epoch, scope, ACTION));
    let size = bincode::serialize(&receipt).unwrap().len();

    // 2. Same member, same epoch: the same nullifier (a second use is refused).
    let (again, _) = prove(x_now, &my_path, epoch, scope);
    assert_eq!(journal(&again).5, null, "nullifier must be stable within an epoch");
    // 3. Next epoch, after the member stepped its secret forward: a fresh nullifier
    //    under the same root.
    let x_next = step(&x_now);
    let (later, _) = prove(x_next, &my_path, next, scope);
    assert_eq!(journal(&later).0, root);
    assert_ne!(journal(&later).5, null);
    // 4. Forward privacy: the secret a seizure in the next epoch finds cannot prove the
    //    earlier epoch (it walks one step too far and misses the root), and the earlier
    //    nullifier is not the one it would compute.
    let (stale, _) = prove(x_next, &my_path, epoch, scope);
    assert_ne!(journal(&stale).0, root, "a later secret proved an earlier epoch");
    assert_ne!(journal(&stale).5, null);
    // 5. Another member: another nullifier, the same root.
    let other = me + 1;
    let (theirs, _) = prove(epoch_secret(&secrets[other], epoch), &path(&levels, other), epoch, scope);
    assert_eq!(journal(&theirs).0, root);
    assert_ne!(journal(&theirs).5, null);
    // 6. An outsider (a secret not in the tree) using a real path: the proof names
    //    another root, which the verifier refuses.
    let outsider = rand_bytes();
    let (fake, _) = prove(outsider, &my_path, epoch, scope);
    assert_ne!(journal(&fake).0, root, "an outsider produced the members' root");
    // 7. A tampered journal (claiming the real root) fails verification.
    let mut forged = fake.clone();
    let mut j = journal(&fake);
    j.0 = root;
    forged.journal = risc0_zkvm::Journal::new(risc0_zkvm::serde::to_vec(&j).unwrap().iter().flat_map(|w| w.to_le_bytes()).collect());
    assert!(forged.verify(MEMBER_ID).is_err(), "a tampered journal verified");
    // 8. The action is bound: a journal claiming another action fails verification.
    let mut moved = receipt.clone();
    let mut j = journal(&receipt);
    j.6 = [0xa5; 32];
    moved.journal = risc0_zkvm::Journal::new(risc0_zkvm::serde::to_vec(&j).unwrap().iter().flat_map(|w| w.to_le_bytes()).collect());
    assert!(moved.verify(MEMBER_ID).is_err(), "a proof was moved to another action");
    // 9. The journal holds nothing about the member.
    assert!(!receipt.journal.bytes.windows(32).any(|w| w == x_now || w == leaf(&secrets[me]) || w == secrets[me]));

    secrets.clear();
    println!(
        "{}",
        serde_json::json!({
            "zkvm": "risc0-zkvm 3.1 (STARK over BabyBear, FRI; succinct receipt, no SNARK wrapper)",
            "members": n,
            "tree_depth": depth,
            "tree_build_seconds": (tree_s * 100.0).round() / 100.0,
            "prove_seconds": (prove_s * 10.0).round() / 10.0,
            "verify_seconds": (verify_s * 1000.0).round() / 1000.0,
            "receipt_bytes": size,
            "journal_bytes": receipt.journal.bytes.len(),
            "lifetime_epochs": LIFETIME,
            "chain_steps_in_proof": LIFETIME - (epoch - START),
            "checks": [
                "stable nullifier within an epoch",
                "fresh nullifier next epoch, after stepping the secret forward",
                "a later epoch's secret cannot prove an earlier epoch (forward privacy)",
                "a proof cannot be moved to another action",
                "distinct members: distinct nullifiers, same root",
                "outsider cannot produce the members' root",
                "tampered journal fails verification",
                "journal carries neither the secret nor the leaf"
            ]
        })
    );
}

fn rand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).unwrap();
    b
}
