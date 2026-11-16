//! Anonymous membership with a forward-private nullifier, proved in the RISC Zero zkVM
//! (a STARK).
//!
//! Every member of a tree enrols at the tree's start epoch E0 with a random `s0` and
//! registers `leaf = SHA-256("avpn/member/v2" || H^N(s0))`, where
//! `H(x) = SHA-256("avpn/fp-step/v1" || x)` and N is the tree's lifetime in epochs. In
//! epoch E0 + k the member holds only `x_k = H^k(s0)`; at each epoch change it computes
//! `x_{k+1} = H(x_k)` and erases `x_k`.
//!
//! Private: `x_k` and its Merkle path. Public (the journal): the root, N, E0, the epoch, the
//! purpose ("scope"), the nullifier and the action it authorizes. The statement:
//!
//!   0 <= k = epoch - E0 <= N;  folding H^(N - k)(x_k) into a leaf and up the path gives
//!   `root`;  nullifier = SHA-256("avpn/nullifier/v2" || x_k || epoch || scope).
//!
//! Forward privacy: a device seized in epoch E0 + k gives up `x_k` and everything after it,
//! never an earlier `x_j` (j < k), which is a preimage of `x_k` under SHA-256. So nullifiers
//! of past epochs, in any scope, cannot be recomputed and past actions stay unlinked. With a
//! single long-lived secret (v1) a seizure linked every past action at once.
//!
//! E0 and N belong to the tree, not the member, so they reveal nothing about who proves.
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    let d = Impl::hash_bytes(&v);
    d.as_bytes().try_into().expect("32 bytes")
}

fn main() {
    let x: [u8; 32] = env::read();
    // (sibling, sibling is on the right) from the leaf up.
    let path: Vec<([u8; 32], bool)> = env::read();
    let lifetime: u64 = env::read();
    let start: u64 = env::read();
    let epoch: u64 = env::read();
    let scope: [u8; 32] = env::read();
    // SHA-256 of the request this proof authorizes: the verifier checks it, so an
    // intercepted proof cannot be attached to another action and burn the nullifier.
    let action: [u8; 32] = env::read();

    assert!(epoch >= start && epoch - start <= lifetime, "epoch outside the tree's lifetime");
    let mut top = x;
    for _ in 0..(lifetime - (epoch - start)) {
        top = h(&[b"avpn/fp-step/v1", &top]);
    }
    let mut node = h(&[b"avpn/member/v2", &top]);
    for (sibling, right) in &path {
        node = if *right {
            h(&[b"avpn/node/v1", &node, sibling])
        } else {
            h(&[b"avpn/node/v1", sibling, &node])
        };
    }
    let nullifier = h(&[b"avpn/nullifier/v2", &x, &epoch.to_be_bytes(), &scope]);
    env::commit(&(node, lifetime, start, epoch, scope, nullifier, action));
}
