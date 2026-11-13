//! Anonymous membership with a nullifier, proved in the RISC Zero zkVM (a STARK).
//!
//! Private: the member's secret `s` and its Merkle path. Public (the journal): the tree
//! root, the epoch, the purpose ("scope") and the nullifier. The statement:
//!
//!   leaf = SHA-256("avpn/member/v1" || s), and folding the path from it gives `root`;
//!   nullifier = SHA-256("avpn/nullifier/v1" || s || epoch || scope).
//!
//! A verifier that knows the current root accepts a proof whose journal names it, and
//! refuses a nullifier it has seen in that epoch and scope: one use per member per epoch,
//! without learning which member. Domain tags keep leaves, inner nodes and nullifiers apart.
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
    let secret: [u8; 32] = env::read();
    // (sibling, sibling is on the right) from the leaf up.
    let path: Vec<([u8; 32], bool)> = env::read();
    let epoch: u64 = env::read();
    let scope: [u8; 32] = env::read();

    let mut node = h(&[b"avpn/member/v1", &secret]);
    for (sibling, right) in &path {
        node = if *right {
            h(&[b"avpn/node/v1", &node, sibling])
        } else {
            h(&[b"avpn/node/v1", sibling, &node])
        };
    }
    let nullifier = h(&[b"avpn/nullifier/v1", &secret, &epoch.to_be_bytes(), &scope]);
    env::commit(&(node, epoch, scope, nullifier));
}
