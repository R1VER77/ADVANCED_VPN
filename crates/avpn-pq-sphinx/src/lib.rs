//! PQ-Sphinx option E for the ADVANCED_VPN mix lane (MIX_LANE_DESIGN.md §2).
//!
//! **Entry ML-KEM-768 + inner X25519**: 1396 B header at v=3, +112 B per extra
//! hop, payload key = HKDF(K_1||…||K_v), §2.3 XOR re-blinding.
//!
//! Modules (all std-only, no external dependencies):
//! - [`sha2`]: SHA-256, HMAC-SHA256, HKDF-SHA256 (Sphinx key schedule)
//! - [`keccak`]: Keccak-f1600, SHA-3, SHAKE (ML-KEM internals)
//! - [`blake3`]: keyed BLAKE3 (per-hop header MACs)
//! - [`x25519`]: RFC 7748 X25519 (inner-hop key agreement)
//! - [`chacha`]: ChaCha20 keystream (shift/cover/rt-block streams) + Poly1305 AEAD
//! - [`mlkem768`]: ML-KEM-768 per FIPS 203 (entry-hop key agreement)
//! - [`sphinx`]: the option E header itself
//!
//! Security posture, stated plainly:
//! - Correctness is cross-verified against independent implementations
//!   (kyber-py / python blake3 / python cryptography / hashlib) via
//!   `vectors.json`; see IMPLEMENTATION_NOTES.md.
//! - This is a REFERENCE implementation: no constant-time guarantees, no
//!   side-channel hardening. Swap in audited crates at integration.
//! - The §2.3 KEM-ciphertext XOR re-blinding remains review-pending, exactly
//!   as flagged in MIX_LANE_DESIGN.md.

// This crate is the byte-identity ORACLE for avpn-mix-lane, never shipped in a binary.
// Its loops transcribe FIPS 203 / RFC 7748 / RFC 8439 index for index; rewriting them
// for clippy's style would make the oracle harder to check against the specs.
#![allow(
    clippy::needless_range_loop,
    clippy::explicit_counter_loop,
    clippy::manual_repeat_n,
    clippy::op_ref,
    clippy::let_and_return,
    clippy::wrong_self_convention,
    clippy::while_let_loop
)]

pub mod blake3;
pub mod chacha;
pub mod keccak;
pub mod mlkem768;
pub mod sha2;
pub mod sphinx;
pub mod x25519;
