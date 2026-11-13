//! avpn-mix-lane — PQ-Sphinx option E on audited primitives, plus the relay
//! mix node (option 1 of the mix-lane rollout plan).
//!
//! Layers:
//! - [`crypto`]: audited-crate adapters (ml-kem, x25519-dalek,
//!   chacha20poly1305, blake3, sha2, hkdf), byte-checked against the
//!   cross-verified std-only reference crate.
//! - [`sphinx`]: the option E header protocol — entry ML-KEM-768 + inner
//!   X25519, 1396 B header at v=3 (+112 B per extra hop), payload key
//!   HKDF(K_1||…||K_v), §2.3 XOR re-blinding (REVIEW-PENDING), SURBs.
//! - [`mix`]: the relay mix — Exp(μ) delays, Little's-law bounded queue
//!   (cover evicted first), rotating replay cache, mailbox store, and the
//!   §1.2 failure discipline (invalid cells occupy a full delay slot before
//!   being discarded).
//!
//! Rollout posture (CUTOVER_KATZENPOST.md): the `avpn mix` lane KEEPS
//! running Katzenpost (X-Wing headers) in production until this crate passes
//! gates G0–G3; only then does the default flip.
//!
//! Security posture:
//! - Primitives are the audited crates above; the protocol logic (`sphinx`)
//!   is byte-identical to the reference crate, which was cross-verified
//!   against independent Python implementations (kyber-py, cryptography,
//!   blake3, hashlib).
//! - The §2.3 KEM-ciphertext XOR re-blinding is NOT a standard, audited
//!   construction. No security claim rests on it until the external review
//!   and the Tamarin effort (`tamarin/`) conclude. See REBLINDING_PLAN.md.
//! - `sphinx::DetRng` and `mix::TestScheduleRng` are INSECURE deterministic
//!   RNGs for tests and vector generation. Production swaps in the platform
//!   CSPRNG at the marked integration points.

pub mod crypto;
pub mod mix;
pub mod sphinx;
