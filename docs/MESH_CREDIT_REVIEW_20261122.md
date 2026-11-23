# Mesh membership and credit verification review

**Date:** 22 November 2026 · **Scope:** ROADMAP section 4, the row "Review mesh
membership and credit verification; keep unreviewed mechanisms fail-closed and
clearly label classical versus post-quantum security assumptions."
**Method:** source review of every mechanism that establishes mesh membership or
verifies a credit, against the shipped code (`tools/mesh.py`, `tools/mesh_tokens.py`,
`tools/mesh_voprf.py`, `tools/voucher.py`, `src/mesh/tokens.rs`,
`tools/managed_profile.py`) and the standing designs
([MESH_DESIGN.md](MESH_DESIGN.md), [ZK_MEMBERSHIP_DESIGN.md](ZK_MEMBERSHIP_DESIGN.md),
[PQ_INVENTORY.md](PQ_INVENTORY.md)). The verdicts are pinned by
[tools/test_mesh_fail_closed.py](../tools/test_mesh_fail_closed.py) (9 tests): if
someone wires an unreviewed mechanism into the product or removes a label, a test
fails before the claim drifts.


> **Corrected on landing (22 November).** The first draft said a quantum adversary
> breaks the private groups' VOPRF unlinkability. It does not: the client blinds with a
> uniformly random scalar, which in a prime-order group is perfectly hiding, so recovering
> the group key enables forgery only. The table, PQ_INVENTORY exception 6 and the pins
> state the corrected rule.

## What membership is, mechanism by mechanism

| Mechanism | What it establishes | Security assumptions | Status |
|---|---|---|---|
| Descriptor identity (`tools/mesh.py`) | A member IS the operator's ML-DSA-65 key; `node_id = SHA-256(public key)`, and `verify_descriptor` checks signature and ID match at ingestion | Post-quantum (ML-DSA-65) | **Shipped.** Fail-closed: `load_directory` drops anything unverified, and publish refuses to gossip a descriptor that fails its own self-check |
| Server-side member routing (`tools/managed_profile.py`) | A server admits a bounded set of members (≤256) by certificate pin; `profile_validate` requires the pin set to equal the serving layer's accepted set | Post-quantum (the pinned inner-layer certs are ML-DSA) | **Shipped**, strictly validated |
| FIDO2 membership assertion (`mesh.py publish` → `membership-proof.json`) | The hardware key's assertion over the same bytes the operator signed | Classical (ES256/EdDSA WebAuthn) | **Advisory artifact only.** Written for the future ZK registration; **no code reads it** — fail-closed by non-use, pinned by test so nothing starts treating it as authorization before a verifier exists |
| ZK anonymous membership (`research/zk-membership/`, `tools/zkid.py`) | Membership and one-action-per-epoch-per-purpose without a stable identifier | Post-quantum (hash-only STARK; the succinct receipt, deliberately not the Groth16 wrapper) | **Research, wired into nothing.** The design says so; a test pins that no shipping command references it |

**Verdict (membership):** the only membership mechanism that carries weight today
is the ML-DSA descriptor with fail-closed ingestion, and its assumptions are
post-quantum and labeled where the claim is made. The two unreviewed mechanisms
(FIDO2 assertion artifact, ZK prototype) are fail-closed by non-use, and the pins
keep them that way.

## What a credit is, mechanism by mechanism

| Mechanism | Who verifies | Unforgeability | Unlinkability | Status |
|---|---|---|---|---|
| Public-pool credits (`tools/mesh_tokens.py`, Chaum blind RSA-FDH, RSA-3072) | Any node with the issuer's public key and the ledger | **Classical** — factoring mints credits | **Information-theoretic — survives a quantum adversary** | Control plane only. Forgery is loud and contained: daily epoch keys, two-day window, `Ledger.audit_supply` revokes on inflation (PQ_INVENTORY exception 1) |
| Data-plane spend verification (`src/mesh/tokens.rs` `verify_spend`) | The Rust data plane | — | — | **Fail-closed: every spend is rejected** until a reviewed constant-time VOPRF/RSA verifier is vendored; public-pool redemption lives only in the control plane. Pinned by test |
| Private-group credits (`tools/mesh_voprf.py`, RFC 9497 ristrette255 VOPRF) | A group node (it holds the group seed) | **Classical** — discrete log | **Information-theoretic — survives a quantum adversary:** blinding by a uniformly random scalar in a prime-order group is perfectly hiding, so recovering the key does not link a redemption to its issuance | Control plane only (same Rust gate). Forgery is contained by epoch keys and the ledger; the HMAC scheme it replaced linked redemptions to the issuer. **Was unlabeled — fixed by this review** (PQ_INVENTORY exception 6, module `QUANTUM_STATUS`) |
| Vouchers (`tools/voucher.py`, blind RSA, REVENUE_ARCHITECTURE Model 1) | Any relay with the mint's public key and the ledger | **Classical** | **Information-theoretic — survives** | Contained like exception 1: monthly epoch keys, double-spend ledger, supply audit. Its label lived only in the module docstring and COMPARISON note 8 — **consolidated into the inventory as exception 7** |
| ZK membership credits (STARK) | Any relay (23 ms) | Post-quantum (hashes) | Post-quantum, no blinding needed | **Designed and measured, not shipped** (planned v1.0; the replacement for both pools) |

## What the review changed

1. **Labeled the VOPRF group credits** (`tools/mesh_voprf.py`). The module now
   states its quantum status in the docstring and in a `QUANTUM_STATUS` constant,
   in the same terms the RSA modules use for themselves: a quantum adversary
   forges credits, and unlinkability survives, because the blinding is perfectly
   hiding. `quota_view`/`cypherpunk mesh quota` now carries both pools' labels in its
   output rows, wherever the balance is stated.
2. **Consolidated the voucher label** into the canonical exceptions list
   (PQ_INVENTORY exception 7), so the inventory's "stated wherever the claim is
   made" rule covers every credit mechanism, not three of the four.
3. **Fixed the inventory's stale exception count** ("the four exceptions" while
   five were listed) and made the count test-enforced against the list.
4. **Pinned the fail-closed posture of every unreviewed mechanism** in
   `tools/test_mesh_fail_closed.py`: the Rust `verify_spend` bail, the quota
   rows' labels, the ZK prototype's non-wiring, the membership-proof artifact's
   non-consumption, and the ML-DSA ingestion gates.

## What the review found already sound

- The public pool's classical/PQ split is honest and old: RSA-3072 labeled
  "~128-bit classical security", the `Inflation` exception documents exactly
  which half a quantum adversary breaks, and the containment (epoch keys, supply
  audit, revocation) is tested.
- `verify_spend` in the data plane rejects everything with the reason in the
  error string; there is no alternate accept path.
- The descriptor pipeline's self-check (never gossip what does not verify) and
  the directory's verified-only load are both present and tested.

## What remains open (unchanged by this review)

- The reviewed constant-time Rust verifier that opens the data plane (the gate
  both pools wait on), and with it the gossiped spent-set the inflation alarm
  needs across relays.
- The ZK membership credits' open items (ZK_MEMBERSHIP_DESIGN "Open before it
  ships"): reproducible guest image ID, a model of the statement in the
  verification plan, sybil resistance at registration.
- Membership *verification of the hardware claim itself* (MESH_DESIGN §2:
  without attestation, "hardware-backed" is a claim) — registration-side, owner
  decision.
