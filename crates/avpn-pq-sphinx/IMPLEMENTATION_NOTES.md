# PQ-Sphinx Option E — Implementation Notes

Status: **built, tested, cross-verified, v0.2.0**. `cargo test` → 57/57
passing (51 unit/property + 6 cross-language suites) on rustc 1.100.0, zero
warnings, zero external dependencies (std-only, edition 2021).

v0.2.0 adds refinements R3 and R4 (two linkability gaps found by the
production port's GPA-lab simulation — see below), full-cell cross-language
vectors (`cells.txt`, via `examples/dump_cells.rs`), and a breaking API
change: `open_surb_reply` now takes the reply-path secrets and `Surb`
carries `path_secrets` (never serialized). The production port
(`avpn-mix-lane`, audited primitives) is byte-identical to this crate by
construction and by test.

This implements MIX_LANE_DESIGN.md Part II as a standalone crate: the option E
header (entry ML-KEM-768 + inner X25519, 1396 B at v=3, +112 B per extra hop),
§2.3 XOR re-blinding, the §2.6 key schedule, SURBs, and the full mix-side
processing pipeline.

## Verification chain (why you can trust the bytes)

Every primitive is checked against an INDEPENDENT implementation
(`gen_vectors.py` → `vectors.txt` → `tests/vectors.rs`):

| Primitive | Independent reference |
|---|---|
| SHA-256, HMAC, HKDF, SHA-3, SHAKE | Python stdlib `hashlib`/`hmac` |
| BLAKE3 (unkeyed + keyed, 15 chunk-boundary lengths) | Python `blake3` package |
| X25519 | Python `cryptography` 44.x |
| ChaCha20-Poly1305 | Python `cryptography` |
| Poly1305 | pure big-int transcription of RFC 8439 §2.5 |
| **ML-KEM-768** | **kyber-py (FIPS 203 final)** |

kyber-py is itself validated against the official NIST KATs, so byte-equality
of ek / dk / ciphertext / shared secret / implicit-rejection key transitively
pins this crate's ML-KEM wire format to the standard.

Protocol-level properties are tested adversarially in `src/sphinx.rs`:
end-to-end at v = 2..5, linkability defense (every downstream slot changes at
every hop), payload tagging traverses to the endpoint and dies in client-side
AEAD, header tampering dies at the next hop, replay-tag determinism, SURB
round-trip + tamper, a repeated mix on the path, and NotMine indistinguishable
from corruption (§1.2 discipline).

## Design refinements forced by implementation (amend §2.2 of the design doc)

**R1 — full-slot shifting.** The doc says hop i re-encrypts the *routing
blocks* of downstream slots. Routing-block-only re-encryption leaves the
downstream MAC fields as static bytes from client to their hop: a passive
observer comparing the entry link with a later link could match them and link
the cell across the observation points. The shift keystream
(`HKDF(K_i, "shift"||i)` → ChaCha20) therefore covers the **entire downstream
slot** (element + MAC + routing block). Tested by
`every_downstream_slot_changes_at_each_hop_and_cover_replaces_consumed`.

**R2 — per-hop MAC covers the header suffix only, not the payload.** §2.2/§1.2
say "header suffix + payload", but (a) §1.7's own anti-tagging story ("a
tagged cell survives to the mailbox and fails client-side decryption") and
(b) §2.5's SURBs both require mixes NOT to authenticate payloads — a SURB
holder cannot compute MACs over a reply payload they choose. MAC_i covers
slot i's routing-block field plus all downstream slots, stopping at the header
boundary. Payload integrity is end-to-end via the AEAD under `payload_key`.
This makes the tagged-payload and tagged-header behaviors exactly what §1.7
describes; both are tested.

**R3 — per-hop payload re-masking (the Sphinx β-layer).** The design
re-encrypts header slots per hop (R1) but left the ~2.7 KB payload region
untouched end-to-end: two colluding observers on different links of a path
could byte-match the payload region straight through the Exp delays. Fix:
the client pre-masks the sealed payload with all v hop-keyed ChaCha20
streams (`HKDF(K_i, "pmask"||i)`); each hop XORs off its own layer — mixes
learn nothing. SURB replies invert the direction (hops ADD masks, the SURB
creator strips them; the replier holds no path secrets) — the per-hop
operation is identical, so no wire flag is needed. Zero size cost. Found by
the GPA-lab linkability check in the production port; tested by
`r3_payload_region_changes_at_every_hop_and_is_transparent` and
`r3_surb_reply_payload_differs_on_every_link`.

**R4 — dead-prefix re-randomization.** R1 shifts only *downstream* slots,
so the cover bytes hop 1 writes into slot 1 rode unchanged on every later
link — a 1168-byte static region, byte-matchable across an honest
intermediate hop. Fix: hop i XORs a hop-keyed stream
(`HKDF(K_i, "dead"||i)`) over the consumed prefix (slots 1..i−1); no MAC
covers that region, so verification is untouched. Tested by
`r4_no_shared_window_between_any_two_hops`: after R1+R3+R4, NO 64-byte
window of the cell is shared between any two hops' views (except the
unavoidable 4-byte fixed prefix).

**§2.5 SURB clarification.** As written, "reply payload is AEAD'd under
HKDF(reply_key_hint || K_last)" gives the replier no way to derive the key.
Implemented as: the SURB embeds a 32-byte X25519 *hint* (ephemeral public
key); the replier does an ephemeral agreement against it for the reply AEAD
key; only the SURB creator (holder of the hint's scalar) can open. Single-use
is enforced by the mixes' replay caches (fresh MAC fields per use), which is
the mechanism the doc already relied on.

**§2.3 re-blinding: still review-pending.** The entry-secret blinding of hop
2's element (`pad_2 = HKDF(K_1, "pad"||2)`, XORed by the client, removed by
hop 1) is now concrete, testable code — which is exactly what the external
crypto reviewer needs. The design-doc caveat stands: this construction is not
a standard, audited one, and no security claim should rest on it until
reviewed. Everything else in the header is standard-primitive composition.

## Security posture — read before shipping

This is a **reference implementation**:

- **NOT constant-time.** Plain i32/u128 arithmetic, branching in ML-KEM
  sampling, a data-dependent branch in decapsulation (implicit rejection),
  non-masked operations in X25519. It is correct, not hardened.
- **Swap points (SWAPPABLE markers in the source):** `SphinxRng` (platform
  CSPRNG; `DetRng` is splitmix64, test-only), and the entire primitive
  modules — replace `mlkem768`, `x25519`, `blake3`, `chacha` with the audited
  crates (`ml-kem`, `curve25519-dalek`, `blake3`, `chacha20poly1305`) at
  integration; the `sphinx` module consumes only their narrow APIs, and the
  cross-language vectors pin the replacement's byte-compatibility.
- **What is NOT here** (integration surface, per the design doc): wire
  transport of cells, the Exp(μ) delay scheduler, Little's-law queues, the
  rotating replay cache (the module exposes `replay_tag`; the caller owns the
  filter), the mailbox store, and the §1.2 failure discipline — on
  `Err(NotMine)` the MIX must enqueue-then-discard with the same delay
  distribution as a healthy cell, never drop immediately. `NotMine` covers
  both foreign cells and corrupted cells by construction.

## Cost profile per cell per mix (try-all-slots, §1.9 position hiding)

1 ML-KEM-768 decaps (~30 µs optimized; more in this build) + (v−1) X25519 +
v keyed-BLAKE3 MACs over ≤ ~1.6 KB. Work is position-independent: every mix
attempts every slot; exactly one verifies; consumed slots are overwritten
with same-length cover bytes, so wire size and work profile are identical at
every hop. At production rates (1280 cells/s) the audited-crates version fits
the design doc's CPU budget; this reference build does not (unoptimized field
arithmetic) and is not intended to.

## Repo placement

```
src/pq_sphinx/            (or flat under src/ — either compiles)
  mod.rs        <- lib.rs module list
  sha2.rs keccak.rs blake3.rs x25519.rs chacha.rs mlkem768.rs sphinx.rs
tests/pq_sphinx_vectors.rs   <- tests/vectors.rs
tools/gen_pq_sphinx_vectors.py
vectors/pq_sphinx_vectors.txt
```

The crate is self-contained; if the repo already depends on audited crypto
crates, swap the primitive modules first and keep `sphinx.rs` (its 48 in-crate
tests then run against the audited backends, and vectors.txt re-verifies
byte-compatibility).

## Regenerating the cross-language vectors

```bash
pip install kyber-py blake3 cryptography   # one time
python3 gen_vectors.py                     # writes vectors.txt
cargo run --example dump_cells --release > cells.txt   # full-cell vectors
cargo test                                 # 57 tests incl. cross-checks
```

`cells.txt` is the byte-identity oracle for the audited-primitives
production crate (`avpn-mix-lane`): given the same seeded DetRng streams,
the production crate must reproduce every cell, secret, and per-hop state
byte for byte. Its seed schedule is documented in the example source.
