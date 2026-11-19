# formal/

Symbolic models of ADVANCED_VPN's own cryptographic constructions (plan:
`docs/VERIFICATION_PLAN.md`). A model is evidence only when CI proves it with a sanity
(existence) lemma and a broken variant the prover must falsify.
`tools/tamarin_check.py` does both for every model listed in it; CI job `formal-models`
runs it with Tamarin 1.12.0 and Maude 3.5.1, pinned by SHA-256. Results:
`docs/evidence/TAMARIN.json`.

| Model | Construction | Proved (15 Nov 2026) |
|---|---|---|
| `dcnet/dcnet_authenticity.spthy` | DC-net frames across rounds (`src/dcnet.rs`, design §3) | frame authenticity (no fabricated or stale-round frames), key secrecy |
| `dcnet/dcnet.spthy` | DC-net decoding | cancellation (zero, the sender's event, or a collision), key secrecy |
| `dcnet/dcnet_no_collusion.spthy` | one round, all honest | no pad derivable |
| `dcnet/dcnet_collusion.spthy` | one round, one colluder | exact decoding; honest key secret; the honest pad **is** derivable |
| `../crates/avpn-mix-lane/tamarin/pq_sphinx_reblind.spthy` | option E's §2.3 re-blinding | element and pad hidden from an entry-link observer; a both-links observer holds the pad symbolically |

Not machine-checked, because equivalence over XOR did not terminate in Tamarin's `--diff`
mode (and ProVerif and DeepSec do not support XOR):
- DC-net sender anonymity: hand proof in `docs/DCNET_CONTROL_DESIGN.md` §6.
- Re-blinding unlinkability: review-pending, external review still required (gate G3).

## VERIFICATION_PLAN items 1–6 (added 19 November 2026)

What each model proves is limited to what it contains. The table lists what each one
abstracts or leaves out, and which lemmas rest on an assumption rather than being derived.
Every model is also pinned to the code by `tools/formal_model_vectors.py`
(`docs/evidence/FORMAL_MODEL_VECTORS_20261119.json`).

| Model | Code | Proved | Abstracted or left out | Rests on an assumption |
|---|---|---|---|---|
| `cloak/cloak.spthy` | `src/cloak.rs` v2 proof | channel and role binding, key-holder-only, server confirmation, no reflection | TLS as a unique exporter per connection; HMAC as an ideal MAC; no timing or decoy indistinguishability | — |
| `link/link.spthy` | `src/link.rs` handshake, `session_keys` | session-key secrecy before a PSK leak; **hybrid forward secrecy**: after a PSK leak a session key is known only if X25519 *and* ML-KEM were both broken for that session; handshake binding; no reflection or amplification | HKDF as a hash over the same inputs; ML-KEM as public-key encryption; the answer travels in the clear (the code seals it, so the model only helps the adversary); no replay window, counters, rotation or responder-ephemeral compromise | — |
| `kem_seal/kem_seal.spthy` | `tools/keyguard.py` `kem_seal`/`kem_open` | **hybrid confidentiality**: the payload is known only if both X25519 and ML-KEM were broken; context binding | X25519 as Diffie-Hellman, ML-KEM as public-key encryption, HKDF as a hash over `_kem_key`'s inputs in its order, AES-GCM as symmetric encryption | — |
| `ohttp/ohttp.spthy` | `tools/ohttp.py` | request secrecy, response secrecy, **response binding** (a response opens only for the request the gateway sealed it to), all unless the gateway key leaks | the hybrid HPKE suite as one public-key encryption (its hybrid composition is `kem_seal`); no header, info strings or JSON | freshness (window, nonce cache, restart rule) is a restriction, exercised by `tools/test_ohttp.py`; unlinkability (an equivalence) is not modelled |
| `credits/credits.spthy` | `tools/mesh_tokens.py` | issuer-only redemption; no double spend | blind RSA-FDH as a plain signature: the blinding, and so unlinkability, is not modelled; no epochs, expiry or inflation check | **no double spend assumes one spent set**: every redemption goes through one `Ledger`; relays with separate ledgers are not covered |
| `enrollment/enrollment.spthy` | `tools/managed_profile.py` bundles | dual-signature binding; no role substitution; an enrollment needs both schemes broken to forge | Ed25519 (or FIDO2) and ML-DSA-65 as the signing builtin; the set.json → manifest → file hash chain as one hash | — |

Each hybrid claim has mutants in `tools/tamarin_check.py` that remove one shared secret from
the KDF; the prover must find the attack, so the proof depends on both halves.
`kem_seal` needs `--derivcheck-timeout=0`: Tamarin's 5-second default cuts its derivation
check short (it passes when allowed to finish).
