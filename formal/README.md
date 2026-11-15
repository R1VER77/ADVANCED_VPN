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
