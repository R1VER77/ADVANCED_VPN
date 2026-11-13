# formal/

Symbolic models of ADVANCED_VPN's own cryptographic constructions, for Tamarin and
ProVerif (plan: `docs/VERIFICATION_PLAN.md`). **Nothing here is proved yet.** A model
becomes evidence only when its CI job runs the prover with a sanity lemma, a broken
variant the prover must falsify, and test vectors pinning the code to the model.

| Model | Construction | Status |
|---|---|---|
| `dcnet/dcnet.spthy` | DC-net control channel (`src/dcnet.rs`) | written by the design pack's author; unproved |
| `../crates/avpn-mix-lane/tamarin/pq_sphinx_reblind.spthy` | option E's §2.3 KEM-ciphertext re-blinding | written by the design pack's author; unproved; external review pending (gate G3) |
