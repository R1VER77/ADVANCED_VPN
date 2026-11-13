# Tamarin plan: the §2.3 XOR re-blinding

## The claim under verification

Option E blinds hop 2's X25519 element with a pad derived from the entry
hop's PQ secret:

```
pad_2 = HKDF(K_1, "avpn/pq-sphinx/pad/v1", 2)
elem2' = elem2 ⊕ pad_2        (client applies)
hop 1:  elem2 ← elem2' ⊕ pad_2 (removed while peeling)
```

The design intent: even an adversary who observes the entry link AND the
hop1→hop2 link cannot recognize hop 2's element across hop 1 unless it can
compute K_1 (i.e., break ML-KEM-768). The concern (why this is
review-pending): XOR-ing a KEM-derived pad into a *different* primitive's
public element is not a standard construction. Specifically we must rule
out:

1. **Pad leakage:** does any quantity the adversary can compute on the
   entry link (ct_1, ek_1, the blinded elem2') correlate with pad_2?
   Formally: pad_2 must be indistinguishable from uniform given the
   adversary's view, conditioned on the KEM's security.
2. **Malleability interplay:** can an adversary flip bits of elem2' on the
   entry link to steer elem2 at hop 2 (X25519 is malleable under XOR
   tampering) in a way that helps a small-subgroup or invalid-curve
   attack? Note hop 2 computes x25519(sk_2, elem2) and checks a MAC —
   there is no key-commitment on the shared secret before MAC use, and
   X25519 rejects nothing (all-zero results simply fail the MAC).
3. **Composition:** does the re-blinding weaken the R1 shift-stream
   guarantees over slot 2's remaining bytes?

## Formalization strategy

Model in Tamarin (spthy) with the built-in XOR theory:

- State facts: `Elem2Fresh(e2)`, `PadFromK1(k1, p2)`, `Blinded(e2, p2, b)`.
- Rules: `ClientBlind`, `EntryPeel` (adversary observes `b` then the mix
  emits `e2`), `ObserverSees(link, bytes)`.
- Restriction: adversary can apply arbitrary XOR masks to traffic in
  transit (`Tag` rule), mirroring active tampering.
- Lemmas:
  - `pad_fresh`: `∀ p2 derived from k1. Pad(p2) ∧ KEM_secret(k1) →
    ∃ e2. Blinded(e2, p2, _) ∧ ∀ adv view. CannotDerive(p2)`.
  - `no_linkability`: for two honest cells with elements e2, f2 and pads
    p2, q2, the adversary's view of (e2 ⊕ p2, f2 ⊕ q2) is
    indistinguishable from (r1, r2) for fresh r1, r2 — via a bisimulation
    argument over pad freshness.
- The malleability question (2) is *not* naturally a Tamarin question;
  it belongs in the reviewer's manual analysis: the MAC over the header
    suffix binds elem2 to the hop-2 secret, so any tampered elem2 yields a
  garbage shared secret and a MAC failure (uniform-in-time discard). The
  formal statement to check by hand: the failure path is
  indistinguishable from a foreign cell.

## Status

- `pq_sphinx_reblind.spthy` in this directory is a **skeleton**: the rules
  and lemma statements above, with TODO markers where the XOR/ephemeral
  handling needs restriction lemmas. It does NOT yet verify.
- Running it requires Tamarin 1.10+ with the XOR theory; expect the
  `no_linkability` lemma to need an source-label refinement on `PadFromK1`.
- The manual malleability analysis (item 2) is drafted for the external
  reviewer in this document, not in the spthy.
- Estimated effort: 2–4 weeks of one formal-methods-literate person, or a
  focused engagement with a group that has Sphinx-family Tamarin models
  (the Katzenpost ecosystem's earlier sphinx formalizations are the
  natural starting point).

This plan is the G3 supporting artifact referenced by
CUTOVER_KATZENPOST.md. Until it (or an equivalent hand proof) concludes
AND the external cryptographer signs off, the §2.3 construction remains
**review-pending** and no security claim may rest on it.
