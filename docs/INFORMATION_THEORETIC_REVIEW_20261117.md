# Information-theoretic security: paper and implementation review

17 November 2026. Project self-review against source revision `2f9e1b0` and the
owner-supplied papers. This is not independent review or production qualification.

## Finding

**A scoped information-theoretic sender-anonymity claim is mathematically valid for
the DC-net construction under explicit pad and observation assumptions.** The papers
support obtaining secret shared randomness under suitable source/channel models.
They do not establish that this implementation satisfies those models, or make the
VPN's encrypted transport information-theoretically confidential.

The present library has the relevant XOR construction and consumes one-time books.
Its default generation path does not yet establish an information-theoretic entropy
bound for those books. `conditional-information-theoretic` is a declared-provenance
label, not a verified security result. DC-net operation is not integrated into a VPN
command. Keep those distinctions in the README, whitepaper and interface.

## What the supplied papers establish

1. **Maurer (1993), pp. 733–742.** Alice and Bob observe correlated variables `X`
   and `Y`; Eve observes `Z` and the entire public discussion `F`. The source model
   must account for Eve's information. Public messages are authenticated in the
   model. Theorem 1 and Corollary 1 (p. 737) bound the resulting key entropy by
   shared information, with reliability and secrecy terms. Theorem 2 (p. 738)
   gives a secret-key-rate upper bound `min(I(X;Y), I(X;Y|Z))`. Two-way discussion
   can enable key agreement in some noisy-source models even when Eve's individual
   channel is better. It does not create private correlation from nothing.
   [Author's paper](https://crypto.ethz.ch/publications/files/Maurer93a.pdf).
2. **Ahlswede–Csiszár (1993), pp. 1121–1132.** Source and channel models separate
   private observations from public communication. Proposition 1 (p. 1124) gives
   key capacity `I(X;Y)` for the source model without Eve's side information.
   Theorem 1 (p. 1125) treats the wiretapper model, including an `I(X;Y|Z)` upper
   bound and a characterization for one-way discussion. These are capacities
   under specified distributions, not entropy certifications for device outputs.
   [Author's paper](https://www.math.uni-bielefeld.de/ahlswede/homepage/public/79.pdf).

Public discussion in these papers is not the same as encrypting a locally generated
secret with ML-KEM/X25519. An unbounded observer of that envelope is outside the
KEM's computational security guarantee. Nor are independent jitter streams on two
machines automatically common observations of a suitable noisy source. A future
Maurer-style mode needs a concrete acquisition channel, an adversary/source model,
reconciliation, privacy amplification and a finite-length analysis.

Asymptotic key-rate results are not a finite-book, composable secrecy bound. These
papers use classical source/side-information models; quantum side information needs
an applicable quantum-proof extraction analysis rather than an automatic extension.

Local copies reviewed (page numbers above are printed journal pages):

| Paper | Owner-supplied PDF SHA-256 |
|---|---|
| Ahlswede–Csiszár | `3b6fe68ab921b8105836529c7b54b57d0b10958ce0276b6091c68a736c84fe3b` |
| Maurer | `4491c826ed369e9a12d6bf99167944d1892fee361d54ca983f5e66b15fe2c89c` |

## The claim our DC-net can make

Let `H` be the honest online members in a round. Give the observer all colluders'
pads and every computationally established edge. Keep only edges whose pads remain
secret under the proposed information-theoretic model. Their graph must connect
the proposed anonymity set; an isolated member has no such anonymity.

For a fixed event `e`, member `i` broadcasts

```text
c_i = (e if i is the sender else 0) XOR XOR_j p_ij.
```

Assume the retained edge pads are jointly uniform and secret conditional on the
observer's prior information, and independent of sender/event selection. Their
vertex sums are then uniform on the zero-XOR
subspace of a connected graph. Adding `e` at any vertex produces the same
distribution on the affine subspace whose total XOR is `e`.

A useful equivalent proof moves the sender along a path: XOR `e` into each edge
pad on the path. Internal vertices see two changes which cancel; the two endpoints
exchange their sender bit. Every broadcast stays identical. This is a bijection
of uniform pad assignments. The Rust regression checks that coupling through
`CellPads`, `transmit`, `Frame::seal` and `group_sum`, using the real 64-byte codec.
It checks the implementation identity, not physical entropy.

Thus the ideal passive-round statement is

```text
I(Sender; Transcript | Event, PriorObserverInformation) = 0.
```

This means the transcript adds no sender information beyond the event and prior
knowledge. It does not make a nonuniform prior uniform. An event containing its
author's identity can identify them despite this conditional property. For a
uniform prior on `h` eligible senders, the posterior remains `1/h`.

If, for each candidate sender, the **joint** real pad/event/side-information law is
within total variation `epsilon_total` of its corresponding ideal, data processing
gives at most `epsilon_total` distance
per sender experiment from its ideal transcript; two sender experiments are within
`2 * epsilon_total` by the triangle inequality. Do not replace this approximate
statement with exact zero mutual information. Derive `epsilon_total` for all relevant
edges, blocks and rounds, not just one extractor call.

This is the standard DC-net distinction between one-time-key and public-key
constructions, rather than a new consequence of hybrid post-quantum encryption.
[Chaum's original paper](https://chaum.com/wp-content/uploads/2022/01/chaum-dc.pdf).

## Mapping the assumptions to current code

| Boundary | Current implementation | Consequence |
|---|---|---|
| Raw source | `padbook.assess`, `raw_health`, `raw_bytes`: jitter samples, empirical SP 800-90B estimate, half counted | Useful evidence; no demonstrated conditional min-entropy bound against Eve, future workloads or correlated blocks |
| Extractor | `extract`: Toeplitz hashing of 1,024-sample blocks | Can support a statistical extraction argument with a justified source/seed model |
| Extractor seed | `assess` obtains the seed through `nitrokey_bytes`; the documented firmware path is ChaCha8 expansion | The ordinary uniform-seed leftover-hash bound is not established for this seed distribution. Supply genuine independent uniform seed material or prove a suitable alternative construction/model |
| Seed reuse | One assessment seed reused for later blocks and books | Need a joint-source and reuse argument. Good marginal entropy in each block is insufficient; repeated blocks can repeat extracted output |
| Extra XOR inputs | Kernel/Nitrokey bytes precede jitter collection | Ordering is not independence. Require conditional uniformity/independence relative to the other contribution, mixed streams and observer information |
| Pair sharing | `seal_contribution` uses hybrid KEM encryption for both delivery labels | In-person custody can keep the envelope outside Eve's observations. If Eve obtains it, confidentiality of its contents is computational |
| Book storage | `write_book`: AES-GCM/ChaCha20-Poly1305, HKDF and hardware-derived wrapping keys | Computational protection if sealed storage is observed or seized; it does not upgrade pad secrecy against an unbounded observer of those ciphertexts |
| Consumption | `PadBook.take`, persistent transactions and skipped-round burning | Enforces normal API non-reuse. Whole snapshots, hostile clocks/kernels, flash remnants and copies remain outside that guarantee |
| Remote chains | `Ratchet`/`chain_pad`: finite seed and SHA-256 expansion | Computational even if the original seed was physically random |
| Authentication | HMAC-SHA256 and computational enrollment mechanisms | No information-theoretic active-adversary guarantee. Passive sender anonymity can be stated under an authenticated-channel assumption |
| Integration | Round core and pad tools only | No deployed whole-VPN or measured network-level anonymity conclusion |

Computational wrapping does not invalidate a passive model in which Eve never
observes the wrapped material. Conversely, saying a transfer was in person is not
enough if its encrypted contents were copied into an observed backup or envelope.
The observation boundary must be explicit.

The leftover-hash lemma permits a public seed; secrecy of the seed is unnecessary.
Its independence and distribution, conditional source entropy, and output length
matter. The current `k - 128` output budget targets a conservative `2^-64` **single
block** distance when the relevant hypotheses hold. It is not a whole-book bound.
The seed gap is not proof that the actual pads are predictable: a particular source
and seed distribution might admit a different statistical argument. That argument
has not been established here.
Repeated-source or source-adaptive seed reuse needs its own treatment; changing to
a physical seed alone does not resolve that issue.
[Extractor definitions and bounds](https://cs.nyu.edu/~dodis/ps/ent-survey.pdf),
[research on dependent sources and seed reuse](https://cs.nyu.edu/~dodis/ps/EDExt.pdf).

## Additional correction: the event tag is not authentication

The public truncated SHA-256 check improves rejection of accidental/nonadaptive
garbling compared with the old linear CRC. It cannot prevent a participating
attacker who knows or correctly guesses an event from replacing it with another:

```text
delta = Encode(known_event) XOR Encode(replacement_event)
attacker_body = ordinary_attacker_body XOR delta
```

The group sum becomes the replacement. The attacker can authenticate its own frame
with its own membership key. No hash collision or MAC forgery is required. The
existing test covered a wrong guess and its name overstated what it proved.
The added regression demonstrates the correct-guess boundary with authenticated
frames. A `2^-72` statement only describes an idealized unpredictable check outcome,
not arbitrary chosen differences or an information-theoretic active guarantee.

The core remains a reference library. Before integration, define event-level
validation, authorization, replay handling and sender-privacy implications, or keep
events explicitly unauthenticated hints with no privileged effect. A public check
must never authorize enrollment, key rotation or a chain-policy change. Adding an
ordinary identity signature without analysis could disclose the sender.

## Work required for a qualified information-theoretic pad profile

- [ ] Define Eve's complete observation boundary, compromise model and exact property:
  passive-round sender anonymity, with explicit active-channel assumptions.
- [ ] Qualify raw-source conditional entropy and dependencies; specify generation
  conditions, health failures and finite entropy budgets. Statistical tests alone
  cannot establish secrecy from an observer.
- [ ] Add independently sourced seed material with provenance and an explicit
  extractor proof; prohibit silently substituting PRG-expanded seed material in
  that profile. Alternatives need their own argument rather than a blanket ban.
- [ ] Resolve seed reuse and cross-block/cross-edge correlations. Derive and record
  a book/cell/session error budget with composition. Marginal per-block bounds
  cannot simply be multiplied or summed without their required joint hypotheses.
- [ ] Exclude observed computational envelopes/storage from the information-theoretic
  secrecy boundary, or provide information-theoretically secure custody/transfer.
- [ ] Bind one-time consumption to a rollback threat model; stop when the budget is
  exhausted; never substitute chains or reusable pads.
- [ ] Validate honest secret-edge connectivity after removing colluders/known edges.
  Report the actual component, not the nominal cell size.
- [ ] Resolve the event-validation boundary above before integration; separate sender
  anonymity, authenticity, confidentiality and availability in tests and labels.
- [ ] Obtain scoped independent review; execute native round/metadata/churn tests
  before making an operational anonymity claim. No funding is required in principle.

## Wording supported now

> Cypherpunk VPN includes an experimental DC-net control-channel library whose
> construction provides information-theoretic sender anonymity within a connected
> honest group when its pairwise one-time pads are jointly uniform, secret and never
> reused, under the stated observation and channel assumptions. The current pad
> generator does not yet establish those assumptions. Ordinary VPN tunnels, remote
> pad chains, authentication and encrypted storage use computational cryptography.

For extracted, approximately uniform pads, replace the ideal claim with the derived
statistical-distance bound once its complete source and composition evidence exists.
Do not advertise “the VPN is information-theoretically secure.”

For one-pad exposure, current-state compromise and future recovery, see the
[assessment and validation guide](PAD_EXPOSURE_VALIDATION.md). It includes existing
evidence, reproducible checks, code sketches and the remaining qualification gates.

## Local validation

- `cargo test --locked --lib dcnet::tests -- --nocapture`: 26 passed, one existing
  recorded-cell-run test ignored. Includes the new exact-transcript coupling and
  authenticated-member substitution boundary.
- `python tools/dcnet_reference.py --check`: committed byte vectors match.
- `python -m unittest discover -s tools -p test_padbook.py -q`: 36 passed.
- `cargo fmt --all -- --check`, `cargo clippy --locked --lib --tests -- -D warnings`,
  and Ruff on the Python mirror passed.

The review changes no codec, primitive, pad generation or wire format.

These checks establish code identities and boundary examples. They do not qualify a
physical source, prove secure erasure or replace independent cryptographic review.
