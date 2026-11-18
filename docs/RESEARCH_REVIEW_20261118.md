# Review of CYPHERPUNK_GLM5.3 research and proposals

Review in progress, 18 November 2026. Inputs: the owner-supplied Downloads folder,
all four validation-bundle versions, the validation PDF and Task 3 patch, and signed
GitHub/main head `5d69623697524796b105dd5f24f0644339a05652`. The earlier implementation
is already published in signed commit `bad0a21`; preserve that history. The original
archives remain unchanged. An SHA-256 inventory and safely extracted review copies
are retained locally in `Documents/CYPHERPUNK/research-review-20261118`.
The [input manifest](evidence/RESEARCH_INPUTS_20261118.json) records supplied file
hashes and every archive member's hash for later reproduction.

The latest full-stack hybrid-PQ and SafeCurves requirements are design targets. This
review preserves them. A benchmark estimate, plausible construction or diagram does
not establish that the current runtime meets those requirements.

## Incorporation decisions

| Proposal | Decision and acceptance gate |
|---|---|
| Task 3 downgrade/repository patch | Integrate after correcting native RPM semantics and hardening repository verification; rerun tests and actual guest lifecycle checks |
| Separation of low-volume anonymous control from bulk transport | Retain as a research direction; specify the complete observable transcript and cross-plane linkage before promotion |
| Ideal constant-rate simulation | Retain as a model sanity check; it cannot replace the frozen live 720-attempt experiment |
| XOR two-server PIR prototype | Retain as a reference; qualify independent operators, consistent authenticated databases, malicious-server behavior and deployed latency |
| Hybrid PQ public-key policy | Preserve the target and current authenticated hybrid baseline; require property-specific combiners, downgrade resistance and versioned migration |
| LSH/hash alternatives | Retain interoperability/KAT research; do not replace fixed WireGuard, ML-KEM or RFC ciphersuite hashes from a speed comparison alone |
| MAYO replacement | Research only; pin current parameters/security category and audit the complete authenticated wire protocol before any runtime change |
| Ristretto + ML-KEM + SHA-3 voucher | Unqualified construction; define issuance, verification and quantum unlinkability/unforgeability games, then prove/test them |
| Information-theoretic label | Restricted to the ideal independent-pad construction under its explicit assumptions; operational pad custody/source/authentication gates remain open |
| New whitepaper/graphs | Incorporate corrected labels and measured scope only; do not publish unconditional, immunity, zero-linkability or production-throughput claims from these artifacts |

## What the artifacts establish

The research scripts explicitly identify the website traces as synthetic, PIR as a
local XOR reference, and several VOPRF costs as proxies/estimates. The companion PDF
also records caveats. Those limitations must survive when their numbers are quoted
in the specification, README or a whitepaper. The root specification currently reads
more strongly than its own evidence.

The reported primitive timings are useful engineering inputs, contingent on their
implementation, host and workload. They are not a deployed VPN throughput measurement
or a complete network/bootstrap benchmark. Local CI replication is useful but is not
GitHub Actions provenance, an independent security audit or physical qualification.

## Corrections required before protocol promotion

1. **Website-fingerprinting evidence.** `avpn_test_wf.py` generates every shaped trace
   as the same fixed-duration, fixed-size grid and its feature extractor discards the
   real/decoy indicators. Equal observables are built into that model. No production
   transport, OS scheduler, link loss, retransmission, page-completion duration or
   payload queue is measured. Accuracy around the 1% chance level and a computed
   0% count delta therefore do not prove live immunity. Keep the positive-control,
   failure-retention, grouped uncertainty and cross-environment gates in the main plan.
2. **PIR scope.** `avpn_test_pir.py` implements uncompressed XOR queries to two local
   array evaluations. DPF bandwidth is an analytical comparison, not an implemented
   DPF protocol. The seeded NumPy RNG is a reproducibility fixture, not secret query
   randomness. A deployed construction needs a CSPRNG; information-theoretic query
   privacy requires the stronger randomness assumptions. Compression using a PRG
   introduces computational assumptions. Two keys/servers do not prove noncollusion.
3. **Voucher security.** Appending a KEM contribution and hash commitment to a
   classical VOPRF does not itself prove PQ issuance authenticity or unlinkability.
   A quantum break of its group leg may expose issuance/spend relationships even if
   another leg still hides a session secret. A public commitment/spent bitset alone
   does not prove authorized issuance. Specify who holds/verifies each secret, what
   the issuer signs/MACs, the zero-knowledge/blinding mechanism, and epoch/issuer/
   amount/spend binding. The current dual-anchor script times operations; it does
   not implement or attack a working voucher protocol. [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html)
   defines the prime-order-group VOPRF; the stronger proposed combiner needs its own analysis.
4. **VOPRF timing.** `avpn_test_dualanchor.py` uses X25519 operations as a Ristretto
   proxy, an assumed 1.25 multiplier, and separate SHA-3/HMAC timings. Its reported
   full-with-DLEQ band is 246.7 microseconds, above the headline 150-microsecond
   target; this is still an estimate rather than an actual RFC 9497 implementation.
   Some raw JSON keys end in `_s` even though that script stores microseconds there.
   Normalize units explicitly in any downstream tooling without altering original evidence.
5. **Handshake accounting.** Count every public key/ciphertext, signature,
   transcript binding, authentication tag, protocol header and transport envelope,
   per flight. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) gives ML-KEM-768
   a 1,184-byte encapsulation key and 1,088-byte ciphertext. The TLS hybrid has a
   1,216-byte client share and 1,120-byte server share before TLS framing, per
   [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html). A ciphertext-only budget
   cannot stand for a full exchange unless authenticated key preprovisioning is
   explicitly included in the design and threat model. Sub-1,200-byte datagrams also
   do not guarantee success on every possible underlay; PMTU and fallback still matter.
6. **MAYO strength/version.** The currently published MAYO implementation lists
   MAYO_1 as category 1 with 1,456-byte public keys and 464-byte signatures;
   [maintainer parameter table](https://github.com/PQCMayo/MAYO-C). It cannot supply
   category-3 authentication merely because the KEM is ML-KEM-768. Older 321-byte
   parameter generations are not interchangeable with current parameters. Do not
   trade an existing authenticated profile for a smaller experimental signature
   without versioned negotiation, complete vectors, analysis and review.
7. **Pads and cross-plane composition.** Keep pad entropy, joint independence,
   non-reuse, adaptive exposure, erasure, authenticated events and honest-edge
   connectivity as explicit gates from the existing paper/pad reviews. Fresh physical
   entropy cannot be inferred from seeded Monte Carlo or TRNG health tests alone.
   Session PSKs and DC-net masks need disjoint allocated secret material and durable
   consumption; reusing bytes across the planes would defeat the intended separation.
   Network-delivered KEM-wrapped pads retain computational custody assumptions.
8. **DC-net simulation and jamming.** The simulation's coalition routine reduces
   each case to the same two-honest-member algebra; its `n` and `n_colluders`
   parameters do not model a distinct deployed coalition topology. Its jam check is
   `total != original_message`, not an authenticated blame or replacement-event
   proof. The existing design explicitly accepts denial of service. Keep algebraic
   correctness, conditional anonymity, event authorization and jamming availability
   as separate properties; small p-values or chance classifiers prove none of them universally.
9. **Bandwidth and latency units.** With 111-byte member broadcasts and 64-byte
   pair masks, n=8 consumes 888 logical broadcast bytes/round, 1,792 unique pad
   bytes/round and 3,584 stored endpoint-copy bytes/round. Each member broadcasts
   111 bytes and consumes 448 pair-pad bytes/round. State whether a budget is per
   member, logical aggregate cell, unique material or stored copies; these quantities
   differ. Physical broadcast/unicast fanout and transport envelopes require additional
   wire accounting.
   At two rounds/minute a round interval is 30 seconds. If bootstrap must wait for a
   new round, a 350 ms target requires a separately specified preallocation/prefetch
   design; a sub-millisecond primitive sum does not solve that scheduling delay.
10. **Current interfaces versus policy.** The runtime still includes P-256 cloak
    key generation in `tools/managed_profile.py`, and hardware credential/CTAP
    interfaces need an explicit algorithm/quantum inventory. Preserve existing keys
    and device compatibility while designing the required transition; never silently
    reset a hardware device. Classical compatibility infrastructure such as current
    SSH/OpenPGP signatures must be disclosed, not described as fully PQ by association.
    There is also a concrete local hardware boundary: `tools/keyguard.py` uses
    python-fido2's `HmacSecretExtension`; the pinned library's PIN/UV protocols 1/2
    use P-256 ECDH (protocol 2 inherits the key agreement from protocol 1).
    [CTAP 2.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html)
    specifies that key agreement. Choosing an Ed25519 credential does not change it.
    Thus today's tested FIDO sealing flow cannot be described as SafeCurves-only or
    hybrid-PQ on every interface. A recorded local CTAP exchange belongs in the
    harvest-now/decrypt-later custody threat model. This is a protocol/capability gap,
    not a udev repair or an algorithm flag the assistant can safely toggle. Preserve
    the available devices and credentials; require a compatible reviewed hardware
    protocol and migration before extending the full-stack claim to this boundary.
    Generic vault enrollment also leaves credential algorithm selection to the
    supported COSE options; it does not force Ed25519. Report the actual credential's
    algorithm, preserve existing credentials, and include an ES256 transition in the
    same inventory. Do not infer curve compliance from a device family name.

## Task 3 patch review

The patch applies cleanly to the current tree. Two concrete corrections were found:

- RPM `%pre` gets an installation-count argument, not the installed version as `$2`.
  The proposed numeric comparison is therefore bypassed on a real transaction. It
  also discards epoch/release ordering. Use the actual installed RPM database and
  native EVR semantics, and test a real RPM transaction before qualifying that path.
- The repository verifier accepts a Release without the required signed index rows,
  permits ambiguous/traversing metadata paths, takes its testing/production label from
  an unsigned manifest, and compares a signing-subkey fingerprint against the primary
  pin. Correct those boundaries. Require all expected SHA-256/SHA-512 index entries,
  strict no-follow paths, snapshot signature inputs, cross-check signed package data,
  signed key classification, freshness and primary/subkey binding. Add adversarial
  counterexamples, including a correctly signed but incomplete Release.

The downloaded repository is explicitly marked **testing** and its key fingerprint is
`9D316CCB29A5D330F9E0DFFAA499C716984CE200`. It is not a production repository. Its
public key is not supplied in this folder, so the downloaded signatures cannot be
independently authenticated here from the artifacts alone. Local new tests use a
separate disposable keyring; they do not provision or publish a hardware key.

## Next validation steps

Finish the hardened Task 3 tests, generate a new candidate from the reviewed source,
and rerun actual guest install/replace/repair/reboot/removal/downgrade checks. The
previous package trial C lost its read-only payload mount after reboot, so its optional
bus-test client was absent; fix/remount the test disk and retain that failed result.
Then complete live-bus/native-GUI validation and continue main-plan stages 4–7. Add
formal composition, real implementations and negative tests for the R&D proposals
within stage 7; do not let simulated results close the outstanding operational gates.

## Additional whitepaper drafts

Also reviewed `whitepaper_content.py` and `whitepaper_content2.py` from the supplied
folder as source text, without executing their generator or importing the modules.
The operational chapters usefully collect pad custody, replenishment, exhaustion and
deniable-storage limitations. Retain those as requirements, with the following corrections:

- **DLEQ batching is bound to actual evaluations.** RFC 9497's proof verifies the
  supplied blinded/evaluated element pairs. A verified proof for one batch or issuer
  epoch does not authenticate arbitrary subsequent evaluations. Amortization requires
  an explicit batch, all its inputs/outputs and its verification work; it cannot
  delete this work by caching an issuer key. Benchmark the complete implemented batch
  protocol, rather than an X25519 proxy, before adopting a per-voucher latency claim.
  See [RFC 9497, proof verification and verifiable mode](https://www.rfc-editor.org/rfc/rfc9497.html).
- **Accountability is not a universal sender-tracing equivalence.** Detecting that
  a participant supplied an invalid contribution is a different property from
  identifying the honest participant whose message is hidden in a valid round.
  [Verdict](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/corrigan-gibbs)
  is prior work on verifiable DC-nets with disruption accountability. Its computational
  machinery does not establish this project's stronger ideal-pad claim or endorse a
  particular mitigation here. Preserve the owner's accept-DoS/no-tracing policy as a
  policy choice; do not describe it as an impossibility theorem. The draft itself
  proposes proving invalid transmissions, which also needs this distinction.
- **A public event tag proves neither membership nor sender count.** Membership
  comes from authenticated contributions. A decodable aggregate with a valid public
  tag does not prove exactly one authorized sender. A malicious member can substitute
  validly encoded events; the draft acknowledges this attack elsewhere. Test and
  authorize event effects separately. The ideal random-collision estimate is not a
  bound against adaptive malicious event replacement.
- **Jamming isolation and fallback need operational tests.** Shared CPU, buffers,
  link capacity, expiry, renewal and revocation dependencies can affect established
  traffic. Not wiring the DC-net into current bulk transport does not prove that
  a future integrated system cannot be degraded. Specify and fault-test these
  dependencies. Any weaker fallback needs explicit policy and visible status;
  availability cannot silently waive a selected privacy requirement.
- **Custody bounds the pad claim.** Hand-delivering a KEM/AEAD envelope does not
  remove the computational assumption for an adversary who records that envelope.
  An assessed min-entropy source and extractor provide a conditional statistical
  bound, not perfect uniformity; account for conditioning, seed independence and
  composition over the full book/epoch. A source test once on an idle machine does
  not qualify every later runtime environment. Validate the exact device firmware
  before quoting a Nitrokey generator's internal algorithm.
- **Pad and transport domains must be disjoint.** A PSK consumes separately allocated
  secret material with durable ownership/consumption rules. Deriving it from the same
  pads used for masked control events needs a composition argument, not an inheritance
  analogy to another deployed protocol. No KDF manufactures more independent secret
  entropy. A finite ratchet counter and operational key lifetime must also replace
  the draft's unbounded “never runs out” wording.
- **Performance and status need the same scope corrections.** The drafts repeat old
  MAYO sizes, full-handshake/fragmentation shortcuts, epoch-amortized estimates,
  synthetic fixed-grid privacy guarantees and “independent” validation labels.
  Primitive loops, symbolic proofs and model tests cannot qualify deployment or
  independence. The 720-attempt run was started and failed collection, rather than
  being unstarted or successfully validated. A full-stack policy commit is not a
  runtime upgrade. Entry-hop PQ encapsulation also does not by itself prove every
  downstream hop's desired PQ properties; analyze each compromise/transcript case.

Keep the drafts unchanged as review inputs. Before publishing a regenerated paper,
resolve these corrections, restore portable figure paths, identify measured versus
proposed features and retain the requested author **Anonymous** and supplied SimpleX
contact. The draft's different author credit is not adopted by this review. Writing
the whitepaper does not close protocol implementation or independent-review gates.

## Executed review counterchecks

The reviewed model functions were evaluated in a bounded local check without running
the downloaded scripts' entry points. Different unshaped visits yield identical shaped
feature vectors, the computed grid is 600 cells in both load cases, both coalition
parameters are unused, and the recorded full-DLEQ estimate is 246.7 us versus the
150 us target. The input archive digest and scoped results are retained in
[evidence](evidence/RESEARCH_COUNTERCHECKS_20261118.json). This is a model-scope
check, not a traffic or voucher-protocol security test.

The primitive AEAD microbenchmark repeats a key/nonce for timing and counts both
encryption and decryption work in its combined MB/s figure. It is a benchmark fixture,
not a packet-encryption example. Do not copy that nonce pattern or read its combined
rate as end-to-end one-way VPN goodput. The reported 313 us KEM budget also adds a
second key-generation operation by convention; map actual protocol roles/operations
before treating that sum as a handshake measurement.
