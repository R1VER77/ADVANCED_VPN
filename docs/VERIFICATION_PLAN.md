# Formal verification plan

We prove the designs we invented, by software, before anyone pays for a review of them.
Standard protocols with published proofs are not re-proved: TLS 1.3, QUIC, WireGuard's
Noise IK, ML-KEM, ML-DSA, HPKE's base mode, Sphinx and Katzenpost's PKI. Our own
cryptographic constructions are proved: each one below is ours, unaudited, and decides
who gets in, what stays secret or who can be linked.

Status (19 Nov 2026): items 1–6 (paced links, the cloak's proof, hybrid KEM sealing, the
oblivious control plane, blind-RSA credits, signed enrollment), the DC-net round core
(item 7) and part of Option E's re-blinding (item 8) are machine-checked in CI, each within
the abstraction its model states: `formal/README.md` lists what each model leaves out and
which lemmas rest on an assumption. The ProVerif equivalences (ohttp and credit
unlinkability) are proved in the same CI job (`tools/proverif_check.py`, results in
`docs/evidence/PROVERIF.json`). Kani proves the link's replay window and reply credit on the
code itself (`src/link_bounds.rs` via `crates/cpvpn-kani`, CI job `kani`), and every parser of
outside bytes is fuzzed (`fuzz/`, coverage-guided, CI job `fuzz`; `tools/test_parser_fuzz.py`
for the Python ones). Still planned: the live Rust vectors for items 1–2. Nothing in the
documentation may claim a property from this list until its model and its gates are in CI.
Proofs run with Tamarin 1.12.0 and Maude 3.5.1 (official release binaries, pinned by
SHA-256 in `.github/workflows/verify.yml`, job `formal-models`); `tools/tamarin_check.py`
fails unless every listed lemma is verified; results in `docs/evidence/TAMARIN.json`.

Lesson from the first runs: equivalence properties over XOR (sender anonymity,
unlinkability) did not terminate in Tamarin's `--diff` mode, and ProVerif and DeepSec do
not support XOR. Those properties get hand proofs, with the trace properties around them
machine-checked.

## How

| Tool | For | Install |
|---|---|---|
| **Tamarin prover** | stateful protocols: replay windows, spent sets, freshness caches; authentication and secrecy under compromise | official Linux release binary plus Maude, pinned by SHA-256 in CI job `formal-models` |
| **ProVerif** | equivalence properties: unlinkability, indistinguishability | `opam install proverif`, pinned in the same image |
| **Kani** (Rust bounded model checker) | the code itself where it is arithmetic state rather than protocol: the replay window, the credit counter | `cargo install kani-verifier` |
| **cargo-fuzz**, **proptest**, **Hypothesis** | the parsers and the edges no model reaches | crates and the Python lock |

A model proves the design, not the code. Every model therefore ships with:

1. **A sanity lemma** (an honest run exists), so a model that can never run cannot pass vacuously.
2. **A mutation check**: a deliberately broken variant of the model (for example, the link key derived without its direction) must be *falsified* by the prover. This is the same mutation discipline as the rest of the repository.
3. **A link to the code**: the model's message formats, labels and key-derivation inputs are written out as test vectors (`tools/testdata/formal/*.json`) that the Rust and Python code must reproduce byte for byte, plus a Kani harness or fuzz target on the real function where the property lives in code.
4. **A CI job** that runs the provers with a time limit and fails on any falsified, unproved or timed-out lemma.

## What, in order of risk

### 1. Paced links (`src/link.rs`)

Fixed-size AES-256-GCM cells between servers. A sender session starts under
HKDF-SHA256(link PSK, salt = random 16-byte session id, info = direction), which carries
only a handshake: inside the cells the sender offers ephemeral X25519 and ML-KEM-768 keys,
the next hop answers with its X25519 key and an ML-KEM ciphertext, and both derive the
next session's keys as HKDF-SHA256(salt = PSK, ikm = both shared secrets, info =
direction || SHA-256 of the exchange), every 120 s. Packets travel only under such keys.
Counter nonce, 128-cell replay window, and replies limited by credit so unauthenticated
packets earn nothing.

- **Forward secrecy against a later PSK compromise**, quantum adversary included: the keys of a completed session stay secret after the PSK leaks, provided either X25519 or ML-KEM held for that session's ephemerals (Tamarin; the mutation drops the shared secrets from the KDF, and the Rust test `a_recorded_link_reveals_no_packet_to_a_later_stolen_psk` already fails on it).
- **Handshake authentication**: without the PSK no one can complete or steer a key exchange, and an answer is bound to its offer (Tamarin; transcript hash in the KDF).
- Secrecy and integrity of every cell (Tamarin).
- **No reflection**: a cell sent in one direction is never accepted in the other (Tamarin; the mutation drops the direction from `info`).
- **No replay**: each counter is accepted at most once per session, and nothing older than the window is accepted, for every interleaving (Kani on the window code, exhaustive to a bound; Tamarin for cross-session replay through the session id). **Proved (Kani, in CI):** over any five counters, none is accepted twice, none 128 or more below the highest accepted, and any above it is accepted; four mutants of the window and credit code are each caught.
- **No amplification**: a sender without the PSK causes no packet in reply (Tamarin, plus Kani on the credit counter: from zero, under any eight receipts and reply attempts and any cap, the replies sent never exceed the cells received, and the credit never exceeds its cap).

### 2. The cloak's proof (`src/cloak.rs`)

A connection becomes a tunnel only when the client sends HMAC(cloak key, TLS exporter).
TLS 1.3 is abstracted as a channel with a unique exporter per connection (proved for TLS
1.3 elsewhere; stated as an assumption).

- **Channel binding**: a proof observed on one connection is useless on any other (Tamarin).
- Only a holder of the cloak key becomes a tunnel; everyone else gets the decoy page (Tamarin). Whether the decoy is indistinguishable from a real origin is a traffic-analysis question, not a formal one: it stays with the labs.

### 3. Hybrid KEM sealing (`tools/keyguard.py` `kem_seal`)

X25519 and ML-KEM-768 shared secrets, both fed into one KDF with the context, the
ephemeral key, the ML-KEM ciphertext and the recipient key. It seals the WireGuard PSK
and the link keys to each device.

- **Hybrid confidentiality**: the payload stays secret while either X25519 or ML-KEM holds; the model lets the adversary break either one, but not both (Tamarin).
- **Context binding**: an envelope sealed for one role or purpose never opens as another (Tamarin; the mutation removes the context from the KDF).
- Test vectors pin the KDF input order to the model's.

### 4. The oblivious control plane (`tools/ohttp.py`)

RFC 9458-style encapsulation over PQ HPKE (ML-KEM-768 + X25519), with one deliberate
deviation: the response is sealed to a per-request reply key instead of an HPKE exporter.
That deviation is exactly what needs proving.

- Request and response secrecy against the relay (Tamarin).
- **Response binding**: a response cannot be swapped onto another request (Tamarin).
- **Freshness**: the 60 s window and the nonce cache accept each request at most once (Tamarin, stateful), across restarts too: the cache lives in memory, so a gateway refuses anything sent before it started (`test_a_restarted_gateway_refuses_replays_of_earlier_requests`).
- **Unlinkability**: the gateway cannot tell whether two requests came from the same client, and the relay learns nothing but sizes and times (ProVerif, observational equivalence). **Proved** (`formal/ohttp/ohttp_unlinkability.pv`), given that every member uses the same gateway key; mutants that reuse a reply key or give each member its own gateway key fail. That condition is enforced by `mesh.check_gateway_key` (two independent beacons must show the gateway operator's signed key; equivocation refused). The request's clock reading is a 30-second bucket of the relay's clock (`mesh.relay_clock`), so a skewed member clock no longer links, and no third party is asked the time (a relay tagging it would need the gateway's collusion, which the proof already excludes); the gateway refuses other values.
- Operator separation (relay and gateway run by different operators) is an assumption of the property, and the code already enforces it (`mesh.beacon_entry`).

### 5. Blind-RSA credits (`tools/mesh_tokens.py`)

Chaum blind RSA with a full-domain hash, issued by the mesh and spent at relays.

- **Unlinkability** of issuance and spending: a signer who sees every issuance cannot tell which one a spend came from (ProVerif, with the blind-signature equational theory). **Proved** (`formal/credits/credits_unlinkability.pv`), given one trusted key per epoch: the ledger enforces one key per epoch at redemption; an issuance client, when one exists, must check it too. The equational theory cannot express RSA's multiplicative tagging attack, so `unblind` verifies each signature before the credit is kept (RFC 9474 Finalize), and `tools/test_mesh_tokens.py` shows the attack on the real arithmetic being refused.
- **No double spending**: a token is accepted at most once across every relay sharing the spent set (Tamarin, with a persistent set). The code side: a redemption holds an exclusive lock while it re-reads, checks and records the spend; eight racing processes accept exactly one (`test_racing_processes_accept_exactly_one_redemption`). Relays that do not share a ledger file still need the mesh's gossiped spent set.
- One-more unforgeability is a computational property that symbolic tools cannot prove. It rests on the RSA blind-signature literature, so the plan also replaces our FDH construction with RFC 9474's RSABSSA (SHA-384, PSS, deterministic) from a reviewed library. Then the computational argument is the published one and the model covers the protocol around it.
- **Not post-quantum.** RSA blind signatures fall to a quantum adversary, and one who can forge credits never needs to break a tunnel. The credits move to a lattice-based blind signature (a reviewed implementation, once one exists) before the project describes itself as post-quantum throughout. The protocol model above carries over unchanged; only the signature's equational theory changes.

### 6. Signed enrollment (`tools/managed_profile.py`)

Every bundle needs both signatures (the Nitrokey's FIDO2 credential and ML-DSA-65) over
one set that names every bundle's manifest hash.

- A device accepts only a bundle covered by both signatures and naming its own keys; no role substitution; no bundle moved between chains (Tamarin, with either signature scheme breakable but not both).

### 7. DC-net control channel (`src/dcnet.rs`)

Pairwise PRG pads that cancel in the group XOR; one event per round. **Proved (Tamarin,
in CI):** frame authenticity across rounds, so fabricated frames and stale-round replays
fail (mutation-checked: no MAC check, or no round in the MAC); cancellation
(mutation-checked); key secrecy; pad secrecy with every member honest; and, with a
colluding member, exact decoding while the honest pair's pad becomes derivable. Models in
`formal/dcnet/`.

- **Sender anonymity within a cell**, against colluding members: hand proof in
  `docs/DCNET_CONTROL_DESIGN.md` §6 (indistinguishability of honest senders; the
  equivalence did not terminate in Tamarin, and ProVerif has no XOR).
- **Round binding of the pads themselves** (a body replayed from another round never
  decodes): the Rust and Python golden vectors fail on it today; the symbolic model binds
  rounds through the MAC.
- The claim stays computational (PRG pads), never information-theoretic.

### 8. Option E's re-blinding (`crates/cpvpn-mix-lane`, design §2.3)

The one non-standard construction in the option E header: the entry hop removes an XOR
pad from hop 2's X25519 element. Model: `crates/cpvpn-mix-lane/tamarin/pq_sphinx_reblind.spthy`
(rewritten 15 Nov 2026: the pack's file was a skeleton that did not parse).

- **Proved (Tamarin, in CI):** an observer of the entry link never learns hop 2's element
  or the pad unless the entry key is compromised (mutation-checked: an unblinded element is
  found); the construction runs.
- **Shown:** an observer of both links holds the pad symbolically (XOR of the right pair),
  so "the pad stays secret" is not the claim to make; the claim is unlinkability.
- **Unlinkability across an honest hop** (no observer of two links can match a cell): an
  equivalence, not machine-checked (Tamarin `--diff` with XOR did not terminate; ProVerif
  has no XOR). Secrecy of the KEM secret itself also did not terminate.
- An external cryptographer's review (gate G3 of the cutover) is still required; no security claim rests on §2.3 until both are done.

### 9. Hardware-bound sessions (`tools/session_auth.py`, `src/session_auth.rs`)

A hardware-protected client's FIDO2 key signs each session (at most 12 h) after a touch and
the PIN; every hop that pinned the key refuses leaves without it
([design](HARDWARE_BOUND_SESSIONS.md)).

- **Proved (Tamarin, in CI, `formal/session/session_auth.spthy`):** every accepted session
  was touched on the device for that identity key and window unless the device key leaked;
  with the identity key copied off the computer, a session still needs a touch in its
  window; the ML-DSA-65 identity is still required; a session nobody asked for needs both
  keys; and (phase 2, per-session keys certified by a short-lived signer) a session key
  taken from the data plane works only in its own window. Mutants: a hop that skips the
  device's statement, a statement without its window, and a certificate and statement
  that do not bind the session key to its window, are each falsified.
- **The code side:** shared vectors (`tools/testdata/session_auth.json`) on which the Python
  reference and the Rust verifier agree, each check mutation-tested in both; real
  assertions from the emulated Solo 1, Solo 2, CanoKey and TKey firmware.

## Not formal, and where it is covered instead

- Traffic analysis (constant-rate stream, per-hop shaping, the mix lane against a global adversary): measured in the labs (`docs/evidence/`), not provable symbolically.
- Firewalls, kill switches, the I2P front's configuration: lab gates.
- Implementation bugs a model cannot see (memory, parsing, side channels): Rust's type system, fuzzing, Kani, and later an independent review whose scope is this list minus whatever the models already settle.

## Deliverables

`formal/` holds one directory per component: the model (`.spthy` or `.pv`), its broken
variant, a README stating the assumptions and lemmas in prose, and the generator for its
test vectors. CI job `formal-models` pins Tamarin and Maude and runs
`tools/tamarin_check.py` (every lemma, every broken variant). `docs/COMPARISON.md` and the threat model cite each property only once its
job is green.
