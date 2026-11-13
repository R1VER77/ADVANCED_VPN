# Formal verification plan

We prove the designs we invented, by software, before anyone pays for a review of them.
Standard protocols with published proofs are not re-proved: TLS 1.3, QUIC, WireGuard's
Noise IK, ML-KEM, ML-DSA, HPKE's base mode, Sphinx and Katzenpost's PKI. Our own
cryptographic constructions are proved: each one below is ours, unaudited, and decides
who gets in, what stays secret or who can be linked.

Status: planned. Nothing here is proved yet, and nothing in the documentation may claim a
property from this list until its model and its gates are in CI.

## How

| Tool | For | Install |
|---|---|---|
| **Tamarin prover** | stateful protocols: replay windows, spent sets, freshness caches; authentication and secrecy under compromise | official Linux release binary plus Maude, pinned in `formal/Dockerfile` |
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

Fixed-size AES-256-GCM cells between servers. Key = HKDF-SHA256(link PSK, salt = random
16-byte session id, info = direction), counter nonce, 128-cell replay window, and replies
limited by credit so unauthenticated packets earn nothing.

- Secrecy and integrity of every cell under the link PSK (Tamarin).
- **No reflection**: a cell sent in one direction is never accepted in the other (Tamarin; the mutation drops the direction from `info`).
- **No replay**: each counter is accepted at most once per session, and nothing older than the window is accepted, for every interleaving (Kani on the window code, exhaustive to a bound; Tamarin for cross-session replay through the session id).
- **No amplification**: a sender without the PSK causes no packet in reply (Tamarin, plus a proptest on the credit counter).

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
- **Freshness**: the 60 s window and the nonce cache accept each request at most once (Tamarin, stateful).
- **Unlinkability**: the gateway cannot tell whether two requests came from the same client, and the relay learns nothing but sizes and times (ProVerif, observational equivalence).
- Operator separation (relay and gateway run by different operators) is an assumption of the property, and the code already enforces it (`mesh.beacon_entry`).

### 5. Blind-RSA credits (`tools/mesh_tokens.py`)

Chaum blind RSA with a full-domain hash, issued by the mesh and spent at relays.

- **Unlinkability** of issuance and spending: a signer who sees every issuance cannot tell which one a spend came from (ProVerif, with the blind-signature equational theory).
- **No double spending**: a token is accepted at most once across every relay sharing the spent set (Tamarin, with a persistent set).
- One-more unforgeability is a computational property that symbolic tools cannot prove. It rests on the RSA blind-signature literature, so the plan also replaces our FDH construction with RFC 9474's RSABSSA (SHA-384, PSS, deterministic) from a reviewed library. Then the computational argument is the published one and the model covers the protocol around it.
- **Not post-quantum.** RSA blind signatures fall to a quantum adversary, and one who can forge credits never needs to break a tunnel. The credits move to a lattice-based blind signature (a reviewed implementation, once one exists) before the project describes itself as post-quantum throughout. The protocol model above carries over unchanged; only the signature's equational theory changes.

### 6. Signed enrollment (`tools/managed_profile.py`)

Every bundle needs both signatures (the Nitrokey's FIDO2 credential and ML-DSA-65) over
one set that names every bundle's manifest hash.

- A device accepts only a bundle covered by both signatures and naming its own keys; no role substitution; no bundle moved between chains (Tamarin, with either signature scheme breakable but not both).

### 7. DC-net control channel (`src/dcnet.rs`)

Pairwise PRG pads that cancel in the group XOR; one event per round. The model from the
design pack (`formal/dcnet/dcnet.spthy`) is a starting point, unproved.

- **Sender anonymity within a cell** against everyone but the sender (ProVerif equivalence: any two members sending the same event are indistinguishable).
- **Round binding**: a body replayed from another round never decodes (Tamarin; the mutation drops the round from the pad context; the Rust and Python golden vectors already fail on it).
- The claim stays computational (PRG pads), never information-theoretic.

### 8. Option E's re-blinding (`crates/avpn-mix-lane`, design §2.3)

The one non-standard construction in the option E header: the entry hop removes an XOR
pad from hop 2's X25519 element. Model: `crates/avpn-mix-lane/tamarin/pq_sphinx_reblind.spthy`
(from the pack, unproved).

- **Unlinkability across an honest hop**: no observer of two links can match a cell (ProVerif equivalence).
- An external cryptographer's review (gate G3 of the cutover) is still required; no security claim rests on §2.3 until both are done.

## Not formal, and where it is covered instead

- Traffic analysis (constant-rate stream, per-hop shaping, the mix lane against a global adversary): measured in the labs (`docs/evidence/`), not provable symbolically.
- Firewalls, kill switches, the I2P front's configuration: lab gates.
- Implementation bugs a model cannot see (memory, parsing, side channels): Rust's type system, fuzzing, Kani, and later an independent review whose scope is this list minus whatever the models already settle.

## Deliverables

`formal/` holds one directory per component: the model (`.spthy` or `.pv`), its broken
variant, a README stating the assumptions and lemmas in prose, and the generator for its
test vectors. `formal/Dockerfile` pins Tamarin, Maude and ProVerif. CI job `formal` runs
everything. `docs/COMPARISON.md` and the threat model cite each property only once its
job is green.
