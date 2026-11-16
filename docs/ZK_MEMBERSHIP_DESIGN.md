# Anonymous membership with zero-knowledge proofs (design and prototype)

**Status (November 2026):** research track, not wired into any command. A measured
prototype exists (`research/zk-membership/`, results in
`docs/evidence/ZK_MEMBERSHIP.json`). Nothing here is part of the shipping claims.

## The problem

Today the mesh knows every member by a public key (`docs/MESH_DESIGN.md` §2): the key
signs, and its hash is the member ID. That is what the network needs to check
signatures, but it means every action a member takes can be linked to one stable
identifier. And the contribution credits that ration the mesh are Chaum blind RSA, which
stays unlinkable against a quantum adversary but becomes forgeable
(`docs/PQ_INVENTORY.md`, the one loud exception).

## The construction

A member never shows a key. It shows a proof:

- **Join.** The member's hardware key releases a secret `s` (FIDO2 hmac-secret, PIN and
  touch), and the member registers only `C = SHA-256("avpn/member/v1" || s)`. The network
  keeps the registered commitments as leaves of a Merkle tree.
- **Act.** To act (spend a credit, join a cell, report), the member proves in zero
  knowledge: *I know an `s` whose commitment is a leaf of the tree with root `R`*, and
  publishes a nullifier for this epoch and purpose (forward-private: see "Forward-private
  nullifiers" below).
- **Check.** The verifier accepts a valid proof for the current root and refuses a
  nullifier already seen in that epoch and scope: one action per member per epoch per
  purpose, without learning which member.

The proof system is a STARK, which rests only on hash functions, so it is post-quantum:
no factoring or discrete logarithm anywhere. Used for the credits, it removes the one
pre-quantum exception in the inventory: forging a credit would mean breaking SHA-256 or
the STARK, not factoring an RSA key.

Nothing is hand-rolled. The statement is ordinary Rust (`research/zk-membership/methods/
guest/src/main.rs`, about 40 lines) proved by the RISC Zero zkVM, which is open source and
has been externally audited. Domain tags keep leaves, inner nodes and nullifiers apart, so
a leaf cannot pose as a node. The proof is RISC Zero's *succinct* receipt, a single STARK,
deliberately not its Groth16 wrapper, which is smaller but rests on elliptic curves and
is not post-quantum.

## Forward-private nullifiers

With one long-lived secret `s`, a device seized later gives up every past nullifier at
once: `SHA-256("avpn/nullifier/v1" || s || epoch || scope)` can be recomputed for every
epoch and scope, and every anonymous action the member ever took becomes linkable. The
prototype therefore uses a secret that only moves forward:

- **Enrol.** A tree has a public start epoch E0 and lifetime N (365 daily epochs in the
  prototype). The member draws `s0` and registers
  `C = SHA-256("avpn/member/v2" || H^N(s0))` with `H(x) = SHA-256("avpn/fp-step/v1" || x)`.
- **Hold.** In epoch E0 + k the device holds only `x_k = H^k(s0)`. At each epoch change it
  computes `x_{k+1} = H(x_k)` and erases `x_k`. `tools/zkid.py` keeps it this way at rest:
  `s0` from kernel XOR Nitrokey, only the current `x_k` stored, in padbook's opaque file
  under the Nitrokey's hmac-secret, stepped forward and saved before it is handed out (its
  hashes are checked against the prototype's, built in Rust). The prototype's host, a
  test, recomputes each `x_k` from `s0` in memory.
- **Prove.** The statement becomes: *I know an `x` such that `H^(N-k)(x)` is committed in a
  leaf of the tree with root `R`*, with nullifier `SHA-256("avpn/nullifier/v2" || x || epoch
  || scope)`. E0 and N belong to the tree, so they say nothing about who proves. The
  journal also carries `action = SHA-256(request)`, which the verifier checks, so an
  intercepted proof cannot be attached to another action and burn the member's nullifier.
- **What it gives.** A device seized in epoch E0 + k reveals `x_k` and every later secret,
  never an earlier one: that would be a SHA-256 preimage. Past nullifiers, in any scope,
  stay unlinkable to the member and to each other. Machine-checked with Tamarin
  1.12.0 in `formal/zk/forward_private_nullifiers.spthy`, unrolled over three epochs
  (`forward_private_epoch1`, `forward_private_epoch2`: an epoch's secret is known only
  after a capture in that epoch or earlier); a device that keeps `s0` falsifies it. The
  unbounded chain did not terminate in Tamarin.
- **What it costs.** Up to N extra SHA-256 compressions inside the proof (360 in the
  prototype's run), on RISC Zero's SHA-256 accelerator. Measured (2018 laptop, CPU only,
  `docs/evidence/ZK_MEMBERSHIP.json`): 458 s for the first proof against v1's 120 s,
  receipt 224 KB as before, verification 34 ms. That run had 8 GiB in swap, so the
  times are an upper bound and the chain's own share is not separated. Members re-enrol into a new tree
  every N epochs; trees overlap so nobody is left without one.
- **Limits.** Nothing protects epochs after a seizure; the captured state must keep
  working. The guarantee also depends on the old `x_k` really being erased: on flash, an
  old copy can survive wear-levelling, the same caveat as the pad store.
- **Why SHA-256, not SHA-3.** Both are post-quantum here (Grover leaves about 128 bits of
  preimage strength), and inputs are fixed-length and domain-tagged, so SHA-3's immunity to
  length extension buys nothing. RISC Zero accelerates SHA-256, and the tree, leaves and
  DC-net chain already use it. Switch only if a measured Keccak build proves as cheap.
- **Prior art.** Forward-secure group signatures (Song, 2001) and hash-chain keys (Lamport,
  PayWord). Semaphore and Zcash use a static identity secret and have no forward privacy.
  New here, as far as we know: forward-private nullifiers from a forward-walked hash chain,
  checked inside a post-quantum STARK.

## Several identities from one key

The nullifier binds a purpose (`scope`), so one secret can act as several unlinkable
identities at once: give each browser profile or role its own scope, and proofs made for
one say nothing about any other, though they come from the same hardware key and the same
registered commitment.

That must not multiply anything that is rationed. A member choosing its own scopes could
invent a new "profile" for every extra allowance, so for a rationed resource (credits,
anything rate-limited) the **verifier** fixes the scopes it accepts, and every profile of
one member draws on the same allowance. Member-chosen scopes are only for actions that
are not rationed, such as proving membership to a service, where a separate identity per
profile costs the network nothing.

## Compared to Zcash Orchard and Tornado Cash

Both solve the same problem, one action per secret without saying whose, and both were
checked against their own sources (Zcash's Orchard book and ZIPs 224 and 2005; Tornado
Cash's `withdraw.circom` and `merkleTree.circom`). We reference the cryptographic
construction, which is standard in the literature, not the Tornado Cash service, whose
sanctions history is a separate matter.

| | Ours (v2, forward-private) | Zcash Orchard | Tornado Cash |
|---|---|---|---|
| Commitment | `SHA-256("avpn/member/v2" ‖ H^N(s0))` | Sinsemilla note commitment | `Pedersen(nullifier ‖ secret)` |
| Tree | SHA-256 Merkle | Sinsemilla Merkle | MiMC Merkle (depth 20) |
| Nullifier | `SHA-256("avpn/nullifier/v2" ‖ x_k ‖ epoch ‖ scope)` | `Extract([(F_nk(ρ) + ψ)]G + cm)`: keyed, bound to the note commitment | `Pedersen(nullifier)` |
| Proof | RISC Zero STARK (succinct receipt) | Halo 2 (Pallas/Vesta) | circom/snarkjs, trusted setup |
| Trusted setup | none | none | yes (a ceremony) |
| Post-quantum | yes: hashes only | no: ZIP 2005 says its note commitments are "not post-quantum binding" | no: Pedersen and pairing-based proofs rest on discrete log |
| Forward privacy | yes: a seized device cannot recompute past nullifiers | no: a static key | no: the deposit note is static |

So we keep ours, for two reasons the table makes plain: both references rest on discrete
logarithms, and Tornado needs a trusted setup. Ours needs neither.

**Taken: bind the proof to the action it authorizes.** Tornado's circuit takes the
recipient, relayer, fee and refund as public inputs, so a proof cannot be lifted onto a
different withdrawal; Orchard binds its nullifier to the spent note's commitment. Our v1
journal, `(root, epoch, scope, nullifier)`, bound nothing of the kind: whoever saw a
member's proof in flight could attach it to a different action first, spending that
member's nullifier for the epoch.

The v2 prototype closes it, still hash-based: the guest reads `action = SHA-256(the request
being authorized)` and commits it in the journal, and the verifier must check it against the
request it is processing. The prototype's run (the forward-private v2 build, six real
proofs over 2^20 members) passed the check that a proof cannot be moved to another action,
along with the other seven (`docs/evidence/ZK_MEMBERSHIP.json`).

## What it does not do

- **Relays and exits stay public.** Clients need their keys to build paths, and the
  operator-diversity rule needs to know who runs what. This is for members *using* the
  mesh, not for nodes.
- **Joining is a visible moment.** The network learns `C` when a member registers; the
  proofs then make every later action unlinkable to that registration and to each
  other. Sybil resistance must be enforced at registration, so it inherits the open
  question in `docs/MESH_DESIGN.md` §2: without attestation, "hardware-backed" is a claim.
- **The secret is in memory while proving.** The hardware key gates `s` (PIN and touch),
  but the proof is computed on the host, as with the keys the client already unseals.
- **Cost.** See the measurements below: fine for a daily action, never per packet.

## Measurements

Real proofs on a 2018 laptop CPU (Intel i7-8565U, 4 cores, no GPU), a tree of 1,048,576
members (`docs/evidence/ZK_MEMBERSHIP.json`), v2 (forward-private, action-bound) with
v1 for comparison:

| | v2 (16 Nov 2026) | v1 (13 Nov 2026) |
|---|---|---|
| Proving one action | 458 s, under memory pressure (six proofs in 2986 s) | 120 s (six in 695 s) |
| Proof size | 224 KB (one succinct STARK) | 224 KB |
| Verifying | 34 ms | 23 ms |
| Public output | root, tree lifetime and start, epoch, purpose, action, nullifier: nothing about the member | root, epoch, purpose, nullifier |
| Building the tree (a million commitments) | 160 s (each leaf commits to a 365-step chain) | about 1 s |

The v2 run had 8 GiB of the machine in swap, so its times are an upper bound. Each
property the design rests on was checked on those proofs: the same member's nullifier
repeats within an epoch (a second use is caught) and changes the next, after the secret
steps forward; a later epoch's secret cannot prove an earlier epoch; a proof cannot be
moved to another action; two members get different nullifiers under one root; a secret
outside the tree cannot produce the members' root; a tampered public output fails
verification; the output contains neither the secret nor its commitment.

## Decision

**Adopted as the design for v1.0, not shipped in v0.10.**

- **Replaces the blind-RSA credits.** Unforgeability then rests on hashes, which removes
  the inventory's one pre-quantum exception, and unlinkability no longer needs blinding at
  all.
- **Practical where it is used.** A relay checks a spend in 23 ms. Proving takes minutes
  on an old laptop (a recent desktop or a GPU is several times faster), so proofs are
  made in the background ahead of need (for the next epoch's credits, while idle), never
  while a user waits.
- **Open before it ships:**
  - *Sybil resistance at registration*: the join step decides who may become a leaf, and
    without attestation "hardware-backed" stays a claim (`docs/MESH_DESIGN.md` §2).
  - *Many spends per epoch*: one proof per nullifier costs minutes each, and one proof
    carrying many nullifiers links those spends to each other. The trade-off is chosen
    per purpose.
  - *A reproducible guest*: verifiers pin the guest program's image ID, so it must be
    built reproducibly (RISC Zero's container build) and the ID published.
  - *A model of the statement* joins `docs/VERIFICATION_PLAN.md`, like every construction
    of ours.
  - *The toolchain* is about 3 GB to build proofs; verifying needs only the library.
