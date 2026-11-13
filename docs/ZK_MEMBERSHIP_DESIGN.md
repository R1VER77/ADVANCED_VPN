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
  publishes the nullifier `N = SHA-256("avpn/nullifier/v1" || s || epoch || scope)`.
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
members (`docs/evidence/ZK_MEMBERSHIP.json`):

| | |
|---|---|
| Proving one action | about 2 minutes (120 s; six proofs in 695 s) |
| Proof size | 224 KB (one succinct STARK) |
| Verifying | 23 ms |
| Public output | root, epoch, purpose, nullifier: nothing about the member |
| Building the tree (a million commitments) | about 1 s |

Each property the design rests on was checked on those proofs: the same member's
nullifier repeats within an epoch (a second use is caught) and changes the next; two
members get different nullifiers under one root; a secret outside the tree cannot produce
the members' root; a tampered public output fails verification; the output contains
neither the secret nor its commitment.

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
