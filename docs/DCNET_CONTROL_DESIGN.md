> **Status (November 2026):** reference design. Adopted as a library and a pad tool only (src/dcnet.rs, tools/padbook.py, tools/dcnet_reference.py, formal/dcnet/), not reachable from any command until the mesh has members. Pads come from hardware only, never a software generator: one-time pads for pairs who met in person (information-theoretic among them when made with an assessed raw noise source), a forward-secure chain for pairs who cannot meet (computational). §2.

# DCNET_CONTROL_DESIGN.md — DC-net control channel for AVPN/Mesh

Status: design proposal. Position taken **after v0.9.0** (I2P front,
Katzenpost mix lane, `avpn mix`, oblivious control plane, VERIFICATION_PLAN.md).
This doc is the step-5 item from `MIX_LANE_DESIGN.md` §4, revised in light of
what actually shipped.

## 0. Position after v0.9.0 — read this first

v0.9.0 changed the calculus. The mix lane (`avpn mix`, unmodified Katzenpost
v0.0.110) already provides computationally anonymous transport for async
traffic, and the oblivious control plane already handles enrollment and
directory queries. So the first question is not *how* to build a DC-net, but
*whether one earns its place*:

| Option for anonymous control events | Trust assumption | Cost | Claim class |
|---|---|---|---|
| **Ride the mix lane** (default, available today) | Katzenpost mix providers non-colluding | zero new code | computational unlinkability |
| **DC-net cell** (this doc) | the other cell members (no infrastructure operator) | new protocol, O(n) round traffic, Nitrokey pads | information-theoretic among members joined by in-person one-time pads; computational over network-seeded chains |
| Oblivious control plane (status quo) | directory servers | already shipped | existing claims |

The DC-net's only honest differentiator is **infrastructure-freedom**: mix
providers can be sybil'd, subpoenaed, or go dark; a DC-net cell's anonymity
depends only on the other members in the cell, who are the same peers whose
servers carry the traffic anyway. Its unique niche is therefore the events
where the *identity of the initiator* is the most damaging thing that could
leak, even if every mix provider is compromised:

- **ENROLL_INTENT** — "someone is joining" before hardware-anchored identity
  is established.
- **CHAIN_SETUP_COMMIT** — the commitment that binds a chain descriptor to a
  session without revealing which member built it.
- **KEY_ROTATION_NOTICE** — announcement that a member's node keys changed
  (the TOFU re-verification event; knowing *who* rotated *when* is itself
  correlation material).
- **MIX_LANE_FALLBACK** — "a member stopped using the mix lane," the event
  most correlated with coercion.

Recommendation: **ship the mix-lane routing of these events first** (a config
flag, days of work), and treat the DC-net cell as the v2 hardening step for
the two events where infrastructure-freedom matters (CHAIN_SETUP_COMMIT,
MIX_LANE_FALLBACK). Everything below is the v2 design.

Non-goals, stated up front: no attempt to carry bulk or interactive traffic;
no accountable-tracing mechanism (see §5 — the jam policy is accept-DoS);
no information-theoretic claim (see §2 — the pads are PRG-derived).

## 1. Architecture

### 1.1 Cells

- Membership is derived deterministically from the existing directory: cell
  assignment = `H(member_id || epoch) mod n_cells`, so no one chooses their
  cellmates and re-assignment happens every epoch (e.g., 24 h) to bound
  long-term pair exposure.
- Cells of **4–60 members** (`CellPads::new` refuses others). Four is the floor:
  one colluder then still leaves three honest members, who keep every pad of theirs
  secret (§2, "Pad exposure"); in a 3-member cell one colluder leaves two, who share
  their round pad with it. Larger cells hide a sender among more people but need a
  pad book or chain per pair, and in-person books need every pair to have met.
- Mesh-mode only. In single-operator mode there is no peer group; the
  construct is meaningless (an anonymity set of 1 is a tautology) and the
  config must refuse to enable it.

### 1.2 Rounds

- Round cadence: **one round every 30 s** per cell (`ROUND_SECS`). Every round burns
  64 bytes of each pair's pads, sent or not; 30 s keeps an in-person book at 184 KB
  per pair per day. Control events are rare, and a 30 s wait is fine for them.
- Round structure: 3 phases, total ≈ 2.5 s + slop:
  1. **Sync** (≈1 s): round number and epoch agreed via the existing gossip
     layer; members who miss sync are treated as silent for the round.
  2. **Transmit** (≈1 s): every online member broadcasts exactly one
     fixed-size transmission (see §3) over their existing constant-rate
     server links.
  3. **Aggregate + verify** (≈0.5 s): any member (or observer) can compute
     the group XOR; decoding follows §4.
- Round numbers are strictly monotonic per cell and **never repeat**, even
  across epochs; each round's pad is that round's alone (round-binding, tested in
  the harness §6-F and `src/dcnet.rs`).

### 1.3 What rides the DC-net

Only the four event types in §0, each ≤ 64 B encoded, one reserved slot per
round. Everything else (descriptors, credits, liveness) stays on existing
channels — the DC-net is a scalpel, not a general bus.

## 2. Pads and the honest security claim

### How the pads work, in plain terms

Take four members A, B, C and D (the smallest cell; see §1.1). Every pair has its own
pads, six pairs in all (AB, AC, AD, BC, BD, CD), 64 bytes per pair per round, and a
round every 30 seconds. Both members of a pair hold the same pad for each round, and
nobody else does.

- Each member broadcasts the XOR of its three pads. A member with an event to send
  also XORs in the event.
- Anyone XORs all four broadcasts. Each pad appears in exactly two of them and
  cancels, leaving zero (nothing was sent) or the event. Each broadcast on its own
  looks random, so nothing says whose it was.
- Two senders in one round collide; the result is garbled and both retry later.

| Who | What they learn about an event |
|---|---|
| An outsider who sees every frame | that it was sent, and that its sender is one of the n members |
| k colluding members | that the sender is one of the n − k others; once only two others are left, also those two's pad for that round, which gives nothing beyond that round (pad exposure, below) |
| everyone but one member | who sent it |

### Where a pair's pads come from

From hardware only, never a software random source. Each pair uses one of two kinds
(`src/dcnet.rs` `PairPads`, `tools/padbook.py`):

| | **Met in person: one-time pads** | **Cannot meet: a forward-secure chain** |
|---|---|---|
| What the pair holds | a book: 64 bytes per round, the XOR of both members' contributions | a 32-byte seed, the XOR of both members' contributions; `s(r+1) = SHA-256("dc-next" ‖ s(r))`, pad = `SHA-256("dc-pad-0" ‖ s(r) ‖ r) ‖ SHA-256("dc-pad-1" ‖ s(r) ‖ r)` |
| Each contribution | kernel output XOR Nitrokey output XOR the extracted output of the member's assessed raw noise source | kernel output XOR Nitrokey output |
| How it travels | on removable media, sealed to the partner's ML-KEM-768 + X25519 key, never on a network | over the network, sealed the same way |
| Claim | **information-theoretic** when at least one contribution carries an assessed raw source and was handed over in person; computational otherwise | **computational** (ML-KEM-768 + X25519 and SHA-256), forward-secure |
| Volume | 184 KB per pair per day, 67 MB per pair per year | none after the seed |
| Runs out | yes: the pair, and so the cell, stops (fails closed) | no |

Mixing is allowed within a cell. Anonymity is information-theoretic among the honest
members joined by information-theoretic books, and computational beyond them (§6).

- **Why the Nitrokey alone is not enough.** Its `rng` command (`nitropy nk3 rng`,
  admin-app command 0x60) returns 57 bytes of Trussed's `random_bytes`, which is a
  ChaCha8 stream seeded once per boot from 32 bytes of the LPC55 TRNG XOR 32 bytes from
  the SE050 (firmware v1.8.3 and v1.9.1 source; no host command exports raw TRNG bytes).
  That is strong but computational: a megabyte book from it carries a few hundred bits
  of physical randomness. Closed tokens (YubiKey GET CHALLENGE, TPM GetRandom) cannot be
  checked at all, and statistical tests cannot tell a good generator from noise.
- **The raw source: CPU timing jitter.** The raw time deltas of the jitterentropy noise
  source (its SP 800-90B raw-noise recorder; low 8 bits per delta), on the member's own
  machine. Once per machine, on an idle system, `padbook.py assess` records a million
  samples and runs NIST's SP 800-90B `ea_non_iid`. The extractor then counts half of its
  min-entropy estimate. Every sample used later passes the SP 800-90B repetition-count
  and adaptive-proportion tests (cutoffs from that estimate, false alarms 2⁻²⁰) and the
  recorder's own health tests.
  - A Toeplitz extractor turns each block of 1,024 samples into bits within 2⁻⁶⁴ of
    uniform (leftover hash lemma: output = counted min-entropy − 128 bits). Its seed is
    public, drawn once from the Nitrokey before any sample is used; the bound needs it
    independent of the noise, not secret.
  - Caveats, stated wherever the claim is: jitter entropy depends on the CPU and its load,
    so the assessment holds for the machine it was made on; it comes from
    microarchitectural timing, debated as physical randomness (Tails relies on the
    kernel's use of it and cites a BSI study validating it); and it lives on the member's
    CPU, which also does the XOR. A dedicated open-hardware noise device with a raw mode
    (for example the Infinite Noise TRNG, `infnoise --raw`) can be XORed in the same
    way; the book stays information-theoretic if either raw source's assessment holds.
- **Three sources per contribution, drawn in order.** The kernel's output (`getrandom`:
  ChaCha20 over a pool of RDSEED, interrupt timing and the rest) and the Nitrokey's are
  drawn *before* any jitter is recorded, then XORed with the extracted noise. XOR with an
  independent stream never weakens a pad, so the contribution fails only if all three
  fail. Only the raw part can make it information-theoretic, and only if the other two do
  not depend on it: the Nitrokey is a separate device, and the kernel bytes are fixed
  before the noise they are mixed with occurs (the kernel's interrupt timings also jostle
  the jitter measurements, so drawing them afterwards would weaken the independence
  argument).
- **One seed, both members.** Each member contributes the same length and the pair
  uses the XOR, so the pads are uniform and secret if either contribution is.
- **At rest, encrypted under the Nitrokey.** A book is stored as one AES-256-GCM record
  per round under a per-round key from a one-way key chain. A chain's state is stored
  the same way. Only the current link is kept, wrapped by a key derived from the
  Nitrokey's FIDO2 hmac-secret (PIN and touch, once per session; never stored). The
  hmac-secret is deterministic, which is right for a wrapping key and never used as a
  pad.
  - Taking a round moves the chain first and then zeroes the used records. A seized
    disk, even with the Nitrokey and its PIN, then opens no round already used (short of
    an old copy of the small state file that flash wear-levelling kept; full-disk
    encryption is still recommended).
  - Rounds follow the clock, so a past round is refused, and a restored old state cannot
    replay pads. The hybrid private key that receives contributions is sealed under the
    same hmac-secret.
- **Pads are used once.** A round's pad is handed out once and wiped, skipped rounds
  are burned, and a refused round consumes nothing (`PadBook`, `Ratchet`, and
  `dcnet_one_time_pads.spthy`).
- **The frame MAC uses its own cell key** (computational authenticity, never member
  identity). A pad forges nothing.
- **What the laptop still sees.** The CPU computes the XOR, so each round's pad is in
  memory for one round, zeroized afterwards. The process takes no core dumps, locks its
  memory where the limit allows, is not dumpable by other processes (`PR_SET_DUMPABLE`),
  and zeroes its live key buffers on exit and on SIGTERM, SIGINT or SIGHUP (after Tails'
  wipe on shutdown and VeraCrypt's RAM key protection). CPython's own immutable copies
  cannot be wiped, so in `padbook.py` this reduces exposure rather than removing it; the
  Rust data plane's `zeroize` is the guarantee.
  - Malware on the member's own laptop is out of scope either way: the event starts
    there.
  - Keeping pads away from the CPU altogether needs the Nitrokey to compute the XOR
    itself, and the stock firmware cannot. That would be a custom firmware applet: a
    book stays encrypted on disk, the token holds its key chain, and each round the token
    returns the body. Future work. Zero-knowledge proofs do not help here: they hide data
    from a verifier, not from the CPU that computes the proof.

### Nothing in the clear, and deniable storage (design)

What padbook stores and sends has no readable structure, after TrueCrypt's volume header (a
random salt, then everything encrypted):
- `book.bin` is a salt, a nonce and the encrypted header, contributions and chain state.
- `pads.bin` grows in 30-day buckets of random-looking records.
- An envelope is an Elligator 2 representative of a dirty X25519 key, an ML-KEM-768
  ciphertext and AES-256-GCM over the padded contents.

Without the Nitrokey (at rest) or the recipient's key (in transit), they are random bytes:
no pair names, cell, round range or delivery label, and sizes that give away only a bucket.
Residual: ML-KEM ciphertext coefficients are near-uniform, not exactly uniform. At rest,
every pad record and `book.bin` are a cascade: ChaCha20-Poly1305 over AES-256-GCM, with
separate keys, so one cipher broken alone opens nothing stored.

**Deniable storage, designed, not built.**
- **Goal:** under coercion, a member opens a decoy set of books, and nothing shows that more
  exist. That matters most for the events closest to coercion (`MixLaneFallback`).
- **Design:** one store of random-looking blocks; each layer is opened by its own Nitrokey
  credential, and the layers are interleaved rather than placed at a fixed offset. This is
  Shufflecake's approach (2023: any number of nested layers on Linux), which improves on
  TrueCrypt's single hidden volume, whose fixed location and size field invite "show me the
  hidden one".
- **Limits, to be stated whenever it is claimed:**
  - an adversary who images the disk twice sees which "random" blocks changed, and books
    change every round, so only a single seizure is covered;
  - flash wear-levelling keeps old blocks;
  - the decoy layer must be used believably.
- **What building it takes:** a block allocator across layers, per-layer keys from separate
  Nitrokey credentials, an unlock that never shows how many layers exist, and tests that a
  store with one layer and a store with three are indistinguishable.

### What we took from TrueCrypt

The TrueCrypt 7.1a source was studied, not used.
- The archive has SHA-256 `e6214e91…81c8dc`.
- It carries a good signature from the TrueCrypt Foundation key, fingerprint
  `C5F4 BAC4 A7B2 2DB8 B8F8 5538 E3BA 73CA F0D6 B1E0` (a 2004 DSA-1024 key, weak today;
  checked in an isolated keyring with the key from the DrWhax archive).

Taken:
- no plaintext metadata or magic: the volume header model;
- authenticated encryption instead of unauthenticated XTS;
- keys from hardware, not a low-iteration PBKDF2;
- randomness that fails closed. The audit found that a failed `CryptAcquireContext` could
  leave the pool weak without warning.
- a cascade of unrelated ciphers.

Not taken:
- its code: TrueCrypt License 3.0 is not an open-source licence this Apache-2.0 project can
  include;
- its binaries: unmaintained since 2014, with VeraCrypt as the maintained successor;
- its random pool: user input and system polls, hashed, so computational.

### What a cell does not give

- **Not for groups under four.** `CellPads::new` refuses them: in a 3-member cell, one
  colluder already leaves two honest members, who then share their round pad with it.
  Four people hide which of the four sent, from outsiders who can see who the four are;
  one colluder narrows it to three, two to a pair.
- **Not a general anonymous network.** A cell carries one 64-byte control event per
  round, of four kinds (§0); traffic, messages and browsing go elsewhere.
- **Not membership privacy.** Who is in a cell and online is visible; every member
  sends every round so that sending reveals nothing.
- **Not jam-proof.** Any member can garble a round; the policy is to abort it (§5).
- **Not usable yet.** A library, a pad tool and models (status line above); cell
  assignment and round sync are not built, and these events ride the mix lane today.

### The mechanics in full

- Member i's transmission in round r:
  `c_i(r) = m_i ⊕ (⊕_{j≠i} pad_ij(r))`. Member i XORs only the pads of
  pairs involving i, so each pad appears exactly twice in the group sum and
  cancels **by construction** (verified by the harness, §6-F.1).
- **Claim discipline.** Say "information-theoretic" only for books made with an assessed
  raw source and handed over in person, only together with "among members joined by
  such books", and with the jitter caveats above. Pads sent over the
  network are as strong as ML-KEM-768 + X25519 and SHA-256, whatever generated them.
- **What is claimed is indistinguishability, not pad secrecy.** Once a member
  colludes, the adversary can learn an honest pair's pad (in a 3-member cell it
  is B's silent frame XOR the pad B shares with the colluder), and still cannot
  tell which honest member sent. The claim, its proof and what is machine-checked
  are in §6.
- **Pad exposure, and what bounds it.** After removing the pads they share, the
  colluders see each honest member's sum of honest-honest pads. Over GF(2) these
  sums have rank |H| − 1 in |H|(|H|−1)/2 unknowns, so:
  - with three or more honest members no single pad follows (machine-checked for
    one colluder in a 4-member cell, `dcnet_collusion_4.spthy`);
  - with exactly two, the honest pair's pad of the round follows. In a null round
    it is a silent frame; in an event round it is one of two values that differ by
    the event, one per possible sender, so holding it is the same as not knowing
    the sender. No pairwise-pad design avoids this: a silent member's frame *is*
    its pad sum, and it is broadcast.

  A learned pad is worth its own round only. A book's pads are independent hardware
  random values (`dcnet_one_time_pads.spthy`: a pad is known only if that round's use
  leaked it), and a chain's state moves one way (`dcnet_ratchet.spthy`: a captured
  state reveals no earlier round). The 4-member floor keeps three honest members
  against one colluder.

## 3. Wire format

```
dc_frame := magic(2) || cell_id(4) || round(8) || flags(1) || body(64)
           || member_mac(32)          // 111 bytes total
```

- `flags`: version/flags byte, **constant 0 in v2 and identical across all
  members in a round.** It must NEVER encode sender state (a "this frame
  carries an event" bit would identify the sender outright — the bodies
  themselves look uniformly random whether or not they carry an event, and
  that is the only thing keeping the sender hidden).
- `body`: every member's body is a full pad XOR (`⊕ over partners j of
  pad_ij(r)`), with the sender additionally XORing the event encoding
  `{ event_type(1) || nonce(8) || payload(46) || crc8(1) || zero(8) }`.
  A silent member's body is NOT zero — it is indistinguishable random-looking
  bytes; only the *group sum* of a null round is all-zero.
- `member_mac`: keyed by a *per-round broadcast key* derived from
  `HKDF(K_ij-family)`? — No: the MAC key cannot identify the member or the
  sum would be linkable. Instead: `member_mac = HMAC(anon_key_r, frame)`,
  where `anon_key_r = HKDF(⊕-of-nothing...)` — concretely, each member uses
  a **pre-committed per-epoch anonymous MAC key** registered blinded with
  the directory (blind-RSA credits machinery, already shipped). The MAC
  exists only to authenticate *membership in the cell* (jam filtering input,
  §5), not to identify the member: the directory can verify the MAC against
  the blinded registration without learning which member sent which frame.
- Total frame: 111 B. Inside the existing constant-rate envelope this is
  noise — the DC-net traffic is indistinguishable from ordinary cell framing
  on the wire.

Per-member per-round transmit volume: 111 B × 1 frame + the group sum they
compute locally from gossip-synced frames: O(n) frames observed ≈ 24 × 111 B
≈ 2.7 KB/round ≈ **0.09 KB/s** steady-state at 30 s rounds. Cheap by design.

## 4. Decoding and collision handling

- Group XOR of all n frames: null rounds decode to all-zero; a sender's
  event survives cancellation.
- **Collision** (two senders in one round): XOR of two different event
  encodings — the CRC-8 check fails and the round decodes as Garbled.
  Policy: both events are lost; each sender re-transmits in a later round
  chosen by exponential backoff keyed to their (private) nonce. Expected
  collision rate at ≤1 event/cell/hour across 24 members: negligible
  (<10⁻⁴/round); at enrollment storms (many ENROLL_INTENTs), backoff
  resolves within seconds.
- **Identical-collision edge (documented, accepted):** two senders
  submitting *byte-identical* events in the same round cancel to a null
  round — indistinguishable from no event. Benign (duplicate events carry
  no information beyond the first), and the per-event nonce makes it
  vanishingly rare by construction.
- **Jam** (member xors garbage every round): group sum is non-decodable
  garbage (harness §6-F.4). Policy in v2: abort the round, do nothing else.
  See §5.

## 5. Jamming policy (decided before the protocol, as promised)

- **v2 accepts DoS.** A jamming member can suppress DC-net rounds
  indefinitely. The events in scope all have non-DC-net fallbacks (mix lane,
  oblivious control plane), so jamming degrades the *stronger* guarantee,
  not availability of the function itself.
- **Accountable tracing is out of scope and must stay out.** Any mechanism
  that can identify a disrupter is a mechanism that can identify a sender.
  If jamming becomes a sustained practical problem, the answer is cell
  re-assignment (epoch churn) — the jammer must re-enroll and re-establish
  pairwise keys each epoch, at hardware-anchored cost — not traitor tracing.
- This trade-off is a documented consequence, not an oversight.

## 6. Verification

Hooks into `VERIFICATION_PLAN.md` (extend its priority list):

8. **DC-net round state machine** — machine-checked with Tamarin 1.12.0 /
   Maude 3.5.1 on 15 Nov 2026, run in CI (`tools/tamarin_check.py`, job
   `formal-models`), results in `docs/evidence/TAMARIN.json`:
   - `formal/dcnet/dcnet_authenticity.spthy`: `frame_authenticity` (every
     accepted frame was transmitted by a member in that very round, so
     fabricated frames and stale-round replays fail), `keys_secret`,
     `executable_accept`. Mutation-checked: without the MAC check, or with the
     round left out of the MAC, Tamarin finds an attack.
   - `formal/dcnet/dcnet.spthy`: `cancellation` (a round decodes to zero, to
     the one sender's event, or, on a collision, two members sent), `keys_secret`.
     Mutation-checked: a silent frame that drops one pad is falsified.
   - `formal/dcnet/dcnet_no_collusion.spthy`: with every member honest, no pad
     of the round is derivable.
   - `formal/dcnet/dcnet_collusion.spthy`: with one member colluding, decoding is
     exact, the honest pair's key stays secret, and the honest pair's **pad is
     derivable** (`collusion_reveals_pad`), which is why pad secrecy is not the
     anonymity claim.
   - `formal/dcnet/dcnet_collusion_4.spthy`: the boundary. One colluder in a
     4-member cell (three honest): no honest-honest pad or key is derivable
     (`pads_secret_with_three_honest`, `keys_secret_with_three_honest`). Two
     colluders (two honest): the pad is derivable (`pad_derived_with_two_honest`).
     Modelled from the colluders' view (their own pads already stripped, which they
     can do themselves): one colluder among four is then exactly an honest 3-member
     cell. Mutation-checked: leaking a third honest member's key falsifies the first.
   - `formal/dcnet/dcnet_one_time_pads.spthy`: a book's pad is used once
     (`pad_used_once`), and an adversary that learns any pads it likes as they are
     used knows a round's pad only if that very use leaked it
     (`pad_known_only_if_leaked`). Mutation-checked: a book a pad can be taken from
     twice, or a use that publishes its pad, is falsified.
   - `formal/dcnet/dcnet_ratchet.spthy`: a network chain is forward-secure, unrolled to
     three rounds with a device seized at most once: a round's pad is known only if the
     device was seized in that round or an earlier one (`forward_secure_round1`,
     `forward_secure_round2`). An unbounded chain did not terminate. Mutation-checked: a
     seized device that also gives up its seed is falsified.
   - In these models `h(<k, r>)` stands for the pair's pad of round r: secret,
     distinct per round, known only to the pair, as a book's pad or a chain's is.

   **Not machine-checked: sender anonymity itself.** It is an equivalence
   property; Tamarin's `--diff` mode with XOR did not terminate, even on the
   two-party core, and ProVerif and DeepSec do not support XOR. Its proof is
   the one below. The first model (pre-15 Nov) had never been run: it did not
   parse, its lemmas quantified over state facts, and its sender-anonymity
   lemma rested on "identification requires learning a pad", which the
   collusion model shows is false.

   **Hand proof of sender anonymity.** A cell has members M and round pads
   `p_ij(r)`, one per pair. Member i sends `c_i = m_i ⊕ (⊕_{j≠i} p_ij)`, where `m_i`
   is the event for the sender and zero otherwise. The adversary controls a set C of
   colluding members (it knows their pads), sees every frame and the decoded event m,
   and H = M \ C are the honest members, |H| ≥ 2. Let I be the honest pairs joined by
   an in-person book, and suppose the graph (H, I) is connected.
   1. Honest-honest pads from information-theoretic books are already (within 2⁻⁶⁴ per
      block) independent uniform strings: each is the XOR of two contributions, at least
      one of them extracted from an assessed raw source and handed over in person, so
      secret and uniform, never on a network. Pads from network chains are
      computationally indistinguishable from uniform (ML-KEM-768 + X25519 and
      SHA-256). For the information-theoretic statement, give the adversary those
      outright, as if the pair colluded on that edge.
   2. For honest i, the adversary can remove the pads i shares with
      colluders: `c'_i = c_i ⊕ (⊕_{j∈C} p_ij) = m_i ⊕ (⊕_{j∈H, j≠i} p_ij)`.
      The colluders' own frames are functions of their keys. So the view is
      `(c'_i)_{i∈H}`, m, and values independent of the honest-honest pads.
   3. Remove the known edges (network chains, given away) as well: what is left is
      the connected graph (H, I) with uniform, unknown edge values. Over GF(2), the
      map from a connected graph's edge values to its vertex sums has rank |H| − 1,
      onto the vectors whose XOR is zero. So `(c'_i)`, with the known edges stripped,
      is uniform over `{x : ⊕_{i∈H} x_i = m}` whichever honest member sent.
   4. So the views for any two honest senders are identical: information-theoretic
      sender anonymity among H when (H, I) is connected. With every edge counted
      (in-person books and chains), the same holds computationally when the full
      honest graph is connected, which it always is. ∎

   Limits: |H| = 1 (everyone else colludes) identifies the sender trivially; if the
   in-person edges split H into parts, the information-theoretic statement holds
   within the sender's part; the proof covers one round's frames, not jamming (§5)
   or network metadata, which the constant-rate links carry.
9. **Pad handling** — `src/dcnet.rs` tests and `tools/test_padbook.py`: a pad is
   handed out once and wiped, skipped rounds are burned, a refused round consumes
   nothing, a used-up book stops the cell; at rest, no pad is on disk in the clear,
   used records are zeroed after the chain moves, a restored old state opens no used
   round, and only the Nitrokey's secret opens a book.

Statistical/empirical harness (`mix_lane_test_harness.py`, section F,
currently 5/5 passing):

- F.1 XOR-cancellation recovers the message; idle round decodes null.
- F.2 decodes for every sender position (24/24).
- F.3 stale round transmission fails to decode (round-binding).
- F.4 jam corrupts the round and is detectable (abort policy).

**Rust reference implementation: `src/dcnet.rs`** — round core, frame
codec, pad books and chains, group aggregation, with an inline test module whose
golden vectors are generated by the byte-exact Python mirror
(`tools/dcnet_reference.py`, writes `docs/evidence/DCNET_VECTORS.json`; 9/9
self-checks passing). Cross-language vector equality is proven on the Python side and
asserted by the Rust tests against the embedded hex vectors.

Live tests to add when the Rust lands in the binary: round-participation
uniformity under idle vs event-carrying epochs (KS, same machinery as
mix-lane test A), and epoch churn coverage (every member sees every
cellmate over K epochs with high probability — coupon-collector bound,
state the K).

## 7. Implementation order

1. Config flag: route CHAIN_SETUP_COMMIT and MIX_LANE_FALLBACK over the
   existing mix lane (days; immediately useful).
2. ~~Rust module `src/dcnet.rs`~~ **authored** — drop in `src/dcnet.rs`,
   wire cell assignment from directory and gossip round-sync at the
   integration layer (`avpn mesh`).
3. ~~Harness section F ported to Rust integration tests; Tamarin model~~
   **authored** — inline `#[cfg(test)]` module in `src/dcnet.rs` (14 tests,
   golden-vector based) + `dcnet.spthy`. Remaining: run `cargo test` and
   `tamarin-prover --prove` in CI (extend `.github/workflows/verify.yml`).
4. ~~Opt-in true-random pad mode~~ **done, and the only kind of pad**: in-person
   one-time books (Nitrokey XOR an assessed raw jitter source) and network chains
   (`tools/padbook.py`). Remaining: the integration layer's book and chain store,
   re-keying on churn, and (hardened, later) a Nitrokey firmware applet that
   computes each round's body, so pads never reach the laptop's CPU.

## 8. Resulting Limits-section wording (proposed)

> The DC-net control channel provides sender unlinkability for a fixed set
> of control events within a cell of concurrently online members, under the
> assumption that at least one pairwise pad per event is uncompromised. Pads come
> only from hardware. Among members joined by one-time pads made with an assessed
> raw noise source and handed over in person, the guarantee is information-theoretic;
> over Nitrokey-only books or pads seeded across the network, it is computational
> (the chains forward-secure). The channel is intentionally narrow: it does
> not carry bulk traffic, it is disabled in single-operator mode, and it
> accepts denial-of-service rather than adopting any accountability
> mechanism that could identify a sender.
