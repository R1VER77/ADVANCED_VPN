# Named techniques

ADVANCED_VPN combines known primitives in ways we have not seen documented together. This file
gives each one a name, says what it does, what it builds on, and where the code and evidence
are. "Novel" here means *as a combination, for this purpose*: each entry lists its prior art,
and none claims a new cryptographic primitive.

Status words: **shipped** (in the build and CI), **experimental** (in the code, off by
default), **library** (code and tests, not reachable from a command yet), **designed** (not
built).

---

## 1. Wire Clock — *experimental*

**What:** the client's outer packets leave on a fixed grid of slots, timed by the kernel, not
by a userspace thread. A feeder runs a short look-ahead (30 ms) ahead of the grid and puts one
full-size datagram in every slot: the next WireGuard datagram, or a decoy the first hop drops
silently. Each packet carries its departure time (`SO_TXTIME`), and the `fq` qdisc releases it
then. Slots survive failed sends; a short stall is caught up within the look-ahead.

**Why:** with today's constant-rate padding in userspace, a busy CPU delays the sender
thread, and the gaps it leaves fingerprint what the browser is doing (k-FP 81% in the pilot,
34% in the re-run). Moving departure timing into the kernel takes the CPU out of the timing.

**Prior art:** constant-rate defences (BuFLO, Tamaraw), DAITA/Maybenot, `SO_TXTIME` pacing.
New here: kernel-paced slot filling as the fix for a CPU-contention side channel.

**Evidence:** real websites, k-FP 34.4% → 9.5% (chance 5%); the residual is the unclocked
downstream. `src/cloak.rs` (`WireClock`, `PacedSocket`), `docs/evidence/WF_REAL_RERUN.json`,
`docs/evidence/KERNEL_PACING.json`.

## 2. Clock-Coupled Window — *experimental*

**What:** when the wire clock runs, *both* ends of the QUIC carrier use a fixed congestion
window; the rate is set by the signed class, as on WireGuard over UDP.

**Why (the finding):** the handshake is unpaced, so quinn's minimum RTT is the link's
(~90 µs), while every later acknowledgement waits up to the look-ahead (~27 ms). BBR sizes its
window from bandwidth × minimum RTT, so the relay's window collapsed to ~11 packets and never
recovered: 96% of the downstream lost, 1 page load in 8. Any sender that delays ACKs by design
breaks a min-RTT congestion controller this way.

**Evidence:** 1/8 loads with BBR, 8/8 fixed, same lab on mains. `server_config_clocked` in
`src/cloak.rs`, test `a_clocked_chains_server_never_shrinks_its_window`,
`docs/evidence/KERNEL_PACING.json` (`downstream_collapse`).

## 3. Busy-CPU Leak Probe — *shipped (lab tool)*

**What:** load the client's cores on a random, balanced on/off schedule while the tunnel idles,
and score how well each window's wire packet count, gap spread and largest gap predict the
schedule (AUC, permutation p-value, shuffled-label control, Bonferroni across features).

**Why:** a count-only test passes a defence that restores packet counts but not timing; this
catches both, and it turns "the CPU leaks" into a regression test.

**Code:** `tools/throughput_bench.py --cpu-probe`, `docs/evidence/CPU_LEAK_PROBE.json`.

## 4. Two-Contribution Pad Books with edge claims — *library*

**What:** each DC-net pair's one-time pad book is the XOR of two contributions, one per
member. A book is **information-theoretic only if at least one contribution both carries an
assessed raw noise source and was handed over in person**; otherwise it is labelled
computational. The claim is computed per edge, sealed with the contribution, and shown by
`padbook.py status`.

**Why:** a pad is secret if either half is, so no single member's device or delivery has to be
trusted; and the label can never say more than the provenance supports.

**Code:** `tools/padbook.py` (`edge_claim`), `src/dcnet.rs` (`PadBook`).

## 5. Draw-Before-Measure mixing — *library*

**What:** a contribution is `kernel ⊕ Nitrokey ⊕ Extract(raw jitter)`, with the kernel and
Nitrokey bytes drawn **before** the raw noise is recorded.

**Why:** XOR with a stream never weakens a pad only if that stream is independent of it. The
kernel's pool is fed by interrupts, which also perturb the jitter measurement; drawn first, its
output depends only on the past, and the noise it is mixed with happens afterwards.

**Prior art:** entropy-pool mixing (Fortuna, Linux RNG). New here: ordering as the
independence argument for an information-theoretic XOR.

**Code:** `contribution_bytes` in `tools/padbook.py`, with an order test.

## 6. Assessed Raw Jitter with a Toeplitz extractor — *library*

**What:** raw CPU-timing deltas from jitterentropy's recorder (low 8 bits), assessed per
machine with NIST SP 800-90B `ea_non_iid` (minimum of three runs, half counted), health-tested
continuously (SP 800-90B RCT/APT with cutoffs from that estimate), and Toeplitz-extracted to
within 2⁻⁶⁴ of uniform per block.

**Why:** a security key's RNG is not raw noise (the Nitrokey 3's is ChaCha8 seeded per boot,
read from its firmware source), and closed tokens cannot be checked at all. This gives a
measured, open, provable source on any laptop.

**Evidence:** this laptop: 6.64 and 7.16 bits/sample. `tools/padbook.py` (`assess`,
`extract`).

## 7. Source-Traced Randomness — *practice*

**What:** a randomness claim is accepted only after tracing the bytes to their generator in
source code, not from vendor descriptions or statistical tests (which cannot tell a good DRBG
from noise). Applied to the Nitrokey 3 (firmware v1.8.3 and v1.9.1: `rng` → Trussed
`random_bytes` → ChaCha8), and recorded with versions.

**Where:** `docs/DCNET_CONTROL_DESIGN.md` §2.

## 8. Forward-Erasing Pad Store — *library*

**What:** every round's pad is its own record under a per-round key from a one-way chain. Taking
a round saves the advanced chain state first, then zeroes the used records; the state is
wrapped by a key derived from the Nitrokey's hmac-secret. Rounds follow the clock, so a past
round is refused even if an old state is restored.

**Why:** a disk seized with the Nitrokey and its PIN still opens no used round, crash order
never leaves a pad readable twice, and backups cannot replay pads.

**Code:** `Book.take` in `tools/padbook.py`, tests in `tools/test_padbook.py`.

## 9. Opaque Envelopes — *library*

**What:** a sealed contribution is `Elligator2(dirty X25519 ephemeral) ‖ ML-KEM-768
ciphertext ‖ nonce ‖ AES-GCM(padded header + data)`. Dirty keys (plus a random order-8 point)
make representatives uniform; padding to 30-day buckets hides the book's length. At rest, book
files are a random salt then a ChaCha20-Poly1305 over AES-256-GCM cascade.

**Why:** a lost USB stick or seized disk must not reveal who pairs with whom.

**Prior art:** Elligator (obfs4), Monocypher's dirty keys, TrueCrypt's headerless volumes. New
here: the combination with a hybrid post-quantum KEM. Residual: ML-KEM ciphertext is
near-uniform, not exactly.

**Code:** `tools/elligator.py` (RFC 9380 vectors), `seal_opaque` in `tools/padbook.py`.

## 10. Mixed-mode DC-net cells — *library*

**What:** within one cell, pairs who met use one-time books and pairs who cannot use a
forward-secure SHA-256 chain. The anonymity claim is information-theoretic among the honest
members connected by information-theoretic edges, computational across the rest — the standard
GF(2) rank argument, restricted to the edges whose pads stay unknown.

**Evidence:** Tamarin models `formal/dcnet/dcnet_one_time_pads.spthy`, `dcnet_ratchet.spthy`,
`dcnet_collusion_4.spthy`, each with mutants; hand proof in `docs/DCNET_CONTROL_DESIGN.md` §6.

## 11. Process memory hygiene for key tools — *library*

**What:** key material in mutable buffers zeroed in place on use, at exit and on terminating
signals; the process non-dumpable (`PR_SET_DUMPABLE=0`), memory locked, no core dumps. After
Tails' RAM wipe and VeraCrypt's RAM key protection, scoped to one process, with the CPython
limit stated (immutable copies cannot be wiped; the Rust data plane `zeroize`s).

**Code:** `Secret`, `harden()` in `tools/padbook.py`.

---

## Designed, not built

- **Downstream Wire Clock:** clock the relay's sends too, to remove the residual 9–10%.
- **Layered deniable pad store:** Shufflecake-style interleaved layers, one Nitrokey credential
  each (`docs/DCNET_CONTROL_DESIGN.md`).
- **Token-side XOR:** a Nitrokey firmware applet that holds a book's key chain and returns each
  round's body, so pads never reach the host CPU.
