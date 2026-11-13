# Design pack assessment (November 2026)

Four packs proposed integrations: the DC-net and mix-lane design pack, the `parity_pack`,
`pq_sphinx_pack` and its production port `mix_lane_pack` (with `CUTOVER_KATZENPOST.md`).
Each item was judged by one question: does it measurably strengthen the posture, and can
we prove it? This page records the verdicts, what was checked, and what the checks found.

## Verdicts

| Item | Verdict | Where it landed |
|---|---|---|
| PQ-Sphinx option E (entry ML-KEM-768 + inner X25519, 1,396-byte header at 3 hops) | **Research, not shipped** (decided 13 Nov) | `crates/avpn-mix-lane`, `crates/avpn-pq-sphinx`, `advanced-vpn-mixnode --experimental` stay as tested research. Its inner hops are classical X25519, so it cannot carry the full post-quantum claim; it is never on by default and is excluded from that claim |
| Post-quantum mix lane (Katzenpost) | **Adopted, and the lane we keep** | `avpn mix` requires X-Wing Sphinx, X-Wing links and hybrid (Ed25519 + SPHINCS+) directory signatures, and refuses anything classical. Its fetch service is our PQ-only plugin (`tools/kp_pq_fetch.py`). Its cost in speed and bandwidth is being measured against the anonymity it buys (a parameter sweep on the live lab), before any setting changes |
| AntiTracker (filter formats, allowlist, CNAME cloaking) | **Adopted** | the exit's DNS forwarder (`src/bin/advanced-vpn-dns.rs`), signed `--dns-allowlist` |
| Kill-switch drift audit | **Adopted** | the supervisor's `TableWatch` restores any deleted or altered kill-switch table |
| DC-net control channel | **Library + model, not wired** | `src/dcnet.rs`, `tools/dcnet_reference.py`, `formal/dcnet/` |
| RAM-only attestation in descriptors | Roadmap | needs TPM2 / SEV-SNP quote verification |
| MASQUE CONNECT-UDP front | Roadmap | needs a real HTTP/3 MASQUE stack |
| Split tunnelling | Declined | it lowers protection by design; `avpn run` already tunnels per application, fail-secure |
| `obfs_stream` bucket ladder | Declined | the TCP fallback already sends one fixed 1,420-byte cell size, which leaks less than a ladder of sizes |
| Multi-platform rule generators | Declined | Linux only for now |

## What was checked, and what it found

**Option E crates.**
- Both build and pass on our pinned rustc 1.95: 57 tests (reference) and 40 (production).
- The reference regenerates the shipped full-cell vectors byte for byte.
- The primitive vectors were regenerated from independent Python implementations (kyber-py 1.2.0, blake3, cryptography 50) and both crates pass against the fresh set. The X25519 records differ on every run, by design: random keys.
- Disabling R3 (payload re-masking) or R4 (dead-prefix re-randomisation) fails the linkability tests.
- Clippy (`-D warnings`) required small fixes: a typed KEM error replaced `Result<_, ()>`, plus test-only lint allowances. All of this runs in CI.

**A gap in option E, resolved.**
- Option E seals a forward cell's payload under a key derived from every hop's secret, so only its sender can open it. Nothing in the design or the crates lets a third party, such as a fetch service, read a request.
- The daemon resolves it the Mixminion way, with no change to the reviewed protocol. The service publishes a pool of single-use reply blocks to its own mailboxes, and a client sends its request through one, carrying its own reply block for the answer.
- Everyone downloads the whole pool, so the service cannot tell who used which block. The mixes' replay caches enforce single use.

**DC-net.**
- The pack's Rust had never been compiled. It compiled and matched the Python reference byte for byte, but one golden-vector test indexed the wrong pairwise key (`K_12` for `K_23`). The test is fixed, the construction was correct, and 14 tests pass.
- A mutation of the pad's round binding fails two golden tests.
- 27 undocumented public items were documented (the library denies missing docs).

**AntiTracker.**
- In the full managed lab, a name that resolves through a CNAME into a blocked domain gets `NXDOMAIN`, and an allowlisted name under the blocked domain resolves.
- With the CNAME check removed, the lab fails on exactly that name.

**Kill-switch watchdog.**
- When another process deletes the app namespace's kill-switch table, the supervisor restores it in 0.6 s. A rogue `accept` rule is removed in 2.1 s.
- With the watchdog disabled, the lab fails.

## Not post-quantum yet (stated plainly)

The full inventory, with the code that enforces each layer and the test that proves it, is
`docs/PQ_INVENTORY.md`. Its exceptions:

- **Mesh contribution credits** are Chaum blind RSA (`tools/mesh_tokens.py`). Their unlinkability survives a quantum adversary; their unforgeability does not. No reviewed post-quantum blind signature exists yet (`docs/VERIFICATION_PLAN.md` §5).
- **The I2P front's routing** is I2P's own classical cryptography; what it carries is post-quantum.
- **Option E's inner hops** are X25519 by design, which is why option E stays research. Katzenpost with X-Wing is post-quantum at every hop, at about five times the header size; recovering that cost by tuning is being measured, not yet claimed.

## The mix lane stays opt-in

Everything goes through the fast lane by default. The mix lane runs only after an explicit
`avpn mix start`, as Mullvad's DAITA is a choice. Seconds of latency, and cover traffic that
costs bandwidth even when idle, are a trade users accept only when they choose it.
