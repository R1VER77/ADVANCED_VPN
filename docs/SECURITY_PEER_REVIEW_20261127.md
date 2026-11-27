# Scoped Technical Security Review — Shaping, Control Boundaries & Multi-Family PQ (27 November 2026)

> **Scope & Honesty Notice:** This is an **internal AI-assisted technical peer review**
> performed against the repository tree on 27 November 2026 (`v0.11.1`, post-`81c6ed7`).
> Per [ROADMAP.md](ROADMAP.md) §4 ("Self-review and CI are not independent review"), this
> document strengthens pre-audit readiness and closes concrete defects found in code
> inspection, but does **not** claim third-party external audit independence or authorize
> enabling public shared access or promoting opt-in wire-clock defaults prior to live
> multi-environment replication.

---

## 1. Traffic-Analysis Resistance & Preemptive Wire-Clock Hardening (`src/cloak.rs`)

### Findings from Code Inspection & 20 November Frozen Replication ([WF_REPLICATION.md](WF_REPLICATION.md))
The 20 November 720-attempt replication reduced k-FP accuracy from **100%** (undefended) to
near the **5%** chance floor (**3.8%** `relay30` both-directions, **8.3%** `relay5`), with
all Holm-adjusted p-values `>= 0.18`. However, the strict local acceptance gate failed on
three checks:
1. **Upstream residual signal** (`relay30` upstream **8.3% [5.0, 12.1]** vs downstream **5.8%** and both **3.8%**).
2. **Load-success & latency penalty** (−6.3 to −7.1 pt lower bound, +1.4–1.9 s median load time).
3. **Relay slot skips at 5 ms look-ahead** (`0.572%` skipped on `relay5` vs `0.00145%` on `relay30`).

### Root Causes Identified & Patched Preemptively
| ID | Severity | Finding in `src/cloak.rs` | Remediation Applied |
|---|---|---|---|
| **WF-1** | **High** | `PacedSocket::try_send` only applied `SO_TXTIME` to packets `>= OUTER_MTU` (1,420 B). Standalone QUIC ACK-only packets (`< OUTER_MTU`, triggered every 64 incoming packets by `ack_eliciting_threshold(64)`) bypassed `SO_TXTIME` and left immediately on Quinn's arrival-driven timing—directly exposing upstream bursts during heavy downstream page loads. | In `clocked_transport()`, raised `ack_eliciting_threshold` to `256` (so ACKs piggyback inside the 4,000 pps constant-rate datagrams) and shortened `max_ack_delay` to `25 ms` (4× faster loss recovery). In `PacedSocket::try_send()`, aligned any rare `< OUTER_MTU` control/ACK packet during an active clocked session to the grid's next `SO_TXTIME` slot (`slots.get(&dest).front()`). |
| **WF-2** | **Medium** | `session()` drained `held.take()` via direct `c.send_datagram()` calls before handing the connection to the feeder, causing unpaced (`unslotted`) bursts on session start/reconnect. | Passed `clock_queue` into `session()`: when the wire clock is active, held datagrams enqueue into the bounded feeder queue and leave strictly on `SO_TXTIME` slots. |
| **WF-3** | **Medium** | Both client and relay feeder queues were capped at `1.0 s` (`packets_per_second` slots = 4,000 packets on `fast`) with only `WIRE_CLOCK_HEADROOM = 1.02` (80 spare slots/s). Under busy loads, stale packets queued up to 1 s behind head-of-line bursts, causing TCP/QUIC timeouts and +1.4–1.9 s page-load latency. | Tightened feeder queue cap to `150 ms` (`wire_clock_queue_cap`, 600 slots on `fast`, floor 64) and raised `WIRE_CLOCK_HEADROOM` to `1.05` (200 spare slots/s, configurable `1.01–1.25` via `CPVPN_WIRE_CLOCK_HEADROOM`), draining bursts **2.5× faster** with zero loss of constant-rate wire flatness (unused slots carry identical full-size decoys). |
| **WF-4** | **Medium** | Client `feed()` and relay `tick` slept a fixed `2 ms` (`tokio::time::sleep`), which with a `5 ms` look-ahead (`relay5`) allowed minor scheduler jitter to overrun the horizon and skip `0.572%` of slots. | Replaced fixed `sleep(2 ms)` with drift-free `tokio::time::interval((lookahead / 4).clamp(500 us, 2 ms))` (`MissedTickBehavior::Skip`), waking every `1.25 ms` on `relay5`. |

### Residual WF Risk (Requires Live Measurement)
- `WF-1` through `WF-4` are unit-tested and structurally sound, but **only a fresh counterbalanced multi-day, multi-network, multi-device replication** can confirm whether 95% upper bounds drop below `10%` and page-load non-inferiority clears `>= -5` pts. Wire-clock controls stay opt-in (`promotes_default: false`).
- GCP mix-lane trials: Day 1 (`us-central1`, 6/6 pass) and Day 2 (`europe-west3`, 5/6 pass; `baseline.arrivals=55 < 60` despite `100%` baseline accuracy) pooled **2.66%–4.94%** across 790 events (all 95% upper bounds `<= 6.37% < 10%`), but still require a clean 6/6 `europe-west3` rerun and Day 3 (`asia-southeast1`) plus non-GCP operators.

---

## 2. Multi-Family Post-Quantum Compositions (`tools/shared_pq.py`, `tools/shared_session.py`, `tools/zk_credits.py`, `tools/i2p.py`)

### Cryptographic Combiner Assessment
| Surface | Combined Primitives | Combiner / Verification Rule | Security Property & Explicit Caveat |
|---|---|---|---|
| **Shared Admission KEX** (`tools/shared_session.py`) | `X25519` + `X448` + `ML-KEM-1024` inside `Ed25519` TLS 1.3 (`OP_NO_TICKET`) | `HKDF-SHA-512(ikm, salt_sha2, info) XOR HKDF-SHA3-512(ikm, salt_sha3, info)` (`dual_hkdf_expand`) | **Sound.** Standard XOR-of-independent-PRFs combiner (Giacon–Heuer–Poettering): confidentiality & PFP hold as long as *any one* of `{X25519, X448, ML-KEM-1024, TLS-KEX}` and *either* `SHA-2` or `SHA-3` remain secure. Full transcript salted into both KDFs; `ikm` zeroized in `finally:`. Zero NIST P-256. |
| **Shared Admission Server Auth** (`tools/shared_session.py`, `tools/shared_pq.py`) | `ML-DSA-87` (FIPS 204) + `SLH-DSA-SHA2-128f` (FIPS 205) + `Ed25519` | Conjunction (AND): every pinned leg verified over `SERVER_CONFIRM_DOMAIN \|\| SHA3-512(transcript)` **before** credit submission | **Sound.** Defeats live quantum TLS MITM even if classical ECC AND Module-LWE lattices break simultaneously (hash-based `SLH-DSA` survives). Zero silent downgrade: if `slhdsa_raw` is pinned and OpenSSL 3.5 `libcrypto` is missing, verification fails closed. |
| **Shared Composite Access Credits** (`tools/shared_pq.py`, `tools/shared_admission.py`, `tools/shared_pool.py`) | `RFC 9578 RSA-2048-PSS` + `ML-DSA-87` + `SLH-DSA-SHA2-128f` + `Ed25519` | RFC 9576 split-authority `PqEpochStamper` verifies both unblinded RSA token and Checkout Attester's multi-family PQ ticket before stamping; relays verify all pinned families | **Sound under non-collusion.** Closes classical RSA-2048 credit forgery against a CRQC while preserving RFC 9578 mathematical blinding. **Explicit caveat:** if Checkout Attester and PQ Epoch Stamper *collude*, the one-time ticket ID correlates checkout to stamping. Must be independently operated until v1.0 STARK credits replace blind-RSA entirely. |
| **v1.0 STARK Credit Bridge** (`tools/zk_credits.py`, `tools/zkid.py`) | SHA-256 Merkle tree + forward-private hash chain `H^k(s0)` + RISC Zero STARK receipt (+ optional `HybridPqPublic` transition stamp) | Exact byte-for-byte guest relation (`guest/src/main.rs`), fixed verifier-chosen `scope`, `action_hash(request)`, atomic SQLite `NullifierLedger` | **Sound.** Removes all algebraic assumptions (hash-based PQ unforgeability + forward-private nullifiers). **Open before production:** reproducible guest `image_id` build, live RISC Zero receipt verifier binding, and Sybil resistance at tree registration. |
| **I2P Front** (`tools/i2p.py`) | `i2pd >= 2.58` LeaseSet type `6` (`ML-KEM-768 + X25519`), `i2pd >= 2.59` `ntcp2 version = 4` | Version-gated auto-adoption with `require_pq=True` fail-closed enforcement | **Sound within upstream I2P limits.** Protects NTCP2 links and end-to-end LeaseSet encryption with hybrid ML-KEM; I2P tunnel-build records remain classical upstream (tracked in [PQ_INVENTORY.md](PQ_INVENTORY.md) Exception 2). |

---

## 3. Enrollment, Hardware-Bound Sessions & Control-Plane Boundaries

### Reviewed Surfaces
- **Short-lived signer (`tools/session_signer.py`) & Split Signing VM (`tools/signing_vm.py`, `deploy/qubes/`):**
  - Preserves exact `{"state", "lanes", "carry"}` JSON contract with strict regex VM-name checks, `262,144`-byte reply ceiling, non-shell `argv` execution, lane-set equality, and `0 < not_after - not_before <= MAX_SECONDS` enforcement.
  - **Limitation:** Qubes `qrexec` protects long-term identities against root compromise inside `sys-vpn`, but does not protect active per-session keys or decrypted traffic inside the VPN VM; on standard desktops without a hypervisor boundary, host root remains inside the trust boundary.
- **Hardware-resident carrier keys (`tools/hw_carrier.py`):**
  - Clean `CarrierKeyProvider` abstraction for OpenPGP v3.4 `PSO:DECIPHER` (`00 2A 80 86`, Nitrokey 3/YubiKey 5/CanoKey/Ledger), Trezor SLIP-0017, and Tillitis TKey device apps, combined with ephemeral `ML-KEM-1024` via `dual_hkdf_expand` (`HKDF-SHA-512 ⊕ HKDF-SHA3-512`) and `bytearray` zeroization.
  - **Open:** Physical smartcard/Trezor/TKey live integration and wiring into userspace GotaTun Noise handshakes (kernel WireGuard requires raw key bytes).
- **Inside-tunnel IPv6 (`tools/ipv6_tunnel.py`):**
  - Strictly enforces global `2000::/3` `/64` exit prefixes, refuses v4-only exits, 6in4/6to4/NAT64, and per-family split-tunneling, preserves 1,380 B fixed cells (`MTU 1280–1340`), and emits per-family symmetric `nftables` guards confining AAAA DNS to loopback DoT.
  - **Open:** Rust data-plane IPv6 payload forwarding inside `src/` and live dual-stack exit qualification before switching the default fail-closed IPv4-only posture.

---

## 4. Review Verdict
- **No critical vulnerabilities** remain unmitigated in the reviewed shared-access, wire-clock, IPv6-scaffold, STARK-bridge, or signing-VM code paths; all 4 concrete wire-clock WF defects identified during inspection (`WF-1`–`WF-4`) are patched and unit-tested.
- **Deployment gates remain fail-closed as designed:** public shared access (`SharedAccessDisabled`), public checkout sales, opt-in wire clock (`promotes_default: false`), and opt-in inside-tunnel IPv6 stay disabled by default pending live multi-day/multi-network measurements and external third-party audit.
