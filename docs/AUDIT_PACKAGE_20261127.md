# External Cryptographic & Systems Audit Package — `cypherpunk_vpn` (`v0.11.1`, 27 November 2026)

This document is a self-contained handoff dossier for an **independent third-party cryptographic and systems auditor**. It maps every security claim to its exact source implementation, formal verification model, mutant test, and known honest boundary.

## 1. Reproducible Offline Verification

Run the complete local verification suite with zero external network dependencies:

```bash
bash tools/audit_verify.sh
```

What `tools/audit_verify.sh` verifies:
1. Rust formatting (`cargo fmt --check`), zero-warning lint (`cargo clippy --locked --offline ... -D warnings`), and all library, DNS forwarder, and CLI tests (`cargo test --locked --offline`).
2. Python formatting and lint (`ruff format --check`, `ruff check tools`).
3. Unit and integration suites covering shared-access admission, multi-family PQ combiners, wire-clock controls, I2P PQ adoption, server egress NTS/quota, managed profiles, split signing VM, hardware carrier ECDH, STARK nullifier ledger, and onion-only shielded checkout (`tools/test_*.py` + `research/shared-access/test_*.py`).
4. Symbolic formal proofs and mandatory mutant falsification under Tamarin 1.12.0 / Maude 3.5.1 (`tools/tamarin_check.py`).
5. Live Linux kernel namespace leak-direction proofs (`tools/tor_lab.py` for `D021` Tor-over-tunnel and `research/shared-access/gotatun_shared_lab.py` for two-hop GotaTun DAITA shared admission).

---

## 2. Cryptographic Architecture & Audit Surface Map

| Surface | Implementation | Formal Proof / Harness | Key Security Property & Combiner |
|---|---|---|---|
| **Inner/Outer QUIC Tunnels** | `src/tls.rs` | `tests/crypto_tests.rs`, `formal/session/session_auth.spthy` | TLS 1.3 `X25519MLKEM768` only + `ML-DSA-65` mutual cert auth; no 0-RTT or resumption |
| **Cloak Camouflage (HTTP/3 & TCP/TLS)** | `src/cloak.rs` | `formal/cloak/cloak.spthy`, `cloak::tests::*` | Role-separated exporter HMAC (`cloak/v2`), fail-closed UDP→TCP refusal when `WireClock` active, bidirectional constant-rate decoy cells on opt-in clocked TCP |
| **Server-to-Server Paced Links (v2)** | `src/link.rs` | `formal/link/link.spthy`, `link::forward_secrecy_tests::*` | Ephemeral `X25519 + ML-KEM-1024` every 120 s + dual-PRF `HKDF-SHA-512 ⊕ HKDF-SHA3-512` over `SHA-512 \|\| SHA3-512` transcript (v1 `ML-KEM-768` responder kept for compat) |
| **Shared-Access Admission Handshake** | `tools/shared_session.py`, `tools/shared_pq.py` | `formal/shared/shared_pq_handshake.spthy` (3 lemmas + 3 mutants) | Triple-KEX (`X25519 + X448 + ML-KEM-1024`) + dual-PRF `HKDF-SHA-512 ⊕ HKDF-SHA3-512` + pinned 3-family server auth (`ML-DSA-87 ∧ SLH-DSA-SHA2-128f ∧ Ed25519`) over dual `SHA-512 \|\| SHA3-512`, `Ed25519` TLS 1.3 (`OP_NO_TICKET`), zero NIST P-256, `49,152`-byte padded frames |
| **Shared-Access Composite Credits** | `tools/shared_admission.py`, `tools/shared_pq.py`, `tools/shared_wallet.py`, `research/shared-access/checkout_service.py` | `formal/shared/shared_pq_credits.spthy` (3 lemmas + 2 mutants) | RFC 9578 blind-RSA (unconditional blindness) + RFC 9576 split-authority `PqEpochStamper` (`ML-DSA-87 ∧ SLH-DSA-SHA2-128f ∧ Ed25519`) + atomic SQLite replay ledger + shuffled constant-size Nitrokey-sealed wallet (`320 KiB` stamped / `8 KiB` legacy) |
| **Enrollment & PSK Sealing** | `tools/keyguard.py` | `formal/kem_seal/kem_seal.spthy`, `formal/enrollment/enrollment.spthy` | `schema=1` (`X25519 + ML-KEM-768`) + `schema=2` (`X25519 + X448 + ML-KEM-1024 + dual HKDF-SHA-512 ⊕ HKDF-SHA3-512`), FIDO2 + `ML-DSA-65` dual operator signatures |
| **Exit DNS-over-TLS Forwarder** | `src/bin/cypherpunk-vpn-dns.rs`, `tools/managed_profile.py` | `cypherpunk-vpn-dns` tests | Enforces `X25519MLKEM768` on every upstream; supports per-query randomized multi-upstream DoT pools (`upstreams`) and optional local recursive Unbound (`--dns-recursive`) |
| **v1.0 STARK Forward-Private Credits** | `tools/zk_credits.py`, `tools/zkid.py`, `research/zk-membership/` | `formal/zk/forward_private_nullifiers.spthy` | Hash-based forward-private nullifiers `H^k(s0)` + Merkle membership + action binding (scaffold pending reproducible RISC Zero `image_id` & Sybil gate) |
| **Split Signing VM & Hardware Carrier** | `tools/signing_vm.py`, `tools/hw_carrier.py`, `deploy/qubes/` | `test_roadmap_scaffolds.py` | Qubes `qrexec` / KVM `AF_UNIX` session-signer boundary + OpenPGP v3.4 / SLIP-0017 / TKey carrier X25519 ECDH + `ML-KEM-1024` hybrid PSK |

---

## 3. Explicit Scope Boundaries & Open Exceptions

1. **Public shared access stays disabled (`shared_access_enabled = False`)** and **public checkout sales stay disabled** until independent external review, 3-distinct-day GCP qualification, and independent third-party operators are established.
2. **Hardware FIDO2 boundary:** `tools/keyguard.py` uses CTAP `hmac-secret` via `python-fido2` (CTAP PIN/UV protocols use P-256 ECDH locally between host and authenticator; tracked transparently in [PQ_INVENTORY.md](PQ_INVENTORY.md)).
3. **Split-authority non-collusion assumption:** Composite PQ credits preserve RFC 9578 unlinkability provided the Checkout Attester and `PqEpochStamper` are operated independently and do not collude (resolved structurally once v1.0 STARK credits ship).
4. **Desktop GUI transitive crate:** Dependabot Alert `#1` (`glib = 0.18.5`, `GHSA-wrw7-89jp-8q8g`) is confined to `apps/cypherpunk-vpn/src-tauri/Cargo.lock` via `tauri = 2.12.6` / Linux `gtk = 0.18`; `glib::VariantStrIter` is unreachable from `cypherpunk-vpn-gui`.
5. **Internal vs. Independent review:** [SECURITY_PEER_REVIEW_20261127.md](SECURITY_PEER_REVIEW_20261127.md) is an internal AI-assisted technical review and does **not** substitute for third-party external audit sign-off.
