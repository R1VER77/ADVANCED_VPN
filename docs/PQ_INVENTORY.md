# Post-quantum inventory

Every asymmetric primitive in ADVANCED_VPN, the layer it protects, and what makes the
post-quantum property hold. "Enforced" means a classical peer is refused, never accepted as
a fallback, and a test fails if the refusal is removed (mutation-checked). Checked
13 November 2026.

## The claim

**Every layer ADVANCED_VPN encrypts, authenticates or terminates uses hybrid post-quantum
key exchange (ML-KEM-768 with X25519) and post-quantum or hybrid signatures, and refuses a
classical peer rather than falling back.** The three exceptions below are named, with what
each one exposes. The claim never says "post-quantum throughout" while one of them stands.

## Layers

| Layer | Key exchange | Authentication | Enforced by | Test (fails without it) |
|---|---|---|---|---|
| Inner and outer tunnels (QUIC, one per server) | X25519MLKEM768 only | ML-DSA-65 certificates and CertificateVerify only | `src/tls.rs` `provider`, `authenticated` | `crypto_tests.rs`: a classical client or ECDSA deployment is refused |
| WireGuard carrier (GotaTun) | X25519 Noise IK, plus a 256-bit PSK sealed to each device by hybrid KEM | WireGuard keys + the PSK | `tools/keyguard.py` `kem_seal` (X25519 + ML-KEM-768) | a supplement: both QUIC layers inside carry the PQ claim on their own |
| Links between servers | AES-256-GCM under a link PSK | the PSK | PSK sealed by `kem_seal` | `link.rs` tests |
| Cloak front (HTTP/3 and TCP/TLS camouflage) | browser-like offer; **a tunnel only over X25519MLKEM768** | pinned server key; HMAC proof bound to the TLS exporter | `src/cloak.rs` `quic_hybrid`, `tls_hybrid` (server and client) | `a_classical_key_exchange_never_becomes_a_tunnel` |
| Exit DNS upstream (DNS over TLS) | X25519MLKEM768 only; DNS fails closed otherwise | WebPKI | `advanced-vpn-dns` `upstream_tls` | `the_upstream_must_offer_hybrid_post_quantum_tls`; live: Cloudflare and Google answer, Quad9 does not |
| Oblivious control plane | HPKE ML-KEM-768 + X25519 (`0x647A`) | gateway key | `tools/ohttp.py` | `test_ohttp.py` |
| Enrollment and signed bundles | hybrid KEM sealing | Ed25519 (FIDO2) **and** ML-DSA-65, both required | `tools/managed_profile.py` | `test_managed.py` |
| Mix lane: Sphinx packets | X-Wing (ML-KEM-768 + X25519) per hop | | `tools/mix.py` `check_config` | `test_mix.py` (classical Sphinx refused) |
| Mix lane: links | X-Wing PQ Noise | X-Wing | `check_config` (`WireKEMScheme`) | `test_mix.py` |
| Mix lane: directory | | Ed25519 + SPHINCS+ (hybrid, hash-based) | `check_config` (`PKISignatureScheme`) | `test_mix.py`; the live lab runs the shipping check on its network |
| Mix lane: fetches to websites | TLS 1.3 with X25519MLKEM768 only; other sites refused (525 / 526) | WebPKI | `tools/kp_pq_fetch.py` (OpenSSL policy) | `test_kp_pq_fetch.py` |

## Exceptions (stated wherever the claim is made)

1. **Mesh contribution credits** (`tools/mesh_tokens.py`): Chaum blind RSA. Blindness is
   information-theoretic, so a quantum adversary still cannot link a spend to its issuance.
   *Unforgeability* is not post-quantum: one who can factor the mesh key can mint credits,
   which buys relay capacity, not decryption or deanonymisation. No reviewed post-quantum
   blind signature exists yet: lattice constructions are academic, at about 20 KB and 100 ms
   per token, with no IETF draft and no audited implementation (checked November 2026). The
   credits move to one when it does (`docs/VERIFICATION_PLAN.md` §5).
2. **The I2P front's routing.** I2P builds tunnels and links routers with X25519 and
   Ed25519. What the front carries is post-quantum twice over (the cloak's enforced hybrid
   TLS, then the tunnel), but its hiding of *which client reached the entry* rests on I2P's
   classical cryptography. i2pd 2.58 added hybrid ML-KEM end-to-end sessions and 2.59 hybrid
   NTCP2 links (`i2cp.leaseSetEncType = 6`, `ntcp2.version = 4`, OpenSSL 3.5+); tunnel
   building stays classical upstream. Roadmap: adopt both settings once the pinned i2pd is
   2.59 or later.
3. **Fast-lane traffic past the exit.** The exit forwards your own connections; their TLS to
   the website is your browser's choice, as with any VPN. (The mix lane is different: its
   fetch service terminates TLS itself, so it enforces post-quantum TLS.)

## Not in the product

- **Option E** (`crates/avpn-mix-lane`, `advanced-vpn-mixnode`): unshipped research. Its inner
  hops are X25519 by design, so it is excluded from the claim and never enabled by default.
- Release and commit signing (FIDO2 Ed25519-SK) protect the supply chain, not traffic.
