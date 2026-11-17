# Post-quantum inventory

Every asymmetric primitive in ADVANCED_VPN, the layer it protects, and what makes the
post-quantum property hold. "Enforced" means a classical peer is refused, never accepted as
a fallback, and a test fails if the refusal is removed (mutation-checked). Checked
16 November 2026.

## The claim

**Every layer ADVANCED_VPN encrypts, authenticates or terminates uses hybrid post-quantum
key exchange (ML-KEM-768 with X25519) and refuses a classical key exchange rather than
falling back. Authentication is a separate property:** post-quantum on the inner tunnels
(ML-DSA-65 certificates) and on the cloak (protocol v2: both ends prove the enrolled
symmetric key with a role-separated HMAC over the hybrid exporter; the ECDSA certificate is
a facade), but classical on the exit's DNS upstream (WebPKI). Enrolment bundles carry both
an Ed25519 and an ML-DSA-65 signature. The four exceptions below are named, with what each
one exposes. The claim never says "post-quantum throughout" while one of them stands, and
the cloak v2 composition is this project's own, tested but not independently reviewed.

## Layers

| Layer | Key exchange | Authentication | Enforced by | Test (fails without it) |
|---|---|---|---|---|
| Inner and outer tunnels (QUIC, one per server) | X25519MLKEM768 only | ML-DSA-65 certificates and CertificateVerify only | `src/tls.rs` `provider`, `authenticated` | `crypto_tests.rs`: a classical client or ECDSA deployment is refused |
| WireGuard carrier (GotaTun) | X25519 Noise IK, plus a 256-bit PSK sealed to each device by hybrid KEM | WireGuard keys + the PSK | `tools/keyguard.py` `kem_seal` (X25519 + ML-KEM-768) | a supplement: both QUIC layers inside carry the PQ claim on their own |
| Links between servers | an ephemeral X25519 + ML-KEM-768 exchange inside the cells every 120 s (forward secret: ephemerals erased); AES-256-GCM | the link PSK (sealed by `kem_seal`) authenticates the exchange | `src/link.rs` (`Initiator`, `respond`, `session_keys`); packets only under exchanged keys | `a_recorded_link_reveals_no_packet_to_a_later_stolen_psk`, `a_packet_under_a_psk_only_key_is_never_forwarded` |
| Cloak front (HTTP/3 and TCP/TLS camouflage) | browser-like offer; **a tunnel only over X25519MLKEM768** | protocol v2: both ends prove the member's 32-byte cloak key with a role-separated HMAC over the TLS exporter before any tunnel data or "connected" state (post-quantum: the exporter comes from the hybrid exchange, the proof is symmetric); the pinned ECDSA certificate is kept only as the camouflage's facade. v1 authenticated the server by that certificate alone | `src/cloak.rs` `role_proof`, `confirm_server`, `quic_hybrid`, `tls_hybrid`; schema-1 chains refused at connect (`CLOAK_V2_REQUIRED`) | `a_classical_key_exchange_never_becomes_a_tunnel`, `audit_v2_proofs_are_role_key_and_exporter_separated`, `audit_tcp_requires_one_well_formed_server_confirmation` |
| Exit DNS upstream (DNS over TLS) | X25519MLKEM768 only; DNS fails closed otherwise | classical WebPKI (exception 4) | `advanced-vpn-dns` `upstream_tls` | `the_upstream_must_offer_hybrid_post_quantum_tls`; live: Cloudflare and Google answer, Quad9 does not |
| Oblivious control plane | HPKE ML-KEM-768 + X25519 (`0x647A`) | gateway key | `tools/ohttp.py` | `test_ohttp.py` |
| Enrollment and signed bundles | hybrid KEM sealing | Ed25519 (FIDO2) **and** ML-DSA-65, both required | `tools/managed_profile.py` | `test_managed.py` |
| Mix lane: Sphinx packets | X-Wing (ML-KEM-768 + X25519) per hop | | `tools/mix.py` `check_config` | `test_mix.py` (classical Sphinx refused) |
| Mix lane: links | X-Wing PQ Noise | X-Wing | `check_config` (`WireKEMScheme`) | `test_mix.py` |
| Mix lane: directory | | Ed25519 + SPHINCS+ (hybrid, hash-based) | `check_config` (`PKISignatureScheme`) | `test_mix.py`; the live lab runs the shipping check on its network |
| Mix lane: fetches to websites | TLS 1.3 with X25519MLKEM768 only; other sites refused (525 / 526) | WebPKI | `tools/kp_pq_fetch.py` (OpenSSL policy) | `test_kp_pq_fetch.py` |

## Which failures may wait

A broken classical primitive fails in one of two ways. A **silent** failure gives an
adversary something without anyone noticing: a recording decrypted later, a sender
linked. Those must be post-quantum today, because harvest-now-decrypt-later cannot be
undone; every row above protects such data with a hybrid key exchange. (Authentication is
different: forging a signature needs a quantum computer at the time of the connection,
not later, so a classical signature is an active-attack exposure, named below.) A **loud** failure costs money or availability
and shows itself: forged credits make more spends than were issued. Those may stay
classical for now if they are contained: detected, bounded in time, and revocable. The
credits below are the one loud exception; exceptions 2 and 3 are outside this project's code, and 4 is a
classical authentication that only an active, quantum-capable attacker could exploit.

## Exceptions (stated wherever the claim is made)

1. **Mesh contribution credits** (`tools/mesh_tokens.py`): Chaum blind RSA. Blindness is
   information-theoretic, so a quantum adversary still cannot link a spend to its issuance.
   *Unforgeability* is not post-quantum: one who can factor the mesh key can mint credits,
   which buys relay capacity, not decryption or deanonymisation. No reviewed post-quantum
   blind signature exists yet: lattice constructions are academic, at about 20 KB and 100 ms
   per token, with no IETF draft and no audited implementation (checked November 2026). The
   credits move to one when it does (`docs/VERIFICATION_PLAN.md` §5).
   Meanwhile a forgery is contained rather than silent. Each daily epoch has its own issuer
   key, and a credit is spendable only under the current or previous epoch's key (the key
   decides, so a stale credit cannot be relabelled), so a broken key mints for two days at
   most. And a ledger compares the redemptions under each epoch key with the count its
   issuer published: more spent than issued revokes that key for good (`Ledger.redeem_live`,
   `Ledger.audit_supply`; `test_forged_credits_trip_the_inflation_alarm_and_the_key_is_revoked`).
   The alarm is as complete as the redemptions a ledger sees: across relays it needs the
   mesh's gossiped spent set.
   The replacement is designed and measured: anonymous membership credits proved as a
   STARK (hash-based, post-quantum), which need no blinding and no RSA
   (`docs/ZK_MEMBERSHIP_DESIGN.md`; a relay verifies a spend in 23 ms). Planned for v1.0.
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
4. **The exit's DNS upstream authentication.** Its key exchange is hybrid and enforced, so a
   recorded DNS session cannot be decrypted later. But the resolver is authenticated by
   classical WebPKI certificates: an attacker who can forge their signatures at the time,
   which needs a quantum computer then, could impersonate the resolver and answer falsely.
   Closing it needs a post-quantum-authenticated resolver or gateway, not yet built.

## Not in the product

- **Option E** (`crates/avpn-mix-lane`, `advanced-vpn-mixnode`): unshipped research. Its inner
  hops are X25519 by design, so it is excluded from the claim and never enabled by default.
- Release and commit signing (FIDO2 Ed25519-SK) protect the supply chain, not traffic.
