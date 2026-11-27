# Post-quantum inventory

Every asymmetric primitive in cypherpunk_vpn, the layer it protects, and what makes the
post-quantum property hold. "Enforced" means a classical peer is refused, never accepted as
a fallback, and a test fails if the refusal is removed (mutation-checked). Checked
16 November 2026, with a hardware-boundary correction on 18 November.

The later full-stack hybrid-PQ/SafeCurves mandate is a target, not a qualification
of the current hardware path. `tools/keyguard.py` uses CTAP `hmac-secret` through
python-fido2. PIN/UV protocols 1/2 in the pinned library use P-256 ECDH, as specified
by [CTAP 2.3](https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html).
An Ed25519 credential does not replace this separate key agreement. Hardware-backed
sealing therefore retains a classical local-channel/custody assumption; recording
that exchange needs explicit future-decryption analysis. The table below concerns
network traffic and enrollment layers and does not qualify this hardware boundary.
Generic vault creation also offers python-fido2's supported credential algorithms;
it does not currently require Ed25519. Record the actual stored COSE algorithm per
credential instead of inferring it from the vendor or FIDO2 label. ES256 credentials
use P-256 and need their own compatibility transition under the new policy.
Keep current credentials intact while designing a versioned compatible transition;
the existing physical setup results do not establish an all-interface PQ claim.

## The claim

**Every layer cypherpunk_vpn encrypts, authenticates or terminates uses hybrid post-quantum
key exchange (ML-KEM-768 with X25519) and refuses a classical key exchange rather than
falling back. Authentication is a separate property:** post-quantum on the inner tunnels
(ML-DSA-65 certificates) and on the cloak (protocol v2: both ends prove the enrolled
symmetric key with a role-separated HMAC over the hybrid exporter; the ECDSA certificate is
a facade), but classical on the exit's DNS upstream (WebPKI). Enrolment bundles carry both
an Ed25519 and an ML-DSA-65 signature. The seven exceptions below are named, with what each
one exposes. The claim never says "post-quantum throughout" while one of them stands, and
the cloak v2 composition is this project's own, tested but not independently reviewed.

## Layers

| Layer | Key exchange | Authentication | Enforced by | Test (fails without it) |
|---|---|---|---|---|
| Inner and outer tunnels (QUIC, one per server) | X25519MLKEM768 only | ML-DSA-65 certificates and CertificateVerify only | `src/tls.rs` `provider`, `authenticated` | `crypto_tests.rs`: a classical client or ECDSA deployment is refused |
| WireGuard carrier (GotaTun) | X25519 Noise IK, plus a 256-bit PSK sealed to each device by hybrid KEM | WireGuard keys + the PSK | `tools/keyguard.py` `kem_seal` (X25519 + ML-KEM-768) | a supplement: both QUIC layers inside carry the PQ claim on their own |
| Links between servers | v2 (default): ephemeral X25519 + **ML-KEM-1024** inside the cells every 120 s (forward secret: ephemerals erased) combined with dual-PRF `HKDF-SHA-512 XOR HKDF-SHA3-512`; AES-256-GCM (v1 ML-KEM-768 responder retained for backward compatibility) | the link PSK (sealed by `kem_seal`) authenticates the exchange | `src/link.rs` (`InitiatorV2`, `respond_v2`, `session_keys_v2`, `dual_hkdf_expand_32`); packets only under exchanged keys | `a_recorded_link_reveals_no_packet_to_a_later_stolen_psk`, `a_packet_under_a_psk_only_key_is_never_forwarded`, `link_v2_mlkem1024_dual_hkdf_agrees_binds_transcript_and_keeps_v1_compat` |
| Shared-access pilot admission (`tools/shared_session.py`, `tools/shared_pq.py`) | **Triple-KEX**: ephemeral X25519 + X448 + ML-KEM-1024 combined with dual-PRF `HKDF-SHA-512 XOR HKDF-SHA3-512` inside TLS 1.3 (`Ed25519` certs, `OP_NO_TICKET`, zero NIST P-256) | Pinned multi-family server handshake confirmation (`ML-DSA-87 + SLH-DSA-SHA2-128f + Ed25519`) verified before credit transmission; optional split-authority `PqEpochStamper` adds `ML-DSA-87 + SLH-DSA-SHA2-128f + Ed25519` composite stamp over RFC 9578 RSA blind credits | `tools/shared_pq.py`, `tools/shared_session.py`, `tools/shared_wallet.py`; formally verified in `formal/shared/shared_pq_handshake.spthy` & `formal/shared/shared_pq_credits.spthy` | `test_shared_session.py`, `tools/tamarin_check.py formal/shared/shared_pq_handshake.spthy formal/shared/shared_pq_credits.spthy` (6 lemmas + 5 falsified mutants) |
| Cloak front (HTTP/3 and TCP/TLS camouflage) | browser-like offer; **a tunnel only over X25519MLKEM768** | protocol v2: both ends prove the member's 32-byte cloak key with a role-separated HMAC over the TLS exporter before any tunnel data or "connected" state (post-quantum: the exporter comes from the hybrid exchange, the proof is symmetric); the pinned ECDSA certificate is kept only as the camouflage's facade. v1 authenticated the server by that certificate alone | `src/cloak.rs` `role_proof`, `confirm_server`, `quic_hybrid`, `tls_hybrid`; schema-1 chains refused at connect (`CLOAK_V2_REQUIRED`) | `a_classical_key_exchange_never_becomes_a_tunnel`, `audit_v2_proofs_are_role_key_and_exporter_separated`, `audit_tcp_requires_one_well_formed_server_confirmation` |
| Exit DNS, recursive mode (`--dns-recursive`, opt-in) | none: plain DNS from the exit to authoritative servers (exception 5) | DNSSEC, classical | `tools/exit_resolver.py` (Unbound), `cypherpunk-vpn-dns` loopback-only | `test_exit_resolver.py`, `a_recursive_exit_never_sends_plain_dns_off_the_host`; live: 20/20 names, dnssec-failed.org refused |
| Exit DNS upstream (DNS over TLS) | X25519MLKEM768 only on every configured upstream (optional multi-upstream randomized distribution via `upstreams`); DNS fails closed otherwise | classical WebPKI (exception 4) | `cypherpunk-vpn-dns` `upstream_tls`, `Resolver::ask` | `the_upstream_must_offer_hybrid_post_quantum_tls`, `multi_upstream_distributes_queries_and_refuses_classical_peers`; live: Cloudflare and Google answer, Quad9 does not |
| Oblivious control plane | HPKE ML-KEM-768 + X25519 (`0x647A`) | gateway key | `tools/ohttp.py` | `test_ohttp.py` |
| Hardware-bound sessions ([design](HARDWARE_BOUND_SESSIONS.md)) | — | the client's ML-DSA-65 identity **and** its FIDO2 key's statement (ES256 or EdDSA, classical), both required by every hop that pins the key | `tools/session_auth.py`, `src/session_auth.rs` | `test_session_auth.py`, `session_auth` Rust tests, `formal/session`; the hardware half is classical, so it adds protection against copied keys, not against a quantum forger, who still needs the ML-DSA-65 key |
| Enrollment and signed bundles | hybrid KEM sealing | the enrolled FIDO2 credential's COSE signature **and** ML-DSA-65, both required; generic enrollment does not enforce Ed25519 | `tools/managed_profile.py`, `tools/keyguard.py` | `test_managed.py`; hardware/channel caveat above |
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
   building stays classical upstream. `tools/i2p.py` and `tools/cypherpunkctl.py` automatically
   detect the installed `i2pd` version and enable `i2cp.leaseSetEncType = 6,4` on 2.58+ and
   `ntcp2.version = 4` on 2.59+ (`require_pq=True` fails closed on older routers).
3. **Fast-lane traffic past the exit.** The exit forwards your own connections; their TLS to
   the website is your browser's choice, as with any VPN. (The mix lane is different: its
   fetch service terminates TLS itself, so it enforces post-quantum TLS.)
4. **The exit's DNS upstream authentication.** Its key exchange is hybrid and enforced, so a
   recorded DNS session cannot be decrypted later. But the resolver is authenticated by
   classical WebPKI certificates: an attacker who can forge their signatures at the time,
   which needs a quantum computer then, could impersonate the resolver and answer falsely.
   Closing it needs a post-quantum-authenticated resolver or gateway, not yet built.
5. **The exit's own recursive resolver** (`cypherpunk init --dns-recursive`, opt-in). Instead of one
   public resolver that sees every name, the exit's Unbound asks the authoritative servers
   itself, with DNSSEC validation and QNAME minimisation. Those queries are plain DNS, neither
   encrypted nor post-quantum, because no authoritative DNS offers either; they leave from the
   exit's address, as the member's traffic does. A recorded exit uplink therefore shows the
   names, as it shows the destinations of the traffic itself; DNSSEC, classical, protects the
   answers. The chain itself is unchanged, and the default stays the hybrid DoT forwarder.
6. **Private-group contribution credits** (`tools/mesh_voprf.py`; added by the 22 November
   membership-and-credit review). RFC 9497 VOPRF on ristretto255: classical
   unforgeability - Shor recovers the group's epoch key from its published public key and
   lets a quantum adversary mint credits. As in exception 1, unlinkability survives: the
   client blinds with a uniformly random scalar, which in a prime-order group is
   perfectly hiding, so not even the key holder can match a redemption to its issuance.
   (The review first said a quantum adversary links them; corrected on landing.) Forgery
   is contained by the epoch keys and the ledger; the HMAC scheme this replaced let the
   issuer link every redemption, with no quantum computer. Labeled in the module (`QUANTUM_STATUS`, pinned by
   `test_mesh_fail_closed.py`); the Rust data plane stays fail-closed for it (exception 1's
   gate covers private groups too). The STARK membership credits are the post-quantum
   replacement for both pools.
7. **The voucher engine's blind RSA** (`tools/voucher.py`, REVENUE_ARCHITECTURE Model 1;
   named here by the same review, which consolidated the label that lived only in the
   module's docstring and COMPARISON note 8). Same primitive and same split as exception 1:
   blindness is information-theoretic (unlinkability survives), unforgeability is classical
   (a forger mints vouchers, buying rate class, not decryption). Contained the same way -
   monthly epoch keys bound the window, and the double-spend ledger plus supply audit make
   forgery loud. It follows exception 1 to the lattice or STARK replacement.

## Not in the product

- **Option E** (`crates/cpvpn-mix-lane`, `cypherpunk-vpn-mixnode`): unshipped research. Its inner
  hops are X25519 by design, so it is excluded from the claim and never enabled by default.
- Release and commit signing (FIDO2 Ed25519-SK) protect the supply chain, not traffic.
