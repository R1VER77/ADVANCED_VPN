> Historical v0.1 evidence. The managed v0.2 release is described in [MANAGED_VALIDATION.md](MANAGED_VALIDATION.md); its added dependencies have a separate audit.

# Local validation — 2026-11-07

This document describes observed prototype behavior, not a production certification.

## Real network path

The release executable ran in separate unprivileged user/mount/network namespaces on the Debian laptop. The client consumed a TUN descriptor from an application namespace with no external interface. Two independently authenticated hybrid-PQ QUIC layers connected it through an opaque relay to an owned-exit namespace, then to a controlled destination using actual Linux masquerade/NAT.

Final routed lab evidence: [NAMESPACE.json](evidence/NAMESPACE.json).

| Measurement | Observed result |
|---|---|
| Established tunnel ICMP RTT, 100 samples | p50 1.035 ms; p95 1.80 ms; p99 2.48 ms |
| TCP stream | 1,048,576 bytes in 0.305 seconds; SHA256 verified |
| RSS snapshot after transfer | client 6,240 KiB; relay 6,100 KiB; exit 6,144 KiB |
| Relay-side ciphertext capture | 1,231,275 bytes; private test marker absent |
| Destination | received and returned the private test marker |
| Inner MTU | 1280; fitting packet accepted and one-byte excess rejected |

These results were obtained on one machine with a synthetic network topology while other compilation work was running. They are neither Frankfurt WAN measurements nor latency/throughput/peak-memory guarantees. The release SHA256 is in the evidence; source-prefix-remapped reproducibility builds have a different, separately recorded binary hash.

The following passed in the routed lab: authenticated traffic, NAT forwarding, exact peer pinning, unlisted and untrusted client rejection, expired-identity rejection, wrong inner-server pin rejection, pin revocation, duplicate ciphertext replay rejection, ciphertext tampering rejection, fail-closed behavior on relay loss and packet drops, and reconnect after relay restart.

An early recovery fixture intermittently failed after rapid rejection tests. The implementation now explicitly closes rejected connections and gives close frames a bounded drain interval before reconnecting. The lab waits for server readiness and separates the rejection fixture from authorized recovery. The final routed, NAT and stream test passes; a long-duration WAN soak is still required.

## Cryptography and key handling

Four Rust tests pass, including genuine TLS handshakes that reject classical-only key exchange and anonymous clients. Eleven Python tests cover the compiled CLI's private-file/permission guards, schema rejection, role separation, pinned MTU/rate profile, sealed descriptor reuse, unsealed descriptor rejection, AEAD envelope tampering/binding, wrong hardware secret and memfd immutability. Formatting and Clippy with warnings denied pass.

The transport's only configured key-exchange group is X25519MLKEM768, and its only application suite is AES-256-GCM. Handshake evidence is checked before IP forwarding. Mutual ECDSA certificates and exact leaf pins authenticate peers; this does not constitute post-quantum certificate authentication.

A real Nitrokey enrolled the separate `advanced-vpn.local` FIDO2 credential. It sealed the two client test keys, the age recovery copy was decrypted and compared, and plaintext key files were removed. A fresh hardware operation unsealed the keys into immutable memfds; the release executable accepted them through `--check`. This is a separate hardware handoff proof, **not** a claim that the full routed test used hardware-unsealed keys. See [HARDWARE.json](evidence/HARDWARE.json).

The hardware envelope protects software keys at rest. It does not keep leaf/session keys non-exportable while running, and does not protect an ordinary cloud guest from its host. Existing token credentials and PIN were preserved. Offline CA private keys were not deployed to a peer or published; automated hardware CA issuance is not implemented.

## Build and operational checks

- Cargo.lock and the Rust toolchain are pinned; Python hardware dependencies are hash locked.
- RustSec reported zero known vulnerabilities and no warnings at this check: [RUSTSEC.json](evidence/RUSTSEC.json). This does not establish absence of vulnerabilities.
- Service templates pass `systemd-analyze verify` when their executable paths are staged to the built binary. They were not installed or runtime-sandbox tested.
- Two fresh builds from different source/output directories produced identical binaries: [REPRODUCIBILITY.json](evidence/REPRODUCIBILITY.json). Their source and lockfiles match this release; same-host equality is not cross-platform reproducibility.
- No existing VPN, host routing, DNS, cloud service or cloud billing configuration was changed.

## Required before operational deployment

Independent review; tested privileged bootstrap and service sandboxes on the actual OS; DNS and management-route isolation; sustained overload and packet-loss tests; WAN MTU validation; certificate issuance/rotation/revocation automation; device/recovery cold-start drills; and a real owned exit. TEE attestation, DAITA-style padding, anonymous access tokens, multi-user multiplexing, IPv6 forwarding and a desktop UI are not included.
