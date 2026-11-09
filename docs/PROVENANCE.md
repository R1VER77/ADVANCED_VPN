# Implementation and upstream components

Original application/controller files are Apache-2.0. No VP.NET implementation was copied or translated; prior inspection means this is not a clean-room representation or a legal-clearance claim.

GotaTun 0.10.2 is used unmodified through its public API for WireGuard and actual DAITA integration. It is MPL-2.0; the license and exact source revision are in `third_party/`. Maybenot 2.2.2 and maybenot-machines 1.0.1 provide public research defense machines under MIT/Apache-2.0. Dependency licenses remain applicable to those components; our license does not replace theirs.

The Maybenot paper describes its lineage as an evolution of Tor's Circuit Padding Framework. Mullvad and Karlstad University developed DAITA around Maybenot and integrated it into their VPN stack. This project reuses the published framework/implementation and public machines, not a claimed copy of Mullvad's private current production machine set.

Patterns adopted from the research include network-namespace isolation, persistent fail-closed routing, separated management/data planes, resource limits, minimal local logging, hardware-authorized encrypted key storage, explicit negative tests, and measured packet-level behavior. No Mullvad/IVPN/Quincy audit or affiliation transfers to this project. No IVPN, Quincy or Tor application source is bundled.

## Primary references

- [Maybenot paper and Tor lineage](https://arxiv.org/abs/2304.09510)
- [Mullvad DAITA overview](https://mullvad.net/en/blog/introducing-defense-against-ai-guided-traffic-analysis-daita)
- [GotaTun source](https://github.com/mullvad/gotatun)
- [Maybenot and public machines](https://github.com/maybenot-io/maybenot)
- [Public DAITA research/profile discussion](https://pulls.name/blog/2025-03-27-daita-v1-and-v2-defenses/)
- [WireGuard protocol and optional PSK](https://www.wireguard.com/protocol/)
- [WireGuard network namespaces](https://www.wireguard.com/netns/)
- [IVPN gateway audit approach](https://www.ivpn.net/blog/ivpn-infrastructure-audit-concluded/)
- [Quincy](https://github.com/quincy-rs/quincy)
- [rustls hybrid key exchange](https://docs.rs/rustls/0.23.46/rustls/crypto/aws_lc_rs/kx_group/static.X25519MLKEM768.html)

The exact Quinn version remains pinned: negotiated-KEX diagnostics use its upstream-internal `__rustls-post-quantum-test` feature. A single-entry provider group list independently enforces hybrid negotiation. An upgrade requires source/API review and the actual classical-only rejection tests.

Post-quantum authentication uses the ML-DSA-65 signing and verification that ship in the pinned rustls 0.23.46 / aws-lc-rs (`PqdsaKeyPair`, `webpki::aws_lc_rs::ML_DSA_65`) and in cryptography 49 for certificate and bundle generation. The verification table is narrowed at runtime to the single ML-DSA-65 mapping; no signature primitive is implemented here. References: [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [ML-DSA in TLS 1.3 (draft-ietf-tls-mldsa)](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/). ML-DSA certificates are about 5.4 KB, so the mutual handshake is larger and can take an extra round trip under QUIC's anti-amplification limit.
