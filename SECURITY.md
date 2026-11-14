# Security scope

This experimental release protects the inner transport from a cloud relay that
does not possess inner credentials. It does not promise anonymity, no provider
logging, availability against an adversarial relay, endpoint security against
root, or confidentiality after traffic leaves the trusted owned exit.

Managed transport uses unmodified GotaTun WireGuard/DAITA outside the two
rustls/AWS-LC/QUIC layers; no new cryptographic primitive is invented. Hybrid
post-quantum key exchange is mandatory in both QUIC layers, while WireGuard
uses its standard protocol with an additional PSK. Certificate and enrollment
signatures are ML-DSA-65 only (FIPS 204); enrollment bundles require both an
Ed25519 and an ML-DSA-65 signature. No hardware attestation is implemented.

The privileged local controller owns networking. Network-facing children run
under a dedicated non-root service identity with no capabilities, and receive
private keys through immutable memory descriptors. Endpoint root/host memory
inspection remains outside this boundary. Hardware sealing protects keys at
rest. Private keys are generated on the device that uses them and never
transferred; see the key-exposure table in README.md.

The traffic-analysis defenses are measured against published website-fingerprinting
attacks (k-FP, Deep Fingerprinting, Tik-Tok) on real websites and in labs; the results,
including where a rate class still leaks, are in docs/evidence/ (WF_REAL_PILOT.json,
DAITA_LAB.json, MIX_LANE.json); README.md summarises the 30-site lab. These are this project's
own measurements, not an independent evaluation. Review README.md, docs/DEPLOYMENT.md
and the current docs/MANAGED_VALIDATION.md before use. The old docs/VALIDATION.md
records v0.1.

Do not publish private keys, credential handles, recovery identities, provider
tokens, production packet captures or raw operational logs in issues.

## Reporting a vulnerability

Report privately through GitHub: the repository's Security tab, "Report a
vulnerability". Please don't open a public issue for anything that could weaken
users' privacy before a fix ships. Fixes are disclosed in the release notes of the
release that carries them, with what was affected and what was not (for example the
kill-switch race note in v0.10.1). No external security audit is claimed.
