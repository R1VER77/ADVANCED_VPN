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

Public defense machines have not undergone a project-specific traffic-analysis
classifier evaluation. Review README.md, docs/DEPLOYMENT.md and the current
docs/MANAGED_VALIDATION.md before use. The old docs/VALIDATION.md records v0.1.

Do not publish private keys, credential handles, recovery identities, provider
tokens, production packet captures or raw operational logs in issues. Use GitHub
private vulnerability reporting if enabled; otherwise contact the repository
owner privately. No external security audit is claimed.
