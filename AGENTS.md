# Project workflow

Owner instruction, 17 November 2026:

- Validate changes and cryptographically verify commit signatures.
- Automatically push signed commits to GitHub and integrate them into `main` without
  asking for another confirmation. This is standing authorization.
- Preserve existing signed commits. Prefer a fast-forward when possible; otherwise
  follow the repository's merge protections and required checks.
- Do not force-push or rewrite signed history. Verify the published branch head and
  report the resulting checks and any genuine blockers.

Roadmap completion means the stated acceptance gate passed. Keep implementation,
simulation, physical validation and independent review distinct in evidence and claims.

## Cryptographic & cypherpunk standard

Owner instruction, 26 November 2026:

- Operate at cypherpunk-maximalist rigor within the project's goals. Do not settle for
  baseline standardized RFCs when they leave classical or single-algorithm gaps; go beyond
  the state of the art using peer-reviewed cryptographic constructions and apply them.
- Post-quantum standards are early-stage and individual algebraic families may break.
  Whenever practical, combine independent cryptographic families (for example, SafeCurves
  `X25519` + `X448` + lattice `ML-KEM-1024` with a dual-hash `SHA-512 ⊕ SHA3-512` KDF
  combiner, and lattice `ML-DSA-87`/`ML-DSA-65` + stateless hash-based FIPS 205
  `SLH-DSA` + SafeCurves `Ed25519` signatures) so breaking any single assumption does not
  undo protection.
- Single-digit to tens-of-milliseconds handshake/control-plane latency is an acceptable
  trade-off to achieve multi-family post-quantum defense-in-depth, while keeping
  steady-state data-plane latency overhead at zero.
- Never introduce new NIST P-256 dependencies. Use SafeCurves (`Ed25519`, `X25519`,
  `X448`) strictly as classical legs inside hybrids, never standalone where PQ is
  required. Fail closed on any missing or invalid pinned PQ leg (zero silent downgrade).
- Preserve strict technical honesty: distinguish peer-reviewed implemented properties and
  their explicit non-collusion assumptions from unproven claims.
