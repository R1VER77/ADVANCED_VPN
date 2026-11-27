# Shared access (pilot)

Shared access lets a client reach a signed entry/exit pool with blind,
one-use Privacy Pass credits instead of persistent device credentials.
Public shared access is **disabled by default** pending protocol review.

## Commands

    cypherpunk shared status
        Show shared-access state, Nitrokey-sealed usable and next-epoch credits,
        required upstream visibility, classical token disclosure, and identity
        leakage limits.

    cypherpunk shared import --pool MANIFEST --pinned-key KEY --batch FILE [--vault PATH]
        Verify a signed pool directory and a fixed-size batch of 4 entry/exit
        credit pairs (8 RFC 9578 tokens), discard any issuance metadata, and
        seal the batch locally with your Nitrokey (PIN + touch). Imported
        credits activate in the next UTC epoch.

    cypherpunk shared connect
        Refused while public shared access is disabled pending protocol review.
        When enabled for an operator-reviewed pilot, requires an active
        configured upstream interface and fails closed if it drops.

    cypherpunk shared disconnect
        Remove active shared peers on exit and entry and preserve the kill
        switch.

## Privacy disclosures

- **Multi-family post-quantum defense-in-depth**: Shared admission channels
  combine SafeCurves `X25519` + `X448` + `ML-KEM-1024` via a dual-hash
  `HKDF-SHA-512 ⊕ HKDF-SHA3-512` combiner over `Ed25519` TLS 1.3 (`OP_NO_TICKET`),
  with mandatory multi-family PQ server confirmation (`ML-DSA-87` + `Ed25519` +
  FIPS 205 hash-based `SLH-DSA-SHA2-128f` when OpenSSL 3.5 is present).
- **Composite access credits**: RFC 9578 RSA-PSS provides unconditionally
  quantum-safe blinding unlinkability; when paired with an independent RFC 9576
  PQ Epoch Stamper (`ML-DSA-87` + `SLH-DSA-SHA2-128f` + `Ed25519`), credit
  unforgeability resists both classical and quantum breaks of any single family
  (requiring non-collusion between the Checkout Attester and PQ Epoch Stamper).
- **Upstream visibility**: The configured upstream operator sees your source
  address. If the upstream drops, admission and VPN traffic stay blocked.
- **Application identity**: Websites and apps can still link sessions through
  logins, cookies, and browser fingerprints even when VPN credits are fresh.
