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

- **Classical token unforgeability**: RFC 9578 RSA-PSS tokens have classical
  unforgeability; unlinkability holds against a quantum observer.
- **Upstream visibility**: The configured upstream operator sees your source
  address. If the upstream drops, admission and VPN traffic stay blocked.
- **Application identity**: Websites and apps can still link sessions through
  logins, cookies, and browser fingerprints even when VPN credits are fresh.
