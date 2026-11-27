# cypherpunk security-level

Detect connected FIDO2/Nitrokey hardware keys, TPM2, and VM isolation (Qubes `qrexec` or KVM),
and display or select one of three seamless protection tiers—modeled on Tor Browser's
Standard / Safer / Safest security levels.

## Usage

    cypherpunk security-level
    sudo cypherpunk security-level --select standard|safer|safest

## Options

- `--select standard|safer|safest`: persist the chosen protection tier in `preferences.json`. Fails closed if `safer` or `safest` is selected without a detected supported hardware key (or without VM isolation for `safest`).

## Security Tiers

1. **Standard (`standard`) — Hardwareless Vault-VM:** Zero hardware dongle required. Seals long-term identities and shared-access credits inside a passphrase-protected `scrypt` + `AES-256-GCM` isolated software vault (`vault-vm`), unsealed only inside short-lived undumpable `session_signer` or a Qubes/KVM signing VM.
2. **Safer (`safer`) — Hardware-Bound Sessions:** Requires a detected Nitrokey 3 or FIDO2 `hmac-secret` key for physical PIN + touch authorization.
3. **Safest (`safest`) — Split Vault-VM + Hardware Token + Strict Hardening:** Requires both a detected hardware key and VM isolation (`qrexec`, KVM, or `CPVPN_SIGNING_VM`), combining hardware-backed vault isolation with strict NTS and ephemeral browser profiles.

## Example

    cypherpunk security-level
    sudo cypherpunk security-level --select standard
