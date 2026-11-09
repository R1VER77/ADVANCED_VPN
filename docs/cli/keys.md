# Keys

- Every device generates its own keys (`avpn request`). The operator only signs public keys.
- **Protection at rest:**
  - Nitrokey FIDO2 hmac-secret envelopes;
  - systemd-creds sealed to host+TPM2 when the TPM is usable;
  - plaintext, lab only.
- **Operator:** a hybrid signature, a Nitrokey FIDO2 Ed25519 assertion plus an ML-DSA-65 key sealed in the vault. Both halves are required.
- **Hand-off:** private keys reach the data plane through sealed, immutable memfds, never through files.
- **No backups:** a lost device is replaced by new keys and a new chain.
