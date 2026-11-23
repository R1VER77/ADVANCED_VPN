# cypherpunk unlock-key

Operator only. Create the operator's unlock key, once. A server whose keys cannot be
sealed to a TPM2 locks them to this key instead (protection `operator`, `cypherpunk help request`), so only your
Nitrokey can let it start after a reboot (`cypherpunk help cloud`, `cypherpunk cloud unlock`).
`cypherpunk cloud chain` runs this for you the first time.

## Usage

    cypherpunk unlock-key (--vault DIR | --software-operator DIR) [--json]

## Options

- `--vault DIR`: the operator's Nitrokey vault. The first run asks for the PIN and a touch; later runs change nothing and need neither.
- `--software-operator DIR`: LAB ONLY. Plaintext operator keys.

## What it changes

Writes two files into the vault:
- `operator-unlock.pub`: a hybrid X25519 + ML-KEM-768 public key, which servers wrap their data key to;
- `operator-unlock.sealed.json`: its private half, sealed under the vault's FIDO2 hmac-secret like the operator's ML-DSA-65 key. It is plaintext only in memory, during an unwrap.

## Security notes

- Losing the vault, or the key holding its credential, locks every server that uses it until it is set up again with new keys.
