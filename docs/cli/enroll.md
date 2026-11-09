# avpn enroll

Verify this device's signed bundle and install it. No network settings change.

## Usage

    sudo avpn enroll BUNDLE --operator-key FILE [--replace]

## Options

- `BUNDLE`: the `.avpn` file the operator produced for this device.
- `--operator-key FILE`: the operator's public key. Get it out of band, not with the bundle.
- `--replace`: switch this device to a new chain. Its keys are kept. Disconnect first.

## What it checks

- Both halves of the hybrid Ed25519 + ML-DSA-65 signature.
- That the bundle is for this device's keys.
- That there are no extra or traversing archive entries.
- That every value that reaches firewall rules is strictly valid.
