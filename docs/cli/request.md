# avpn request

Generate this device's keys on the device itself and write a public request for the
operator. Private keys never leave the device.

## Usage

    sudo avpn request --role ROLE --protect MODE [--vault DIR] --out FILE

## Options

- `--role`: `client`, `relay`, `middle` or `exit`. What this device will be in the chain.
- `--protect`: how the private keys are sealed at rest.
  - `nitrokey`: FIDO2 hmac-secret envelope. Needs the key present (PIN + touch) to start.
  - `systemd-creds`: sealed with the host key, and with the TPM2 when one is usable (`host+tpm2`). Use it on servers.
  - `none`: plaintext, root-only. Lab use only.
- `--vault DIR`: the Nitrokey vault (with `--protect nitrokey`). The default is `/etc/advanced-vpn/vault`, created on first use (PIN + touch). The VPN service reads it as root, so a vault must be a private directory owned by root. One in your home directory is refused before anything is created.
- `--out FILE`: the public request. Copy only this file to the operator.

`sudo python3 tools/install.py --apply --role ROLE --protect MODE` runs this for you
right after installing.

## What it changes

Creates the keys in the enrollment directory (mode 0700, root-owned):
- an ML-DSA-65 identity;
- a WireGuard key;
- an X25519 + ML-KEM-768 key that receives the PSK.

## Security notes

- Requests carry public keys only.
- If a device is lost, generate new keys and re-run `init`. There are no key backups by design.
