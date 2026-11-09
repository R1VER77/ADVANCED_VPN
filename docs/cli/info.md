# avpn info

A non-secret summary of this device: role, chain, key protection, preferences and
status. It is safe to paste into a bug report.

## Usage

    sudo avpn info

## Fields

- `role`: `client`, `relay`, `middle` or `exit`.
- `hops`: 1, 2 or 3.
- `chain`: the public endpoints, in the order the client reaches them.
- `protection`: `nitrokey`, `systemd-creds` or `none`. `creds_key` is `host+tpm2` when the sealing key is bound to the TPM.
- `mode`: `applications` (only `avpn run` programs) or `whole-device`.
- `defense`: `balanced` or `strong` (see `avpn help preferences`).
- `daily limit`: the optional fail-closed cap; `none` by default.
- `status`: the supervisor state (see `avpn help status`).

## What it changes

Nothing.

## Security notes

No private key, PSK or certificate content is ever included. A test enforces this.
