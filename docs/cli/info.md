# avpn info

A non-secret summary of this device: role, chain, key protection, preferences and
status. It is safe to paste into a bug report.

## Usage

    sudo avpn info

## Fields

- `role`: `client`, `relay`, `middle` or `exit`.
- `hops`: 1, 2 or 3.
- `padded`: `true` when the chain pads every hop to constant cells. `false` only for a chain signed before padding existed; it cannot connect until it is re-signed (`avpn help threat-model`).
- `camouflaged`: `true` when this device's link to the first hop runs behind the HTTP/3 and TLS 1.3 camouflage. `false` only for a chain signed before it existed, which cannot connect until re-signed; `null` on a server that runs no carrier.
- `chain`: the public endpoints, in the order the client reaches them.
- `protection`: `nitrokey`, `systemd-creds` or `none`. `creds_key` is `host+tpm2` when the sealing key is bound to the TPM.
- `mode`: `applications` (only `avpn run` programs) or `whole-device`.
- `rate`: the chain's signed constant-rate stream class (`metered`, `standard`, `fast`, or `line`; see `avpn help init`).
- `daily limit`: the optional fail-closed cap; `none` by default.
- `status`: the supervisor state (see `avpn help status`).

## What it changes

Nothing.

## Security notes

No private key, PSK or certificate content is ever included. A test enforces this.
