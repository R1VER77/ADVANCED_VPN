# avpn doctor

Self-checks for the installation, keys, firewall, resolver isolation and services.
Each check prints `✓` or `✗` with a detail.

## Usage

    sudo avpn doctor [--check-egress]

## Options

- `--check-egress`: also fetch the public address this device shows outside the tunnel (`https://checkip.amazonaws.com`). That is the address your first hop sees. With an upstream entry configured, it should be the upstream's address, not yours.

## Checks

- running as root
- trusted `ip`, `nft`, `mount`, `systemctl`: each found only in system directories, root-owned and not writable by others
- post-quantum crypto library: ML-DSA and ML-KEM are available
- device keys generated, enrolled in a chain
- constant-cell padding: the enrolled chain pads every hop; a chain signed before padding existed fails here, with the command to re-sign it
- on servers, no retained data: journal in RAM only, `/var/log` in RAM, no disk logger running, no login database on disk, no swap. A server's VPN will not start while any of these fail (`avpn help retention`); a shared host reports that its logging is outside this tool's control
- keys bound to TPM2 (systemd-creds protection), or the key protection mode
- whole-device kill switch table (whole-device clients)
- `advanced-vpn.service` and `advanced-vpn-guard.service` installed
- resolver isolation: which host resolver sockets are hidden from protected programs

## What it changes

Nothing. `--check-egress` makes one HTTPS request outside the tunnel.

## Exit status

0 when the controller ran. Use `--json` and the `healthy` field in scripts.
