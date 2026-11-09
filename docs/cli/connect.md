# avpn connect

Start the VPN service (`advanced-vpn.service`) and show its status.

## Usage

    sudo avpn connect
    sudo avpn connect --foreground [--whole-device | --app-only]

## Options

- `--foreground`: run the supervisor in this terminal instead of the service. It stops with Ctrl-C. Lab and debugging use only.
- `--whole-device`: with `--foreground`, route the whole device for this run.
- `--app-only`: with `--foreground`, protect only `avpn run` programs for this run.

Without `--foreground`, the mode comes from `avpn preferences --mode`.

## What it changes

- Starts the supervisor, which builds the tunnel layers, the WireGuard + DAITA carrier, the nftables kill switch and the protected network namespace.
- If a Nitrokey protects the keys, it asks for the PIN (terminal, desktop dialog, or `avpn unlock`).

## Failure modes

- The PIN is never answered: the service waits up to 5 minutes, then fails closed.
- The daily cap is reached: traffic is blocked, not leaked. The status shows `blocked`.

## Security notes

The service is never enabled at boot by the installer. Enable it yourself with
`systemctl enable advanced-vpn.service` once you have tested it.
