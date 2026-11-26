# cypherpunk preferences

Change the saved connection preferences. Connection preferences apply on the next `cypherpunk connect`.

## Usage

    sudo cypherpunk preferences [--mode applications|whole-device] \
        [--daily-limit-mib N | --no-daily-limit] \
        [--upstream-interface IFACE [--upstream-gateway IP] | --no-upstream]

    sudo cypherpunk preferences --lockdown on|off [--keep-guard]

## Options

- `--lockdown on|off`: set offline protection while the VPN is stopped. In the interactive CLI, press `k` to review it and reconnect if needed.
- `--keep-guard`: with `--lockdown off`, retain the running firewall rules during a planned restart.
- `--mode`: select the saved traffic scope. Use Ctrl+Shift+Tab or m in the interactive view to switch.
  - `applications`: only programs started with `cypherpunk run`.
  - `whole-device`: all traffic. The nftables kill switch drops anything else, IPv6 included.
- `--daily-limit-mib N`: a fail-closed daily cap, 1..10240 MiB. Client only, because servers store no byte counts.
- `--no-daily-limit`: remove the cap (the default).
- `--upstream-interface IFACE`: send the traffic to your first hop only through IFACE, for example an existing VPN. If IFACE is down, the first hop is unreachable rather than reached directly. See `cypherpunk help privacy`.
- `--upstream-gateway IP`: with `--upstream-interface`, the next hop on an Ethernet-like upstream interface. Point-to-point interfaces (WireGuard, tun) need none. Without it, a gateway the interface already routes through, in any routing table, is used; if there is none, connecting is refused.
- `--no-upstream`: reach the first hop over the normal route (the default).
- `--protect-app EXECUTABLE`: save an executable name or absolute path for protected launch from the Applications menu.
- `--forget-app EXECUTABLE`: remove a saved launcher.

## Security notes

Traffic-analysis defense is always on: every chain runs the constant-rate stream at the rate class signed by `cypherpunk init --rate` (`metered`, `standard`, `fast`, or `line`). There is no preference to weaken or disable it.
