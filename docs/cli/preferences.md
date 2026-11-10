# avpn preferences

Change the saved connection preferences. They apply on the next `avpn connect`.

## Usage

    sudo avpn preferences [--mode applications|whole-device] [--defense balanced|strong] \
        [--daily-limit-mib N | --no-daily-limit] \
        [--upstream-interface IFACE [--upstream-gateway IP] | --no-upstream]

## Options

- `--mode`: what the tunnel protects by default.
  - `applications` (default): only programs started with `avpn run`.
  - `whole-device`: all traffic. The nftables kill switch drops anything else, IPv6 included.
- `--defense`: DAITA traffic-analysis defense.
  - `balanced` (default): constant packet size and decoys around each burst, at full speed. Cheap, but measured not to stop a website-fingerprinting classifier (`avpn help threat-model`).
  - `strong`: constant-rate Tamaraw shaping, rounding every trace to a 2 s step. Very slow (~0.3 Mbit/s) and about 168 GB a month each way even when idle, by design. Use it only when hiding which site you visit matters more than speed and data.
- `--daily-limit-mib N`: a fail-closed daily cap, 1..10240 MiB. Client only, because servers store no byte counts.
- `--no-daily-limit`: remove the cap (the default).
- `--upstream-interface IFACE`: send the traffic to your first hop only through IFACE, for example an existing VPN. If IFACE is down, the first hop is unreachable rather than reached directly. See `avpn help privacy`.
- `--upstream-gateway IP`: with `--upstream-interface`, the next hop on an Ethernet-like upstream interface. Point-to-point interfaces (WireGuard, tun) need none. Without it, a gateway the interface already routes through, in any routing table, is used; if there is none, connecting is refused.
- `--no-upstream`: reach the first hop over the normal route (the default).
