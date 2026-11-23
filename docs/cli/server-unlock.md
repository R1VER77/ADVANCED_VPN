# cypherpunk server-unlock

Server only. Accept the operator's data key on stdin and hold it in RAM
(`/run/cypherpunk-vpn-unlock`, root only) until the next reboot, so the VPN service can open
the server's keys. `cypherpunk cloud chain` and `cypherpunk cloud unlock` run it over SSH.

## Usage

    printf '%s\n' HEX | sudo cypherpunk server-unlock [--json]

## What it changes

Nothing unless the key opens every locked key on this server; a wrong key is refused and
nothing is written. A right key is written to a tmpfs file, mode 0600, which a reboot
erases: the server is then locked again until the operator unlocks it.
