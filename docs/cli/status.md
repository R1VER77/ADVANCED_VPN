# avpn status

Show the runtime status the supervisor writes to RAM: its state, child processes, and
the bytes used when a daily cap is set.

## Usage

    sudo avpn status

## Output

- `state`:
  - `supervising`: the tunnel is up and watched.
  - `blocked`: the supervisor stopped, or the daily cap was reached (`reason`). Traffic is held by the kill switch, not leaked.
  - `unlocked`: `avpn reset --allow-cleartext` removed the kill switch.
  - `not running`: no status since boot.
- `kill_switch`: whether the nftables guard is in place.
- `children`: each data-plane process, with its PID and whether it is alive.

## What it changes

Nothing. A read-only query never creates runtime files.

## Failure modes

- `not running`: the service is stopped. Start it with `avpn connect`.
- `PermissionError`: run it with `sudo`.

## Files

`/run/advanced-vpn/state-*/status.json`. This is tmpfs, so it is gone after power-off.
