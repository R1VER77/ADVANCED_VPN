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
  - `waiting for the Nitrokey PIN`: the service is asking for the PIN; answer it with `sudo avpn unlock`.
  - `unknown`: run without `sudo` while the service runs; its status is readable by root only.
- `detail` and `next`: why, and what to run next, when there is something to do.
- `kill_switch`: whether the nftables guard is in place.
- `children`: each data-plane process, with its PID and whether it is alive.

## What it changes

Nothing. A read-only query never creates runtime files.

## Failure modes

- `not running`: the service is stopped. Start it with `avpn connect`.
- `unknown` (`next: sudo avpn status`): you ran it as yourself; run it with `sudo`.
- `detail: no answer through the chain since HH:MM` (a client): the chain stopped answering for a minute, or never answered after a start; a desktop notification says the same. A server may be stopped by its provider (free tiers stop idle servers), locked after a reboot, out of credits or unreachable. Traffic stays blocked meanwhile. `next` says to run `avpn cloud health` as yourself, which finds which and gives the fix.

## Files

`/run/advanced-vpn/state-*/status.json`. This is tmpfs, so it is gone after power-off.
