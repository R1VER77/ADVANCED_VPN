# Interactive view

Run `cypherpunk` with no command in a terminal. For local enrollment and
Nitrokey unlock, open it with `sudo cypherpunk`.

- **Header:** the version, the chain, the mode, the key protection and the service state.
- **History:** one cell per action. `•` marks a result, `└` its details, `✓` / `✗` doctor checks, `■` an error.
- **Footer:** the keys.

## Keys

- `c` connect, `u` answer a pending Nitrokey prompt, `d` disconnect
- `e` set up this device or change its enrolled chain
- `l` locations and saved signed chains, `p` VPN settings
- `h` hops, `s` status, `i` info, `o` doctor
- `?` help, `PgUp` / `PgDn` scroll, `q` or `Esc` quit
- `/` search commands. Type a prefix, use Tab to complete, and press Enter to run.
- `k` or `/killswitch-disarm` opens internet recovery. The confirmation stops the VPN
  and permits ordinary internet access through your ISP. Close protected apps first.

On an enrolled Nitrokey client, `c` from the privileged view starts the
service and opens the terminal PIN prompt if the service requests one.
The PIN is hidden. After unlocking, the live status names the next
connection check. Traffic stays blocked until the tunnel has fresh
protection evidence. In applications mode this applies to programs
started through `cypherpunk run`. Disconnect keeps that guard in place.

An already-open browser uses ordinary networking in Applications mode.
To check the exit IP without opening another browser, press `p`, choose
**Check the public IPv4 of a protected app**, and confirm the request to
ipify. This runs curl inside the protected namespace. To route your
existing browser through the VPN, choose **Whole device** under Traffic
scope, then disconnect and reconnect so the new scope takes effect.

In setup, you can create or export a public device request, install a
signed bundle or replace your current bundle after disconnecting. Use the
server planning option when you operate your own relay and exit. Return
to setup once you have a signed bundle and a separately verified operator
public key.

On first client enrollment, guided setup offers Whole device (the default)
and Applications. Review the scope in Settings even after setup. Switching
from an armed whole-device guard to Applications requires disconnecting and
explicitly allowing ordinary traffic outside the protected apps.

The CLI inherits the terminal background and uses Catppuccin Mocha text accents.
Use `--reduced-motion` for a static working indicator, and `--no-color` (or `NO_COLOR`)
for monochrome output.
