# Interactive view

Run `cypherpunk` with no command in a terminal. For local enrollment and
Nitrokey unlock, open it with `sudo cypherpunk`.

- **Header:** the version, the chain, the mode, the key protection and the service state.
- **History:** one cell per action. `•` marks a result, `└` its details, `✓` / `✗` doctor checks, `■` an error.
- **Footer:** the keys.

## Keys

- `c` connect, `u` answer a pending Nitrokey prompt, `d` disconnect
- `Ctrl+Shift+Tab` or `m` switches traffic scope. Use `/scope` if your terminal intercepts the shortcut.
- `/applications` saves and launches protected applications.
- `e` set up this device or change its enrolled chain
- `l` locations and saved signed chains, `p` VPN settings
- `h` hops, `s` status, `i` info, `o` doctor
- `?` help, `PgUp` / `PgDn` scroll, `q` or `Esc` quit
- `/` search commands. Type a prefix and press Enter to run the highlighted match. Use arrow keys to move the highlight and Tab to complete.
- `k` or `/lockdown` reviews Lockdown. Changing it during a connection offers to
  reconnect through the protected restart flow.
- `/killswitch-disarm` restores ordinary internet access after confirmation.

Whole device is the default for new setups. In Applications mode, launch
selected programs through `/applications`. Apps opened normally use the
ordinary connection. In Whole device mode, all apps use the VPN. The automatic
kill switch protects the selected scope throughout the session. When you
deliberately disconnect,
Lockdown controls whether ordinary internet access resumes or remains blocked.
The Nitrokey PIN prompt hides input and returns to live connection status after unlock.

In setup, you can create or export a public device request, install a
signed bundle or replace your current bundle after disconnecting. Use the
server planning option when you operate your own relay and exit. Return
to setup once you have a signed bundle and a separately verified operator
public key.

The CLI inherits the terminal background and uses Catppuccin Mocha text accents.
Use `--reduced-motion` for a static working indicator, and `--no-color` (or `NO_COLOR`)
for monochrome output.
