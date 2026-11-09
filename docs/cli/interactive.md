# Interactive view

Run `avpn` with no command in a terminal.

- **Header:** the version, the chain, the mode, the key protection and the service state.
- **History:** one cell per action. `•` marks a result, `└` its details, `✓` / `✗` doctor checks, `■` an error.
- **Footer:** the keys.

## Keys

- `c` connect, `d` disconnect
- `h` hops, `s` status, `i` info, `o` doctor
- `?` help, `PgUp` / `PgDn` scroll, `q` or `Esc` quit

Use `--reduced-motion` for a static working indicator, and `--no-color` (or `NO_COLOR`)
for monochrome output.
