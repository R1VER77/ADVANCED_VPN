# cypherpunk preflight

Check installation requirements before changing this system. Preflight never installs
packages, changes networking, logs into providers or modifies security keys.

## Usage

    cypherpunk preflight [--package DIR] [--target DIR] [--protect MODE] [--hardware]
    cypherpunk --json preflight
    python3 tools/preflight.py --json

The standalone script uses only the standard library and runs on Python 3.8+. It can
explain that the installer needs Python 3.10 and venv even on an older host.

## Options

- `--package DIR`: inspect staged ELF files for their glibc requirement. Without it use
  the release baseline. This does not authenticate a package: verify release provenance.
- `--target DIR`: installation location for the free-space check; default `/opt`. A supplied package
  adds its file size to the 500 MiB baseline space margin.
- `--operator-only`: check the command-line-only operator install. It needs a compatible
  OS/architecture, glibc, Python/venv and space; it does not require VPN networking or
  systemd features. The user installer selects this mode automatically.
- `--protect MODE`: intended protection: `nitrokey`, `systemd-creds`, `operator` or `none`. An
  older systemd gets a warning for systemd-creds; on a server without a usable TPM2, use `operator`. This never changes protection or enables plaintext.
- `--hardware`: also inspect attached keys using the installed hardware environment.
  Omit it for the Python 3.8 bootstrap script. No PIN or touch is requested.
- `--provider KEY`: explicitly check an existing catalog provider with its installed CLI.
  Repeat for multiple providers. These checks can contact the provider; none run by default. Run them as your ordinary
  user, never root, so CLI credentials and environment overrides stay unprivileged.
  They reuse the existing readiness contract: a configured file is not proof of a live login.
- `--profile NAME`: CLI profile for explicitly selected provider checks.
- `--json`: findings, counts, readiness and a suggested package command. The controller
  wraps them under `preflight`; the standalone script prints the report directly.

## Findings

A blocker prevents readiness; warnings need review. Failure to run a required check is a
blocker. Checks cover documented OS versions, architecture, glibc, TUN, programs,
nf_tables, seccomp, Landlock visibility, systemd, Python/venv, space and VPN-like interfaces.
A read-only preflight cannot prove every privileged runtime operation will succeed.
Unknown Landlock visibility is not proof it is disabled. Interface names are clues, not
proof another VPN is up. Provider network requests occur only with an explicit provider selection.

Missing packages form one suggested apt/dnf/pacman/zypper command; review and run it yourself.
Exit status is zero when ready, one when blocked. `cypherpunk doctor` shares the host checks,
then adds enrollment and runtime checks. See `cypherpunk help setup` for the resumable checklist.
