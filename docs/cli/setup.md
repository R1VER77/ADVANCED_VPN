# cypherpunk setup

Recheck client setup and show the next action. Only current checks complete steps. This
command does not create servers, generate keys, sign routes or activate networking by itself.

## Usage

    sudo cypherpunk setup
    sudo cypherpunk --json setup --vault /etc/cypherpunk-vpn/vault
    cypherpunk setup --repair install_udev_rule
    cypherpunk setup --repair yubikey_enable_fido2 --device SERIAL

## Options

- `--vault DIR`: saved FIDO2 credential directory. Default: the device protection record,
  or `/etc/cypherpunk-vpn/vault`. Inspection never creates a credential.
- `--checkpoint-dir DIR`: private directory for non-secret `setup.json`. Default: per-route
  local user state, or the enrollment's `setup` directory as root. It must belong to the caller.
- `--repair ID`: show an available `install_udev_rule` or `yubikey_enable_fido2` plan.
  Fresh diagnosis must offer it. Arbitrary commands are refused.
- `--device ID`: select the diagnosed hidraw device or vendor-confirmed YubiKey serial.
- `--apply`: apply a selected repair only with its current confirmation token.
- `--confirm TOKEN`: token from reviewing that exact plan, paired with `--apply`.
  Changed findings invalidate it. No PIN, password or lock code belongs here.
- `--json`: one result containing `setup` or `repair`.

## Checklist and resume

Checks cover host requirements, key capabilities, the public credential record, installed
route, configured endpoints, the traffic guard and fresh end-to-end connection evidence.
Use `cypherpunk request`, `cypherpunk init`, `cypherpunk enroll` and `cypherpunk cloud` to perform setup actions.
An operator can provide a signed device file; an owner can configure their own servers.
Endpoint configuration does not prove reachability; the final check verifies the path.

This is the FIDO2 client path, not server/TPM-only enrollment. Full automated provisioning,
GUI integration and a trained Gemma helper are separate work. The command supplies checks
those interfaces can call. A valid credential record does not prove possession of the
matching key: normal PIN/touch unlock and connection verify that later.

States: `pending`, `running`, `waiting_for_user`, `waiting_for_hardware`, `blocked`, `failed`,
`complete`, `skipped`. An unfinished checklist exits zero when inspection succeeded;
inspect `finished` and individual states in JSON. Checkmarks never come from cached state.

Run again to resume. Every check runs again; changed input fingerprints invalidate earlier
downstream evidence. Checkpoints hold only summaries, hashes and times, no credentials.
Concurrent checks serialize; private checkpoint replacement is atomic and synced.

Guard and connection checks require fresh status bound to a live supervisor identity and
fresh cloak confirmation, handshake and route-probe timestamps. Missing, stale or
future-dated evidence cannot complete setup. The guard covers the configured mode:
application mode is not a claim of whole-device protection.

## Hardware repair

Diagnose as the intended local user: root can open devices an ordinary user cannot.
A FIDO classification tag is distinct from desktop `uaccess`. If access is already tagged
but denied, investigate the session/ACL; another rule is not an established fix.

A rule repair installs a fixed local-session rule for Nitrokey, YubiKey, Trezor and Ledger,
reloads udev and rechecks access. Wallet rules require the system's `fido_id` helper and
grant access only to FIDO-classified HID interfaces, never the separate wallet transport.
It refuses to overwrite a different existing rule. A key reconnect
may be needed. Privileged commands resolve trusted system executables.

YubiKey enable repair needs the vendor tool to confirm FIDO2 is disabled on USB and identify
a single target. Missing HID alone is insufficient. Unknown/locked configurations get
guidance, with no lock bypass. Only USB FIDO2 changes; OTP slots, PIV, OpenPGP and NFC stay
unchanged. Fresh vendor and CTAP checks must show the target usable afterwards.

Review the plan, then repeat its repair/device arguments with `--apply` and `--confirm TOKEN`.
Exit status alone never proves a repair worked. No repair resets FIDO, deletes credentials,
guesses PINs or updates firmware. A blocked PIN requires a separate recovery decision:
resetting would remove existing FIDO credentials.

See `cypherpunk help keys`, `cypherpunk help preflight` and `cypherpunk help doctor`.
Physical capability, disposable vault and missing-access checks are documented in
[`docs/HARDWARE_SETUP_TESTS.md`](../HARDWARE_SETUP_TESTS.md).

The confirmation token binds a plan, not a person. A future assistant may request a plan;
its tool adapter must reserve applying it for an explicit user approval, never let the
model approve its own proposal. No model or shell access is included in this implementation.
