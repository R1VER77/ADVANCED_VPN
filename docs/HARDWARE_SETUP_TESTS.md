# Physical setup validation

The setup inspector reads CTAP capabilities without a PIN or touch. That establishes
capability availability, not possession of a saved credential, hardware authenticity or
a successful unlock. Test these separately before marking a model/firmware physically
validated for setup.

## Capability check

Connect the intended key. Run as the ordinary desktop user, never root:

```sh
python tools/hardware_setup_test.py --family nitrokey --out NEW_PRIVATE_DIRECTORY
```

The family is `nitrokey`, `yubikey`, `trezor` or `ledger`. The output directory must not
already exist. Results contain no credential handles, vendor serials, PINs or derived
secrets. Two usable keys cause a request to unplug the extra key; the tool never guesses
which one holds the user's credential. A recognized USB vendor is not proof of support.

## Disposable vault round trip

Leave one intended usable key connected:

```sh
python tools/hardware_setup_test.py --family nitrokey --out NEW_PRIVATE_DIRECTORY \
  --roundtrip --confirm-create-test-credential
```

This explicitly creates a separate non-resident test credential. It validates the
public credential record, obtains a hardware secret, seals random test bytes, obtains a
fresh verified assertion and uses its recovered secret to unseal those bytes. It also
rejects a corrupted envelope. The temporary local vault is removed on success or failure.
This does not reset the key or remove existing credentials; it does not invoke credential
deletion on the device. Some authenticators may retain implementation-specific metadata
or advance counters when a test credential is used.

The tool runs no cloud or VPN activation commands. Do not substitute a production vault,
use a wallet recovery phrase, set a new PIN or retry a failed PIN automatically. Test one
device at a time, using the existing PIN through the trusted terminal or device prompt.
On Trezor and other devices reporting configured on-device verification, perform that
verification on the device. For Ledger, unlock it and open the Security Key app first;
a locked or different application may expose only U2F or no FIDO interface.

## Missing access and confirmed repair

Run these scenarios in a recoverable local session, with backed-up rules and ACLs:

1. Record the baseline as the ordinary user.
2. Temporarily disable vendor-specific rules; check again. Modern systemd's generic
   FIDO access rules may legitimately keep the device usable.
3. With a temporary, device-specific test rule, remove access for that device. Confirm
   setup reports a permission blocker and offers the reviewed rule repair. A device
   already tagged for desktop access but still denied needs session/ACL diagnosis.
4. Review `avpn setup --repair install_udev_rule --device hidrawN`. Apply the exact
   current plan with `--apply --confirm TOKEN`; use the local sudo prompt when needed.
5. Require a fresh ordinary-user CTAP probe to succeed. A command returning zero is
   insufficient, and a reconnect may be needed.
6. Restore the original rules, ownership, mode and ACLs, reload/retrigger only the
   affected device, and confirm baseline access again, including after failure or
   interruption. Keep an independent restoration watchdog during a real access trial.

Do not uninstall the udev service, change unrelated device access, make hidraw devices
world-writable or grant wallet transport access to fix FIDO permissions. The fallback
rule gives local-session access to recognized key interfaces. For Trezor/Ledger it
requires FIDO classification using systemd's `fido_id` helper and never grants the
separate wallet transport. Its vendor identifiers are based on the
[Trezor rules](https://data.trezor.io/udev/51-trezor.rules) and
[Ledger rules](https://github.com/LedgerHQ/udev-rules/blob/master/20-hw1.rules);
its permissions are deliberately narrower than vendor-wide wallet-access rules.

## Record results separately

For each device record the date, model/firmware when safely known, capability result,
vault round trip, missing-access diagnosis, actual confirmed repair, restoration and
remaining limitations. Do not count synthetic tests as physical tests or historical
enrollment evidence as a test of new setup/repair code. Preserve negative results.

YubiKey's disabled-USB-FIDO2 repair is a separate scenario: vendor evidence must identify
one unlocked configuration and explicitly report disabled FIDO2. Do not disable a live
signing key merely to create the scenario; use an agreed test window or spare key, and
restore its original USB application settings. Never reset FIDO credentials, change
OTP slots, bypass a configuration lock or update firmware as a troubleshooting shortcut.
