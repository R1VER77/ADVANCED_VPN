# Firmware compatibility laboratory

The laboratory asks whether a named authenticator implementation can perform the
VPN's actual key-protection and enrollment operations. It is independent of the
production CLI/controller: no virtual-device switch is added to the installed app.
It implements four backends: Solo 1's experimental upstream PC firmware (`solo1-pc`), CanoKey's
upstream virtual card (`canokey-udp`), Solo 2's authenticator on a PC (`solo2-pc`) and the TKey
FIDO2 app on Tillitis' QEMU TKey (`tkey-qemu`).

## Recorded Solo build

See [build inputs](evidence/SOLO1_PC_BUILD_20261118.json) and
[operation results](evidence/SOLO1_PC_VPN_OPERATIONS_20261118.json).

- Repository: <https://github.com/solokeys/solo1>.
- Source: `fc8d2867c5ba8161302b809c80fa1fd6a4df94a2`, described as
  `4.1.5-8-gfc8d286`.
- Build uses the repository-root Makefile for its `pc/` backend, not a board
  firmware or a directory named `targets/pc`. That Makefile enables
  `SOLO_EXPERIMENTAL=1` and `DEBUG_LEVEL=1`. No firmware source changes were made.
- The build record pins the checked-out crypto/CBOR submodules, resulting binary
  digest and local build/run image identity. This identifies the trial; it does not
  claim independent reproducible builds or a publicly published container image.
- The local Ubuntu 22.04 build environment adds `libsodium-dev`, `git`, `python3`
  and `python-is-python3` to the existing compiler image. Build as an ordinary user
  with networking disabled after dependencies and submodules have been fetched.

Upstream source preparation, in a **separate disposable directory**, is:

```sh
git clone https://github.com/solokeys/solo1 solo1
git -C solo1 checkout --detach fc8d2867c5ba8161302b809c80fa1fd6a4df94a2
git -C solo1 submodule update --init --recursive
```

Compare the recorded submodule revisions before compiling. Run `make main` from
the source root in the prepared constrained build container. Do not invoke upstream
flash, bootloader, reset or USB deployment commands. Only the resulting PC binary
is used. A rebuild that changes inputs/hash needs a new reviewed build record;
the runner deliberately refuses a binary that differs from its selected record.

## Solo 2 (solo2-pc)

See [build inputs](evidence/SOLO2_PC_BUILD_20261119.json) and
[operation results](evidence/SOLO2_PC_VPN_OPERATIONS_20261119.json).

- Source: <https://github.com/solokeys/solo2> `45311f0`, `Cargo.lock` unchanged,
  `fido-authenticator` at its locked git revision `fae4a1e`. No firmware source changes.
- Upstream's PC runner (`runners/pc`) builds the Trussed service but serves no CTAPHID; its
  test suite calls the authenticator in process, and its own notes say the socket and
  device paths panic. So the project adds one file to that test crate,
  `tools/lab/solo2_ctaphid_udp_host.rs`: CTAPHID framing (INIT, PING, WINK, MSG, CBOR,
  CANCEL, channel and sequence errors) over loopback UDP into the authenticator's
  `ctaphid_app::App::call`, the entry `usbd-ctaphid` uses on the device. The authenticator
  is configured as the lpc55 build configures it (`solo-apps` `fido_config`).
- It reuses upstream's in-process Trussed runtime (`tests/support/sim.rs`), whose RNG is
  seeded with 32 zero bytes, and grants presence to every request.
- Built with Rust 1.94.1 (the repository's `rust-toolchain.toml`) in a Debian image with
  libclang and the hidapi build libraries, network disabled after `cargo fetch --locked`.

GetInfo reports FIDO 2.3, hmac-secret, PIN/UV protocols 2 and 1, and ES256, EdDSA and
ML-DSA-44 (COSE -48) credentials. Every operation passed on protocol 2.

**Third operator half.** The lab runs a second instance on other ports
(`CPVPN_CTAPHID_PORTS`, its own flash file) as a separate key. It checks that
`keyguard enroll-pq-signer` refuses the key holding the operator's credential. It then
creates the ML-DSA-44 credential on the second key, signs with all three halves (each key
picked by the credential it holds), and requires refusal of a wrong message, a missing
ML-DSA-44 half and a tampered one. The signed client enrollment then goes through the real
bundle writer and reader with three halves. On a real Solo 2 only the Hacker build offers
FIDO2 ML-DSA-44 (`mldsa44-fido`); the Secure build does not.

## TKey (tkey-qemu)

See [build inputs](evidence/TKEY_QEMU_BUILD_20261119.json) and
[operation results](evidence/TKEY_QEMU_VPN_OPERATIONS_20261119.json).

- App: <https://github.com/tillitis/tkey-fido2> `7fdf8ea`, with tkey-libs `add_littlefs`
  (`c7ef7ea`), built by `build-tkey.sh`'s commands in upstream's CI image
  `ghcr.io/tillitis/tkey-builder:5rc1`, network disabled. No source changes.
- Emulator: Tillitis' QEMU, branch `tk1` at `d8413fe` (the commit upstream's
  `tkey-devtools/tkey-qemu.dockerfile` pins), machine `tk1-castor`; its subprojects are
  fetched at their `.wrap` revisions first, then it builds with networking disabled.
- Firmware and flash image: the Castor test images upstream's own FIDO2 tests use
  (`tkeytest-py` `5953932`, `test/device.py` `CastorPre`).
- Transport: upstream's `qemu_usb_mux.py` splits the TKey's USB-mode stream into CDC and
  FIDO pseudo-terminals; `tkey-runapp` (`tkey-devtools` `740715a`, `--not-usb-device`) loads
  the app over CDC; real 64-byte CTAPHID reports then travel over the FIDO one.
- The simulator is a bundle directory of six files; the build record pins each file and
  the runner refuses any other set or digest.

**Finding.** The app advertises PIN/UV protocols 1 and 2, but its hmac-secret parser takes
only protocol 1's 32/64-byte encrypted salts (`fido2/src/ctap_extensions.c`), so the
default protocol-2 client gets `CTAP1_ERR_INVALID_LENGTH` ([trial without the fix](evidence/TKEY_QEMU_PROTOCOL2_REFUSED_20261119.json):
`cause_ctap_error_code: 3`). With the client limited to protocol 1, every operation
passed. `tools/keyguard.py` now names this AAGUID (`PIN_UV_PROTOCOL_1_ONLY`) and uses
protocol 1 with it from the start, as it already must with Trezor, Ledger and Solo 1;
it is not a fallback after a failure. Touch reads as pressed in the emulator.

## Run the recorded trial

From the VPN repository, using this machine's retained simulator and the fully
verified offline Python runtime:

```sh
.venv/bin/python -B tools/device_compatibility_lab.py \
  --backend solo1-pc \
  --simulator /home/debian/vm/cypherpunk-vpn/hardware-lab-20261118/solo-build-a/source/main \
  --build-record docs/evidence/SOLO1_PC_BUILD_20261118.json \
  --runtime /home/debian/vm/cypherpunk-vpn/offline-package-20261117/runtime-31318 \
  --out /home/debian/vm/cypherpunk-vpn/hardware-lab-20261118/solo-next-trial
```

The output directory must not already exist. The local Docker image identified by
the selected build record must be present. These example absolute paths describe
the retained development lab, not portable release locations or public downloads.

The host verifies the build identity, binary and pinned runtime before running.
The container uses the ordinary UID, no capabilities, no privilege escalation,
a read-only root/source/runtime, private temporary storage and a network containing
only loopback. It receives no host USB devices, home, SSH agent or commissioned
vault. UDP ports 7112/8111 exist only inside that network; nothing is published.

The worker refuses exposed USB/hidraw or external interfaces, creates a fresh virtual
PIN and disposable credentials, executes the real VPN operations and removes its
temporary secret state. The host stops/removes its own container on exit. Results
contain booleans, algorithms, hashes and error classes; private console/sandbox
records stay in the output directory. The fixture PIN is never a production PIN.

## Interpret the result

`passed_key_sealing_operator_and_enrollment_operations` means exactly those named
operations passed for the pinned PC firmware and production source hashes. It
does not mean a live tunnel was connected. The result explicitly records:

```json
{
  "physical_device_tested": false,
  "tunnel_connection_tested": false,
  "usb_channel": "p256_ecdh_ctap_pin_uv_1_2"
}
```

PIN/UV protocol 1 uses P-256 even when an Ed25519 credential succeeds. Since 19 November
that channel is flagged, not blocking (results recorded before then carry
`strict_hardware_eligible: false` instead); see the device ranking in
[DEVICE_COMPATIBILITY_VALIDATION.md](DEVICE_COMPATIBILITY_VALIDATION.md). The GetInfo algorithms array
is empty on this build; the separate actual Ed25519 credential/assertion trial
establishes that capability rather than guessing from advertisement.

A future physical confirmation should target the remaining differences, rather
than repeat all of this cryptographic suite: shipped firmware/configuration,
transport permissions, real verification/presence prompts, and persistence across
unplug/restart. The physical Nitrokey, YubiKey, Trezor and Ledger baseline need not
be repeated to validate this additional candidate.
