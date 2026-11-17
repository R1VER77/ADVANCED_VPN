# Pinned offline installation

Implementation added 17 November 2026; not yet a tagged release. Offline release
tarballs contain a pinned CPython 3.13.18 distribution, its license material and
hash-locked binary-wheel dependencies. Installation runs from that interpreter:
the host needs neither Python nor a connection to PyPI. System packages and kernel
features such as TUN, nftables and systemd remain host requirements. Optional provider
and vendor command-line tools are not bundled by the core Python lock.

The November pin refresh replaces the inherited CI artifact (Python 3.13.13 / OpenSSL
3.5.6) with Python 3.13.18 / OpenSSL 3.5.9. See the upstream
[Python security release](https://www.python.org/downloads/release/python-31318/) and
[OpenSSL release notes](https://www.openssl-library.org/news/openssl-3.5-notes/index.html).
The exact standalone archive digest is pinned from its publisher's release metadata;
builds check it before extraction. Review interpreter/TLS advisories as well as the pip
lock when refreshing this pin; pip-audit does not cover CPython's bundled libraries.

## Authenticate, inspect, then install

Verify the release's build-provenance attestation and published checksums before
unpacking or executing any package code. Use the verification instructions attached
to that exact release; a checksum downloaded beside a package alone is not independent
authentication. The embedded content manifest is an integrity check, not a replacement
for release authentication. The bootstrap necessarily executes the bundled interpreter
before that Python program checks the manifest.

From a verified, unpacked **offline** release:

```sh
./install.sh --out NEW_REVIEW_DIRECTORY
./install.sh --user
# Or, for a system installation after reviewing the preflight findings:
sudo ./install.sh --apply
```

`--out` stages files only. `--user` installs operator commands under the user's home;
it cannot install or activate the system tunnel. `--apply` checks host readiness before
staging, installs under `/opt/advanced-vpn`, creates service identities and installs
units. It never starts or enables VPN services. Enrolling a role, unlocking a key and
connecting remain explicit actions. Do not run root installation merely to try the UI.

The installer verifies the runtime's complete files, safe relative symlinks, modes,
upstream pin and dependency-lock digest. Unknown files, changed files, missing files,
unsafe links and a different lock are refused. A bundled install never calls pip or
falls back to the host interpreter. A new runtime is copied with each bundle upgrade;
an older venv is not reused. The cloud command launcher uses the same interpreter.
`-B -E -s` suppresses bytecode writes and ignores Python environment/user-site injection.

Source-only and legacy tarball installation remains available through `tools/install.py`
and may still create a venv using network access. The offline promise applies to a
complete runtime-bearing package using `install.sh`. Existing cloud SSH bootstrap
scripts are not yet converted to this offline package path; do not infer that server
provisioning is offline. Static musl preflight, `.deb`, `.rpm` and a signed apt repository
remain separate roadmap items. An SSH hardware commit key is not an apt OpenPGP key.

## Upgrade, removal and recovery limits

Repeat the verified package's installation command to upgrade in place. Staging and
verification happen before replacing application files; enrolled keys, operator/cloud
inventory and persistent private state are kept. An upgrade does not activate services
or remove a traffic guard. This is not a rolling multi-host protocol upgrade; all
peers still need compatible signed enrollment and release versions.

Failed dependency builds leave the live runtime intact. A synchronous final-rename
failure restores the previous application. A host crash during the short two-rename
replacement window may leave an `.old-PID` directory beside the target; use the recovery
console to inspect and restore that complete tree before restarting services. This
change does not claim a crash-atomic filesystem exchange or a live upgrade validation.

User removal is `./install.sh --user --uninstall`; it preserves
`~/.config/advanced-vpn`, including cloud inventory and SSH material. System removal is
`sudo ./install.sh --apply --uninstall` from the verified unpacked release. It refuses
while a unit is active/enabled, a VPN firewall table, namespace or managed interface
exists, an installed program is running, or required checks fail. Modified/foreign
unit files are refused; unrelated command launchers are preserved. Removal never
stops/disables a guard or clears network rules. Do not connect/reconfigure concurrently.

Use the documented disconnect and explicit recovery workflow before removing a
protected installation; a disconnect alone deliberately leaves its guard. The command
removes inactive owned application files/units and reloads systemd. It preserves private
state, keys, service users and local AppArmor includes. Reinstalling the same compatible
release makes those retained files available again; there is no automatic key purge.

## Reproduce the build and validation

Use the exact archive URL and SHA256 in `tools/bundled_runtime.py` (the same Python
artifact already pinned in protocol CI). Download it, then build as an ordinary user:

```sh
python3 tools/bundled_runtime.py --archive DOWNLOADED_CPYTHON.tar.gz --out NEW_RUNTIME
python3 tools/install.py --pack NEW_RELEASE.tar.gz --runtime NEW_RUNTIME
python3 tools/bundled_runtime.py --verify NEW_RUNTIME
```

The builder checks the upstream hash before extraction/execution, downloads only
hash-locked wheels, installs them from a local wheel directory and exercises the required
ML-KEM, ML-DSA and FIDO imports. Build-time downloads are allowed; install-time downloads
are not. The manifest records file hashes, modes, links and the dependency-lock hash.
It does not establish that CPython or a dependency is independently audited.

CI runs `tools/offline_user_test.sh` in minimal containers with `--network none` and no
host Python, checking user install, upgrade, working commands, runtime integrity and
configuration-preserving removal. Containers establish user-space/ABI behavior, not
systemd, reboot or real traffic protection. For a clean supported cloud-image VM:

```sh
python3 tools/offline_package_test.py --base CLEAN_IMAGE.qcow2 \
  --package NEW_RELEASE.tar.gz --work NEW_VM_WORK_DIRECTORY
```

The harness uses an overlay, a read-only payload disk and the guest agent; it never
installs on the host. Guest prerequisites may be downloaded before the trial. Actual
installer subprocesses run in an isolated guest network namespace with no external
interface. Results distinguish system install/upgrade without activation, user removal,
corruption refusal and untouched firewall/service state. Removal trials include refusal
under an enabled unit, a retained synthetic table and a foreground installed program,
then inactive removal preserving state. These are not reboot-protection tests or tests
of an enrolled live tunnel. Preserve failed runs and report each distribution separately.

On 17 November the refreshed runtime package passed these trials on clean Debian 12,
Debian 13, Ubuntu 22.04 and Ubuntu 24.04 VMs. Installed `preflight` reported ready and
`doctor`'s host findings agreed; missing enrollment remains a separate expected failure.
The [aggregate record](evidence/OFFLINE_PACKAGE_20261117.json) contains package/source
hashes, environment and negative results. All 604 Python tests passed on both 3.10 and
3.13, with 19 environment-dependent skips per suite. The older Python/OpenSSL artifact's
functional passes were superseded by the security-refreshed package before publication.
