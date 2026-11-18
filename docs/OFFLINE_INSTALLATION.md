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
provisioning is offline. Static musl preflight and `.deb` packages exist today; RPM
qualification and repository publication follow
[the signed repository procedure](SIGNED_REPOSITORY.md). An SSH hardware commit key
is not an apt OpenPGP key.

## Upgrade, removal and recovery limits

Repeat the verified package's installation command to upgrade in place. Staging and
verification happen before replacing application files; enrolled keys, operator/cloud
inventory and persistent private state are kept. An upgrade does not activate services
or remove a traffic guard. This is not a rolling multi-host protocol upgrade; all
peers still need compatible signed enrollment and release versions.

Native packages refuse downgrades: `preinst` uses dpkg's native version comparison;
RPM `%pre` queries the installed database and compares epoch, version and release
with native RPM ordering. Its scriptlet argument is a package count, not an installed
version. Both guards abort when installed code is newer than the candidate. Reinstalling the same
version stays allowed — that is the package-managed replacement path — and an
installed version the guard cannot compare against is refused rather than guessed.
Rolling back application code is the slot system's transaction, which retains the
verified previous release; it never touches keys, counters or profiles. Do not
use `dpkg -i`/`dnf downgrade` with an older archive to work around this.

Failed staging leaves the selected runtime intact. System installations use verified
versioned slots, a durable journal and an atomic `current` symlink replacement.
Legacy directory adoption uses a separately journaled Linux atomic exchange and
requires explicit approval while stopped. Recover using the verified installer's
transaction record; do not choose a damaged slot or roll back private security state.
Unit fault tests and local guest lifecycle results do not qualify physical power loss
or every live upgrade failure point. User-only installation has its own replacement
path; the system-slot guarantee does not extend to that path.

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

## Native package trials

Build unsigned candidates as an ordinary user (the pinned runtime section above
explains `NEW_RUNTIME`; `--format rpm` additionally requires `rpmbuild`):

```sh
python3 tools/native_package.py --runtime NEW_RUNTIME --out NEW_PACKAGE_DIR \
  --format deb --epoch SOURCE_COMMIT_TIMESTAMP
```

Build the GNU core on the declared glibc 2.35 baseline, rather than the development
host's newer glibc, and build the bootstrap helpers statically with musl. The builder
checks the staged ELF requirements before emitting an archive and refuses a candidate
whose required glibc exceeds the shared release baseline. Package dependencies and
preflight use that same baseline. A core built on Debian 13 can otherwise require
glibc 2.38 even if its metadata says 2.35: the 18 November Debian 12 trial caught and
refused exactly that mismatch. Keep this failed candidate distinct from any rebuilt
and requalified one.

The lifecycle trial runs inside one disposable KVM guest per distribution; it
installs, replaces, repairs damaged code, reboots without activation, refuses
armed removal and verifies state-preserving removal, with external probe
witnesses. Feed it a publisher-verified clean cloud image of each declared
distribution and a fresh work directory:

```sh
python3 tools/package_vm_test.py --base CLEAN_IMAGE.qcow2 \
  --package cypherpunk-vpn_VERSION-1_amd64.deb --work NEW_VM_WORK_DIRECTORY \
  --downgrade-package cypherpunk-vpn_OLDER_VERSION-1_amd64.deb
```

`--downgrade-package` is an older built candidate (check out the older release
tag and build it the same way): its `dpkg -i` installation must be refused by
the package's own guard before anything is unpacked, with the selected slot
unchanged. Preserve each trial's `RESULT.json`; report each distribution
separately, including failed runs. A trial that has not run on a distribution
does not qualify it, and a local VM result is not physical-device validation.

The [18 November native Debian matrix](evidence/NATIVE_PACKAGE_MATRIX_20261118.json)
passed all four declared Debian/Ubuntu distributions with rebuilt candidate B. Preserve
the earlier ABI and harness failures. Its downgrade archive is a
[metadata-only fixture](evidence/NATIVE_PACKAGE_DOWNGRADE_FIXTURE_20261118.json), not
a historical release; real cross-release protocol compatibility remains separate.
The current harness prepares system dependencies first, then runs local dpkg or RPM
installation/replacement/repair inside an isolated network namespace. It supplies a
fixed system PATH to guest-exec; an explicit environment replaces guest defaults.
Ubuntu 24.04 exposed apt's local-file `--no-download` behavior and the missing-PATH
harness fault before the final dpkg-based trial passed. Timeouts remain bounded;
failed trials retain package/process diagnostics when the guest is reachable.

The harness now accepts `--family rpm` for `dnf` dependency preparation and native
RPM transactions. Local lifecycle trials now pass on Fedora 45/Rocky Linux 10.3;
full release/protection qualification is still open.
Use publisher-signature/hash-verified images. An unsigned archive
[builds and passes scriptlet/file inspection](evidence/NATIVE_RPM_BUILD_20261118.json)
in an ordinary-user Ubuntu container. The recipe disables automatic global build-ID
links so the archive contains only its declared payload and aliases. Earlier failed
build/inspection results remain preserved. This does not qualify Fedora/Rocky or an
RPM VPN lifecycle.

Fedora's confined QEMU guest agent refused administrative execution before the first
trial reached VPN installation. The RPM-only VM fixture enables the distribution's
`virt_qemu_ga_run_unconfined` boolean and uses a root-only hook in its predefined
QGA hook directory for trusted test administration. This follows the
[Fedora SELinux transition](https://github.com/fedora-selinux/selinux-policy/blob/9d23da6917bb69fc423ab5771c42aed0a13b9e71/policy/modules/contrib/virt_supplementary.te).
The harness verifies that administration context and SELinux enforcing mode; it never
uses permissive mode or installs an extra product allow rule. This grant exists
only in the disposable guest and is recorded as a fixture, not a production setup
recommendation or proof that every product process has a dedicated SELinux domain.

The fixture explicitly enables only the guest-agent RPCs needed for this local
test: ping, delimited synchronization, execution/status and shutdown. RPM/DNF run
as transient root systemd services, the normal administrative execution context;
the VPN's own units and sandbox remain unchanged. RPM trials require an explicitly
pinned public test key and signed test copies; they never bypass package signatures.
Ephemeral software test keys are destroyed after signing and are not production
trust roots.

Both distributions reached install/replace/repair/reboot but initially failed the
authorized controller test. [Fedora diagnostics](evidence/NATIVE_RPM_SELINUX_DIAGNOSTIC_20261118.json)
identified copied `lib_t` labels on application executables instead of the host's
configured `bin_t`. Correcting the application-tree labels let the same bus check
pass with enforcing mode still enabled. The installer now applies `restorecon` to
each newly prepared system slot, using the host's installed mappings, and fsyncs it
before activation. Failure preserves the previous selection. No private state is
relabelled, no allow rule is installed and no enforcement setting changes.

The diagnostic controller used Fedora's default `unconfined_service_t` service
domain. This is a functional label correction, not qualification of a dedicated
confined VPN domain. Such a policy and its full hardware/network-operation tests
remain assurance work. Fresh corrected RPM lifecycle trials are required; the
earlier failed trials remain failed.

The [fresh corrected-candidate trials](evidence/NATIVE_RPM_MATRIX_20261118.json)
subsequently passed on both distributions: signature verification, installation,
downgrade refusal, replacement with previous-slot retention, damaged-code repair,
reboot without activation, real-bus denial and test-authorized operations, armed
removal refusal with zero external probe markers, recovered removal preserving
the private fixture, and reboot with a working positive control. SELinux remained
enforcing. The failed intermediate candidate also exposed `restorecon`'s dispatch
through a `setfiles` symlink; the installer now preserves `restorecon` as argv[0]
while executing the resolved, ownership-checked binary. These unsigned-origin,
software-test-signed candidates are not a production release.

Optional `--rpm-checks` runs native RPM epoch/version/release comparison cases inside
the Debian-family guest. That is compatibility evidence for the comparison function;
it does not replace an actual RPM build, scriptlet transaction or Fedora/Rocky trial.
Separately, [real RPM transactions](evidence/RPM_GUARD_TRANSACTIONS_20261118.json)
with empty disposable packages passed upgrade/reinstall and refused lower version,
release and epoch while preserving installed metadata. They execute the generated
guard and native database machinery, without installing a VPN or changing the host.
Optional `--controller-client` accepts the compiled disposable bus-validation client.
Its positive authorization rule is a VM-only fixture and does not qualify a native
Polkit authentication agent or the desktop's authorization interaction.
