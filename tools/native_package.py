#!/usr/bin/env python3
"""Build offline native Linux packages as an ordinary user, without activation.

Package-manager signatures/provenance must authenticate the output before root
installation. Local checksums and runtime manifests are damage checks, not signatures.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

import bundled_runtime
import install
from release_slots import inventory
from sysexec import trusted_exe

PAYLOAD = "/usr/lib/cypherpunk-vpn/payload"
COMMANDS = {"cypherpunk": "avpn", "avpn": "avpn", "avpnctl": "avpnctl"}
ROOT = Path(__file__).resolve().parents[1]


def version(root):
    """A bounded upstream version cannot inject package metadata or shell syntax."""
    found = re.search(r'^version\s*=\s*"([^"]+)"', (root / "Cargo.toml").read_text(), re.MULTILINE)
    if not found or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?", found[1]):
        raise ValueError("invalid package version")
    return found[1]


def preinstall():
    """Refuse foreign commands and unreviewed adoption before package extraction."""
    return """#!/bin/sh
set -eu
if [ -e /opt/advanced-vpn ] || [ -L /opt/advanced-vpn ]; then
    marker=/var/lib/cypherpunk-vpn/package-owner
    if [ ! -f "$marker" ] || [ -L "$marker" ] ||
       [ "$(/usr/bin/stat -c '%u:%a' /var/lib/cypherpunk-vpn)" != 0:700 ] ||
       [ "$(/usr/bin/stat -c '%u:%a' "$marker")" != 0:600 ] ||
       [ "$(/usr/bin/cat "$marker")" != 'cypherpunk-vpn package ownership v1' ]; then
        printf '%s\\n' 'Unmanaged installation retained. Explicitly adopt using a verified offline release with --apply --adopt-legacy --package-managed before package installation.' >&2
        exit 1
    fi
fi
for name in avpn avpnctl cypherpunk; do
    command=/usr/bin/$name
    target=/opt/advanced-vpn/bin/$name
    [ "$name" != cypherpunk ] || target=/opt/advanced-vpn/bin/avpn
    if [ -e "$command" ] || [ -L "$command" ]; then
        if [ ! -L "$command" ] || [ "$(/usr/bin/readlink "$command")" != "$target" ]; then
            printf '%s\\n' "Foreign command retained: $command" >&2
            exit 1
        fi
    fi
done
"""


def configure(debian=True):
    """The verified bundled runtime installs slots and units without starting them."""
    action = "exec " + PAYLOAD + "/install.sh --apply --package-managed\n"
    if debian:
        action = 'case "${1:-}" in configure)\n' + action + ";; esac\n"
    return "#!/bin/sh\nset -eu\n" + action


def remove(debian=True):
    """Removal never disables a guard or stops a running operation implicitly."""
    condition = 'case "${1:-}" in remove|deconfigure)' if debian else 'if [ "${1:-1}" -eq 0 ]; then'
    end = ";; esac" if debian else "fi"
    return (
        "#!/bin/sh\nset -eu\n"
        + condition
        + "\n"
        + PAYLOAD
        + "/install.sh --apply --package-managed --uninstall\n"
        + end
        + "\n"
    )


def stage(root, runtime, destination):
    """Copy only the reviewed release inputs and pinned runtime into a new payload."""
    bundled_runtime.verify(runtime, root / "tools/hardware-requirements.txt")
    destination.mkdir(mode=0o755, parents=True, exist_ok=False)
    payload = destination / PAYLOAD.lstrip("/")
    payload.mkdir(mode=0o755, parents=True)
    for name in install.SOURCES:
        source = root / name
        target = payload / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(source, target)
    binaries = payload / "target/release"
    binaries.mkdir(mode=0o755, parents=True)
    for name in install.BINARIES:
        shutil.copy2(root / "target/release" / name, binaries / name)
    shutil.copytree(runtime, payload / "runtime", symlinks=True)
    shutil.copy2(root / "tools/install-offline.sh", payload / "install.sh")
    for path in [destination, *destination.rglob("*")]:
        if not path.is_symlink():
            if path.is_dir():
                path.chmod(0o755)
            else:
                path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    (payload / "install.sh").chmod(0o755)
    bundled_runtime.verify(payload / "runtime", payload / "tools/hardware-requirements.txt")
    # Validate links/special files before adding the three fixed absolute aliases.
    contents = inventory(payload)
    (payload / "PACKAGE_CONTENTS.json").write_text(json.dumps(dict(schema=1, entries=contents), sort_keys=True) + "\n")
    (payload / "PACKAGE_CONTENTS.json").chmod(0o644)
    bindir = destination / "usr/bin"
    bindir.mkdir(mode=0o755, parents=True)
    for name, target in COMMANDS.items():
        (bindir / name).symlink_to("/opt/advanced-vpn/bin/" + target)
    return payload


def debian(root, runtime, output, epoch):
    """Build root-owned dpkg metadata without running package scripts or sudo."""
    number = version(root).replace("-", "~", 1) + "-1"
    package = output / ("cypherpunk-vpn_" + number + "_amd64.deb")
    if package.exists():
        raise FileExistsError("package output already exists")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-deb-", dir=output) as temporary:
        tree = Path(temporary) / "root"
        stage(root, runtime, tree)
        control = tree / "DEBIAN"
        control.mkdir(mode=0o755)
        (control / "control").write_text(
            "Package: cypherpunk-vpn\nVersion: " + number + "\nArchitecture: amd64\n"
            "Maintainer: Anonymous\nSection: net\nPriority: optional\n"
            "Depends: libc6 (>= 2.35), libgcc-s1, systemd, nftables, iproute2, mount, passwd, dbus, polkitd | policykit-1\n"
            "Homepage: https://github.com/R1VER77/ADVANCED_VPN\n"
            "Description: cypherpunk_vpn private network controller\n"
            " Offline application slots and an independent opt-in boot guard.\n"
            " Installation never starts a tunnel or enrolls a device.\n"
        )
        (control / "control").chmod(0o644)
        for name, text in (("preinst", preinstall()), ("postinst", configure()), ("prerm", remove())):
            install.launcher(control / name, text.removeprefix("#!/bin/sh\n").rstrip("\n"))
        environment = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
        subprocess.run(
            [trusted_exe("dpkg-deb"), "--root-owner-group", "--build", str(tree), str(package)],
            check=True,
            env=environment,
            timeout=300,
        )
    return package


def rpm_spec(number):
    """Render an offline RPM recipe with the same reviewed lifecycle hooks."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", number):
        raise ValueError("RPM builds currently require a stable upstream version")
    return f"""%global __os_install_post %{{nil}}
%global debug_package %{{nil}}
Name: cypherpunk-vpn
Version: {number}
Release: 1
Summary: cypherpunk_vpn private network controller
License: AGPL-3.0-or-later
URL: https://github.com/R1VER77/ADVANCED_VPN
Source0: payload.tar
BuildArch: x86_64
Requires: glibc >= 2.35, libgcc, systemd, nftables, iproute, util-linux, shadow-utils, dbus, polkit
AutoReqProv: no
%description
Offline application slots and an independent opt-in boot guard. No activation on install.
See the bundled LICENSE for the project's additional exception.
%prep
%build
%install
mkdir -p %{{buildroot}}
tar -xf %{{SOURCE0}} -C %{{buildroot}}
%pre
{preinstall().removeprefix("#!/bin/sh" + chr(10)).replace("%", "%%")}
%post
{configure(False).removeprefix("#!/bin/sh" + chr(10))}
%preun
{remove(False).removeprefix("#!/bin/sh" + chr(10))}
%files
%defattr(-,root,root,-)
/usr/lib/cypherpunk-vpn
/usr/bin/avpn
/usr/bin/avpnctl
/usr/bin/cypherpunk
"""


def rpm(root, runtime, output, epoch):
    """Build the RPM with unprivileged rpmbuild; no package scripts are executed."""
    number = version(root)
    spec = rpm_spec(number)
    executable = trusted_exe("rpmbuild")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-rpm-", dir=output) as temporary:
        top = Path(temporary)
        tree = top / "payload"
        stage(root, runtime, tree)
        for name in ("SOURCES", "SPECS", "BUILD", "BUILDROOT", "RPMS", "SRPMS"):
            (top / name).mkdir(mode=0o755)
        with tarfile.open(top / "SOURCES/payload.tar", "w") as archive:

            def normalize(member):
                member.uid = member.gid = 0
                member.uname = member.gname = "root"
                member.mtime = epoch
                return member

            archive.add(tree / "usr", arcname="usr", filter=normalize)
        recipe = top / "SPECS/cypherpunk-vpn.spec"
        recipe.write_text(spec)
        subprocess.run(
            [executable, "-bb", "--define", "_topdir " + str(top), "--define", "_buildhost localhost", str(recipe)],
            check=True,
            env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)),
            timeout=300,
        )
        built = list((top / "RPMS").rglob("*.rpm"))
        if len(built) != 1:
            raise ValueError("unexpected RPM outputs")
        package = output / built[0].name
        if package.exists():
            raise FileExistsError("package output already exists")
        shutil.copy2(built[0], package)
    return package


def main():
    """Build an unsigned candidate; publishing requires the project's signing gates."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--format", choices=("deb", "rpm", "both"), default="deb")
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise PermissionError("build packages as an ordinary user")
    if args.epoch < 0:
        raise ValueError("invalid reproducible-build epoch")
    args.out.mkdir(mode=0o755, parents=True, exist_ok=False)
    packages = []
    for name, builder in (("deb", debian), ("rpm", rpm)):
        if args.format in (name, "both"):
            package = builder(args.source.resolve(), args.runtime.resolve(), args.out, args.epoch)
            packages.append(
                dict(name=package.name, sha256=bundled_runtime.sha256(package), size=package.stat().st_size)
            )
    (args.out / "BUILD.json").write_text(
        json.dumps(dict(schema=1, status="unsigned_unqualified_candidate", packages=packages), indent=2) + "\n"
    )
    print(json.dumps(packages, indent=2))


if __name__ == "__main__":
    main()
