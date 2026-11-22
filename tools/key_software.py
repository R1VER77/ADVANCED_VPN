#!/usr/bin/env python3
"""The distribution packages a detected security key needs, and installing them.

The desktop setup's first stage checks the key; this is its software half. Only the
packages named here can be installed, only from the system's own package sources, and
only through the root controller after the person approves the reviewed plan:

- missing packages are installed as part of setup;
- a newer version of an installed package is only offered: upgrading is a separate,
  explicit approval, since someone may keep an older or custom build on purpose.

The udev rule that gives the desktop user access to a key is the existing
`install_udev_rule` repair (tools/hwkey.py), not a package.
"""

import re
import subprocess

# Every FIDO2 key: libfido2's udev rules mark security keys for the desktop session.
BASE = ("libfido2-1",)
# A key family's own tool, where the distribution ships one. Nitrokey's nitropy and
# Ledger Live are not distribution packages, so nothing is installed for them.
FAMILY = {
    "YubiKey": ("yubikey-manager",),
    "Trezor": ("trezor",),
}
ALLOWED = set(BASE) | {p for v in FAMILY.values() for p in v}
NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{1,62}\Z")
ENV = dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C")


def wanted(families):
    """The packages for these key families (names from hwkey.key_name), in a fixed order."""
    out = list(BASE)
    for family in sorted(set(families)):
        out += [p for p in FAMILY.get(family, ()) if p not in out]
    return out


def installed_version(package, run=subprocess.run):
    """The installed version, or None."""
    r = run(["dpkg-query", "-W", "-f=${Status}\t${Version}", package], capture_output=True, text=True,
            timeout=20, env=ENV)  # fmt: skip
    if r.returncode != 0 or "\t" not in r.stdout:
        return None
    status, version = r.stdout.split("\t", 1)
    return (version.strip() or None) if status.endswith(" installed") else None


def candidate_version(package, run=subprocess.run):
    """The version the system's package sources offer (local cache only), or None."""
    r = run(["apt-cache", "policy", package], capture_output=True, text=True, timeout=30, env=ENV)
    m = re.search(r"^\s*Candidate:\s*(\S+)", r.stdout or "", re.M)
    return m.group(1) if m and m.group(1) != "(none)" else None


def newer(candidate, installed, run=subprocess.run):
    """Whether `candidate` is a newer Debian version than `installed`."""
    r = run(["dpkg", "--compare-versions", installed, "lt", candidate], capture_output=True, timeout=20, env=ENV)
    return r.returncode == 0


def status(families, run=subprocess.run):
    """[{package, installed, candidate, state}] with state ok, missing, upgrade or unavailable."""
    rows = []
    for package in wanted(families):
        have, offer = installed_version(package, run), candidate_version(package, run)
        if have is None:
            state = "missing" if offer else "unavailable"
        elif offer and newer(offer, have, run):
            state = "upgrade"
        else:
            state = "ok"
        rows.append(dict(package=package, installed=have, candidate=offer, state=state))
    return rows


def selection(rows, mode):
    """The packages one approval covers: the missing ones, or (separately) the upgrades."""
    if mode not in ("install", "upgrade"):
        raise ValueError("mode")
    picked = [r["package"] for r in rows if r["state"] == ("missing" if mode == "install" else "upgrade")]
    if any(p not in ALLOWED or not NAME.fullmatch(p) for p in picked):
        raise ValueError("package outside the allowlist")
    return picked


def command(mode, packages):
    """The one command: apt-get in a transient system unit, outside the controller's sandbox
    (dpkg's maintainer scripts need more than the controller's capability set)."""
    if not packages or any(p not in ALLOWED for p in packages):
        raise ValueError("package outside the allowlist")
    apt = ["/usr/bin/apt-get", "install", "-y", "--no-install-recommends"]
    if mode == "upgrade":
        apt.append("--only-upgrade")
    elif mode != "install":
        raise ValueError("mode")
    return ["systemd-run", "--wait", "--collect", "--quiet", "--unit=cypherpunk-key-software",
            "--setenv=DEBIAN_FRONTEND=noninteractive", "--", *apt, "--", *packages]  # fmt: skip
