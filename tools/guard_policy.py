"""Persist explicit whole-device opt-in independently of replaceable application slots.

Only explicit reset with cleartext approval disarms it. Installation stages the
native guard and unit; arming never happens merely because a package was installed.
"""

import os
import json
from pathlib import Path
import stat
import subprocess

from keyguard import atomic, read_private
from sysexec import trusted_exe

MARKER = Path("/etc/advanced-vpn/whole-device.guard")
MARKER_BYTES = b"cypherpunk-vpn whole-device guard v1\n"
NATIVE = Path("/usr/libexec/cypherpunk-vpn-bootguard")
UNIT = "advanced-vpn-guard.service"
POLICY = json.loads((Path(__file__).resolve().parents[1] / "deploy/bootguard-policy.json").read_text())
if POLICY.get("schema") != 1:
    raise ValueError("unknown boot guard dependency policy")
MANAGERS = tuple(POLICY["managers"])
DROPIN = POLICY["dropin"]
REQUIRE = POLICY["requires"].encode()
STATE = Path("/etc/advanced-vpn/enrolled")
UNITS = Path("/etc/systemd/system")


def protected_directory(path):
    """Private policy or system-unit directories must be real and root-owned."""
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError("unsafe persistent guard directory")


def native_guard():
    """Only the stable system guard, outside /opt application slots, is executable."""
    meta = NATIVE.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or not meta.st_mode & 0o111:
        raise ValueError("independent native boot guard is unavailable")
    protected_directory(NATIVE.parent)
    return str(NATIVE)


def arm(apply=False, state=STATE):
    """Durable deny intent precedes dependencies/network changes; no implicit disarm."""
    if os.geteuid() != 0:
        raise PermissionError("persistent guard requires root")
    if Path(state).resolve() != STATE:
        raise ValueError("persistent whole-device guard requires the installed default state")
    program = native_guard()
    MARKER.parent.mkdir(mode=0o700, exist_ok=True)
    protected_directory(MARKER.parent)
    if MARKER.exists() or MARKER.is_symlink():
        if read_private(MARKER) != MARKER_BYTES:
            raise ValueError("unrecognized persistent guard marker; protection is retained")
    else:
        atomic(MARKER, MARKER_BYTES)
    units = UNITS
    protected_directory(units)
    for manager in MANAGERS:
        parent = units / (manager + ".d")
        parent.mkdir(mode=0o755, exist_ok=True)
        protected_directory(parent)
        path = parent / DROPIN
        if path.exists() or path.is_symlink():
            if (
                path.is_symlink()
                or path.read_bytes() != REQUIRE
                or path.stat().st_uid != 0
                or path.stat().st_mode & 0o022
            ):
                raise ValueError("foreign guard dependency; protection is retained")
        else:
            atomic(path, REQUIRE)
    systemctl = trusted_exe("systemctl")
    subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)
    subprocess.run([systemctl, "enable", UNIT], check=True, timeout=15)
    if apply:
        subprocess.run([program], check=True, timeout=15)


def disarm(state=STATE):
    """Called only by the controller's explicit reset --allow-cleartext path."""
    if os.geteuid() != 0:
        raise PermissionError("persistent guard requires root")
    if Path(state).resolve() != STATE:
        raise ValueError("a different state cannot disarm the installed device's guard")
    if MARKER.exists() or MARKER.is_symlink():
        if read_private(MARKER) != MARKER_BYTES:
            raise ValueError("foreign persistent guard marker; removal refused")
    paths = []
    for manager in MANAGERS:
        path = UNITS / (manager + ".d") / DROPIN
        if path.exists() or path.is_symlink():
            protected_directory(path.parent)
            if (
                path.is_symlink()
                or path.stat().st_uid != 0
                or path.stat().st_mode & 0o022
                or path.read_bytes() != REQUIRE
            ):
                raise ValueError("foreign guard dependency; removal refused")
            paths.append(path)
    systemctl = trusted_exe("systemctl")
    # Disable first; a crash at any intermediate point can still leave the marker
    # and native deny policy in place, which is stricter than the approved reset.
    subprocess.run([systemctl, "disable", UNIT], check=True, timeout=15)
    for path in paths:
        path.unlink()
        from release_slots import sync_directory

        sync_directory(path.parent)
    MARKER.unlink(missing_ok=True)
    if MARKER.parent.exists():
        from release_slots import sync_directory

        sync_directory(MARKER.parent)
    subprocess.run([systemctl, "daemon-reload"], check=True, timeout=15)
