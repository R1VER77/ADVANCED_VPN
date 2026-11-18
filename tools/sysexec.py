"""Trusted resolution of system executables for root-run commands.

Standard library only: the installer imports this before the hash-locked
environment (and its third-party packages) exists."""

import os
from pathlib import Path
import stat


TRUSTED_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def trusted_exe(name):
    """Absolute path of a system executable, never taken from $PATH.

    Root-run commands resolve only inside fixed system directories, and the binary
    must be owned by root (or by the unmapped real root inside a test user
    namespace) and not writable by group or others."""
    if "/" in name or not name:
        raise ValueError("bare executable name required")
    owners = {0}
    try:
        mappings = [tuple(map(int, line.split())) for line in Path("/proc/self/uid_map").read_text().splitlines()]
        # Unmapped host root is trusted only inside an actual unprivileged test
        # namespace. A real root process must never trust a nobody-owned program.
        if os.geteuid() == 0 and mappings and not any(start == 0 for _, start, count in mappings if count):
            owners.add(int(Path("/proc/sys/kernel/overflowuid").read_text()))
    except (OSError, ValueError):
        pass
    for d in TRUSTED_DIRS:
        p = Path(d) / name
        if not p.exists():
            continue
        real = p.resolve()
        m = real.stat()
        if (
            stat.S_ISREG(m.st_mode)
            and m.st_uid in owners
            and not m.st_mode & 0o022
            and os.access(real, os.X_OK)
            and all(parent.stat().st_uid in owners and not parent.stat().st_mode & 0o022 for parent in real.parents)
        ):
            return str(real)
    raise FileNotFoundError("trusted executable not found: " + name)
