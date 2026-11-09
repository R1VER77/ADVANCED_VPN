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
    try:
        overflow = int(Path("/proc/sys/kernel/overflowuid").read_text())
    except (OSError, ValueError):
        overflow = -1
    for d in TRUSTED_DIRS:
        p = Path(d) / name
        if not p.exists():
            continue
        real = p.resolve()
        m = real.stat()
        if stat.S_ISREG(m.st_mode) and m.st_uid in (0, overflow) and not m.st_mode & 0o022 and os.access(real, os.X_OK):
            return str(real)
    raise FileNotFoundError("trusted executable not found: " + name)
