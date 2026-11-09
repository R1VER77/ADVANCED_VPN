#!/usr/bin/env python3
"""Explicit privileged TUN handoff; no network/route/DNS creation.

Attach a pre-existing TUN in an isolated application namespace, return to the
underlay namespace, drop to the selected UID/GID, and exec the Rust client.
Requires Python 3.12+ on Linux. Review deployment.md before using outside tests.
"""

import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import struct


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--application-ns", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--uid", type=int, required=True)
    p.add_argument("--gid", type=int, required=True)
    a = p.parse_args()
    if os.geteuid() != 0 or a.uid <= 0 or a.gid <= 0:
        raise ValueError("requires bootstrap root and an explicit non-root service UID/GID")
    if not all(v.is_absolute() for v in [a.application_ns, a.config, a.binary]):
        raise ValueError("absolute paths required")
    # Config belongs to target service UID; inspect it through an opened inode before switching.
    fd = os.open(a.config, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != a.uid or m.st_mode & 0o077 or m.st_size > 65536:
            raise ValueError("invalid service configuration")
        c = json.loads(f.read(65537))
    if c["role"] != "client" or not c["tun"].isalnum() or len(c["tun"]) >= 16:
        raise ValueError("client TUN required")
    current = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    app = os.open(a.application_ns, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    os.setns(app, 0)
    os.close(app)
    tun = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(tun, 0x400454CA, struct.pack("16sH", c["tun"].encode(), 0x1001))
    os.setns(current, 0)
    os.close(current)
    # The service cannot enter a different network namespace after privilege drop.
    os.setgroups([])
    os.setgid(a.gid)
    os.setuid(a.uid)
    os.set_inheritable(tun, True)
    os.execv(a.binary, [str(a.binary), "--config", str(a.config), "--tun-fd", str(tun)])


if __name__ == "__main__":
    main()
