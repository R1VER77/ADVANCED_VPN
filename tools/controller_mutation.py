"""Serialize cooperating short controller mutations across CLI and desktop entry points."""

import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import threading

_registry_lock = threading.Lock()
_registry = {}


@contextlib.contextmanager
def locked(state):
    """Reentrant within one thread, exclusive across processes; never locks status reads."""
    import avpnctl

    if os.geteuid() == 0:
        root = avpnctl.runtime_dir(state)
    else:
        # Ordinary-user operator key generation also cooperates, without asking
        # that user to create or access root's /run controller directory.
        base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "cypherpunk-vpn/locks"
        root = base / hashlib.sha256(str(Path(state).resolve()).encode()).hexdigest()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("unsafe operator mutation-lock directory")
    key = (os.getpid(), str(root))
    with _registry_lock:
        entry = _registry.setdefault(key, dict(lock=threading.RLock(), local=threading.local()))
    with entry["lock"]:
        local = entry["local"]
        depth = getattr(local, "depth", 0)
        if depth:
            local.depth += 1
            try:
                yield
            finally:
                local.depth -= 1
            return
        fd = os.open(root / "actions.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("invalid controller mutation lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            local.depth = 1
            try:
                yield
            finally:
                local.depth = 0
        finally:
            os.close(fd)
