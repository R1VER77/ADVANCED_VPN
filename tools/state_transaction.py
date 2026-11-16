"""Exclusive, descriptor-validated transactions for local secret state.

This serializes cooperating processes and threads. It is not protection against an
attacker restoring a complete filesystem snapshot or controlling the kernel.
"""

import contextlib
import fcntl
import os
import stat


@contextlib.contextmanager
def locked_file(path):
    """Lock an existing private regular file through a fresh descriptor per operation."""
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise ValueError("invalid private state file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def directory(path):
    """Serialize a directory's state using a stable private lock file, never renamed."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        meta = os.fstat(fd)
        if meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
            raise ValueError("invalid private state directory")
        lock = os.open(".state.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            lm = os.fstat(lock)
            if not stat.S_ISREG(lm.st_mode) or lm.st_uid != os.geteuid() or lm.st_mode & 0o077:
                raise ValueError("invalid state lock")
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock)
    finally:
        os.close(fd)
