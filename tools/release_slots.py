"""Durable application-only release transactions; never roll back enrollment state.

The caller authenticates the release before building a slot. The manifest below
detects local damage; a self-authored content hash is not a publisher signature.
Only this module's private application directory is mutated. No service is started
and no firewall, replay counter, profile, vault or key directory is accepted here.
"""

import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

MANIFEST = "CYPHERPUNK_RELEASE.json"
SLOT = re.compile(r"[a-f0-9]{64}-[a-f0-9]{16}\Z")
PHASES = {"prepared", "activated", "committed", "rolled_back"}
ALIASES = {
    "app",
    "bin",
    "tools",
    "venv",
    "third_party",
    "docs",
    "deploy",
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
}


def sync_directory(path):
    """Persist directory entry updates on the installation's own filesystem."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def checked_directory(path):
    """Refuse symlinks, foreign ownership and writable application directories."""
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o7022:
        raise ValueError("unsafe application directory: " + str(path))


def digest(path):
    """Hash regular file contents in bounded memory."""
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def inventory(root):
    """Reject special files and links outside the immutable application slot."""
    checked_directory(root)
    resolved = root.resolve(strict=True)
    result = {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if name == MANIFEST:
            continue
        info = path.lstat()
        if info.st_uid != os.geteuid():
            raise ValueError("foreign-owned slot entry: " + name)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            try:
                inside = not Path(target).is_absolute() and path.resolve(strict=True).is_relative_to(resolved)
            except (OSError, RuntimeError):
                inside = False
            if not inside:
                raise ValueError("slot link escapes application: " + name)
            result[name] = dict(kind="link", target=target)
        elif stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
            if info.st_mode & 0o7022:
                raise ValueError("unsafe slot permissions: " + name)
            entry = dict(kind="directory" if path.is_dir() else "file", mode=stat.S_IMODE(info.st_mode))
            if path.is_file():
                entry.update(size=info.st_size, sha256=digest(path))
            result[name] = entry
        else:
            raise ValueError("special file in application slot: " + name)
    return result


def read_json(path):
    """Bound metadata reads and refuse an attacker-controlled link or file."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o7022
            or info.st_size > 16 << 20
        ):
            raise ValueError("unsafe release metadata")
        with os.fdopen(fd, "r", closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(fd)


def durable_json(path, value):
    """Create exclusively, fsync, atomically replace, then fsync the parent."""
    fd, name = tempfile.mkstemp(prefix=".metadata-", dir=path.parent)
    pending = Path(name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        sync_directory(path.parent)
    finally:
        pending.unlink(missing_ok=True)


def sync_tree(root):
    """Persist slot bytes before making its pointer visible."""
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    directories = [p for p in root.rglob("*") if p.is_dir() and not p.is_symlink()]
    for path in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        sync_directory(path)
    sync_directory(root)


class Store:
    """One exclusive transaction owner; keep all old slots until explicit safe pruning."""

    def __init__(self, root):
        self.root = Path(root).absolute()
        self.releases = self.root / "releases"
        self.journal = self.root / "TRANSACTION.json"
        self.locked = False

    @contextlib.contextmanager
    def transaction(self):
        """The lock covers recovery, preparation, activation and post-activation checks."""
        if self.locked:
            raise RuntimeError("release transaction already held")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        checked_directory(self.root)
        self.releases.mkdir(mode=0o700, exist_ok=True)
        checked_directory(self.releases)
        fd = os.open(self.root / ".upgrade.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("unsafe upgrade lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.locked = True
            self.recover()
            self.recover_adoption()
            yield self
        finally:
            self.locked = False
            os.close(fd)

    def require_lock(self):
        """Mutations through an unlocked store are programming errors."""
        if not self.locked:
            raise RuntimeError("release operation requires the exclusive upgrade lock")

    def slot_path(self, name):
        """Journal and pointer strings can only identify direct release children."""
        if not isinstance(name, str) or not SLOT.fullmatch(name):
            raise ValueError("invalid release slot name")
        path = self.releases / name
        checked_directory(path)
        return path

    def current(self):
        """Read exactly one relative pointer without accepting an arbitrary pathname."""
        path = self.root / "current"
        if not path.exists() and not path.is_symlink():
            return None
        if not path.is_symlink():
            raise ValueError("current release must be a relative symbolic link")
        target = os.readlink(path)
        prefix = "releases/"
        if not target.startswith(prefix):
            raise ValueError("current release is outside the store")
        name = target[len(prefix) :]
        self.slot_path(name)
        return name

    def verify(self, name):
        """Verify every file, directory, permission and link before selecting a slot."""
        path = self.slot_path(name)
        manifest = read_json(path / MANIFEST)
        if not isinstance(manifest, dict) or manifest.get("schema") != 1 or inventory(path) != manifest.get("entries"):
            raise ValueError("application slot differs from its manifest")
        content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(content).hexdigest() != name[:64]:
            raise ValueError("application manifest does not match slot identity")
        return path

    def prepare(self, builder):
        """Build privately, seal contents, sync, rename and verify without activation."""
        self.require_lock()
        stage = Path(tempfile.mkdtemp(prefix=".prepare-", dir=self.releases))
        try:
            builder(stage)
            manifest = dict(schema=1, entries=inventory(stage))
            content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            name = hashlib.sha256(content).hexdigest() + "-" + uuid.uuid4().hex[:16]
            durable_json(stage / MANIFEST, manifest)
            sync_tree(stage)
            path = self.releases / name
            stage.rename(path)
            sync_directory(self.releases)
            self.verify(name)
            return name
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def pointer(self, name):
        """Only application bytes move; retained security state has no rollback path."""
        self.require_lock()
        if name is None:
            (self.root / "current").unlink(missing_ok=True)
        else:
            self.verify(name)
            pending = self.root / (".current-" + uuid.uuid4().hex)
            try:
                pending.symlink_to("releases/" + name)
                os.replace(pending, self.root / "current")
            finally:
                pending.unlink(missing_ok=True)
        sync_directory(self.root)

    def activate(self, name, check, repair_damaged=False):
        """Roll back a failed application check; do not restart or activate any service."""
        self.require_lock()
        self.verify(name)
        previous = self.current()
        unusable = None
        if previous is not None:
            try:
                self.verify(previous)
            except (ValueError, OSError):
                if not repair_damaged:
                    raise
                # A damaged application is retained as evidence, never selected
                # as a rollback target. Independent boot protection stays put.
                unusable, previous = previous, None
        record = dict(schema=1, phase="prepared", previous=previous, candidate=name)
        if unusable is not None:
            record["unusable_previous"] = unusable
        durable_json(self.journal, record)
        try:
            self.pointer(name)
            record["phase"] = "activated"
            durable_json(self.journal, record)
            check(self.verify(name))
            record["phase"] = "committed"
            durable_json(self.journal, record)
        except BaseException:
            # A failed rollback is itself surfaced, leaving the durable journal
            # for a later locked recovery. Never report a commit on uncertainty.
            self.pointer(previous)
            record["phase"] = "rolled_back"
            durable_json(self.journal, record)
            raise
        return self.slot_path(name)

    def recover(self):
        """Recover a torn pointer/journal transition using only verified local slots."""
        self.require_lock()
        if not self.journal.exists() and not self.journal.is_symlink():
            return
        record = read_json(self.journal)
        if not isinstance(record, dict) or record.get("schema") != 1 or record.get("phase") not in PHASES:
            raise ValueError("unrecognized release transaction journal")
        self.slot_path(record.get("candidate"))
        previous = record.get("previous")
        if previous is not None:
            self.slot_path(previous)
        unusable = record.get("unusable_previous")
        if unusable is not None:
            self.slot_path(unusable)
            if previous is not None or unusable == record["candidate"]:
                raise ValueError("invalid damaged-slot recovery journal")
        if record["phase"] in {"prepared", "activated"}:
            actual = self.current()
            if actual not in (previous, record["candidate"], unusable):
                raise ValueError("release pointer changed outside the recorded transaction")
            self.pointer(previous)
            record["phase"] = "rolled_back"
            durable_json(self.journal, record)
        elif self.current() != (record["candidate"] if record["phase"] == "committed" else previous):
            raise ValueError("release pointer disagrees with completed transaction")

    def exchange(self, first, second):
        """Linux atomic exchange preserves a usable path even across directory/link migration."""
        self.require_lock()
        if first not in ALIASES or not re.fullmatch(r"\.adopt-[a-f0-9]{32}", second):
            raise ValueError("invalid application exchange names")
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            rename = libc.renameat2
        except AttributeError:
            raise RuntimeError("atomic legacy migration needs Linux renameat2") from None
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if rename(fd, os.fsencode(first), fd, os.fsencode(second), 2) != 0:  # RENAME_EXCHANGE
                code = ctypes.get_errno()
                raise OSError(code, "atomic legacy exchange refused")
        finally:
            os.close(fd)
        sync_directory(self.root)

    def adopt(self, candidate, names):
        """Adopt an explicitly approved, quiescent flat tree; retain all original inodes.

        The caller first builds/verifies CANDIDATE from the old application and
        checks no old application process is using its unpinned paths. Every alias
        changes with atomic exchange; loss of power never leaves its name absent.
        """
        self.require_lock()
        if self.current() is not None or not names or not set(names) <= ALIASES:
            raise ValueError("legacy adoption requires one unselected known application tree")
        if (self.root / "ADOPTION.json").exists() or (self.root / "legacy-flat").exists():
            raise ValueError("legacy adoption metadata already exists")
        entries = []
        for name in sorted(set(names)):
            original = (self.root / name).lstat()
            if original.st_uid != os.geteuid():
                raise ValueError("foreign legacy application entry")
            entries.append(
                dict(name=name, temporary=".adopt-" + uuid.uuid4().hex, device=original.st_dev, inode=original.st_ino)
            )
        self.verify(candidate)
        record = dict(schema=1, phase="prepared", candidate=candidate, entries=entries)
        durable_json(self.root / "ADOPTION.json", record)
        self.activate(candidate, lambda _: None)
        self.recover_adoption()

    def recover_adoption(self):
        """Resume idempotently from before/after each exchange without clearing state."""
        self.require_lock()
        path = self.root / "ADOPTION.json"
        if not path.exists() and not path.is_symlink():
            return
        record = read_json(path)
        if (
            not isinstance(record, dict)
            or record.get("schema") != 1
            or record.get("phase") not in ("prepared", "complete")
            or not isinstance(record.get("entries"), list)
            or not 1 <= len(record["entries"]) <= len(ALIASES)
        ):
            raise ValueError("invalid legacy adoption journal")
        if record["phase"] == "complete":
            return
        candidate = record.get("candidate")
        self.verify(candidate)
        if self.current() is None:
            # Interrupted before the initial activation's durable commit. Select
            # the same verified legacy bytes before exposing any aliases.
            self.activate(candidate, lambda _: None)
        if self.current() != candidate:
            raise ValueError("application pointer changed during legacy adoption")
        backup = self.root / "legacy-flat"
        backup.mkdir(mode=0o700, exist_ok=True)
        checked_directory(backup)
        seen = set()
        for entry in record["entries"]:
            name = entry.get("name")
            temporary = entry.get("temporary")
            if (
                name not in ALIASES
                or name in seen
                or not isinstance(temporary, str)
                or not re.fullmatch(r"\.adopt-[a-f0-9]{32}", temporary)
                or type(entry.get("device")) is not int
                or type(entry.get("inode")) is not int
            ):
                raise ValueError("invalid legacy adoption entry")
            seen.add(name)
            alias, pending, saved = self.root / name, self.root / temporary, backup / name
            target = "current" if name == "app" else "current/" + name

            def original_identity(node, expected=(entry["device"], entry["inode"])):
                try:
                    meta = node.lstat()
                    return meta.st_uid == os.geteuid() and (meta.st_dev, meta.st_ino) == expected
                except FileNotFoundError:
                    return False

            if original_identity(alias):
                if not pending.exists() and not pending.is_symlink():
                    pending.symlink_to(target)
                    sync_directory(self.root)
                if not pending.is_symlink() or os.readlink(pending) != target:
                    raise ValueError("legacy exchange staging path changed")
                self.exchange(name, temporary)
            if not alias.is_symlink() or os.readlink(alias) != target:
                raise ValueError("legacy alias changed outside adoption")
            if original_identity(pending):
                if saved.exists() or saved.is_symlink():
                    raise ValueError("legacy backup already exists")
                pending.rename(saved)
                sync_directory(backup)
                sync_directory(self.root)
            elif not original_identity(saved):
                raise ValueError("original legacy application entry is missing")
        record["phase"] = "complete"
        durable_json(path, record)
