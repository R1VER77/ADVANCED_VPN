#!/usr/bin/env python3
"""Experimental deniable store v2: eight layers, paired authenticated headers.

Only completed transactions promise durable replacement. Data is copy-on-write;
header generations are encrypted. A torn replacement leaves an authenticated prior
or committed root. Obsolete roots and blocks are scrubbed before a successful return.

This does not defeat complete snapshot rollback, flash remanence, hostile kernels or
multiple-image analysis. Erasure is conditional on filesystem/storage behavior. A
lower layer cannot see higher layers and can overwrite them; open decoys read-only
under coercion. V1 stores are never migrated or modified automatically: provision a
fresh v2 store. Unused storage remains random-looking and file size is fixed.
"""

import argparse
import contextlib
import copy
import getpass
import hashlib
import json
import os
import secrets
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyguard  # noqa: E402
import padbook  # noqa: E402
import state_transaction  # noqa: E402

LAYERS = 8
SLOTS = 2 * LAYERS
SLOT = BLOCK = 4096
NONCE, TAGS, SALT = 12, 32, 32
PAYLOAD = BLOCK - NONCE - TAGS
HEADER = SLOT - SALT - NONCE - TAGS
DEFAULT_MIB = 64


def layer_salt(passphrase):
    """Hardware hmac-secret context; distinct from the unsupported v1 format."""
    if not passphrase:
        raise ValueError("a layer needs a passphrase")
    return hashlib.sha256(b"cypherpunk-vpn/padstore/v2|layer|" + passphrase.encode()).digest()


def _slot_keys(layer_secret, salt):
    return padbook._hkdf(layer_secret + salt, b"padstore/v2/slot", 64)


def _aad(slot):
    return b"padstore/v2/slot|" + slot.to_bytes(4, "big")


def create(path, mib=DEFAULT_MIB):
    """Create a private fixed-size random-filled v2 container without replacing anything."""
    if not isinstance(mib, int) or mib < 1:
        raise ValueError("store size must be a positive integer MiB")
    path = Path(path)
    size = SLOTS * SLOT + (mib * (1 << 20) // BLOCK) * BLOCK
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as f:
        while size:
            n = min(size, 1 << 20)
            f.write(os.urandom(n))
            size -= n
        f.flush()
        os.fsync(f.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return path


def _pad(header):
    blob = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    if 4 + len(blob) > HEADER:
        raise RuntimeError("layer header full: too many files or extents")
    return len(blob).to_bytes(4, "big") + blob + bytes(HEADER - 4 - len(blob))


def _unpad(plain):
    n = int.from_bytes(plain[:4], "big")
    if not 0 < n <= len(plain) - 4:
        raise ValueError("invalid layer header")
    return json.loads(plain[4 : 4 + n])


def _extents(blocks):
    out = []
    for b in blocks:  # Preserve file order: COW substitutions need not be monotonic.
        if out and out[-1][0] + out[-1][1] == b:
            out[-1][1] += 1
        else:
            out.append([b, 1])
    return out


def _blocks(extents):
    return [s + i for s, n in extents for i in range(n)]


def _owned(header):
    return {b for f in header["files"].values() for b in _blocks(f["extents"])}


class Store:
    """A private container; one descriptor lock serializes all its layer transactions."""

    def __init__(self, path):
        self.path = Path(path)
        self._local = threading.local()
        with self.locked():
            size = os.fstat(self._local.fd).st_size
            if size < SLOTS * SLOT + BLOCK or (size - SLOTS * SLOT) % BLOCK:
                raise ValueError("not a store")
            self.blocks = (size - SLOTS * SLOT) // BLOCK

    @contextlib.contextmanager
    def locked(self):
        """Lock through a fresh descriptor; nesting on this Store reuses its transaction."""
        if getattr(self._local, "fd", None) is not None:
            yield
            return
        with state_transaction.locked_file(self.path) as fd:
            self._local.fd, self._local.layers = fd, {}
            try:
                yield
            finally:
                self._local.fd = None
                self._local.layers = {}

    def _read(self, offset, n):
        with self.locked():
            data = os.pread(self._local.fd, n, offset)
            if len(data) != n:
                raise OSError("short container read")
            return data

    def _write(self, offset, data):
        with self.locked():
            done = 0
            while done < len(data):
                n = os.pwrite(self._local.fd, data[done:], offset + done)
                if n <= 0:
                    raise OSError("short container write")
                done += n

    def _sync(self):
        os.fsync(self._local.fd)

    def _try_slot(self, i, root):
        raw = self._read(i * SLOT, SLOT)
        salt, nonce, ct = raw[:SALT], raw[SALT : SALT + NONCE], raw[SALT + NONCE :]
        try:
            h = _unpad(padbook.cascade_open(_slot_keys(root, salt), nonce, ct, _aad(i)))
            if h.get("v") != 2 or h["logical"] != i // 2 or not 0 <= h["generation"] < 2**64:
                return None
            if len(bytes.fromhex(h["id"])) != 16 or len(bytes.fromhex(h["data"])) != 64:
                return None
            blocks = [b for f in h["files"].values() for b in _blocks(f["extents"])]
            if len(blocks) != len(set(blocks)) or any(not 0 <= b < self.blocks for b in blocks):
                return None
            for f in h["files"].values():
                if not 0 <= f["size"] <= len(_blocks(f["extents"])) * PAYLOAD:
                    return None
            return h
        except (ValueError, KeyError, TypeError):
            return None
        except Exception:  # Wrong keys and damaged AEAD tags reveal no layer information.
            return None

    def _select(self, root, slots):
        valid = [(i, h) for i in slots if (h := self._try_slot(i, root)) is not None]
        if not valid:
            raise LookupError("no layer opens with this key")
        if len({(h["id"], h["logical"]) for _, h in valid}) != 1:
            raise ValueError("conflicting layer headers")
        highest = max(h["generation"] for _, h in valid)
        choices = [(i, h) for i, h in valid if h["generation"] == highest]
        if len(choices) == 2 and choices[0][1] != choices[1][1]:
            raise ValueError("conflicting layer generations")
        i, h = choices[0]
        return Layer(self, h["logical"], root, h, i)

    def _pair(self, root, slot):
        if not 0 <= slot < LAYERS:
            raise ValueError("invalid layer reference")
        return self._select(root, [2 * slot, 2 * slot + 1])

    def open(self, layer_secret):
        """Try every physical header, choosing the newest authenticated v2 generation."""
        with self.locked():
            return self._select(bytes(layer_secret), range(SLOTS))

    def first_layer(self, layer_secret):
        """Create the bottom layer. Unknown hidden layers cannot be protected from this."""
        return self._add(layer_secret, None)

    def add_layer(self, layer_secret, top):
        """Create a nested layer that knows all lower layers through their root keys."""
        return self._add(layer_secret, top)

    def _add(self, root, top):
        root = bytes(root)
        with self.locked():
            try:
                self.open(root)
            except LookupError:
                pass
            else:
                raise ValueError("this key already opens a layer")
            if top is not None:
                if self.path.resolve() != top.store.path.resolve():
                    raise ValueError("lower layer belongs to another container")
                top = self._pair(top.keys, top.slot)
            known = {} if top is None else top.known()
            free = [i for i in range(LAYERS) if i not in known]
            if not free:
                raise RuntimeError("every slot is in use")
            slot = free[secrets.randbelow(len(free))]
            h = dict(
                v=2,
                logical=slot,
                id=os.urandom(16).hex(),
                generation=-1,
                level=0 if top is None else top.header["level"] + 1,
                data=os.urandom(64).hex(),
                files={},
                lower=[dict(slot=l.slot, root=l.keys.hex()) for l in known.values()],
            )
            layer = Layer(self, slot, root, h, 2 * slot + 1, new=True)
            with layer.transaction():
                layer._tx().dirty = True
            return layer


class _Transaction:
    def __init__(self, layer):
        self.layer = layer
        self.original = copy.deepcopy(layer.header)
        self.old_active = layer.active
        self.protected = _owned(self.original)
        self.allocated = set()
        self.dirty = False
        self.published = False

    def commit(self):
        if not self.dirty:
            return
        l, s = self.layer, self.layer.store
        h = copy.deepcopy(l.header)
        h["generation"] = self.original["generation"] + 1
        plain = _pad(h)  # Reject overflow before any root is replaced.
        target = self.old_active ^ 1
        salt, nonce = os.urandom(SALT), os.urandom(NONCE)
        sealed = salt + nonce + padbook.cascade_seal(_slot_keys(l.keys, salt), nonce, plain, _aad(target))
        s._sync()  # All new data must be durable before its root can become durable.
        s._write(target * SLOT, sealed)
        s._sync()
        self.published = True
        l.header, l.active, l.new = h, target, False
        s._write(self.old_active * SLOT, os.urandom(SLOT))
        dead = (self.protected | self.allocated) - _owned(h)
        for b in dead:
            s._write(SLOTS * SLOT + b * BLOCK, os.urandom(BLOCK))
        s._sync()  # Retire obsolete state before any caller receives a secret.


class Layer:
    """A layer's operations reload and transact against its newest durable root."""

    def __init__(self, store, slot, keys, header, active, new=False):
        self.store, self.slot, self.keys = store, slot, bytes(keys)
        self.header, self.active, self.new = header, active, new

    def _tx(self):
        return self.store._local.layers[self.slot]

    @contextlib.contextmanager
    def transaction(self):
        """Serialize and stage all files changed by one caller operation."""
        with self.store.locked():
            existing = self.store._local.layers.get(self.slot)
            if existing:
                yield existing.layer
                return
            if not self.new:
                fresh = self.store._pair(self.keys, self.slot)
                self.header, self.active = fresh.header, fresh.active
            tx = _Transaction(self)
            self.store._local.layers[self.slot] = tx
            try:
                yield self
                tx.commit()
            except BaseException:
                if not tx.published:
                    self.header, self.active = tx.original, tx.old_active
                raise
            finally:
                del self.store._local.layers[self.slot]

    def lower(self):
        """Fresh lower layers, not cached copies of their allocation maps."""
        with self.transaction() as l:
            return [l.store._pair(bytes.fromhex(r["root"]), r["slot"]) for r in l.header["lower"]]

    def known(self):
        """This layer and the lower layers it is allowed to know."""
        with self.transaction() as l:
            return {**{x.slot: x for x in l.lower()}, l.slot: l}

    def used(self):
        """Blocks held by this layer and its lower layers."""
        with self.transaction() as l:
            return {b for x in l.known().values() for b in _owned(x.header)}

    def save_header(self):
        """Commit through the paired-header transaction, never an in-place replacement."""
        with self.transaction() as l:
            l._tx().dirty = True

    def _allocate(self, n):
        tx = self._tx()
        used = self.used() | tx.protected | tx.allocated
        order = range(self.store.blocks) if self.header["level"] == 0 else range(self.store.blocks - 1, -1, -1)
        got = []
        for b in order:
            if b not in used:
                got.append(b)
                if len(got) == n:
                    tx.allocated.update(got)
                    return sorted(got)
        raise RuntimeError("the store is full; no state committed")

    def _put(self, b, payload):
        nonce = os.urandom(NONCE)
        ct = padbook.cascade_seal(
            bytes.fromhex(self.header["data"]), nonce, payload.ljust(PAYLOAD, b"\0"), b"padstore/v2/block|%d" % b
        )
        self.store._write(SLOTS * SLOT + b * BLOCK, nonce + ct)

    def _get(self, b):
        raw = self.store._read(SLOTS * SLOT + b * BLOCK, BLOCK)
        return padbook.cascade_open(
            bytes.fromhex(self.header["data"]), raw[:NONCE], raw[NONCE:], b"padstore/v2/block|%d" % b
        )

    def names(self):
        """Names in the newest authenticated root."""
        with self.transaction() as l:
            return sorted(l.header["files"])

    def exists(self, name):
        """Whether a file exists in the newest authenticated root."""
        with self.transaction() as l:
            return name in l.header["files"]

    def write(self, name, data):
        """Stage a whole-file COW replacement; publish it only at transaction commit."""
        with self.transaction() as l:
            blocks = l._allocate(max(1, -(-len(data) // PAYLOAD)))
            for i, b in enumerate(blocks):
                l._put(b, data[i * PAYLOAD : (i + 1) * PAYLOAD])
            l.header["files"][name] = dict(size=len(data), extents=_extents(blocks))
            l._tx().dirty = True

    def read(self, name, limit=None):
        """Read an authenticated file under the container lock."""
        with self.transaction() as l:
            f = l.header["files"].get(name)
            if f is None:
                raise FileNotFoundError(name)
            if limit is not None and f["size"] > limit:
                raise ValueError("file too large")
            return l.read_at(name, 0, f["size"])

    def read_at(self, name, offset, n):
        """Read bytes without accepting negative offsets or lengths."""
        if offset < 0 or n < 0:
            raise ValueError("negative file range")
        with self.transaction() as l:
            f = l.header["files"][name]
            n = max(0, min(n, f["size"] - offset))
            blocks, out = _blocks(f["extents"]), bytearray()
            while len(out) < n:
                i, o = divmod(offset + len(out), PAYLOAD)
                out += l._get(blocks[i])[o : o + n - len(out)]
            return bytes(out)

    def write_at(self, name, offset, data):
        """COW every touched block; a torn write cannot corrupt adjacent unused pads."""
        with self.transaction() as l:
            f = l.header["files"][name]
            if offset < 0 or offset + len(data) > f["size"]:
                raise ValueError("past the end of the file")
            if not data:
                return
            blocks = _blocks(f["extents"])
            first, last = offset // PAYLOAD, (offset + len(data) - 1) // PAYLOAD
            new = l._allocate(last - first + 1)
            for i, b in zip(range(first, last + 1), new, strict=True):
                block = bytearray(l._get(blocks[i]))
                lo, hi = max(offset, i * PAYLOAD), min(offset + len(data), (i + 1) * PAYLOAD)
                block[lo - i * PAYLOAD : hi - i * PAYLOAD] = data[lo - offset : hi - offset]
                l._put(b, bytes(block))
                blocks[i] = b
            f["extents"] = _extents(blocks)
            l._tx().dirty = True

    def remove(self, name):
        """Remove a reference and scrub retired blocks after publishing the new root."""
        with self.transaction() as l:
            del l.header["files"][name]
            l._tx().dirty = True


class LayerFiles:
    """Transactional padbook file interface inside one layer."""

    def __init__(self, layer, prefix):
        if not prefix or "/" in prefix:
            raise ValueError("a book name is one path component")
        self.layer, self.prefix = layer, prefix

    @contextlib.contextmanager
    def transaction(self):
        """Stage state advancement and erasure in the same authenticated root commit."""
        with self.layer.transaction() as layer:
            yield LayerFiles(layer, self.prefix)

    def _n(self, name):
        return self.prefix + "/" + name

    def create(self):
        """Refuse a prefix already claimed by a book."""
        if any(n.startswith(self.prefix + "/") for n in self.layer.names()):
            raise FileExistsError(self.prefix)

    def read(self, name, limit):
        """Read a book file."""
        return self.layer.read(self._n(name), limit)

    def write(self, name, data):
        """Stage a book file replacement."""
        self.layer.write(self._n(name), data)

    def read_at(self, name, offset, n):
        """Read a range of a book file."""
        return self.layer.read_at(self._n(name), offset, n)

    def write_at(self, name, offset, data):
        """Stage a COW update of a book file."""
        self.layer.write_at(self._n(name), offset, data)


def unlock(vault, store, passphrase):
    """(vault secret, vault meta, the layer the passphrase opens): one PIN + touch."""
    secret, layer_secret, meta = keyguard.hardware_secrets(vault, layer_salt(passphrase))
    with padbook.Secret(layer_secret) as ls:
        return secret, meta, Store(store).open(ls.bytes)


def main():
    """Command line: create, add-layer, ls."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--store", type=Path, required=True)
    c.add_argument("--mib", type=int, default=DEFAULT_MIB)
    for name in ("add-layer", "ls"):
        s = sub.add_parser(name)
        s.add_argument("--vault", type=Path, required=True)
        s.add_argument("--store", type=Path, required=True)
    a = p.parse_args()
    padbook.harden()
    if a.cmd == "create":
        create(a.store, a.mib)
        print(json.dumps(dict(store=str(a.store), mib=a.mib)))
        return
    store = Store(a.store)
    if a.cmd == "ls":
        _, _, lay = unlock(a.vault, a.store, getpass.getpass("layer passphrase: "))
        print(json.dumps(dict(level=lay.header["level"], books=sorted({n.split("/")[0] for n in lay.names()}))))
        return
    top = None
    below = getpass.getpass("passphrase of the current top layer (empty for a new store): ")
    if below:
        _, _, top = unlock(a.vault, a.store, below)
    new = getpass.getpass("passphrase of the new layer: ")
    if new != getpass.getpass("again: "):
        raise SystemExit("passphrases differ")
    _, layer_secret, _ = keyguard.hardware_secrets(a.vault, layer_salt(new))
    with padbook.Secret(layer_secret) as ls:
        try:
            store.open(ls.bytes)
            raise SystemExit("that passphrase already opens a layer")
        except LookupError:
            pass
        lay = store.first_layer(ls.bytes) if top is None else store.add_layer(ls.bytes, top)
    print(json.dumps(dict(level=lay.header["level"])))


if __name__ == "__main__":
    main()
