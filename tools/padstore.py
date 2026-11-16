#!/usr/bin/env python3
"""Deniable layered store for pad books (docs/DCNET_CONTROL_DESIGN.md, "Deniable storage").

One file of random-looking bytes, fixed in size when it is created: SLOTS header slots,
then data blocks. A layer is one slot plus the blocks it owns. Its slot is found by trying
every slot with the layer's key, so an unlock does the same work whatever the number of
layers, and an unused slot or block is random bytes like a used one: one image of the
store does not show how many layers it holds.

A layer's key comes from the Nitrokey: the hmac-secret for a salt derived from the layer's
passphrase (keyguard.hardware_secrets: one touch also gives the vault's own secret, which
seals the books inside). So the token alone opens no layer, a passphrase alone opens none,
and nothing on disk (no vault, no credential) counts the layers. Under coercion a member
gives the token, the PIN and the decoy passphrase.

Layers are nested, after Shufflecake (2023) rather than TrueCrypt's single hidden volume:
each layer's header holds the slot keys of the layers below it, so the top layer, used
day to day, sees every block in use and never overwrites a lower layer. The decoy (level
0) allocates from the front, hidden layers from the back. Opened alone, a lower layer does
not know the higher ones: writing to it can overwrite them once its free space meets
theirs (the hidden-volume trade-off), so under coercion it is opened for reading.

Limits, stated wherever this is claimed:
- two images of the store show which blocks changed, and books change every round: one
  seizure is covered, not repeated ones;
- flash wear-levelling and journaling file systems keep old blocks;
- the decoy must be used believably (it should hold books of its own, in use).

usage: padstore.py create --store FILE [--mib 64]
       padstore.py add-layer --vault DIR --store FILE   (passphrases asked; the first
           layer needs none below it, each later one the current top's passphrase)
       padstore.py ls --vault DIR --store FILE
A book goes into a layer with padbook's --store FILE (padbook.py make/accept/status).
"""

import argparse
import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyguard  # noqa: E402
import padbook  # noqa: E402

SLOTS = 8
SLOT = 4096
BLOCK = 4096
NONCE = 12
TAGS = 32  # the cascade's two 16-byte tags
SALT = 32
PAYLOAD = BLOCK - NONCE - TAGS
HEADER = SLOT - SALT - NONCE - TAGS  # a slot's plaintext, padded to this size
DEFAULT_MIB = 64


def layer_salt(passphrase):
    """The hmac-secret salt of the layer a passphrase names (32 bytes)."""
    if not passphrase:
        raise ValueError("a layer needs a passphrase")
    return hashlib.sha256(b"advanced-vpn/padstore/v1|layer|" + passphrase.encode()).digest()


def _slot_keys(layer_secret, salt):
    return padbook._hkdf(layer_secret + salt, b"padstore/slot", 64)


def create(path, mib=DEFAULT_MIB):
    """A new store of `mib` MiB, every byte from the kernel's CSPRNG (0600; refuses an
    existing file). Random filler is not pad material, so the kernel source is enough."""
    path = Path(path)
    size = SLOTS * SLOT + (mib * (1 << 20) // BLOCK) * BLOCK
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as f:
        left = size
        while left:
            n = min(left, 1 << 20)
            f.write(os.urandom(n))
            left -= n
        f.flush()
        os.fsync(f.fileno())
    return path


class Store:
    """An existing store file."""

    def __init__(self, path):
        self.path = Path(path)
        size = self.path.stat().st_size
        if size < SLOTS * SLOT + BLOCK or (size - SLOTS * SLOT) % BLOCK:
            raise ValueError("not a store")
        self.blocks = (size - SLOTS * SLOT) // BLOCK

    def _read(self, offset, n):
        with open(self.path, "rb") as f:
            f.seek(offset)
            return f.read(n)

    def _write(self, offset, data):
        with open(self.path, "r+b") as f:
            f.seek(offset)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def _try_slot(self, i, layer_secret):
        raw = self._read(i * SLOT, SLOT)
        salt, nonce, ct = raw[:SALT], raw[SALT : SALT + NONCE], raw[SALT + NONCE :]
        keys = _slot_keys(layer_secret, salt)
        try:
            plain = padbook.cascade_open(keys, nonce, ct, b"padstore/slot")
        except Exception:
            return None
        return salt, keys, plain

    def open(self, layer_secret):
        """The layer this key opens (and, through its header, every layer below it).
        Every slot is tried whatever happens, so the work does not depend on how many
        layers exist or where this one is. LookupError when no slot opens."""
        found = None
        for i in range(SLOTS):
            r = self._try_slot(i, layer_secret)
            if r is not None and found is None:
                found = (i, r)
        if found is None:
            raise LookupError("no layer opens with this key")
        i, (salt, keys, plain) = found
        return Layer(self, i, salt, keys, _unpad(plain))

    def first_layer(self, layer_secret):
        """Add the bottom layer (the decoy) to a new store, in a random slot."""
        return self._add(layer_secret, None)

    def add_layer(self, layer_secret, top):
        """Add a layer above `top` (the current top layer, opened), in a random slot that
        no known layer uses. Its header records every layer below it."""
        return self._add(layer_secret, top)

    def _add(self, layer_secret, top):
        known = {} if top is None else top.known()
        used = {lay.slot for lay in known.values()}
        free = [i for i in range(SLOTS) if i not in used]
        if not free:
            raise RuntimeError("every slot is in use")
        slot = free[secrets.randbelow(len(free))]
        salt = os.urandom(SALT)
        keys = _slot_keys(layer_secret, salt)
        header = dict(
            v=1,
            level=0 if top is None else top.header["level"] + 1,
            data=os.urandom(64).hex(),
            files={},
            lower=[] if top is None else [dict(slot=lay.slot, key=lay.keys.hex()) for lay in known.values()],
        )
        lay = Layer(self, slot, salt, keys, header)
        lay.save_header()
        return lay


def _pad(header):
    blob = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    if 4 + len(blob) > HEADER:
        raise RuntimeError("layer header full: too many files or extents")
    return len(blob).to_bytes(4, "big") + blob + bytes(HEADER - 4 - len(blob))


def _unpad(plain):
    n = int.from_bytes(plain[:4], "big")
    return json.loads(plain[4 : 4 + n])


def _extents(blocks):
    out = []
    for b in sorted(blocks):
        if out and out[-1][0] + out[-1][1] == b:
            out[-1][1] += 1
        else:
            out.append([b, 1])
    return out


def _blocks(extents):
    return [s + i for s, n in extents for i in range(n)]


class Layer:
    """One opened layer: named files stored in its blocks, each block a fresh nonce and
    the cascade (ChaCha20-Poly1305 over AES-256-GCM) under the layer's data key."""

    def __init__(self, store, slot, salt, keys, header):
        self.store, self.slot, self.salt, self.keys, self.header = store, slot, salt, keys, header
        self._lower = None

    def lower(self):
        """The layers below this one, opened from its header."""
        if self._lower is None:
            self._lower = []
            for ref in self.header["lower"]:
                raw = self.store._read(ref["slot"] * SLOT, SLOT)
                keys = bytes.fromhex(ref["key"])
                plain = padbook.cascade_open(keys, raw[SALT : SALT + NONCE], raw[SALT + NONCE :], b"padstore/slot")
                self._lower.append(Layer(self.store, ref["slot"], raw[:SALT], keys, _unpad(plain)))
        return self._lower

    def known(self):
        """This layer and every one below it, by slot."""
        out = {lay.slot: lay for lay in self.lower()}
        out[self.slot] = self
        return out

    def used(self):
        """Blocks this layer and the ones below it hold."""
        return {b for lay in self.known().values() for f in lay.header["files"].values() for b in _blocks(f["extents"])}

    def save_header(self):
        """Seal and write this layer's header into its slot (a fresh nonce)."""
        nonce = os.urandom(NONCE)
        ct = padbook.cascade_seal(self.keys, nonce, _pad(self.header), b"padstore/slot")
        self.store._write(self.slot * SLOT, self.salt + nonce + ct)

    def _data_keys(self):
        return bytes.fromhex(self.header["data"])

    def _allocate(self, n):
        used = self.used()
        order = range(self.store.blocks) if self.header["level"] == 0 else range(self.store.blocks - 1, -1, -1)
        got = []
        for b in order:
            if b not in used:
                got.append(b)
                if len(got) == n:
                    return sorted(got)  # file order = block order (the extents are sorted)
        raise RuntimeError("the store is full")

    def _put(self, b, payload):
        nonce = os.urandom(NONCE)
        ct = padbook.cascade_seal(self._data_keys(), nonce, payload.ljust(PAYLOAD, b"\0"), b"padstore/block|%d" % b)
        self.store._write(SLOTS * SLOT + b * BLOCK, nonce + ct)

    def _get(self, b):
        raw = self.store._read(SLOTS * SLOT + b * BLOCK, BLOCK)
        return padbook.cascade_open(self._data_keys(), raw[:NONCE], raw[NONCE:], b"padstore/block|%d" % b)

    def _scrub(self, blocks):
        for b in blocks:
            self.store._write(SLOTS * SLOT + b * BLOCK, os.urandom(BLOCK))

    def names(self):
        """The files in this layer."""
        return sorted(self.header["files"])

    def exists(self, name):
        """Whether this layer holds a file of that name."""
        return name in self.header["files"]

    def write(self, name, data):
        """Replace a whole file: new blocks first, then the header, then the old blocks
        overwritten with random bytes (a crash leaves the old or the new file, never half)."""
        old = self.header["files"].get(name)
        blocks = self._allocate(max(1, -(-len(data) // PAYLOAD)))
        for i, b in enumerate(blocks):
            self._put(b, data[i * PAYLOAD : (i + 1) * PAYLOAD])
        self.header["files"][name] = dict(size=len(data), extents=_extents(blocks))
        self.save_header()
        if old:
            self._scrub(_blocks(old["extents"]))

    def read(self, name, limit=None):
        """A whole file, refused when larger than `limit`."""
        f = self.header["files"].get(name)
        if f is None:
            raise FileNotFoundError(name)
        if limit is not None and f["size"] > limit:
            raise ValueError("file too large")
        return self.read_at(name, 0, f["size"])

    def read_at(self, name, offset, n):
        """`n` bytes of a file at `offset`."""
        f = self.header["files"][name]
        n = max(0, min(n, f["size"] - offset))
        blocks, out = _blocks(f["extents"]), bytearray()
        while len(out) < n:
            i, o = divmod(offset + len(out), PAYLOAD)
            out += self._get(blocks[i])[o : o + n - len(out)]
        return bytes(out)

    def write_at(self, name, offset, data):
        """Overwrite bytes inside a file in place (each touched block re-encrypted under a
        fresh nonce, so the old ciphertext is gone from this block)."""
        f = self.header["files"][name]
        if offset + len(data) > f["size"]:
            raise ValueError("past the end of the file")
        blocks, done = _blocks(f["extents"]), 0
        while done < len(data):
            i, o = divmod(offset + done, PAYLOAD)
            block = bytearray(self._get(blocks[i]))
            k = min(len(data) - done, PAYLOAD - o)
            block[o : o + k] = data[done : done + k]
            self._put(blocks[i], bytes(block))
            done += k

    def remove(self, name):
        """Delete a file: header first, then its blocks scrubbed."""
        f = self.header["files"].pop(name)
        self.save_header()
        self._scrub(_blocks(f["extents"]))


class LayerFiles:
    """A book's files inside a layer, under `prefix/` (padbook.DirFiles' calls)."""

    def __init__(self, layer, prefix):
        if not prefix or "/" in prefix:
            raise ValueError("a book name is one path component")
        self.layer, self.prefix = layer, prefix

    def _n(self, name):
        return self.prefix + "/" + name

    def create(self):
        """Claim the prefix: refuses a book name already in the layer."""
        if any(n.startswith(self.prefix + "/") for n in self.layer.names()):
            raise FileExistsError(self.prefix)

    def read(self, name, limit):
        """A whole file of the book."""
        return self.layer.read(self._n(name), limit)

    def write(self, name, data):
        """Replace a whole file of the book."""
        self.layer.write(self._n(name), data)

    def read_at(self, name, offset, n):
        """`n` bytes at `offset`."""
        return self.layer.read_at(self._n(name), offset, n)

    def write_at(self, name, offset, data):
        """Overwrite bytes in place at `offset`."""
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
