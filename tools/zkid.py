#!/usr/bin/env python3
"""Forward-private membership secret at rest (docs/ZK_MEMBERSHIP_DESIGN.md,
"Forward-private nullifiers"; the statement is research/zk-membership's guest v2).

A member enrols into a tree with start epoch E0 and lifetime N: it draws s0 from hardware
(kernel XOR Nitrokey, as padbook's contributions), registers
leaf = SHA-256("cpvpn/member/v2" || H^N(s0)) with H(x) = SHA-256("cpvpn/fp-step/v1" || x),
and keeps only x_k = H^k(s0) for the current epoch E0 + k. Opening the store in a later
epoch steps the secret forward and saves it before handing it out, so the stored file never
again holds an earlier x: a device seized in epoch E0 + k gives up x_k and later secrets,
never an earlier one (a SHA-256 preimage), so past nullifiers stay unlinkable.

At rest the store is padbook's opaque book file: a random salt, then a ChaCha20-Poly1305
over AES-256-GCM cascade keyed from the Nitrokey's hmac-secret; no readable structure.
Limits: the old file is replaced by a rename, and a journaling file system or flash
wear-levelling can keep the old blocks; CPython's own copies of the hex string cannot be
wiped (padbook.Secret's caveat).

usage: zkid.py enrol --vault DIR --store DIR --start E0 [--lifetime N]
       zkid.py status --vault DIR --store DIR
Epochs are UTC days since 1970-01-01.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import keyguard  # noqa: E402
import padbook  # noqa: E402

KIND = "zk-identity"
LIFETIME = 365  # one tree a year of daily epochs, as the prototype


def h(*parts):
    """SHA-256 of the concatenation (the guest's `h`)."""
    return hashlib.sha256(b"".join(parts)).digest()


def step(x):
    """One epoch forward: H(x) = SHA-256("cpvpn/fp-step/v1" || x)."""
    return h(b"cpvpn/fp-step/v1", x)


def walk(x, n):
    """H^n(x)."""
    for _ in range(n):
        x = step(x)
    return x


def leaf(s0, lifetime):
    """The commitment a member registers: SHA-256("cpvpn/member/v2" || H^N(s0))."""
    return h(b"cpvpn/member/v2", walk(s0, lifetime))


def leaf_from(x, epoch, start, lifetime):
    """The same leaf from the epoch's secret: what the guest folds (N - k steps)."""
    k = epoch - start
    if not 0 <= k <= lifetime:
        raise ValueError("epoch outside the tree's lifetime")
    return h(b"cpvpn/member/v2", walk(x, lifetime - k))


def nullifier(x, epoch, scope):
    """SHA-256("cpvpn/nullifier/v2" || x || epoch (8 bytes, big-endian) || scope)."""
    if len(scope) != 32:
        raise ValueError("scope is 32 bytes")
    return h(b"cpvpn/nullifier/v2", x, epoch.to_bytes(8, "big"), scope)


def epoch_now(now=None):
    """The current epoch: UTC days since 1970-01-01."""
    return int((time.time() if now is None else now) // 86400)


def enrol(directory, start, lifetime, secret, meta, s0=None, now=None):
    """Create the store in `directory` (new, 0700) for the tree (`start`, `lifetime`) and
    return the leaf to register. `s0` defaults to kernel XOR Nitrokey (hardware only)."""
    if lifetime < 1 or start < 0:
        raise ValueError("bad tree")
    e = epoch_now(now)
    if e > start + lifetime:
        raise ValueError("the tree has ended")
    s0 = bytearray(padbook.contribution_bytes(32) if s0 is None else s0)
    if len(s0) != 32:
        raise ValueError("s0 is 32 bytes")
    try:
        commitment = leaf(bytes(s0), lifetime)
        k = max(0, e - start)  # enrolling late: start at today's step, keep nothing earlier
        x = walk(bytes(s0), k)
    finally:
        padbook._memzero(s0)
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    salt = os.urandom(padbook.SALT)
    info = dict(book=dict(kind=KIND, start=start, lifetime=lifetime), state=dict(epoch=start + k, x=x.hex()))
    padbook._save(directory, salt, padbook.file_keys(secret, meta, salt), info)
    return commitment


class Identity:
    """An opened store. `secret(epoch)` steps forward (saved first) and returns x_epoch."""

    def __init__(self, directory, secret, meta, clock=time.time):
        self.dir = padbook.files(directory)
        self.salt, keys, self.info = padbook._load(self.dir, secret, meta)
        self.keys = padbook.Secret(keys)
        if self.info["book"].get("kind") != KIND:
            raise ValueError("not a %s store" % KIND)
        self.clock = clock

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.keys.wipe()

    @property
    def start(self):
        """The tree's start epoch E0."""
        return self.info["book"]["start"]

    @property
    def lifetime(self):
        """The tree's lifetime N in epochs."""
        return self.info["book"]["lifetime"]

    @property
    def epoch(self):
        """The durable epoch, including changes made by other handles."""
        with self.dir.transaction():
            self.info = padbook.reload_info(self.dir, self.salt, self.keys.bytes)
            return self.info["state"]["epoch"]

    def secret(self, epoch=None):
        """Release an epoch secret only after a serialized, durable forward advance.

        Old snapshots, hostile kernels and immutable CPython copies are outside this
        software guarantee. The guarantee concerns completed state advances.
        """
        with self.dir.transaction():
            info = padbook.reload_info(self.dir, self.salt, self.keys.bytes)
            if info["book"] != self.info["book"]:
                raise ValueError("state identity changed; reopen the store")
            self.info = info
            e = epoch_now(self.clock()) if epoch is None else epoch
            current = info["state"]["epoch"]
            if e < current:
                raise ValueError("that epoch's secret was erased")
            if e > self.start + self.lifetime:
                raise ValueError("the tree has ended: enrol in the next one")
            x = bytearray(bytes.fromhex(info["state"]["x"]))
            try:
                for _ in range(current, e):
                    x[:] = step(bytes(x))
                out = bytes(x)
                if e != current:
                    info["state"] = dict(epoch=e, x=out.hex())
                    padbook._save(self.dir, self.salt, self.keys.bytes, info)
            finally:
                padbook._memzero(x)
        return out


def main():
    """Command line: enrol or status."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("enrol", "status"):
        s = sub.add_parser(name)
        s.add_argument("--vault", type=Path, required=True, help="the Nitrokey vault (keyguard enroll)")
        s.add_argument("--store", type=Path, required=True)
        if name == "enrol":
            s.add_argument("--start", type=int, required=True, help="the tree's start epoch E0")
            s.add_argument("--lifetime", type=int, default=LIFETIME)
    a = p.parse_args()
    padbook.harden()
    secret, meta = keyguard.hardware_secret(a.vault)
    with padbook.Secret(secret) as s:
        if a.cmd == "enrol":
            print(json.dumps(dict(leaf=enrol(a.store, a.start, a.lifetime, s.bytes, meta).hex())))
        else:
            with Identity(a.store, s.bytes, meta) as ident:
                e = epoch_now()
                print(json.dumps(dict(
                    epoch_held=ident.epoch, epoch_now=e, tree_start=ident.start,
                    tree_end=ident.start + ident.lifetime,
                    steps_in_proof=max(0, ident.start + ident.lifetime - max(e, ident.epoch)),
                )))  # fmt: skip


if __name__ == "__main__":
    main()
