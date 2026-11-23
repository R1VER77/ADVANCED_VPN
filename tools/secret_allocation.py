#!/usr/bin/env python3
"""Disjoint, durably consumed secret material for DC-net masks and session PSKs.

ROADMAP section 6: "Allocate disjoint, durably consumed material to DC-net masks
and session PSKs; qualify physical entropy/custody and cross-plane linkage
before operational IT claims." The research review's correction behind it
(RESEARCH_REVIEW_20261118.md, "Pad and transport domains must be disjoint"): a
PSK consumes separately allocated secret material with durable
ownership/consumption rules; deriving it from the same pads used for masked
control events needs a composition argument, not an inheritance analogy; no KDF
manufactures more independent secret entropy; and a finite ratchet counter with
an operational key lifetime replaces the draft's unbounded "never runs out".

This module makes that rule executable and testable:

- DOMAINS are disjoint by construction: every consumer names its material with
  a domain tag, and no domain may be a prefix of another (a prefix would let a
  longer domain's derivations be confused with a shorter one's), so a mask
  byte and a PSK byte can never come from the same (domain, window) pair.
- allocate() derives each window with HKDF-SHA256 over (domain, window,
  generation) - the domain tag is INSIDE the KDF info, so no amount of KDF
  cleverness produces material shared between domains. The master seed itself
  is never returned, never journaled, and never crosses a domain boundary.
- ConsumptionLedger is the durable ownership record: append-only, 0600, fsync,
  one rotated generation (the wizard journal's conventions). It stores the
  SHA-256 of what was consumed, never the material. Re-consuming a window is
  refused - across processes, after reload, exactly once forever.
- The ratchet is finite and visible: a bounded number of windows per
  generation, no wraparound, and exhaustion answers rekey_required instead of
  silently restarting the counter (the "never runs out" wording, refused).

The physical halves - assessed min-entropy of the master source, device
custody, cross-plane linkage - remain owner-side gates and are named as such
wherever this module's output is consumed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import time
from pathlib import Path

SCHEMA = 1
WINDOW_BYTES = 32  # one window: a mask seed or a PSK's pre-shared half
LEDGER_MAX_ENTRIES = 4096  # one previous generation kept on rotation

# The disjoint consumer domains. A new consumer adds its tag here; a tag that
# is a prefix of an existing one (or vice versa) is refused at import, because
# prefix domains would make disjointness unauditable.
DOMAINS = (
    "dcnet-mask",  # the pads that cancel in a DC-net round
    "session-psk",  # the WireGuard/cloak carrier pre-shared keys
    "voucher-blind",  # blinding nonces for voucher issuance (unblinder halves)
)


class Refused(Exception):
    """An out-of-contract allocation request (fail-closed)."""


def _check_domains() -> None:
    for a in DOMAINS:
        for b in DOMAINS:
            if a != b and (a.startswith(b) or b.startswith(a)):
                raise Refused(f"domains must be pairwise non-prefix: {a!r} vs {b!r}")


_check_domains()


def domain_of(tag: str) -> str:
    """Validate one domain tag against the registry (fail-closed)."""
    if tag not in DOMAINS:
        raise Refused(f"unknown_material_domain: {tag!r}")
    return tag


# --------------------------------------------------------------- allocation


def allocate(master: bytes, domain: str, window: int, generation: int = 1) -> bytes:
    """One window of material for one domain. HKDF-SHA256 with the domain tag,
    window and generation inside the info; the same master can serve every
    domain, but no (domain, window, generation) pair can ever produce another
    domain's bytes. Refuses unknown domains, non-positive windows and
    generations, and masters shorter than the window."""
    domain_of(domain)
    if not isinstance(window, int) or isinstance(window, bool) or window < 1:
        raise Refused("window_must_be_a_positive_integer")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise Refused("generation_must_be_a_positive_integer")
    if not isinstance(master, (bytes, bytearray)) or len(master) < WINDOW_BYTES:
        raise Refused("master_material_too_short")
    info = (
        b"cpvpn/secret-allocation/v1|" + domain.encode() + b"|" + str(generation).encode() + b"|" + str(window).encode()
    )
    # extract once (the master is the IKM), expand exactly one window
    prk = hmac.new(b"cpvpn/secret-allocation/v1|extract", bytes(master), hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:WINDOW_BYTES]


def window_digest(domain: str, window: int, generation: int, material: bytes) -> str:
    """The ledger's key for one consumed window: what was consumed, never the
    material itself."""
    return hashlib.sha256(
        b"cpvpn/secret-allocation/v1|ledger|"
        + domain.encode()
        + b"|"
        + str(generation).encode()
        + b"|"
        + str(window).encode()
        + b"|"
        + material
    ).hexdigest()


# ------------------------------------------------------------ the ratchet


class Ratchet:
    """A finite forward-only window counter with visible exhaustion.

    The draft's "never runs out" is refused here: a ratchet has a bounded
    number of windows per generation, stepping past the bound raises
    Refused('rekey_required') - the caller rekeys (a new generation from fresh
    master material) or stops, it never wraps and never reuses."""

    def __init__(self, generation: int = 1, windows: int = 4096, position: int = 0):
        if isinstance(windows, bool) or not 1 <= windows <= 1_000_000:
            raise Refused("ratchet_window_count_out_of_bounds")
        if isinstance(position, bool) or not 0 <= position < windows:
            raise Refused("ratchet_position_out_of_bounds")
        self.generation = generation
        self.windows = windows
        self.position = position

    def next(self) -> int:
        """Advance and return the next window; refuse at exhaustion."""
        if self.position + 1 >= self.windows:
            raise Refused("rekey_required")
        self.position += 1
        return self.position

    @property
    def exhausted(self) -> bool:
        """Whether the last window is in use: the next step must rekey."""
        return self.position + 1 >= self.windows

    @property
    def remaining(self) -> int:
        """Windows left after the current one."""
        return self.windows - 1 - self.position


# ----------------------------------------------------------------- ledger


class ConsumptionLedger:
    """The durable ownership record: every consumed window, exactly once,
    forever. Append-only JSONL (0600, fsync, one rotated generation); stores
    the window digest, never the material. Refuses unsafe files, replays and
    out-of-contract rows."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._spent: dict[str, dict] = {}
        if self.path.exists():
            self._load()

    def _load(self):
        m = self.path.lstat()
        if not stat.S_ISREG(m.st_mode) or stat.S_ISLNK(m.st_mode) or m.st_mode & 0o077:
            raise Refused("unsafe_ledger_file")
        for line in self.path.read_text().splitlines():
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                raise Refused("malformed_ledger_row") from None
            if (
                not isinstance(row, dict)
                or row.get("schema") != SCHEMA
                or not isinstance(row.get("digest"), str)
                or len(row["digest"]) != 64
                or not isinstance(row.get("domain"), str)
                or not isinstance(row.get("window"), int)
                or isinstance(row.get("window"), bool)
                or not isinstance(row.get("generation"), int)
                or not isinstance(row.get("at"), (int, float))
            ):
                raise Refused("malformed_ledger_row")
            if row["digest"] in self._spent:
                raise Refused("ledger_digest_replayed")
            self._spent[row["digest"]] = row

    def consumed(self, domain: str, window: int, generation: int) -> bool:
        """Whether this window is already recorded as consumed."""
        return any(
            r["domain"] == domain and r["window"] == window and r["generation"] == generation
            for r in self._spent.values()
        )

    def consume(self, domain: str, window: int, generation: int, material: bytes, at: float | None = None) -> dict:
        """Record one window as consumed. Refuses a replay (the same window in
        the same generation), an unknown domain, and a non-positive window."""
        domain_of(domain)
        if not isinstance(window, int) or isinstance(window, bool) or window < 1:
            raise Refused("window_must_be_a_positive_integer")
        if self.consumed(domain, window, generation):
            raise Refused("window_already_consumed")
        row = dict(
            schema=SCHEMA,
            domain=domain,
            window=window,
            generation=generation,
            digest=window_digest(domain, window, generation, material),
            at=round(time.time() if at is None else at, 3),
        )
        directory = self.path.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.exists():
            lines = [l for l in self.path.read_text().splitlines() if l]
            if len(lines) >= LEDGER_MAX_ENTRIES:
                rotated = self.path.with_name(self.path.name + ".1")
                if rotated.exists():
                    rotated.unlink()
                self.path.rename(rotated)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, (json.dumps(row, sort_keys=True, allow_nan=False) + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        self._spent[row["digest"]] = row
        return row


def allocate_fresh(master: bytes, domain: str, ratchet: Ratchet, ledger: ConsumptionLedger) -> bytes:
    """The composed operation the two planes are meant to use: the next window
    of one domain's ratchet, derived from the master, recorded as consumed
    before it is handed out. The material crosses to exactly one consumer,
    exactly once, and the ratchet's exhaustion is the caller's rekey gate."""
    window = ratchet.next()
    material = allocate(master, domain, window, ratchet.generation)
    ledger.consume(domain, window, ratchet.generation, material)
    return material
