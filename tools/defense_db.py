#!/usr/bin/env python3
"""defense-db: generate the ephemeral defense database (AVPN/Mesh, DAITA v2+).

The carrier (advanced-vpn-wireguard) can run the full strong DAITA posture from
a randomized parameterization instead of the shipped constants. This tool writes
the rotation schedule: a sequence of profiles, each valid for one time window,
each drawn within SAFE_RANGES. The posture is identical everywhere - netflow +
re-armed FRONT + rounding Tamaraw + bidirectional constant-rate cover - but its
fingerprint expires on schedule:

- an observer who characterizes one window's schedule finds it gone at the next;
- a captured database reveals past and current windows only if stolen in time,
  and says nothing about windows not yet generated;
- every hop still draws within the profile from its own OS-seeded RNG, so
  per-hop independence is preserved inside each window.

Invariants (fail-closed, mirrored by DefenseProfile::validate in src/daita.rs):
the cover clock ALWAYS equals the Tamaraw clock (cover and shaped traffic are
indistinguishable on the wire), and out-of-range values are refused, never
clamped. A window with no profile in force refuses the run - rotate before the
last window ends, never after.

Usage:
  defense_db.py generate --out FILE [--seed S] [--start EPOCH] [--count N] [--step SEC]
  defense_db.py current --db FILE [--now EPOCH]     (last stdout line: JSON)
"""

import argparse
import json
import os
import random
import secrets
import time
from pathlib import Path

SCHEMA = 1
DEFAULT_WINDOW_SECONDS = 6 * 3600   # one profile every 6 h
DEFAULT_COUNT = 56                  # two weeks of windows per generation

# Every bound mirrors DefenseProfile::validate in src/daita.rs. The ranges are
# the strong posture's safe operating envelope: wide enough that fingerprints
# differ per window, narrow enough that the defense properties (constant-rate
# clock, trace rounding, bidirectional cover) are preserved everywhere inside.
SAFE_RANGES = {
    "tamaraw_interval_seconds": (0.01, 0.05),
    "tamaraw_l": (50, 400),
    "front_budget_max": (64, 512),
    "front_window_lo": (0.5, 8.0),
    "front_window_hi": (0.5, 8.0),
    "front_states": (4, 32),
    "burst_packets": (4.0, 32.0),
    "burst_window_seconds": (0.25, 4.0),
    "front_cooldown_seconds": (1.0, 30.0),
}

PROFILE_FIELDS = [
    "id", "not_before", "not_after", "tamaraw_interval_seconds", "tamaraw_l",
    "front_budget_max", "front_window_seconds", "front_states", "burst_packets",
    "burst_window_seconds", "front_cooldown_seconds", "cover_interval_seconds",
]


def draw_profile(rng: random.Random, not_before: int, not_after: int) -> dict:
    """One randomized parameterization within SAFE_RANGES (fail-closed elsewhere)."""
    interval = round(rng.uniform(*SAFE_RANGES["tamaraw_interval_seconds"]), 4)
    lo = round(rng.uniform(*SAFE_RANGES["front_window_lo"]), 3)
    hi = round(rng.uniform(max(lo, SAFE_RANGES["front_window_hi"][0]),
                           SAFE_RANGES["front_window_hi"][1]), 3)
    return {
        "id": secrets.token_hex(8),
        "not_before": not_before,
        "not_after": not_after,
        "tamaraw_interval_seconds": interval,
        "tamaraw_l": rng.randint(*SAFE_RANGES["tamaraw_l"]),
        "front_budget_max": rng.randint(*SAFE_RANGES["front_budget_max"]),
        "front_window_seconds": [lo, hi],
        "front_states": rng.randint(*SAFE_RANGES["front_states"]),
        "burst_packets": round(rng.uniform(*SAFE_RANGES["burst_packets"]), 1),
        "burst_window_seconds": round(rng.uniform(*SAFE_RANGES["burst_window_seconds"]), 3),
        "front_cooldown_seconds": round(rng.uniform(*SAFE_RANGES["front_cooldown_seconds"]), 2),
        "cover_interval_seconds": interval,  # invariant: cover clock == tamaraw clock
    }


def validate_profile(p: dict) -> list[str]:
    """Structural + range checks; mirrors DefenseProfile::validate exactly."""
    errors = []
    if set(p) != set(PROFILE_FIELDS):
        errors.append("profile fields must match the schema exactly")
    if not p.get("id") or len(str(p.get("id", ""))) > 64:
        errors.append("bad id")
    if p.get("not_after", 0) <= p.get("not_before", 1):
        errors.append("empty validity window")
    iv = p.get("tamaraw_interval_seconds", 0)
    if not SAFE_RANGES["tamaraw_interval_seconds"][0] <= iv <= SAFE_RANGES["tamaraw_interval_seconds"][1]:
        errors.append("tamaraw interval out of range")
    if p.get("cover_interval_seconds") != iv:
        errors.append("cover clock must equal the tamaraw clock")
    l = p.get("tamaraw_l", 0)
    if not SAFE_RANGES["tamaraw_l"][0] <= l <= SAFE_RANGES["tamaraw_l"][1] or int(l) != l:
        errors.append("tamaraw L out of range")
    if not SAFE_RANGES["front_budget_max"][0] <= p.get("front_budget_max", 0) <= SAFE_RANGES["front_budget_max"][1]:
        errors.append("FRONT budget out of range")
    w = p.get("front_window_seconds", [0, 0])
    if not (SAFE_RANGES["front_window_lo"][0] <= w[0] <= w[1] <= SAFE_RANGES["front_window_hi"][1]):
        errors.append("FRONT window out of range")
    if not SAFE_RANGES["front_states"][0] <= p.get("front_states", 0) <= SAFE_RANGES["front_states"][1]:
        errors.append("FRONT states out of range")
    if not SAFE_RANGES["burst_packets"][0] <= p.get("burst_packets", 0) <= SAFE_RANGES["burst_packets"][1]:
        errors.append("burst size out of range")
    if not SAFE_RANGES["burst_window_seconds"][0] <= p.get("burst_window_seconds", 0) <= SAFE_RANGES["burst_window_seconds"][1]:
        errors.append("burst window out of range")
    if not SAFE_RANGES["front_cooldown_seconds"][0] <= p.get("front_cooldown_seconds", 0) <= SAFE_RANGES["front_cooldown_seconds"][1]:
        errors.append("FRONT cooldown out of range")
    return errors


def generate(seed: int, start: int, count: int, step: int) -> dict:
    """A full database: COUNT contiguous windows of STEP seconds from START."""
    rng = random.Random(seed)
    profiles = [draw_profile(rng, start + i * step, start + (i + 1) * step)
                for i in range(count)]
    return {"schema": SCHEMA, "profiles": profiles}


def load(path) -> dict:
    if isinstance(path, str):
        path = Path(path)
    doc = json.loads(path.read_bytes())
    if doc.get("schema") != SCHEMA:
        raise SystemExit("unsupported defense database schema")
    for p in doc.get("profiles", []):
        errors = validate_profile(p)
        if errors:
            raise SystemExit(f"profile {p.get('id')}: " + "; ".join(errors))
    return doc


def select(profiles: list[dict], now: int) -> dict | None:
    """The entry with the latest not_before whose window contains now (Rust parity)."""
    current = [p for p in profiles if p["not_before"] <= now < p["not_after"]]
    return max(current, key=lambda p: p["not_before"]) if current else None


def main() -> int:
    p = argparse.ArgumentParser(prog="defense-db")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write a fresh rotation schedule")
    g.add_argument("--out", required=True)
    g.add_argument("--seed", type=int, default=None,
                   help="reproducible for tests; default: OS random")
    g.add_argument("--start", type=int, default=None, help="default: now, floored to the hour")
    g.add_argument("--count", type=int, default=DEFAULT_COUNT)
    g.add_argument("--step", type=int, default=DEFAULT_WINDOW_SECONDS)
    c = sub.add_parser("current", help="print the profile in force (last line: JSON)")
    c.add_argument("--db", required=True)
    c.add_argument("--now", type=int, default=None)
    a = p.parse_args()
    if a.cmd == "generate":
        seed = secrets.randbelow(2**63) if a.seed is None else a.seed
        start = (int(time.time()) // 3600) * 3600 if a.start is None else a.start
        db = generate(seed, start, a.count, a.step)
        tmp = a.out + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(db, indent=1) + "\n")
        os.replace(tmp, a.out)
        print(f"defense database: {a.count} windows of {a.step}s from {start} -> {a.out}")
        print("rotate before the last window ends; the carrier refuses a run with "
              "no profile in force, never a weakened one.")
        return 0
    db = load(a.db)
    now = int(time.time()) if a.now is None else a.now
    profile = select(db["profiles"], now)
    if profile is None:
        print("no profile in force; rotate the database", flush=True)
        return 1
    print(json.dumps({"profile": profile}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
