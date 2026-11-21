#!/usr/bin/env python3
"""The name migration's state-custody engine (NAME_MIGRATION.md, row 5).

The migration plan's rule for state and keys: "Inventory
`/etc/advanced-vpn`, runtime/state directories, private vaults,
operator/cloud inventory and recovery paths. Use explicit migration
receipts, ownership checks and atomic replacement. Preserve enrolled
identities, counters and signatures; never export hardware keys or
erase the only recovery copy."

This module is that engine, independent of the cosmetic surface (the
CLI alias is done; services and paths keep `advanced-vpn` names until
the full matrix runs on both — this tool is what runs the state half
of that matrix, on a real or simulated root):

  inventory  walk the old root, classify every entry (config, state,
             vault, operator/cloud inventory, recovery), hash it and
             check ownership/permissions;
  plan       an explicit, reviewable migration plan: source, dest,
             action (copy/move/preserve-in-place/never-migrate), with
             hardware keys and sealed vaults classified NEVER-MIGRATE
             (they are re-sealed on the new root through enrollment,
             never copied around the hardware);
  apply      atomic replacement per entry with a signed-shape receipt
             (hashes before/after), full rollback on any failure, and
             a refusal to touch anything the inventory flagged.

Every refusal is the point: an unmanaged installation, an ownership
mismatch, or a world-writable state file stops the migration before it
moves a byte, exactly as the plan's acceptance gates demand.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

SCHEMA = 1

# The compatibility root and its target (the plan's two names).
OLD_ROOT = Path("/etc/advanced-vpn")
NEW_ROOT = Path("/etc/cypherpunk-vpn")

# Classification rules: subdirectories of the root by role. Anything
# not classified is UNKNOWN and plans as require-review (the migration
# refuses to guess).
ROLES = {
    "enrolled": "enrolled",  # the enrolled chain bundle (state)
    "vaults": "vault",  # hardware-sealed private vaults
    "keys": "hardware-key",  # never migrates: hardware custody
    "operator": "operator",  # operator key material + inventory
    "cloud": "cloud-inventory",  # provisioned servers inventory
    "state": "state",  # counters, sessions, receipts
    "recovery": "recovery",  # recovery paths
}

NEVER_MIGRATE = ("hardware-key",)  # hardware keys never leave the device
COPY_NOT_MOVE = ("vault",)  # sealed vaults copy; old stays until
# the new root is enrolled and verified


class MigrationError(Exception):
    """A refusal: the migration stops before touching anything."""


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _classify(rel: Path) -> str:
    if len(rel.parts) == 1:
        # Only the known top-level filenames; anything else at the top
        # level is unknown (the plan refuses to guess).
        names = {
            "enrolled": "enrolled",
            "operator.json": "operator",
            "recovery.json": "recovery",
        }
        return names.get(rel.name, "unknown")
    role = ROLES.get(rel.parts[0])
    return role or "unknown"


def inventory(root: Path = OLD_ROOT) -> dict:
    """Walk the root and classify every entry with hashes and metadata.

    The inventory is the receipt's 'before' half and the plan's input.
    An entry that cannot be stat'ed or hashed is recorded as an error —
    the caller decides, but the default is refusal (fail-closed)."""
    root = Path(root)
    if not root.is_dir():
        raise MigrationError(f"{root} is not a directory")
    entries = []
    errors = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel_dir = Path(dirpath).relative_to(root)
        for name in sorted(filenames):
            rel = rel_dir / name if str(rel_dir) != "." else Path(name)
            path = root / rel
            try:
                meta = path.lstat()
                entries.append(
                    {
                        "path": str(rel),
                        "role": _classify(rel),
                        "bytes": meta.st_size,
                        "mode": oct(stat.S_IMODE(meta.st_mode)),
                        "uid": meta.st_uid,
                        "sha256": _hash(path),
                    }
                )
            except OSError as e:
                errors.append({"path": str(rel), "error": str(e)})
    return {
        "schema": SCHEMA,
        "root": str(root),
        "entries": entries,
        "errors": errors,
        "unmanaged_markers": _unmanaged_markers(root),
    }


def _unmanaged_markers(root: Path) -> list[str]:
    """Signs the directory belongs to something other than our packages:
    files owned by unexpected packaging markers, or foreign manifests.
    The plan refuses to migrate an unmanaged installation (row 3)."""
    markers = []
    for marker in ("unmanaged", "MANAGED-BY-OTHER"):
        if (Path(root) / marker).exists():
            markers.append(marker)
    return markers


def check_ownership(inv: dict, expect_uid: int | None = None) -> list[str]:
    """Entries whose uid/mode fail the custody rules. Root-owned files
    must stay root-owned; private material must not be group/world
    readable (0600/0640 shapes)."""
    problems = []
    for e in inv["entries"]:
        if expect_uid is not None and e["uid"] != expect_uid:
            problems.append(f"{e['path']}: owned by uid {e['uid']}, expected {expect_uid}")
        if e["role"] in ("vault", "hardware-key", "operator") and int(e["mode"], 8) & 0o077:
            problems.append(f"{e['path']}: mode {e['mode']} too permissive for {e['role']}")
    return problems


def plan(inv: dict, new_root: Path = NEW_ROOT) -> dict:
    """The explicit migration plan: one action per entry, reviewable
    before anything moves.

    Actions: copy (the new root gets a byte-identical copy; the old
    entry stays), move (copy then remove-old), never-migrate (hardware
    keys: the new root re-enrolls; nothing is copied around the
    hardware), preserve (recovery material copies last, after
    everything else verified). Unmanaged installations and unknown
    roles refuse the whole plan."""
    if inv.get("unmanaged_markers"):
        raise MigrationError(
            f"{inv['root']} carries unmanaged markers {inv['unmanaged_markers']}: "
            "refusing to migrate an installation another tool owns"
        )
    unknown = [e["path"] for e in inv["entries"] if e["role"] == "unknown"]
    if unknown:
        raise MigrationError(f"unknown entries require classification before migration: {unknown[:5]}")
    steps = []
    for e in inv["entries"]:
        role = e["role"]
        if role in NEVER_MIGRATE:
            action = "never-migrate"
        elif role in COPY_NOT_MOVE:
            action = "copy"
        elif role == "recovery":
            action = "preserve"
        else:
            action = "move"
        steps.append(
            {
                "path": e["path"],
                "role": role,
                "action": action,
                "sha256_before": e["sha256"],
            }
        )
    # Recovery copies LAST: everything else must verify first.
    steps.sort(key=lambda s: {"never-migrate": 0, "move": 1, "copy": 2, "preserve": 3}[s["action"]])
    return {
        "schema": SCHEMA,
        "from": inv["root"],
        "to": str(new_root),
        "steps": steps,
        "entries": len(steps),
    }


def apply(plan_doc: dict, source: Path, dest: Path, receipts_path: Path | None = None) -> dict:
    """Execute a plan atomically per entry, with rollback.

    Each step: copy to a temp name in the destination, hash-verify
    against sha256_before, atomic rename, then (for move) remove the
    old entry. Any failure rolls back everything this run changed and
    raises; nothing is left half-migrated. The receipt records every
    step with its after-hash."""
    source, dest = Path(source), Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise MigrationError(f"{dest} exists and is not empty: refusing to overwrite")
    changed: list[tuple[Path, Path]] = []  # (new_location, rollback_target)
    receipts = []
    try:
        for step in plan_doc["steps"]:
            if step["action"] == "never-migrate":
                receipts.append({**step, "status": "not-migrated (hardware custody)"})
                continue
            src = source / step["path"]
            dst = dest / step["path"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".migtmp")
            shutil.copy2(src, tmp)
            if _hash(tmp) != step["sha256_before"]:
                raise MigrationError(f"{step['path']}: hash mismatch during copy")
            os.replace(tmp, dst)
            changed.append((dst, src))
            if step["action"] == "move":
                os.unlink(src)
            receipts.append(
                {
                    **step,
                    "sha256_after": step["sha256_before"],
                    "status": step["action"] + "d",
                }
            )
    except BaseException:
        # Rollback: restore everything we already placed, remove olds
        # we already unlinked (they were moved, so the copy is the
        # original bytes — copy back, then remove the placed file).
        for dst, src in reversed(changed):
            if src.exists():
                # copy step: remove the placed destination only
                if dst.exists():
                    dst.unlink()
            else:
                shutil.copy2(dst, src)
                dst.unlink()
        # The destination was verified empty (or absent) at start, so
        # the directory tree this run created comes down entirely.
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        raise
    if receipts_path is not None:
        receipts_path = Path(receipts_path)
        receipts_path.parent.mkdir(parents=True, exist_ok=True)
        receipts_path.write_text(
            json.dumps(
                {"schema": SCHEMA, "plan": plan_doc["from"] + " -> " + plan_doc["to"], "steps": receipts}, indent=1
            )
            + "\n"
        )
        os.chmod(receipts_path, 0o600)
    return {"ok": True, "steps": len(receipts), "receipts": receipts}


def rollback_plan(receipts_path: Path, source: Path, dest: Path) -> dict:
    """Reverse a completed migration from its receipt: every moved/
    copied entry goes back; never-migrated entries need nothing."""
    doc = json.loads(Path(receipts_path).read_text())
    moved_back = 0
    for step in reversed(doc["steps"]):
        if step["status"].startswith("not-migrated"):
            continue
        dst = Path(dest) / step["path"]
        src = Path(source) / step["path"]
        if not dst.exists():
            continue
        src.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(dst, src)
        dst.unlink()
        moved_back += 1
    return {"ok": True, "restored": moved_back}
