#!/usr/bin/env python3
"""The client's profile store: more than one enrolled chain, one active.

ROADMAP section 3: "A profile store: the client holds more than one enrolled
chain with an active selection, and a viability check (verified, current,
protection intact, servers healthy) that decides what each launch shows."

Layout - the runtime's view of the world is unchanged, it still reads the one
enrolled directory it always read:

    <root>/enrolled                  the ACTIVE chain (exactly today's state)
    <root>/profiles/<name>/          stored, INACTIVE chains
    <root>/profiles/selection.json   {"schema": 1, "active": "<name>"}

with <root> = /etc/cypherpunk-vpn. Rules the store holds itself to:

- names are bounded and lowercase ([a-z][a-z0-9-]{0,15}); no traversal, no
  collisions, no adopting over an existing slot;
- adopt() moves a COMPLETE client enrollment into the store - the controller's
  own loader must accept it first (verified + current), because a stored chain
  that could never connect is clutter, not a choice;
- select() swaps by rename and refuses beneath a guard: the caller supplies
  the live guard state and the store fails closed (an unconfirmed caller can
  never swap protection out from under a running route, the D006
  removal-beneath-guard rule carried over);
- an interrupted swap is a first-class state: selection.json is written last,
  so a crash between the two renames is detected and completed by repair();
  a launch never offers a half-swapped world;
- viability is four honest answers: verified (the controller's own loader
  accepts the profile), current (require_current: padded, cloaked when a
  carrier runs), protection_intact (the state directory is guard-ready: a
  valid mode preference and the pre-VPN network snapshot a clean teardown
  needs) and servers_healthy (every hop endpoint is configured - the live
  reachability probe stays the connection check's job unless the controller
  supplies one, and the verdict says so, probe: "not_run");
- launch_view() is the decision each launch shows: "connect" (the active
  chain is viable), "choose" (only stored chains are viable) or "setup"
  (nothing viable; back to provisioning). It never invents a protection
  claim: a chain that has not been verified says so.

The verifier is a parameter so the store is testable without the hash-locked
cryptography environment; production uses production_verifier(), which lazily
imports the controller's own loader (cypherpunkctl.load_profile and
managed_profile.require_current).
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:  # the backend imports this module from tools/
    sys.path.insert(0, str(TOOLS))

SCHEMA = 1
NAME_CHARS = re.compile(r"[a-z][a-z0-9-]{0,15}\Z")
MAX_STORED = 8  # a bounded store; more is a fleet, not a client
MODES = ("applications", "whole-device")


class Refused(Exception):
    """A malformed or out-of-contract store request (fail-closed)."""


def paths(root: Path | None = None) -> dict:
    """The store's production layout (root overridable for tests)."""
    base = Path(root) if root else Path("/etc/cypherpunk-vpn")
    return {
        "root": base,
        "active": base / "enrolled",
        "store": base / "profiles",
        "selection": base / "profiles" / "selection.json",
    }


def production_verifier(state: Path) -> dict:
    """The controller's own verdict on one enrolled state directory: the
    profile must load through the strict validator and be current (padded,
    cloaked when a carrier runs). Returns the facts the launch view states."""
    import cypherpunkctl
    from managed_profile import require_current

    profile = require_current(cypherpunkctl.load_profile(Path(state)))
    chain = cypherpunkctl.chain_of(profile)
    return {
        "role": profile["role"],
        "hops": len(chain),
        "endpoints": [endpoint for _, endpoint in chain],
    }


# ------------------------------------------------------------- the bookkeeping


def _safe_dir(path: Path) -> os.stat_result:
    """A directory we own, with no group/other write bits and no symlink."""
    m = path.lstat()
    if stat.S_ISLNK(m.st_mode):
        raise Refused("symlinked_store_path")
    if not stat.S_ISDIR(m.st_mode):
        raise Refused("not_a_directory")
    if m.st_uid != os.geteuid():
        raise Refused("store_not_owned_by_us")
    if m.st_mode & 0o022:
        raise Refused("unsafe_store_permissions")
    return m


def _valid_name(value) -> bool:
    return value is None or (isinstance(value, str) and bool(NAME_CHARS.fullmatch(value)))


def read_selection(where: dict) -> dict:
    """selection.json, or the empty selection when absent. Strict: schema 1,
    a well-formed active name or null, and - when a swap is in flight - the
    phase marker with its two well-formed names. Anything else is refused
    rather than guessed."""
    path = Path(where["selection"])
    if not path.exists():
        return {"schema": SCHEMA, "active": None}
    m = path.lstat()
    if not stat.S_ISREG(m.st_mode) or stat.S_ISLNK(m.st_mode) or m.st_mode & 0o077:
        raise Refused("unsafe_selection_file")
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        raise Refused("unreadable_selection") from None
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != SCHEMA
        or not ("active" in doc)
        or not _valid_name(doc["active"])
    ):
        raise Refused("malformed_selection")
    if "phase" in doc:
        if (
            doc["phase"] != "swap"
            or not _valid_name(doc.get("from"))
            or not _valid_name(doc.get("to"))
            or (doc.get("from") is None and doc.get("to") is None)
            or set(doc) - {"schema", "active", "phase", "from", "to"}
        ):
            raise Refused("malformed_swap_marker")
    elif set(doc) - {"schema", "active"}:
        raise Refused("malformed_selection")
    return doc


def write_selection(where: dict, name: str | None, **extra) -> dict:
    """Atomically write selection.json (0600, fsync, rename over a temp file
    in the same directory). The steady state names the chain now living in
    the active slot; select() first writes the same file with a swap marker
    so every crash window is repairable from pure existence facts."""
    if name is not None and not (isinstance(name, str) and NAME_CHARS.fullmatch(name)):
        raise Refused("invalid_profile_name")
    doc = {"schema": SCHEMA, "active": name, **extra}
    directory = Path(where["store"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _safe_dir(directory)
    temp = directory / ".selection.new"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    try:
        payload = json.dumps(doc, sort_keys=True, allow_nan=False)
        os.write(fd, payload.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, Path(where["selection"]))
    return doc


def _slot(name: str, where: dict) -> Path:
    if not (isinstance(name, str) and NAME_CHARS.fullmatch(name)):
        raise Refused("invalid_profile_name")
    return Path(where["store"]) / name


# --------------------------------------------------------- adopt and select


def adopt(source, name: str, where: dict | None = None, verifier=None) -> dict:
    """Move a complete client enrollment into the store under `name`. The
    controller's verifier must accept it first; production is
    production_verifier (lazy imports, so this stays testable). Refuses name
    collisions, unsafe sources and non-client roles."""
    where = where or paths()
    verifier = verifier or production_verifier
    source = Path(source)
    _safe_dir(source)
    facts = verifier(source)  # raises when the chain is not verified+current
    if facts.get("role") not in (None, "client"):
        raise Refused("only_client_chains_are_stored")
    slot = _slot(name, where)
    if slot.exists():
        raise Refused("profile_name_taken")
    directory = Path(where["store"])
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _safe_dir(directory)
    if len([p for p in directory.iterdir() if p.is_dir()]) >= MAX_STORED:
        raise Refused("profile_store_full")
    try:
        os.rename(source, slot)  # one atomic move; cross-device refuses below
    except OSError as error:
        if error.errno == 18:  # EXDEV: the store and the source must share a filesystem
            raise Refused("store_and_source_must_share_a_filesystem") from None
        raise
    return {"schema": SCHEMA, "name": name, "stored": facts}


def select(
    name: str, where: dict | None = None, unprotected: bool = False, store_current_as: str | None = None, verifier=None
) -> dict:
    """Make the stored chain `name` the active one. Fails closed unless the
    caller confirms no guard is running (unprotected=True): the store never
    swaps protection out from under a live route. The previously active
    chain is stored first, under selection.json's recorded name or the
    caller's explicit store_current_as. A swap marker is written BEFORE the
    first rename and the steady selection after the last, so any crash in
    between is a state repair() can resolve from existence facts alone."""
    where = where or paths()
    verifier = verifier or production_verifier
    if unprotected is not True:
        raise Refused("refused_beneath_a_guard")  # fail closed on an unconfirmed caller
    target = _slot(name, where)
    if not target.exists():
        raise Refused("no_such_stored_profile")
    _safe_dir(target)
    verifier(target)  # never swap in a chain the controller would refuse
    active = Path(where["active"])
    current = None
    if active.exists():
        _safe_dir(active)
        current = store_current_as or read_selection(where)["active"]
        if current is None:
            raise Refused("name_the_active_chain_to_store_it_first")
        if _slot(current, where).exists():
            raise Refused("profile_name_taken")
    # Phase 1 - the marker: from this point every crash is repairable.
    write_selection(where, current, phase="swap", **{"from": current, "to": name})
    try:
        if current is not None:
            os.rename(active, _slot(current, where))
        os.rename(target, active)
    except OSError:
        # put the world back before refusing: a failed swap must not leave
        # the previous chain homeless; the marker still lets repair() check.
        if current is not None and not active.exists() and _slot(current, where).exists():
            os.rename(_slot(current, where), active)
        if active.exists() and not target.exists():
            pass  # the second rename never happened; the marker says which world
        write_selection(where, current)
        raise
    # Phase 2 - the steady state.
    write_selection(where, name)
    return {"schema": SCHEMA, "active": name, "stored_previous": current}


def repair(where: dict | None = None) -> dict:
    """Detect and resolve an interrupted swap from existence facts alone.
    With a swap marker present, the (active?, from-slot?, to-slot?) triple
    names exactly one recovery: complete the half-done swap, undo it, or
    finalize the finished one. Without a marker, a stale selection that
    names a promoted slot is re-recorded. Never invents a swap: ambiguity
    that cannot be resolved is reported, not guessed."""
    where = where or paths()
    selection = read_selection(where)
    active = Path(where["active"])
    if selection.get("phase") == "swap":
        source, target = selection["from"], selection["to"]
        a = active.exists()
        f = source is not None and _slot(source, where).exists()
        t = target is not None and _slot(target, where).exists()
        if a and f and not t:
            write_selection(where, target)  # the swap completed before the final write
            return {"schema": SCHEMA, "repaired": "finalized_completed_swap", "active": target}
        if a and not f and t:
            write_selection(where, source)  # the swap never started
            return {"schema": SCHEMA, "repaired": "cleared_unstarted_swap", "active": source}
        if a and f and t:  # both slots and the active chain: refuse to guess
            return {"schema": SCHEMA, "repaired": "ambiguous_swap_state", "active": selection["active"]}
        if a and not f and not t:
            # from was None (a promotion) and the target is active: finalize it;
            # otherwise no rename ever happened and the source chain still rules.
            if source is None:
                write_selection(where, target)
                return {"schema": SCHEMA, "repaired": "finalized_completed_swap", "active": target}
            write_selection(where, source)
            return {"schema": SCHEMA, "repaired": "cleared_unstarted_swap", "active": source}
        if not a and f and t:
            os.rename(_slot(source, where), active)  # undo: the first rename only
            write_selection(where, source)
            return {"schema": SCHEMA, "repaired": "undid_half_swap", "active": source}
        if not a and not f and t:
            os.rename(_slot(target, where), active)  # complete the promotion
            write_selection(where, target)
            return {"schema": SCHEMA, "repaired": "completed_interrupted_swap", "active": target}
        if not a and f and not t:
            os.rename(_slot(source, where), active)  # the target vanished; restore the source
            write_selection(where, source)
            return {"schema": SCHEMA, "repaired": "restored_source_after_lost_target", "active": source}
        write_selection(where, None)  # nothing anywhere: an empty store is honest
        return {"schema": SCHEMA, "repaired": "emptied_inconsistent_store", "active": None}
    recorded = selection["active"]
    if active.exists():
        if recorded and not _slot(recorded, where).exists():
            write_selection(where, recorded)  # the named chain was promoted into the slot
            return {"schema": SCHEMA, "repaired": "selection_rerecorded", "active": recorded}
        return {"schema": SCHEMA, "repaired": None, "active": recorded}
    if recorded:
        slot = _slot(recorded, where)
        if slot.exists():
            os.rename(slot, active)  # a promotion crashed between rename and write
            write_selection(where, recorded)
            return {"schema": SCHEMA, "repaired": "completed_interrupted_swap", "active": recorded}
    return {"schema": SCHEMA, "repaired": None, "active": None}


# ------------------------------------------------------------- the viability


def _read_json_private(path: Path, limit: int = 65536):
    """A bounded safe JSON read (regular file, no symlink, 0600, uid-owned).
    The controller has the same reader; this local copy keeps the store
    importable without the hash-locked cryptography environment."""
    path = Path(path)
    if not path.exists():
        return None
    m = path.lstat()
    if not stat.S_ISREG(m.st_mode) or stat.S_ISLNK(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
        raise Refused("unsafe_state_file")
    if m.st_size > limit:
        raise Refused("state_file_too_large")
    try:
        return json.loads(path.read_text())
    except ValueError:
        raise Refused("malformed_state_file") from None


def _guard_ready(state: Path) -> tuple[bool, str]:
    """Protection intact, as the store can honestly check it: the mode
    preference (when present) is one of the two the guard knows, and the
    pre-VPN network snapshot a clean teardown needs exists."""
    preferences = _read_json_private(Path(state) / "preferences.json")
    if preferences is not None:
        if not isinstance(preferences, dict) or preferences.get("mode") not in MODES:
            return False, "preferences_out_of_contract"
    if not (Path(state) / "network-before.json").exists():
        return False, "missing_network_snapshot"
    return True, "ok"


def viability(state, name: str | None = None, where: dict | None = None, verifier=None, probe=None) -> dict:
    """One chain's launch verdict: verified, current, protection_intact,
    servers_healthy. `probe` (controller-supplied) maps an endpoint to a
    boolean; without it, servers_healthy states configuration only and says
    the probe did not run - the live reachability check stays the
    connection's job."""
    where = where or paths()
    verifier = verifier or production_verifier
    state = Path(state)
    detail: dict = {}
    verified = current = False
    if not state.is_dir():
        detail["verified"] = "no_such_state"
    else:
        try:
            facts = verifier(state)
        except Exception as error:  # the loader's refusals are the verdict, not a crash
            reason = error.args[0] if error.args else type(error).__name__
            detail["verified"] = reason if isinstance(reason, str) else type(error).__name__
            detail["role"], detail["hops"], detail["endpoints"] = None, 0, []
        else:
            verified = True
            # The production verifier proves both at once (require_current); a
            # stub may model a chain signed before the current features.
            current = facts.get("current", True) is True
            detail.update(
                role=facts.get("role"), hops=facts.get("hops", 0), endpoints=list(facts.get("endpoints") or [])
            )
    if state.is_dir():
        try:
            protection_intact, protection_detail = _guard_ready(state)
        except Refused as error:  # an unsafe state file is a verdict, not a crash
            protection_intact, protection_detail = False, error.args[0]
    else:
        protection_intact, protection_detail = False, "no_such_state"
    detail["protection"] = protection_detail
    endpoints = detail.get("endpoints") or []
    configured = bool(endpoints) and all(isinstance(e, str) and e for e in endpoints)
    if probe is None:
        servers_healthy, detail["probe"] = configured, "not_run"
    else:
        try:
            answers = [bool(probe(e)) for e in endpoints]
        except Exception:
            servers_healthy, detail["probe"] = False, "probe_error"
        else:
            servers_healthy = configured and all(answers)
            detail["probe"] = "run"
            detail["answers"] = answers
    viable = verified and current and protection_intact and servers_healthy
    return {
        "schema": SCHEMA,
        "name": name,
        "verified": verified,
        "current": current,
        "protection_intact": protection_intact,
        "servers_healthy": servers_healthy,
        "viable": viable,
        "detail": detail,
    }


def launch_view(where: dict | None = None, verifier=None, probe=None, now=None) -> dict:
    """What each launch shows: the active chain's verdict, every stored
    chain's verdict, and the offer - "connect" (a viable active chain),
    "choose" (only stored chains are viable) or "setup" (nothing viable;
    back to provisioning)."""
    where = where or paths()
    now = time.time() if now is None else now
    repaired = repair(where)  # a launch never offers a half-swapped world
    profiles = []
    active = Path(where["active"])
    if active.exists():
        active_name = read_selection(where)["active"]
        verdict = viability(active, active_name, where, verifier, probe)
        verdict["where"] = "active"
        profiles.append(verdict)
    directory = Path(where["store"])
    if directory.is_dir():
        for slot in sorted(p for p in directory.iterdir() if p.is_dir()):
            if not NAME_CHARS.fullmatch(slot.name):
                continue  # a foreign directory is not ours to offer
            verdict = viability(slot, slot.name, where, verifier, probe)
            verdict["where"] = "stored"
            profiles.append(verdict)
    active_viable = any(p["where"] == "active" and p["viable"] for p in profiles)
    stored_viable = [p["name"] for p in profiles if p["where"] == "stored" and p["viable"]]
    offer = "connect" if active_viable else "choose" if stored_viable else "setup"
    return {
        "schema": SCHEMA,
        "generated": round(now, 3),
        "repaired": repaired["repaired"],
        "active": next((p["name"] for p in profiles if p["where"] == "active"), None),
        "offer": offer,
        "profiles": profiles,
        "note": "Viability states verified, current, protection-intact and server "
        "configuration; live reachability is the connection check's claim.",
    }
