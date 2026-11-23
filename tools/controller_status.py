"""Sanitized authoritative desktop status with inode freshness and PID-reuse checks."""

import json
import math
import os
import stat
import time

from protection import MAX_AGE


def read_generation(path):
    """Return bounded private content and the mtime of the same opened inode."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != os.geteuid()
            or meta.st_mode & 0o077
            or meta.st_size > 65536
        ):
            raise ValueError("invalid controller status file")
        value = json.loads(os.read(fd, 65537))
        if not isinstance(value, dict):
            raise ValueError("invalid controller status schema")
        return value, meta.st_mtime
    finally:
        os.close(fd)


def verified(runtime, now=None, identity=None):
    """Unknown on contradictions; a negative protection verdict is not proof of a guard."""
    from cypherpunkctl import identity_of

    identity = identity or identity_of
    supplied = now
    result = dict(protection="unknown", kill_switch="unknown", state="unknown", scope="unknown", evidence=None, since=0)
    try:
        value, modified = read_generation(runtime / "status.json")
        controller, _ = read_generation(runtime / "controller.json")
        now = time.time() if supplied is None else supplied
        result["observed_at"] = now
        if (
            type(controller.get("pid")) is not int
            or controller["pid"] <= 0
            or controller.get("identity") is None
            or identity(controller["pid"]) != controller["identity"]
            or not 0 <= now - modified <= 1.5
        ):
            return result
        if value.get("kill_switch") is not True:
            return result
        scope = value.get("scope")
        if scope not in ("applications", "whole-device"):
            return result
        children = value.get("children")
        children_live = (
            isinstance(children, dict)
            and bool(children)
            and all(
                isinstance(c, dict)
                and type(c.get("pid")) is int
                and c["pid"] > 0
                and c.get("alive") is True
                and c.get("identity") is not None
                and identity(c["pid"]) == c["identity"]
                for c in children.values()
            )
        )
        evidence = value.get("evidence") if isinstance(value.get("evidence"), dict) else {}
        limits = dict(
            cloak_confirmed_at=MAX_AGE["cloak"], carrier_handshake_at=MAX_AGE["carrier"], path_probe_at=MAX_AGE["probe"]
        )
        fresh = all(
            type(evidence.get(k)) in (int, float)
            and math.isfinite(evidence[k])
            and -0.001 <= now - evidence[k] <= limit
            for k, limit in limits.items()
        )
        if value.get("protection") == "protected" and value.get("state") == "supervising" and children_live and fresh:
            result.update(
                protection="protected",
                kill_switch="active",
                state="connected",
                scope=scope,
                evidence={k: evidence[k] for k in limits},
            )
        elif value.get("protection") == "blocked" and value.get("state") in ("supervising", "blocked"):
            result.update(
                protection="blocked",
                kill_switch="active",
                scope=scope,
                state="reconnecting" if value.get("lifecycle") == "reconnecting" else "disconnected",
            )
        since = value.get("since")
        if type(since) in (int, float) and math.isfinite(since) and 0 <= since <= now:
            result["since"] = since
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        pass
    result.setdefault("observed_at", time.time() if supplied is None else supplied)
    return result


def snapshot(state):
    """Only public, validated configuration; no private key paths or raw diagnostics."""
    import cypherpunkctl
    from managed_profile import require_current

    result = dict(
        schema=1,
        observed_at=time.time(),
        enrolled=False,
        state="unknown",
        protection="unknown",
        scope="unknown",
        since=0,
        reason=None,
        next=None,
        chain=[],
        rate=None,
        kill_switch="unknown",
        unlock="none",
        crypto=None,
        exit_ip=None,
    )
    try:
        if not (state / "profile.json").exists():
            result.update(state="not_enrolled", scope="none")
            return result
        profile = require_current(cypherpunkctl.load_profile(state))
        if profile["role"] != "client":
            return result
        pref = cypherpunkctl.read_json_private(state / "preferences.json", {})
        scope = pref.get("mode", "applications")
        if scope not in ("applications", "whole-device"):
            return result
        result.update(enrolled=True, scope=scope, rate=(profile.get("carrier") or {}).get("rate"))
        result.update(verified(cypherpunkctl.runtime_dir(state, create=False)))
        if cypherpunkctl.pin_pending() and result["state"] != "connected":
            result.update(state="locked", next="unlock")
        protection = cypherpunkctl.read_json_private(state / "protection.json", {})
        result["unlock"] = {"nitrokey": "hardware", "systemd-creds": "systemd-creds"}.get(
            protection.get("mode"), "none"
        )
        # Endpoint strings are public, but a profile does not currently sign
        # geographic coordinates/provider labels. Do not invent map locations.
        result["route_endpoints"] = [
            dict(hop=name, endpoint=endpoint) for name, endpoint in cypherpunkctl.chain_of(profile)
        ]
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        result.update(protection="unknown", kill_switch="unknown", state="unknown")
    return result
