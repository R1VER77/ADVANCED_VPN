"""Bounded read-only observations during lab page loads; never manufacture protected status."""

import json
import math
import os
import stat
import threading
import time

from protection import MAX_AGE


def read_generation(path):
    """Read one bounded private inode and its own mtime despite atomic replacement."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise ValueError("invalid private status generation")
        value = json.loads(os.read(fd, 65537))
        if not isinstance(value, dict):
            raise ValueError("status must be an object")
        return value, info.st_mtime
    finally:
        os.close(fd)


def snapshot(runtime, now=None):
    """Read fresh controller evidence with PID-reuse checks, retaining no private profile data."""
    from cypherpunkctl import identity_of

    supplied_time = now
    row = dict(
        time=time.time() if now is None else now,
        monotonic=time.monotonic(),
        protection="unknown",
        reason="missing_status",
    )
    try:
        path = runtime / "status.json"
        status, modified = read_generation(path)
        controller, _ = read_generation(runtime / "controller.json")
        now = time.time() if supplied_time is None else supplied_time
        row.update(time=now, monotonic=time.monotonic())
        alive = controller.get("identity") is not None and identity_of(controller["pid"]) == controller["identity"]
        fresh = 0 <= now - modified <= 1.5
        children = status.get("children") or {}
        children_alive = bool(children) and all(
            c.get("alive") is True and c.get("identity") is not None and identity_of(c["pid"]) == c["identity"]
            for c in children.values()
        )
        evidence = status.get("evidence") or {}
        stale = status.get("stale", {})
        if not isinstance(evidence, dict) or not isinstance(stale, dict):
            raise ValueError("invalid controller evidence")
        evidence_fresh = {
            kind: isinstance(evidence.get(key), (int, float))
            and not isinstance(evidence[key], bool)
            and math.isfinite(evidence[key])
            and -0.001 <= now - evidence[key] <= MAX_AGE[kind]
            for key, kind in (
                ("cloak_confirmed_at", "cloak"),
                ("carrier_handshake_at", "carrier"),
                ("path_probe_at", "probe"),
            )
        }
        row.update(
            lifecycle=status.get("lifecycle"),
            kill_switch=status.get("kill_switch") is True,
            status_age=now - modified,
            controller_alive=alive,
            children_alive=children_alive,
            controller_protection=status.get("protection"),
            controller_stale=[kind for kind in MAX_AGE if kind in stale],
            evidence_fresh=evidence_fresh,
        )
        if not fresh or not alive or not children_alive:
            row["reason"] = "stale_or_dead_controller"
        elif (
            status.get("protection") == "protected"
            and status.get("state") == "supervising"
            and all(evidence_fresh.values())
            and row["kill_switch"]
        ):
            row.update(protection="protected", reason="fresh_controller_evidence")
        else:
            row.update(protection="blocked", reason="controller_not_protected")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        pass
    return row


class Observer:
    """Sample through a load, explicitly retaining the observation interval and gaps."""

    def __init__(self, path, runtime=None, interval=0.5):
        self.path, self.runtime, self.interval = path, runtime, interval
        self.stop = threading.Event()
        self.failure = None
        self.thread = threading.Thread(target=self._run, daemon=True, name="wf-protection-observer")

    def _run(self):
        try:
            with self.path.open("x") as stream:
                while True:
                    row = (
                        snapshot(self.runtime)
                        if self.runtime
                        else dict(
                            time=time.time(),
                            monotonic=time.monotonic(),
                            protection="control",
                            reason="undefended_control",
                        )
                    )
                    stream.write(json.dumps(row, allow_nan=False) + "\n")
                    stream.flush()
                    if self.stop.is_set():
                        break
                    self.stop.wait(self.interval)
        except Exception as error:
            self.failure = error

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive() or self.failure:
            raise RuntimeError("protection observer did not finish cleanly") from self.failure
