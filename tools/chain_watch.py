"""Make a broken chain obvious (owner, 20 Nov 2026): a server stopped by its provider (an
idle Always Free reclaim), locked after a reboot (operator protection), out of credits or
unreachable shows up on the client as a chain that stops answering. The supervisor feeds
each protection verdict here; after a grace period it raises one desktop notification and
puts a notice in `cypherpunk status`, and another when the chain answers again.

Nothing here touches the network: the provider APIs that say *why* are asked only when the
person runs `cypherpunk cloud health` (calling them on a timer from home would tie this address
to the servers in the providers' logs)."""

import os
from pathlib import Path
import subprocess
import time

DOWN_GRACE = 60  # seconds without an answer, after it had worked
START_GRACE = 120  # seconds after start without ever answering
NEXT = "on your computer, as yourself: cypherpunk cloud health  (it says why, and the fix)"


def _clock(ts):
    return time.strftime("%H:%M", time.localtime(ts))


class ChainWatch:
    """Turn verdicts into at most one 'down' notice per outage and one 'back' notice."""

    def __init__(self, notify, started=None):
        self.notify = notify
        self.started = time.time() if started is None else started
        self.ever = False
        self.down_since = None
        self.announced = False

    def observe(self, now, verdict):
        """Feed one verdict; return the status fields to add ({} while fine)."""
        if verdict.get("protection") == "protected":
            if self.announced:
                self.notify("VPN protected again", "The chain answers again (%s)." % _clock(now))
            self.ever, self.down_since, self.announced = True, None, False
            return {}
        if self.down_since is None:
            self.down_since = now
        waited = now - (self.down_since if self.ever else self.started)
        if waited < (DOWN_GRACE if self.ever else START_GRACE):
            return {}
        since = self.down_since if self.ever else self.started
        stale = verdict.get("stale", {})
        if "probe" in stale and "cloak" not in stale and "carrier" not in stale:
            detail = "exit DNS check unanswered since %s. The first hop and carrier still report in" % _clock(since)
        else:
            detail = (
                "no answer through the chain since %s. A server may be stopped (a free tier reclaims idle ones), "
                "locked after a reboot, out of credits or unreachable; traffic stays blocked meanwhile" % _clock(since)
            )
        if not self.announced:
            self.notify(
                "VPN chain not answering",
                detail[0].upper() + detail[1:] + ".\nFor ordinary internet access, open sudo cypherpunk and press k.",
            )
            self.announced = True
        return dict(detail=detail, next=NEXT)


def desktop_target():
    """(uid, gid, environment) of the desktop to notify, or None. Through sudo: the invoking
    person's session (keyguard.desktop_session). As the system service: the one person with a
    graphical session on this machine, if exactly one."""
    from keyguard import desktop_session

    found = desktop_session()
    if found and found[0] is not None:
        return found
    if found:  # this process's own session (not root)
        return None, None, found[2]
    candidates = []
    for runtime in Path("/run/user").glob("[0-9]*"):
        uid = int(runtime.name)
        if uid == 0 or not (runtime / "bus").exists():
            continue
        wayland = sorted(p.name for p in runtime.glob("wayland-[0-9]*") if not p.name.endswith(".lock"))
        if not wayland and not Path("/tmp/.X11-unix/X0").exists():  # noqa: S108 - fixed X socket, checked only
            continue
        env = {"PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": str(runtime),
               "DBUS_SESSION_BUS_ADDRESS": "unix:path=%s" % (runtime / "bus")}  # fmt: skip
        if wayland:
            env["WAYLAND_DISPLAY"] = wayland[0]
        else:
            env["DISPLAY"] = ":0"
        candidates.append((uid, runtime.stat().st_gid, env))
    return candidates[0] if len(candidates) == 1 else None


def desktop_notify(title, body, target=None, run=subprocess.run):
    """Show a notification on the person's desktop; quietly nothing without one."""
    from sysexec import trusted_exe

    target = desktop_target() if target is None else target
    if not target:
        return False
    uid, gid, env = target
    try:
        exe = trusted_exe("notify-send")
    except (FileNotFoundError, ValueError):
        return False
    kwargs = dict(env=env, capture_output=True, timeout=10, check=False)
    if uid is not None and os.geteuid() == 0:
        kwargs.update(user=uid, group=gid, extra_groups=[])
    try:
        return run([exe, "--app-name=Cypherpunk VPN", "--urgency=critical", title, body], **kwargs).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
