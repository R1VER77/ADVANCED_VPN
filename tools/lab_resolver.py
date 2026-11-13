"""A private, writable /etc/resolv.conf for a lab's own mount namespace (standard library only).

Whole-device mode rewrites the resolver file. A lab must give it one of its own and never
write the host's. Hosts differ: on Ubuntu (and GitHub's runners) /etc/resolv.conf is a
symlink into /run, which the lab has replaced with its own tmpfs, so the link dangles
(and util-linux refuses to mount onto it); elsewhere it is a real file.
"""

from pathlib import Path
import subprocess


def private_resolver(etc=Path("/etc/resolv.conf"), run=Path("/run")):
    """Make `etc` resolve to an empty, writable file private to this mount namespace.
    Call after mounting a fresh tmpfs on `run`. Returns the file now behind `etc`."""
    if etc.is_symlink():
        target = etc.resolve()
        if run not in target.parents:
            raise RuntimeError("the resolver link leaves the lab's private /run: %s" % target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("")
        target.chmod(0o644)
        return target
    private = run / "lab-resolv.conf"
    private.write_text("")
    private.chmod(0o644)
    subprocess.run(["/usr/bin/mount", "--bind", str(private), str(etc)], check=True, capture_output=True)  # noqa: S603
    return private
