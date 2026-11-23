"""Fly.io Machines API, and ssh/scp over its exec API, for a chain server on a Fly Machine
(standard library only: cloud.py runs under the system Python).

A Fly Machine runs no sshd: `cypherpunk cloud` reaches it through the Machines API's exec call,
which runs a command in the Machine and returns its output. `fly-ssh` and `fly-scp`
(tools/) give that the shape of ssh and scp, so the cloud tool's host scripts run on a
Fly exit unchanged:

    fly-ssh --app APP MACHINE COMMAND...         # like ssh: the words joined, run by sh
    fly-scp [-q] --app APP SRC MACHINE:DST       # upload (base64 on stdin)
    fly-scp [-q] --app APP MACHINE:SRC DST       # download

The token is a Fly deploy token for the app, read from a file only the user can read
(CPVPN_FLY_TOKEN_FILE, default ~/.config/cypherpunk-vpn/fly-deploy-token); it is never
printed or put in an argument list.
"""

import base64
import json
import os
from pathlib import Path
import shlex
import sys
import urllib.error
import urllib.request

API = "https://api.machines.dev/v1"
EXEC_TIMEOUT = 600  # the exec API's maximum


class FlyError(Exception):
    """A Machines API call failed."""


def token_path():
    """Where the deploy token is kept."""
    return Path(os.environ.get("CPVPN_FLY_TOKEN_FILE") or Path.home() / ".config/cypherpunk-vpn/fly-deploy-token")


def token():
    """The deploy token, refusing a file others can read."""
    p = token_path()
    try:
        if p.stat().st_mode & 0o077:
            raise FlyError("%s is readable by others: chmod 600 it" % p)
        return p.read_text().strip()
    except FileNotFoundError:
        raise FlyError("no Fly deploy token at %s" % p) from None


def api(method, path, body=None, timeout=60):
    """One Machines API call; the parsed JSON reply."""
    req = urllib.request.Request(  # noqa: S310 (API is a fixed https URL)
        API + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": token(), "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https URL)
            raw = r.read()
    except urllib.error.HTTPError as e:
        detail = e.read()[:300].decode(errors="replace")
        raise FlyError("Fly API %s %s: HTTP %d %s" % (method, path.split("?")[0], e.code, detail)) from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise FlyError("Fly API unreachable: %s" % e) from None
    return json.loads(raw) if raw.strip() else {}


def run(app, machine, argv, stdin=None, timeout=EXEC_TIMEOUT):
    """Run `argv` in the Machine: (exit code, stdout, stderr)."""
    body = dict(command=list(argv), timeout=timeout)
    if stdin is not None:
        body["stdin"] = stdin
    r = api("POST", "/apps/%s/machines/%s/exec" % (app, machine), body, timeout=timeout + 30)
    return r.get("exit_code") or 0, r.get("stdout") or "", r.get("stderr") or ""


def _app(args):
    if len(args) < 2 or args[0] != "--app":
        raise SystemExit("usage: --app APP ...")
    return args[1], args[2:]


def ssh_main(args):
    """fly-ssh --app APP MACHINE [COMMAND...]: like ssh, the words run by a shell, stdin passed on."""
    app, rest = _app(args)
    while rest and rest[0].startswith("-"):  # ssh options the cloud tool may add: ignored
        rest = rest[2:] if rest[0] in ("-o", "-F", "-i") else rest[1:]
    if not rest:
        raise SystemExit("usage: fly-ssh --app APP MACHINE COMMAND...")
    machine, command = rest[0], " ".join(rest[1:]) or "true"
    stdin = None if sys.stdin.isatty() else sys.stdin.read()
    code, out, err = run(app, machine, ["/bin/sh", "-c", command], stdin=stdin or None)
    sys.stdout.write(out)
    sys.stderr.write(err)
    return code


def scp_main(args):
    """fly-scp [-q] --app APP SRC DST, one side MACHINE:PATH."""
    args = [a for a in args if a != "-q"]
    app, rest = _app(args)
    if len(rest) != 2:
        raise SystemExit("usage: fly-scp [-q] --app APP SRC DST")
    src, dst = rest
    if ":" in dst and ":" not in src:
        machine, path = dst.split(":", 1)
        data = base64.b64encode(Path(src).read_bytes()).decode()
        command = "umask 077; base64 -d > %s" % shlex.quote(path)
        code, _out, err = run(app, machine, ["/bin/sh", "-c", command], stdin=data)
    elif ":" in src and ":" not in dst:
        machine, path = src.split(":", 1)
        code, out, err = run(app, machine, ["base64", "-w0", path])
        if code == 0:
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(base64.b64decode(out))
    else:
        raise SystemExit("fly-scp: exactly one side must be MACHINE:PATH")
    sys.stderr.write(err)
    return code


def main(argv):
    """Entry point for tools/fly-ssh and tools/fly-scp."""
    try:
        return {"ssh": ssh_main, "scp": scp_main}[argv[0]](argv[1:])
    except FlyError as e:
        sys.stderr.write("%s\n" % e)
        return 255


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
