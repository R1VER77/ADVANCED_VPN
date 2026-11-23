"""Evidence-driven, resumable client setup. Checks alone complete steps.

No check installs software, logs into a provider, changes a token, unseals a key or
changes networking. The checkpoint contains public summaries and fingerprints only;
all facts are checked again on resume. Authentication still happens in trusted dialogs.
"""

import base64
import hashlib
import json
import math
import os
import secrets
import stat
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from state_transaction import directory

STATES = ("pending", "running", "waiting_for_user", "waiting_for_hardware", "blocked", "failed", "complete", "skipped")
CHECKPOINT = "setup.json"
MAX_CHECKPOINT = 256 * 1024
STATUS_MAX_AGE = 5.0


@dataclass
class Result:
    """One check's state, human prompt and deliberately limited public evidence."""

    state: str
    say: str
    evidence: dict = field(default_factory=dict)
    fingerprint: str | None = None
    findings: list = field(default_factory=list)

    def __post_init__(self):
        if self.state not in STATES:
            raise ValueError("unknown setup state")


@dataclass
class Step:
    """One step and its earlier dependencies; check(context) returns a Result."""

    id: str
    title: str
    depends: tuple
    check: object


def fingerprint(*parts):
    """A domain-separated digest of public inputs; never key material."""
    raw = json.dumps(parts, sort_keys=True, default=str).encode()
    return hashlib.sha256(b"cpvpn/setup/v1\0" + raw).hexdigest()


def load(state_dir):
    """Read a bounded private checkpoint; malformed data conveys no completion."""
    path = Path(state_dir) / CHECKPOINT
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return dict(schema=1, steps={})
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077:
            raise ValueError("unsafe setup checkpoint")
        raw = f.read(MAX_CHECKPOINT + 1)
    try:
        record = json.loads(raw) if len(raw) <= MAX_CHECKPOINT else None
        if not isinstance(record, dict) or record.get("schema") != 1 or not isinstance(record.get("steps"), dict):
            raise ValueError("invalid checkpoint")
        return record
    except (ValueError, UnicodeError):
        return dict(schema=1, steps={})


def save(state_dir, record):
    """Commit a private checkpoint without following symlinks or exposing a partial file."""
    parent = Path(state_dir)
    meta = parent.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
        raise ValueError("unsafe setup directory")
    tmp = parent / (".setup-" + secrets.token_hex(12))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(record, f, indent=1, sort_keys=True, allow_nan=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, parent / CHECKPOINT)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


def run(steps, context, state_dir, now=time.time):
    """Recheck all steps under a private directory lock, invalidating changed dependencies."""
    ids = set()
    for step in steps:
        if step.id in ids or any(d not in ids for d in step.depends):
            raise ValueError("setup steps need unique ids and earlier dependencies")
        ids.add(step.id)
    state_dir = Path(state_dir)
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    with directory(state_dir):
        old = load(state_dir).get("steps", {})
        current, done, changed, out = {}, {}, set(), []
        context = dict(context, now=now)
        for step in steps:
            if not all(done.get(d) in ("complete", "skipped") for d in step.depends):
                r = Result("pending", "Complete the earlier checks first.")
            else:
                try:
                    r = step.check(context)
                    if not isinstance(r, Result):
                        raise TypeError("check did not return a Result")
                except Exception as e:
                    # Exception text can contain credentials or command arguments.
                    r = Result(
                        "failed",
                        "This check could not finish. Review the diagnostic and retry.",
                        dict(error=type(e).__name__),
                    )
            prev = old.get(step.id, {})
            if not isinstance(prev, dict):
                prev = {}
            if prev.get("fingerprint") != r.fingerprint and prev.get("fingerprint") is not None:
                changed.add(step.id)
            if any(d in changed for d in step.depends):
                changed.add(step.id)
            done[step.id] = r.state
            out.append((step, r))
            current[step.id] = dict(
                state=r.state,
                say=r.say,
                evidence=r.evidence,
                fingerprint=r.fingerprint,
                checked_at=round(now(), 3),
                inputs_changed=step.id in changed,
            )
        save(
            state_dir,
            dict(
                schema=1,
                steps=current,
                total=len(out),
                complete=sum(r.state in ("complete", "skipped") for _, r in out),
                current=next((s.id for s, r in out if r.state not in ("complete", "skipped")), None),
            ),
        )
        return out


def check_host(ctx):
    """Use exactly the same host checks as preflight and doctor."""
    import preflight

    report = ctx.get("preflight", lambda: preflight.inspect_host())()
    data = dict(ready=report["ready"], blockers=report["blockers"], warnings=report["warnings"])
    return Result(
        "complete" if report["ready"] else "blocked",
        "System requirements checked." if report["ready"] else "Resolve the preflight blockers first.",
        data,
        fingerprint(data),
        report["findings"],
    )


def check_key(ctx):
    """Check protocol capability; this does not prove possession of a saved credential."""
    import hwkey

    findings = ctx.get("diagnose", lambda: hwkey.diagnose(hwkey.hid_devices(), hwkey.usb_devices()))()
    blocking = [f for f in findings if f.severity == "blocker"]
    ready = [f for f in findings if f.code == "key_ready"]
    data = [dict(code=f.code, severity=f.severity, message=f.message, repair=f.repair) for f in findings]
    if len(ready) == 1 and not blocking:
        f = ready[0]
        fp = fingerprint(f.device, f.detail.get("vendor"), f.detail.get("product"), f.detail.get("firmware"))
        return Result("complete", f.message, dict(keys=1, scope="capability_only"), fp, data)
    if len(ready) > 1:
        return Result("waiting_for_user", "Leave only the intended key connected, then check again.", findings=data)
    if blocking and blocking[0].code == "no_key":
        return Result("waiting_for_hardware", blocking[0].message, findings=data)
    return Result("blocked", blocking[0].message if blocking else "No usable key.", findings=data)


def check_vault(ctx):
    """Validate the saved public credential record; possession is verified at connection."""
    from fido2.webauthn import AttestedCredentialData
    from keyguard import RP, read_private

    path = Path(ctx["vault"]) / "credential.json"
    if not path.exists():
        return Result("waiting_for_user", "Create this device's VPN keys using the trusted PIN and touch prompt.")
    try:
        meta = json.loads(read_private(path))
        if (
            not isinstance(meta, dict)
            or type(meta.get("schema")) is not int
            or meta["schema"] != 1
            or meta.get("rp") != RP
        ):
            raise ValueError("wrong vault")
        if type(meta.get("counter")) is not int or not 0 <= meta["counter"] <= 0xFFFFFFFF:
            raise ValueError("invalid credential counter")
        public = AttestedCredentialData(base64.b64decode(meta["credential"], validate=True))
        if len(base64.b64decode(meta["salt"], validate=True)) != 32 or not public.credential_id:
            raise ValueError("invalid credential")
    except (ValueError, TypeError, KeyError):
        return Result("blocked", "The VPN credential record is invalid; use the enrollment recovery flow.")
    return Result(
        "complete",
        "The public VPN credential record is valid; unlock will verify the key.",
        dict(rp=RP, possession_verified=False),
        fingerprint(meta["credential"]),
    )


def check_profile(ctx):
    """Read the controller's validated enrolled profile; never import an unchecked bundle."""
    import cypherpunkctl
    from managed_profile import require_current

    state = Path(ctx["state"])
    if not (state / "profile.json").exists():
        return Result(
            "waiting_for_user", "Sign and enroll this device's route, or obtain its signed file from your operator."
        )
    try:
        profile = require_current(cypherpunkctl.load_profile(state))
    except (ValueError, RuntimeError, OSError):
        return Result("blocked", "The installed route is unreadable or unsupported; check enrollment.")
    ctx["profile"] = profile
    return Result(
        "complete",
        "The installed route passes the controller's profile checks.",
        dict(hops=len(cypherpunkctl.chain_of(profile))),
        fingerprint(profile),
    )


def check_servers(ctx):
    """Public endpoints exist in the enrolled route; reachability is tested end to end later."""
    import cypherpunkctl

    profile = ctx.get("profile")
    if not profile:
        return Result("waiting_for_user", "Add your servers and enroll the signed route first.")
    hops = cypherpunkctl.chain_of(profile)
    return Result(
        "complete",
        "Server endpoints are configured; the final connection check verifies reachability.",
        dict(configured_endpoints=len(hops), reachability_verified=False),
        fingerprint(hops),
    )


def status(ctx):
    """One fresh supervisor snapshot, bound to a live process identity; never cached completion."""
    if "_setup_status" in ctx:
        return ctx["_setup_status"]
    if "status" in ctx:
        value = dict(ctx["status"]() or {})
    else:
        import cypherpunkctl

        state = Path(ctx["state"])
        rt = cypherpunkctl.runtime_dir(state, create=False)
        value = cypherpunkctl.read_status(state) or {}
        try:
            controller = cypherpunkctl.read_json_private(rt / "controller.json", {})
            live = cypherpunkctl.identity_of(controller["pid"]) == controller["identity"]
            age = ctx.get("now", time.time)() - (rt / "status.json").stat().st_mtime
            value["_fresh"] = live and 0 <= age <= STATUS_MAX_AGE
        except (OSError, ValueError, KeyError, TypeError):
            value["_fresh"] = False
    ctx["_setup_status"] = value
    return value


def check_guard(ctx):
    """Require a fresh running supervisor report for the configured traffic guard."""
    s = status(ctx)
    if s.get("_fresh") is True and s.get("state") in ("supervising", "blocked") and s.get("kill_switch") is True:
        return Result("complete", "The configured traffic guard is active.", dict(state=s["state"]))
    return Result("waiting_for_user", "Start the VPN, then recheck its traffic guard.")


def check_protected(ctx):
    """Fresh mutual confirmation, carrier handshake and path probe are all required."""
    from protection import MAX_AGE

    s = status(ctx)
    evidence = s.get("evidence") or {}
    now = ctx.get("now", time.time)()
    limits = dict(
        cloak_confirmed_at=MAX_AGE["cloak"], carrier_handshake_at=MAX_AGE["carrier"], path_probe_at=MAX_AGE["probe"]
    )
    fresh = all(
        isinstance(evidence.get(k), (int, float))
        and not isinstance(evidence.get(k), bool)
        and math.isfinite(evidence[k])
        and 0 <= now - evidence[k] <= limit
        for k, limit in limits.items()
    )
    if (
        s.get("_fresh") is True
        and s.get("state") == "supervising"
        and s.get("kill_switch") is True
        and s.get("protection") == "protected"
        and fresh
    ):
        return Result(
            "complete",
            "The configured route is connected and verified.",
            dict(evidence={k: evidence[k] for k in limits}),
        )
    if s.get("reason") == "privacy_budget":
        prompt = "The optional daily budget is exhausted. Wait for its reset or review the budget preferences."
    elif s.get("_fresh") is not True:
        prompt = "Current supervisor status is unavailable. Check the service and permissions, then retry."
    elif s.get("lifecycle") == "reconnecting":
        prompt = "The route is reconnecting under the guard. Wait, or inspect status for the connection failure."
    else:
        prompt = "Connect and wait for fresh route, handshake and guard checks."
    return Result("waiting_for_user", prompt, dict(lifecycle=s.get("lifecycle"), reason=s.get("reason")))


def client_steps():
    """The deterministic client checks; server creation and signing use existing commands."""
    return [
        Step("host", "Check this system", (), check_host),
        Step("key", "Check your security key", ("host",), check_key),
        Step("vault", "Check the VPN credential record", ("key",), check_vault),
        Step("profile", "Check the enrolled route", ("vault",), check_profile),
        Step("servers", "Check configured server endpoints", ("profile",), check_servers),
        Step("guard", "Verify the traffic guard", ("servers",), check_guard),
        Step("protected", "Verify the complete connection", ("guard",), check_protected),
    ]


def report(out):
    """A single controller/GUI result with typed findings and the current prompt."""
    rows = [dict(id=s.id, title=s.title, depends=list(s.depends), **asdict(r)) for s, r in out]
    complete = sum(r.state in ("complete", "skipped") for _, r in out)
    return dict(
        schema=1,
        complete=complete,
        total=len(rows),
        finished=complete == len(rows),
        current=next((r["id"] for r in rows if r["state"] not in ("complete", "skipped")), None),
        steps=rows,
    )
