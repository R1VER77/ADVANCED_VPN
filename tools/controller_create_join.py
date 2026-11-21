#!/usr/bin/env python3
"""The GUI setup wizard's create/join branches (gap #2's write side).

The read side (tools/controller_extension.py) is observe-only by design;
this module is the other half of gap #2: the two setup branches and the
write actions each branch may offer, through the controller's existing
Preview/Apply contract.

  join    this desktop enrolls as a client into an existing operator's
          signed route - the existing client steps, now branch-labelled,
          with the client actions (request_device, import_bundle via the
          GUI's own content, connect).

  create  this desktop's user creates their own route and is its first
          client: the operator unlock key on their security key
          (create_operator_keys), the exit identity request under
          operator protection (request_exit), the chain signing with a
          stated allowance (sign_route), then the same verified tail
          (import_bundle, connect).

Discipline, test-enforced:

- checks are evidence-only: a check never installs, generates, signs or
  provisions anything (the setup_flow contract);
- every write action is branch-bound: an action offered by one branch
  is refused when previewed through the other;
- apply is a spec, not a shell line: exact hardcoded argument lists with
  validated fields only - endpoints and names match fixed character sets
  and length bounds, the allowance is an integer in range, and request
  paths are always the wizard's own files, never caller-supplied paths;
- the GUI always states an allowance for sign_route: --accept-cost is a
  CLI-informed act and is deliberately not reachable from the GUI;
- previews re-verify their preconditions and refuse when the world
  changed (the same fail-closed posture as the backend's own prepare);
- every applied action is journaled append-only: caller, action, branch
  and the SHA-256 of the canonical request - never the request content.
"""

from __future__ import annotations

import hashlib
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

import setup_flow
from setup_flow import Result, Step

SCHEMA = 1
BRANCHES = ("create", "join")
KEM_PUBLIC_LEN = 32 + 1184  # keyguard.KEM_PUBLIC (X25519 + ML-KEM-768); read once here


def _pq_crypto_available() -> bool:
    """Whether this environment's cryptography build has mlkem + mldsa
    (the hash-locked environment of tools/hardware-requirements.txt)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401

        import managed_profile  # noqa: F401

        return True
    except ImportError:
        return False


# The operator unlock public key file (keyguard HardwareOperator.create_unlock_key
# writes it into the device vault; managed_profile's servers wrap to it).
OPERATOR_UNLOCK = "operator-unlock.pub"

# Fixed bounds for every field a write action accepts.
MAX_ENDPOINT = 64
MAX_COVER_NAME = 64
MAX_REQUEST_NAME = 64
ALLOWANCE_RANGE = (1, 1_000_000)  # GiB; the cost gate needs a stated number
ENDPOINT_CHARS = re.compile(r"[A-Za-z0-9.:\[\]-]{1,%d}\Z" % MAX_ENDPOINT)
COVER_CHARS = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,%d}\Z" % (MAX_COVER_NAME - 1))
NAME_CHARS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,%d}\Z" % (MAX_REQUEST_NAME - 1))
HOPS = (1, 2, 3)  # the documented 3-hop ceiling (DECISIONS.md D012)

# The append-only journal of applied write actions.
JOURNAL_NAME = "wizard-journal.jsonl"
JOURNAL_MAX_ENTRIES = 512  # one previous generation is kept on rotation


class Refused(Exception):
    """A malformed or out-of-contract write request (fail-closed)."""


def paths(root: Path | None = None) -> dict:
    """The wizard's production layout (root overridable for tests)."""
    base = Path(root) if root else Path("/etc/advanced-vpn")
    return {
        "state": base / "enrolled",  # this desktop's client state (the existing STATE)
        "vault": base / "vault",  # the device vault (avpnctl.DEVICE_VAULT in production)
        "exit": base / "wizard-exit",  # the exit identity this wizard requests
        "requests": base / "wizard-requests",  # relay/middle requests the operator collected
        "signed": base / "wizard-signed",  # avpn init's output directory
        "journal": base / JOURNAL_NAME,
    }


def _operator_unlock(vault: Path) -> bytes | None:
    """The operator unlock public key, read with the safe reader, or None."""
    from keyguard import read_private

    path = Path(vault) / OPERATOR_UNLOCK
    if not path.exists():
        return None
    try:
        return read_private(path, limit=4096)
    except (OSError, ValueError):
        raise Refused("operator_unlock_unreadable") from None


# ------------------------------------------------------------- the checks


def check_operator(ctx):
    """The operator's unlock public key: present and exactly the hybrid
    KEM public key length (X25519 + ML-KEM-768, keyguard.KEM_PUBLIC).
    Production creates it on the security key (one PIN + touch); the
    public half is exported to the vault. This check only reads."""
    from keyguard import KEM_PUBLIC

    try:
        raw = _operator_unlock(ctx["vault"])
    except Refused:
        return Result("blocked", "The operator unlock key file is unreadable; recreate it on the security key.")
    if raw is None:
        return Result(
            "waiting_for_user",
            "Create the operator keys on your security key, then export the unlock public key.",
            dict(unlock_present=False),
        )
    if len(raw) != KEM_PUBLIC:
        return Result(
            "blocked",
            "The operator unlock key file has the wrong length; recreate it on the security key.",
            dict(unlock_present=True, unlock_bytes=len(raw), expected=KEM_PUBLIC),
        )
    return Result(
        "complete",
        "The operator unlock key is present and well-formed.",
        dict(unlock_sha256=hashlib.sha256(raw).hexdigest()),
        setup_flow.fingerprint("operator-unlock", hashlib.sha256(raw).digest()),
    )


def check_exit(ctx):
    """An exit-role device request exists, operator-protected and bound to
    this operator's unlock key. The live cloud provisioning (Task 6's
    surface) happens after this check; nothing here provisions anything."""
    directory = Path(ctx["exit"])
    request_path = directory / "request.json"
    if not request_path.exists():
        return Result(
            "waiting_for_user",
            "Request the exit identity (operator-protected) once the operator keys exist.",
            dict(exit_present=False),
        )
    from keyguard import read_private

    try:
        req = json.loads(read_private(request_path, limit=1024 * 1024))
    except (OSError, ValueError, json.JSONDecodeError):
        return Result("blocked", "The exit request is unreadable; reset and request it again.")
    unlock = req.get("unlock") if isinstance(req, dict) else None
    if req.get("role") != "exit" or not isinstance(unlock, dict):
        return Result("blocked", "The stored request is not an operator-protected exit request.")
    binding = unlock.get("operator_unlock_sha256")
    if not isinstance(binding, str) or not re.fullmatch("[0-9a-f]{64}", binding or ""):
        return Result("blocked", "The exit request's unlock record is malformed.")
    try:
        operator = _operator_unlock(ctx["vault"])
    except Refused:
        return Result("blocked", "The operator key is unreadable; the exit request cannot be verified.")
    if operator is None:
        return Result("blocked", "The operator key is gone; the exit request cannot be verified.")
    if binding != hashlib.sha256(operator).hexdigest():
        return Result(
            "blocked",
            "The exit request is bound to a different operator key; reset and request it again.",
        )
    return Result(
        "complete",
        "The exit identity request exists and is bound to this operator's key.",
        dict(role="exit", protection="operator", unlock_sha256=binding),
        setup_flow.fingerprint("exit-request", binding),
    )


# ------------------------------------------------------ the branch shapes


def join_steps():
    """The join branch: this desktop is a client of an existing route."""
    return setup_flow.client_steps()


def create_steps():
    """The create branch: operator keys, the exit request, then the same
    verified tail - the creating desktop is its own route's first client."""
    return [
        Step("host", "Check this system", (), setup_flow.check_host),
        Step("key", "Check your security key", ("host",), setup_flow.check_key),
        Step("vault", "Check the VPN credential record", ("key",), setup_flow.check_vault),
        Step("operator", "Check the operator keys", ("vault",), check_operator),
        Step("exit", "Check the exit identity request", ("operator",), check_exit),
        Step("profile", "Check the enrolled route", ("exit",), setup_flow.check_profile),
        Step("servers", "Check configured server endpoints", ("profile",), setup_flow.check_servers),
        Step("guard", "Verify the traffic guard", ("servers",), setup_flow.check_guard),
        Step("protected", "Verify the complete connection", ("guard",), setup_flow.check_protected),
    ]


def steps_for(branch: str):
    """The steps of one branch; unknown branches never reach a step list."""
    if branch == "create":
        return create_steps()
    if branch == "join":
        return join_steps()
    raise Refused("invalid_setup_branch")


# ---------------------------------------------------- the write actions
#
# The three new actions are create-branch only. request_device,
# import_bundle, connect, repair and unlock stay exactly where they are
# (the backend's existing handlers); the GUI's own import surface carries
# the bundle content for import_bundle on both branches.

CREATE_ACTIONS = {
    "operator": ("create_operator_keys",),
    "exit": ("request_exit",),
    "profile": ("sign_route",),
}


def validate(branch: str, name: str, request) -> dict:
    """Shape-validate one write request against its branch's contract.
    Returns the bounded fields; refuses anything out of contract."""
    if branch not in BRANCHES:
        raise Refused("invalid_setup_branch")
    if name == "create_operator_keys" or name == "request_exit":
        if branch != "create" or name not in CREATE_ACTIONS["operator" if name == "create_operator_keys" else "exit"]:
            raise Refused("action_not_offered_on_this_branch")
        if request not in (None, {}):
            raise Refused("action_takes_no_arguments")
        return {}
    if name == "sign_route":
        if branch != "create":
            raise Refused("action_not_offered_on_this_branch")
        if not isinstance(request, dict):
            raise Refused("malformed_sign_route")
        hops = request.get("hops")
        if hops not in HOPS:
            raise Refused("hops_out_of_range")
        out = {"hops": hops}
        for field in ("exit", "relay", "middle"):
            value = request.get(field)
            if value is None:
                if field == "exit" or (field == "relay" and hops >= 2) or (field == "middle" and hops == 3):
                    raise Refused(f"{field}_endpoint_required")
                continue
            if field != "exit" and hops == 1:
                raise Refused("single_hop_has_no_relay_or_middle")
            if not isinstance(value, str) or not ENDPOINT_CHARS.fullmatch(value):
                raise Refused(f"invalid_{field}_endpoint")
            # A concrete endpoint, as `avpn init` itself parses it: never a flag (a value
            # like `--accept-cost` must not depend on the parser to fail), IPv4 on the
            # first hop, IPv6 allowed on a later one (reached over a TCP link).
            first = field == "relay" or (field == "exit" and hops == 1)
            try:
                from managed_profile import endpoint_parts

                endpoint_parts(value, ipv6=not first)
            except ValueError:
                raise Refused(f"invalid_{field}_endpoint") from None
            out[field] = value
        allowance = request.get("allowance_gib")
        if not isinstance(allowance, int) or isinstance(allowance, bool):
            raise Refused("allowance_must_be_an_integer")
        if not ALLOWANCE_RANGE[0] <= allowance <= ALLOWANCE_RANGE[1]:
            raise Refused("allowance_out_of_range")
        out["allowance_gib"] = allowance
        cover = request.get("cover_name")
        if cover is not None:
            if not isinstance(cover, str) or not COVER_CHARS.fullmatch(cover):
                raise Refused("invalid_cover_name")
            out["cover_name"] = cover
        extras = request.get("extra_requests", [])
        if not isinstance(extras, list) or len(extras) > 4:
            raise Refused("extra_requests_out_of_bounds")
        names = []
        for item in extras:
            if not isinstance(item, dict) or item.get("role") not in ("relay", "middle"):
                raise Refused("extra_request_role_must_be_relay_or_middle")
            file_name = item.get("name")
            if not isinstance(file_name, str) or not NAME_CHARS.fullmatch(file_name):
                raise Refused("invalid_request_name")
            names.append((item["role"], file_name))
        needed = {"relay"} if hops >= 2 else set()
        needed |= {"middle"} if hops == 3 else set()
        if {role for role, _ in names} != needed:
            raise Refused("extra_requests_must_match_the_hops")
        out["extra_requests"] = names
        return out
    raise Refused("unknown_action")


def prepare(branch: str, name: str, request, where: dict | None = None) -> dict | None:
    """The bounded preview for the create-branch actions: a fixed summary
    and effect list. Returns None when the action is not one of ours (the
    backend's existing handlers apply). Preconditions are re-verified and
    a changed world refuses instead of previewing."""
    where = where or paths()
    if name not in ("create_operator_keys", "request_exit", "sign_route"):
        return None
    fields = validate(branch, name, request)
    if name == "create_operator_keys":
        return dict(
            schema=SCHEMA,
            summary="Create the operator signing keys on your security key",
            effects=[
                "Use the trusted native PIN/device prompts and touch confirmation.",
                "Generate the operator unlock key pair (X25519 + ML-KEM-768) on the security key.",
                "Seal the private half under the key's hardware secret; export only the public half.",
                "Record the creation in the controller journal.",
            ],
        )
    if name == "request_exit":
        operator = _operator_unlock(where["vault"])
        if operator is None:
            raise Refused("operator_keys_must_exist_first")
        if (Path(where["exit"]) / "request.json").exists():
            raise Refused("exit_request_already_exists")
        return dict(
            schema=SCHEMA,
            summary="Request the exit identity under operator protection",
            effects=[
                "Use the trusted native PIN/device prompts and touch confirmation.",
                "Generate the exit server's keys on this machine and seal them under the operator's unlock key.",
                "Write the public request for the operator to sign; private keys never leave this directory.",
                "Bind the request to operator unlock key SHA-256: " + hashlib.sha256(operator).hexdigest() + ".",
                "Record the request in the controller journal.",
            ],
        )
    # sign_route: the requests the wizard itself produced must all exist.
    for role, path in _route_requests(fields, where):
        if not path.exists():
            raise Refused(f"{role}_request_missing")
    effects = [
        "Sign the chain from the requests this wizard produced (one PIN + touch on the security key).",
        "Hops: %d (the documented 3-hop ceiling)." % fields["hops"],
        "Exit endpoint: %s." % fields["exit"],
    ]
    if "relay" in fields:
        effects.append("Entry relay endpoint: %s." % fields["relay"])
    if "middle" in fields:
        effects.append("Middle relay endpoint: %s." % fields["middle"])
    effects.append(
        "State the cover-traffic allowance: %d GiB per month (the cost gate refuses an unstated allowance)."
        % fields["allowance_gib"]
    )
    if "cover_name" in fields:
        effects.append("First-hop camouflage name: %s." % fields["cover_name"])
    effects.append("Write the signed bundles for every device into the wizard's signed directory.")
    effects.append("Record the signing in the controller journal.")
    return dict(schema=SCHEMA, summary="Sign the chain from this wizard's requests", effects=effects)


def _route_requests(fields: dict, where: dict):
    """The (role, path) pairs sign_route passes to avpn init: always the
    wizard's own files, never caller-supplied paths."""
    out = [("client", Path(where["state"]) / "device.req")]
    for role, name in fields.get("extra_requests", []):
        out.append((role, Path(where["requests"]) / (name + ".req")))
    out.append(("exit", Path(where["exit"]) / "device.req"))
    return out


def apply(branch: str, name: str, request, where: dict | None = None) -> dict:
    """The exact execution spec for a create-branch action. The backend
    executes this spec under the authenticated prompt; nothing here runs
    anything, and no caller text beyond the validated fields appears."""
    where = where or paths()
    fields = validate(branch, name, request)
    if name == "create_operator_keys":
        return {
            "kind": "dispatch",
            "state": None,
            "argv": ["unlock-key", "--vault", str(Path(where["vault"]))],
            "journal": True,
        }
    if name == "request_exit":
        operator = _operator_unlock(where["vault"])
        if operator is None:
            raise Refused("operator_keys_must_exist_first")
        if (Path(where["exit"]) / "request.json").exists():
            raise Refused("exit_request_already_exists")
        return {
            "kind": "dispatch",
            "state": str(Path(where["exit"])),
            "argv": [
                "request",
                "--role",
                "exit",
                "--protect",
                "operator",
                "--unlock-key",
                str(Path(where["vault"]) / OPERATOR_UNLOCK),
                "--out",
                str(Path(where["exit"]) / "device.req"),
            ],
            "journal": True,
        }
    # sign_route
    for role, path in _route_requests(fields, where):
        if not path.exists():
            raise Refused(f"{role}_request_missing")
    argv = [
        "init",
        "--out",
        str(Path(where["signed"])),
        "--vault",
        str(Path(where["vault"])),
        "--hops",
        str(fields["hops"]),
        "--exit",
        fields["exit"],
        "--allowance-gib",
        str(fields["allowance_gib"]),
    ]
    if "relay" in fields:
        argv += ["--relay", fields["relay"]]
    if "middle" in fields:
        argv += ["--middle", fields["middle"]]
    if "cover_name" in fields:
        argv += ["--cover-name", fields["cover_name"]]
    for role, path in _route_requests(fields, where):
        argv += ["--request", f"{role}={path}"]
    return {"kind": "dispatch", "state": None, "argv": argv, "journal": True}


# ---------------------------------------------------------------- journal


def _digest(branch: str, name: str, request) -> str:
    """SHA-256 of the canonical request: the journal records what was
    approved, never the request content itself."""
    canonical = json.dumps({"branch": branch, "action": name, "request": request}, sort_keys=True, allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def journal_append(journal_path, branch: str, name: str, request, uid: int, now=None) -> dict:
    """Append one applied action to the append-only journal (0600, fsync,
    one rotated generation kept). Refuses anything but a regular file."""
    path = Path(journal_path)
    entry = dict(
        schema=SCHEMA,
        at=round(time.time() if now is None else now, 3),
        uid=int(uid),
        branch=branch,
        action=name,
        input_digest=_digest(branch, name, request),
    )
    if path.exists():
        m = path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_mode & 0o077:
            raise Refused("unsafe_journal")
        lines = path.read_text().splitlines()
        if len(lines) >= JOURNAL_MAX_ENTRIES:
            rotated = path.with_name(path.name + ".1")
            if rotated.exists():
                rotated.unlink()
            path.rename(rotated)
            lines = []
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    line = json.dumps(entry, sort_keys=True, allow_nan=False)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return entry


# ------------------------------------------------- the setup report's actions


def decorate(branch: str, report: dict, findings=()) -> None:
    """Fill each step's actions for one branch, in place, with the same
    rules as the backend's existing loop: an action is offered only at a
    step that is not complete, and connect only at the current step."""
    if branch not in BRANCHES:
        raise Refused("invalid_setup_branch")
    for step in report["steps"]:
        step["actions"] = []
        if step["state"] in ("complete", "skipped"):
            continue
        current = report["current"] == step["id"]
        if step["id"] == "key":
            for finding in findings:
                if finding.repair:
                    selector = (
                        finding.detail.get("serial") if finding.repair == "yubikey_enable_fido2" else finding.device
                    )
                    step["actions"].append(dict(action="repair", repair=finding.repair, selector=selector))
        elif step["id"] == "vault" and step["state"] == "waiting_for_user":
            step["actions"].append(dict(action="request_device"))
        elif step["id"] == "operator" and branch == "create" and current:
            step["actions"].append(dict(action="create_operator_keys"))
        elif step["id"] == "exit" and branch == "create" and current:
            step["actions"].append(dict(action="request_exit"))
        elif (
            step["id"] == "profile"
            and current
            and not Path(report.get("_state", "/nonexistent")).joinpath("profile.json").exists()
        ):
            step["actions"].append(dict(action="request_device"))
            if branch == "create":
                step["actions"].append(dict(action="sign_route"))
        elif step["id"] in ("guard", "protected") and current:
            step["actions"].append(dict(action="connect", scope="applications"))


def decorate_report(branch: str, report: dict, state: Path, findings=()) -> dict:
    """The backend-facing wrapper: annotate the report with the state path
    (the profile action needs it) and decorate the steps."""
    report["_state"] = str(state)
    decorate(branch, report, findings)
    del report["_state"]
    return report
