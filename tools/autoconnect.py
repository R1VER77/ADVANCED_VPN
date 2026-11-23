#!/usr/bin/env python3
"""Auto-connect on untrusted networks (COMMERCIAL_FEATURE_GAP gap #8).

Every commercial VPN has "connect automatically on untrusted Wi-Fi";
this project's equivalent fits the landed preflight/guard model instead
of growing a daemon:

  - the TRIGGER is the system's own network event (the NetworkManager
    dispatcher script in deploy/, installed by the package, calling
    this module with the event on argv);
  - the DECISION is a local, fail-closed policy: a network is trusted
    only if it is explicitly allowlisted (SSID list, or "wired is
    trusted"); everything else — every new network, every open Wi-Fi,
    every hotel and conference SSID — is untrusted;
  - the ACTION is exactly one thing: bring the tunnel up
    (`cypherpunk connect`, the supervisor the enrolled unit already runs).
    The module NEVER disconnects: auto-disconnect would sever a live
    session without the user asking, and the kill switch already
    handles the dangerous direction (tunnel down -> no traffic).

Safety properties, all test-enforced:

  - opt-in only: a missing or disabled policy takes no action, ever
    (the whole-device guard's arming discipline, applied here);
  - fail-closed: a malformed event, an unreadable policy or a policy
    schema mismatch yields NO-OP, never a bypass;
  - no SSID telemetry: the policy file is local 0600; the module logs
    nothing but the decision to the local journal;
  - wired is opt-in trust (a docking station at home), not default
    trust: the default policy trusts nothing.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SCHEMA = 1
POLICY_PATH = Path("/etc/cypherpunk-vpn/autoconnect.json")
SSID_MAX = 32  # IEEE 802.11 SSID length

# What the dispatcher may ask us to do about a decision.
CONNECT = "connect"
NO_OP = "noop"


class PolicyError(Exception):
    """The policy file is present but invalid: the fail-closed signal."""


def load_policy(path: Path = POLICY_PATH) -> dict | None:
    """The policy, or None when auto-connect is not opted in.

    A missing file is a valid "off" (the default posture). A present
    but malformed file is ALSO off, with the reason recorded in the
    returned sentinel's place — the caller (the dispatcher) treats any
    PolicyError as fail-closed no-op."""
    try:
        raw = path.read_text()
    except OSError:
        return None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise PolicyError(f"policy is not JSON: {e}") from e
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise PolicyError("unsupported policy schema")
    if not doc.get("enabled", False):
        return None
    trusted = doc.get("trusted", {})
    if not isinstance(trusted, dict):
        raise PolicyError("trusted must be an object")
    ssids = trusted.get("ssids", [])
    if not isinstance(ssids, list) or any(not isinstance(s, str) or not s or len(s.encode()) > SSID_MAX for s in ssids):
        raise PolicyError("trusted.ssids must be a list of 1-32-byte strings")
    if not isinstance(trusted.get("wired", False), bool):
        raise PolicyError("trusted.wired must be true or false")
    return doc


def classify(event: dict, policy: dict | None) -> str:
    """(decision) for a network event: CONNECT or NO_OP.

    The event carries: action (up/connectivity), interface type (wifi
    or wired as NetworkManager reports DEVICE_TYPE / the interface
    name), and the SSID/connection id for wireless. Trust is decided
    ONLY by the policy: a wifi network not in the allowlist is
    untrusted; wired is trusted only when the policy says so."""
    if policy is None:
        return NO_OP  # opted out: never act
    if event.get("action") not in ("up", "connectivity-change"):
        return NO_OP  # down/removed/lost events are never interesting
    medium = event.get("medium")
    if medium == "wired":
        return NO_OP if policy["trusted"].get("wired", False) else CONNECT
    if medium == "wifi":
        ssid = event.get("ssid", "")
        allowlist = policy["trusted"].get("ssids", [])
        return NO_OP if ssid and ssid in allowlist else CONNECT
    return NO_OP  # unknown medium: fail-closed no-op


def connect_command() -> list[str]:
    """The action: the enrolled supervisor's connect, nothing else.

    Runs as the dispatcher's user (root) but targets the user service
    the same way `cypherpunk connect` does; the kill switch and namespace
    model are unchanged — this module adds a trigger, not a privilege."""
    return ["/opt/cypherpunk-vpn/bin/cypherpunk", "connect"]


def handle(event: dict, policy: dict | None, run=None) -> dict:
    """Decide and (optionally) act. `run` is injectable so the tests
    exercise the real decision path without executing anything; the
    dispatcher passes subprocess.run. The returned record is the whole
    story for the journal: event, decision, action, exit code."""
    try:
        decision = classify(event, policy)
    except PolicyError as e:
        return {"decision": NO_OP, "reason": f"fail-closed: {e}", "rc": None}
    if decision == NO_OP:
        return {"decision": NO_OP, "reason": "trusted or out of scope", "rc": None}
    if run is None:
        return {"decision": decision, "action": connect_command(), "rc": None}
    completed = run(connect_command())
    return {"decision": decision, "action": connect_command(), "rc": completed.returncode}


# ------------------------------------------------------- NM dispatcher
#
# NetworkManager calls dispatcher scripts with the interface as $1 and
# the action as $2, plus the connection's environment: CONNECTION_ID
# (the user-visible name), DEVICE_TYPE (ethernet/wifi), and for wifi
# the connection's SSID. The deploy/ script translates that contract
# to this module's event shape; the translation itself is tested.


def event_from_env(argv: list[str], env: dict) -> dict | None:
    """Translate NetworkManager's dispatcher contract to an event.

    Returns None for events we never act on (no interface or action),
    so the dispatcher can exit 0 immediately."""
    if len(argv) < 3:
        return None
    action = argv[2]
    device_type = env.get("NM_DEVICE_TYPE", env.get("DEVICE_TYPE", ""))
    conid = env.get("CONNECTION_ID", "") or env.get("SSID", "")
    medium = (
        "wired"
        if "ethernet" in device_type.lower()
        else ("wifi" if "wireless" in device_type.lower() or bool(conid) else None)
    )
    if medium is None:
        return None
    return {"action": action, "medium": medium, "ssid": conid, "interface": argv[1]}


def main(argv=None) -> int:
    """Command line: show or apply the auto-connect decision."""
    argv = list(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ)
    try:
        policy = load_policy()
    except PolicyError as e:
        # Fail-closed: log to the journal, act on nothing.
        print(f"autoconnect: policy error, no action: {e}", file=sys.stderr)
        return 0
    if policy is None:
        return 0  # not opted in
    event = event_from_env(argv, env)
    if event is None:
        return 0
    import subprocess

    record = handle(event, policy, run=subprocess.run)
    if record.get("rc") not in (None, 0):
        print(f"autoconnect: connect exited {record['rc']}", file=sys.stderr)
    return 0  # the dispatcher never fails the network event


if __name__ == "__main__":
    raise SystemExit(main())
