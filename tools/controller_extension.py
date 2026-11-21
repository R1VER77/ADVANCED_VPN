#!/usr/bin/env python3
"""The GUI's three new observation commands (gap #2's read side).

The controller contract's observe-access discipline: every new surface
is a READ. The GUI can SEE streaming eligibility, the multihop presets
and the autoconnect posture; none of the three is a plan or an
operation (the write side stays GetSetup/Preview/Apply).

  GetStreamingEligibility   the generated eligibility table (the dated,
                            measured-or-class-unmeasured rows from
                            tools/streaming_table.py), bounded and
                            schema-validated - the GUI renders the same
                            honesty the CLI prints.
  GetMultihopPresets        the preset definitions (Always / When
                            needed / Never + the streaming and bulk
                            profiles): names, hop counts, protection
                            labels - the policy the user can choose,
                            read-only.
  GetAutoconnectPolicy      the autoconnect POSTURE only: enabled,
                            wired-trusted, and the COUNT of trusted
                            SSIDs. The SSIDs themselves NEVER cross
                            this boundary (test-enforced): a GUI
                            process must not become a place where the
                            home network's name is readable.

Every payload carries schema 1 and bounded arrays, mirroring the
TypeScript side's validation (apps/.../controller/real.ts rejects the
same shapes this module refuses to emit).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCHEMA = 1
TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:  # the backend imports this module from tools/
    sys.path.insert(0, str(TOOLS))
EVIDENCE = TOOLS.parent / "docs" / "evidence"
MAX_TABLE_ROWS = 200
MAX_PRESETS = 8


class ExtensionError(Exception):
    """A malformed request or an unshippable payload (fail-closed)."""


# ---------------------------------------------------- streaming eligibility


def streaming_eligibility(evidence_dir: Path = EVIDENCE) -> dict:
    """The table from docs/evidence/STREAMING_ELIGIBILITY.json, checked
    and bounded for the GUI. Rows are the CLI's own artifact - the GUI
    never invents a row."""
    path = evidence_dir / "STREAMING_ELIGIBILITY.json"
    if not path.exists():
        return {
            "schema": SCHEMA,
            "rows": [],
            "source": "none",
            "note": "no eligibility table generated yet; run `avpn stream-check` and the table generator",
        }
    try:
        table = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ExtensionError(f"unreadable eligibility table: {error}") from error
    rows = table.get("rows", [])
    if not isinstance(rows, list) or len(rows) > MAX_TABLE_ROWS:
        raise ExtensionError("eligibility table out of bounds")
    out_rows = []
    for row in rows:
        out_rows.append(
            {
                "kind": row.get("kind", "measured"),
                "exit": row.get("exit"),
                "provider": row.get("provider"),
                "service": str(row.get("service", ""))[:64],
                "region": row.get("region"),
                "result": str(row.get("result", "unknown"))[:48],
                "transport_profile": row.get("transport_profile"),
                "checked": row.get("checked"),
                "stale": bool(row.get("stale", False)),
                "unmeasured": bool(row.get("unmeasured", False)),
            }
        )
    return {
        "schema": SCHEMA,
        "rows": out_rows,
        "source": "docs/evidence/STREAMING_ELIGIBILITY.json",
        "generated": table.get("generated"),
        "note": "measured rows are dated facts; class rows are unmeasured "
        "background knowledge and are labelled as such",
    }


# -------------------------------------------------------- multihop presets


def multihop_presets(presets_module=None) -> dict:
    """The preset definitions from tools/multihop_presets.py, read-only:
    what the user may choose, with the protection label the GUI must
    carry. Resolving a preset against the live pool is the chain
    planner's job (a plan), not an observation."""
    import multihop_presets as mp

    presets = presets_module.PRESETS if presets_module else mp.PRESETS
    if not isinstance(presets, dict) or not presets or len(presets) > MAX_PRESETS:
        raise ExtensionError("preset registry out of bounds")
    out = []
    for name, spec in sorted(presets.items()):
        if not isinstance(spec, dict) or "hops" not in spec:
            raise ExtensionError(f"malformed preset {name!r}")
        out.append(
            {
                "name": str(name)[:32],
                "hops": int(spec["hops"]),
                "label": str(spec.get("label", ""))[:96],
                "description": str(spec.get("description", ""))[:400],
                "rate": spec.get("rate"),
                "requires": spec.get("requires"),
            }
        )
    return {
        "schema": SCHEMA,
        "presets": out,
        "default": "when-needed",
        "ceiling": 3,
        "note": "presets degrade only downward (3->2->1) with a visible "
        "reason; the 3-hop ceiling is the documented maximum",
    }


# ------------------------------------------------------ autoconnect policy


def autoconnect_policy(policy=None) -> dict:
    """The autoconnect POSTURE for the GUI: enabled, wired-trusted, and
    the COUNT of trusted SSIDs. The SSIDs NEVER cross this boundary -
    a GUI process is not a place where the home network's name should
    be readable (test-enforced below and in the payload assertion)."""
    import autoconnect as ac

    if policy is None:
        try:
            policy = ac.load_policy()
        except Exception:  # noqa: BLE001 (the posture is observable; details are not)
            policy = None
    if policy is None:
        return {
            "schema": SCHEMA,
            "enabled": False,
            "wired_trusted": False,
            "trusted_ssids_count": 0,
            "note": "no policy installed (fail-closed): auto-connect is off "
            "until the owner writes /etc/advanced-vpn/autoconnect.json",
        }
    trusted = policy.get("trusted", {})
    ssids = trusted.get("ssids", [])
    payload = {
        "schema": SCHEMA,
        "enabled": bool(policy.get("enabled", False)),
        "wired_trusted": bool(trusted.get("wired", False)),
        "trusted_ssids_count": len(ssids) if isinstance(ssids, list) else 0,
        "note": "the trusted SSID list itself stays on the device; only the count is observable",
    }
    # the privacy property, enforced at emission time: no SSID text may
    # appear anywhere in the payload (defense in depth against future edits)
    blob = json.dumps(payload)
    for ssid in ssids if isinstance(ssids, list) else []:
        if isinstance(ssid, str) and len(ssid) >= 4 and ssid in blob:
            raise ExtensionError("SSID leaked into the policy payload")
    return payload


# -------------------------------------------------------- dispatch wiring


def dispatch_extension(method: str, value) -> dict | None:
    """The observe-access wiring for tools/controller_backend.py's
    dispatch loop: returns the payload for the three new methods, None
    for unknown ones (the caller raises unknown_method)."""
    if method == "GetStreamingEligibility":
        return streaming_eligibility()
    if method == "GetMultihopPresets":
        return multihop_presets()
    if method == "GetAutoconnectPolicy":
        return autoconnect_policy()
    return None
