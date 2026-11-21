#!/usr/bin/env python3
"""Multihop presets: Always / When needed / Never (and the workload profiles).

COMMERCIAL_FEATURE_GAP_20261119.md section 5.3 records Mullvad's August
2026 multihop modes (Always / When needed / Never, plus automatic entry
choice) as a "small parity item, planned by structure". This module is
that structure: named presets over the landed chain planner
(`tools/mesh.py select_chain`, 1-3 hops across distinct operators,
providers and countries), plus the two workload profiles
PATH_SELECTION_DESIGN.md section 6 designs.

The presets are policy, not mechanism: each one fixes the hop count and
a protection label the GUI and plan must carry, and resolves against
the live mesh directory — degrading ONLY downward (3 -> 2 -> 1) with a
visible reason, never upward without the user asking. "When needed" is
the honest default: 2 hops (sticky guard + exit) unless the mesh
cannot satisfy diversity at 2, in which case it falls to 1 with the
reduced-separation label shown.

The 3-hop ceiling stays the documented maximum (the market note: with
Perfect Privacy shut down, no live commercial VPN offers user-chosen
cascades deeper than 3; depth parity is already true).

Presets and profiles:

  always       3 hops, "maximum separation" — distinct operator,
               provider and country on every hop (the planner's rule).
  when-needed  2 hops, the default (guard + exit); falls to 1 hop,
               labelled, when the pool cannot staff 2.
  never        1 hop (exit only), "reduced separation", user-chosen.
  streaming    2 hops + line rate class + exit eligibility by the
               dated stream-check descriptor field (PATH_SELECTION
               section 6.1 strong-only posture).
  bulk         2 hops + the exit's inbound bulk admission (section 6.2;
               connect-only P2P works on any exit).
"""

from __future__ import annotations

SCHEMA = 1
MAX_HOPS = 3  # the documented ceiling; a 4th hop is a chain-planner
# extension nobody needs (depth parity is already true)

PRESETS = {
    "always": {
        "hops": 3,
        "label": "maximum separation",
        "description": "3 hops across distinct operators, providers and countries; the planner's full diversity rule.",
    },
    "when-needed": {
        "hops": 2,
        "label": "balanced (the default)",
        "description": "2 hops (sticky guard + exit); falls to 1 hop, labelled, only when the pool cannot staff 2.",
    },
    "never": {
        "hops": 1,
        "label": "reduced separation",
        "description": "1 hop (exit only); the user chose speed over multi-operator separation.",
    },
    "streaming": {
        "hops": 2,
        "label": "streaming profile (strong-only)",
        "description": "2 hops, line rate class, exit eligibility by the "
        "dated streaming descriptor field; no adaptive "
        "posture (PATH_SELECTION section 6.1 option 1).",
        "rate": "line",
        "requires": "streaming-eligible exit (dated descriptor field)",
    },
    "bulk": {
        "hops": 2,
        "label": "bulk profile",
        "description": "2 hops; inbound listening ports only through exits "
        "whose exit_policy admits the bulk plan "
        "(connect-only swarms work on any exit).",
        "requires": "exit_policy bulk admission for listening ports",
    },
}


class PresetError(Exception):
    """Unknown preset, or a preset the pool cannot honor."""


def resolve(name: str, select, nodes, **kwargs) -> dict:
    """Resolve a preset to a chain plan using the caller's select_chain.

    `select` is mesh.select_chain (injected: the tests pass a stub that
    reproduces its refusal semantics); the preset fixes `hops` and
    degrades downward on refusal, recording the reason. Returns the
    plan: {preset, hops, degraded, reason, label, chain (from select)}.
    """
    if name not in PRESETS:
        raise PresetError(f"unknown preset: {name} (known: {', '.join(sorted(PRESETS))})")
    preset = PRESETS[name]
    hops = preset["hops"]
    last_error = None
    while hops >= 1:
        try:
            chain = select(nodes, hops, **kwargs)
            return {
                "schema": SCHEMA,
                "preset": name,
                "hops": hops,
                "requested_hops": preset["hops"],
                "degraded": hops < preset["hops"],
                "reason": (
                    f"pool could not staff {preset['hops']} hops with diversity; fell to {hops}"
                    if hops < preset["hops"]
                    else "preset honored"
                ),
                "label": preset["label"],
                "chain": chain,
            }
        except SystemExit as e:  # select_chain refuses: diversity unmet
            last_error = str(e)
            hops -= 1
    raise PresetError(f"the pool cannot staff even 1 hop: {last_error}")


def apply_preset_flags(name: str) -> dict:
    """The extra planner flags a preset implies (rate class, gates)."""
    preset = PRESETS[name]
    flags = {"hops": preset["hops"]}
    if "rate" in preset:
        flags["rate"] = preset["rate"]
    return flags
