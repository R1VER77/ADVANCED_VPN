#!/usr/bin/env python3
"""The descriptor's `exit_policy` field: what an exit admits, as a signed fact.

PATH_SELECTION_DESIGN.md section 2 designs the field ("ports/protocols
admitted, egress ceiling — exit eligibility per destination, Tor-style
exit policy"); section 6.2 constrains it: port admission is opt-in and
scarce, an exit offering it must say so in the plan, and it must never
be required for a profile to work. This module is that field's
semantics, shared by the descriptor validator (`tools/mesh.py
validate`) and the traffic-class profiles:

  policy = {
    "schema": 1,
    "default": "refuse",                  # fail-closed; the only default
    "rules": [                            # ordered; first match wins
      {"proto": "tcp", "ports": "1-65535", "direction": "outbound",
       "effect": "accept"},
      {"proto": "tcp", "ports": "25", "direction": "outbound",
       "effect": "reject"},               # the carve-out (spam port)
      {"proto": "tcp", "ports": "6881-6889", "direction": "inbound",
       "effect": "accept", "plan": "bulk",
       "abuse_contact": "operator-pseudonym@mesh"}   # inbound is scarce
    ],
    "egress_ceiling_gib_month": 4096,
    "inbound_admission": "static-manual",
    "notes": "opt-in admission per PATH_SELECTION section 6.2"
  }

Rules that hold the design to its own constraints:

- Default refuse. A policy that does not say `accept` admits nothing;
  a missing policy field means an exit that admits nothing beyond the
  tunnel's own carrier (the default posture of every exit today).
- Inbound accepts REQUIRE a `plan` label and an `abuse_contact` —
  the abuse/ToS caution in section 6.2, machine-checked at validation
  time instead of trusted to prose. A missing contact is a validation
  error, not a warning.
- The dynamic consumer form (NAT-PMP/UPnP self-configuration plus
  DDNS naming, the hide.me/AirVPN shape) is deliberately NOT
  implemented: it widens the exit's attack surface to LAN-grade
  protocols and needs its own gate. `inbound_admission` carries the
  decision ("static-manual"); anything else is a validation error
  today, so a future change is a visible, reviewed edit.
- Every accept is attributable: the profile that uses it (streaming,
  bulk) can answer "which rule admitted this flow".

The streaming profile's gate is `admits_streaming()` (outbound TCP 443
— the services' carrier) and the bulk profile's gate is
`admits_inbound_bulk()` (an inbound accept labelled `plan: bulk`).
"""

from __future__ import annotations

import re

SCHEMA = 1
PROTOS = ("tcp", "udp")
DIRECTIONS = ("outbound", "inbound")
POLICY_KEYS = {"schema", "default", "rules", "egress_ceiling_gib_month", "inbound_admission", "notes"}
RULE_KEYS = {"proto", "ports", "direction", "effect", "plan", "abuse_contact"}
PORT_MIN, PORT_MAX = 1, 65535

# The Mullvad-style outbound hygiene set: ports no exit should speak
# (mail submission/SMB/mDNS/UPnP surfaces), refused by default even in
# an otherwise-open outbound policy. A descriptor MAY re-accept them
# explicitly, but the default outbound template below does not.
DEFAULT_REFUSED_OUTBOUND = ("25", "137-139", "445", "1900", "2869")

_PORT_RANGE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def _parse_ports(spec: str) -> list[tuple[int, int]]:
    """'443' -> [(443,443)]; '6881-6889' -> [(6881,6889)]; [] on error."""
    m = _PORT_RANGE.match(spec or "")
    if not m:
        return []
    lo = int(m.group(1))
    hi = int(m.group(2) or m.group(1))
    if lo < PORT_MIN or hi > PORT_MAX or lo > hi:
        return []
    return [(lo, hi)]


def validate_policy(policy) -> list[str]:
    """Structural errors; an empty list means the field may be signed."""
    if policy is None:
        return []  # a missing field is the default refuse-everything posture
    if not isinstance(policy, dict):
        return ["exit_policy must be an object"]
    errors = []
    # A closed schema, like the Rust descriptor (deny_unknown_fields): a key this
    # validator does not know is refused, never silently signed and later rejected.
    unknown = set(policy) - POLICY_KEYS
    if unknown:
        errors.append("exit_policy: unknown keys %s" % sorted(unknown))
    if policy.get("schema") != SCHEMA:
        errors.append("unsupported exit_policy schema")
    if policy.get("default") != "refuse":
        errors.append("the only supported default is refuse (fail-closed)")
    rules = policy.get("rules")
    if not isinstance(rules, list):
        errors.append("exit_policy.rules must be a list")
        return errors
    for i, rule in enumerate(rules):
        where = f"rule {i}"
        if not isinstance(rule, dict):
            errors.append(f"{where}: must be an object")
            continue
        if set(rule) - RULE_KEYS:
            errors.append(f"{where}: unknown keys {sorted(set(rule) - RULE_KEYS)}")
        if rule.get("proto") not in PROTOS:
            errors.append(f"{where}: proto must be tcp or udp")
        if rule.get("direction") not in DIRECTIONS:
            errors.append(f"{where}: direction must be outbound or inbound")
        if rule.get("effect") not in ("accept", "reject"):
            errors.append(f"{where}: effect must be accept or reject")
        if not _parse_ports(str(rule.get("ports", ""))):
            errors.append(f"{where}: ports must be N or N-M within 1-65535")
        if rule.get("effect") == "accept" and rule.get("direction") == "inbound":
            if not rule.get("plan"):
                errors.append(f"{where}: an inbound accept must name its plan")
            if not rule.get("abuse_contact"):
                errors.append(f"{where}: an inbound accept must carry an abuse_contact")
    ceiling = policy.get("egress_ceiling_gib_month")
    if ceiling is not None and (not isinstance(ceiling, int) or ceiling <= 0):
        errors.append("egress_ceiling_gib_month must be a positive integer")
    admission = policy.get("inbound_admission", "none")
    if admission not in ("none", "static-manual"):
        errors.append(
            "inbound_admission must be none or static-manual; the dynamic "
            "NAT-PMP/UPnP form is a separate owner decision with its own gate"
        )
    if any_inbound_accept(policy) and admission == "none":
        errors.append("inbound accepts require inbound_admission: static-manual")
    return errors


def _rule_matches(rule: dict, proto: str, port: int, direction: str) -> bool:
    if rule.get("proto") != proto or rule.get("direction") != direction:
        return False
    for lo, hi in _parse_ports(str(rule.get("ports", ""))):
        if lo <= port <= hi:
            return True
    return False


def admits(policy, proto: str, port: int, direction: str) -> tuple[bool, str]:
    """(admitted, reason) for one flow. First matching rule wins; the
    default is refuse, so an unmatched flow is refused with the policy
    default as the reason. A missing policy refuses everything."""
    if policy is None:
        return False, "no exit_policy: the exit admits only the tunnel carrier"
    if direction == "inbound" and policy.get("inbound_admission") == "none":
        return False, "inbound admission is off"
    for rule in policy.get("rules", []):
        if _rule_matches(rule, proto, port, direction):
            if rule.get("effect") == "accept":
                label = rule.get("plan") or "policy"
                return True, f"accepted by rule {rule.get('ports')} ({label})"
            return False, f"rejected by rule {rule.get('ports')}"
    return False, "no rule matched; default refuse"


def any_inbound_accept(policy) -> bool:
    """Whether the policy admits any inbound connection at all."""
    if not isinstance(policy, dict):
        return False
    return any(
        isinstance(r, dict) and r.get("direction") == "inbound" and r.get("effect") == "accept"
        for r in policy.get("rules", [])
    )


# --------------------------------------------------------------- gates
# The profile gates: what the streaming and bulk profiles need an exit
# to admit before they will consider it.


def admits_streaming(policy) -> tuple[bool, str]:
    """Streaming profile gate: outbound TCP 443 (the services' carrier)."""
    return admits(policy, "tcp", 443, "outbound")


def admits_inbound_bulk(policy) -> tuple[bool, str]:
    """Bulk/P2P profile gate: at least one inbound accept labelled for
    the bulk plan (a listening port the exit explicitly offers)."""
    if not any_inbound_accept(policy):
        return False, "the exit offers no inbound admission"
    if not isinstance(policy, dict):
        return False, "no exit_policy"
    for rule in policy.get("rules", []):
        if (
            isinstance(rule, dict)
            and rule.get("direction") == "inbound"
            and rule.get("effect") == "accept"
            and rule.get("plan") == "bulk"
        ):
            return True, f"inbound {rule.get('proto')} {rule.get('ports')} for bulk"
    return False, "no inbound accept is labelled for the bulk plan"


def default_outbound() -> dict:
    """A sensible outbound-only policy: everything out except the
    hygiene set, nothing in. Rules are ordered; first match wins, so
    the specific rejects come BEFORE the broad accepts (Tor exit
    policy convention). The template `cypherpunk mesh publish` offers; the
    operator edits from here."""
    rules = []
    for spec in DEFAULT_REFUSED_OUTBOUND:
        for proto in ("tcp", "udp"):
            rules.append({"proto": proto, "ports": spec, "direction": "outbound", "effect": "reject"})
    rules.append({"proto": "tcp", "ports": "1-65535", "direction": "outbound", "effect": "accept"})
    rules.append({"proto": "udp", "ports": "1-65535", "direction": "outbound", "effect": "accept"})
    return {
        "schema": SCHEMA,
        "default": "refuse",
        "rules": rules,
        "egress_ceiling_gib_month": None,
        "inbound_admission": "none",
        "notes": "outbound-only template; edit before publish and set the egress ceiling from the provider's allowance",
    }


def p2p_extension(port_spec: str = "6881-6889", abuse_contact: str = "") -> dict:
    """The opt-in inbound admission extension for the bulk profile.
    Returns the rule to append (with the required plan label and the
    abuse contact) plus the inbound_admission switch to set."""
    return {
        "rule": {
            "proto": "tcp",
            "ports": port_spec,
            "direction": "inbound",
            "effect": "accept",
            "plan": "bulk",
            "abuse_contact": abuse_contact,
        },
        "inbound_admission": "static-manual",
    }
