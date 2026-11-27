#!/usr/bin/env python3
"""cpvpn-mesh: the CPVPN/Mesh community tool (installed as /opt/cypherpunk-vpn/bin/cpvpn-mesh).

Runs as the user, never as root: it uses the user's own cloud sign-ins (via
cpvpn-cloud / tools/cloud.py) and the user's own hardware token.

There is no account. A member IS their hardware device: the member ID is the
truncated SHA-256 of the operator public key produced by `cypherpunk init` (the
ML-DSA-65 operator key sealed under the device's FIDO2 credential - Nitrokey
preferred, any capable token works). Descriptors are signed with that key.

Subcommands: identity, nodes, chain, offer, publish, quota.
All commands accept --json (default in this launcher): the last stdout line
is one JSON object, the contract src/bin/cypherpunk/mesh.rs parses.
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import providers  # the catalog's legal-parent table (same directory)

SCHEMA = 1
DESCRIPTOR_TTL_SECONDS = 7 * 24 * 3600
GOSSIP_HOP_LIMIT = 3
MESH_DIR = Path(os.environ.get("CPVPN_MESH_DIR", Path.home() / ".config" / "cypherpunk-vpn" / "mesh"))
CLOUD = os.environ.get("CPVPN_CLOUD", "/opt/cypherpunk-vpn/bin/cpvpn-cloud")
KEYGUARD = os.environ.get("CPVPN_KEYGUARD", "/opt/cypherpunk-vpn/tools/keyguard.py")
VAULT = Path(os.environ.get("CPVPN_VAULT", Path.home() / ".config" / "cypherpunk-vpn" / "vault"))
# The member's identity is the operator's own ML-DSA-65 key from `cypherpunk init --vault`: its
# public half beside the vault, its private half sealed under the vault's FIDO2 credential
# (managed_profile.HardwareOperator). CPVPN_OPERATOR_KEY may instead name a raw public key or
# the operator.pub file `cypherpunk init` writes into the bundles.
OPERATOR_KEY = Path(os.environ.get("CPVPN_OPERATOR_KEY", VAULT / "operator-mldsa65.pub"))
OPERATOR_ENVELOPE = Path(os.environ.get("CPVPN_MESH_ENVELOPE", VAULT / "operator-mldsa65.sealed.json"))
# The role its envelope is bound to: the operator's (HardwareOperator) or a separately
# sealed mesh key (keyguard mesh-seal).
OPERATOR_ROLE = os.environ.get(
    "CPVPN_MESH_ROLE",
    "operator-mldsa65" if OPERATOR_ENVELOPE.name == "operator-mldsa65.sealed.json" else "mesh-operator",
)
MLDSA65_PUBLIC = 1952

# Always-free capacity a member can contribute. Ranked by free egress: egress is
# what a relay burns. egress_gib_month=0 means "unsuitable as a relay".
FREE_TIERS = [
    {
        "rank": 1,
        "slug": "oci",
        "name": "Oracle Cloud Always Free",
        "spec": "ARM VM, up to 4 cores / 24 GB RAM",
        "egress_gib_month": 10240,
        "expiry": "none (always free)",
        "role_fit": ["entry", "relay", "exit"],
        "provision": ["oci", "server"],
        "notes": "Best free egress of any provider. Check ToS before enabling role exit.",
    },
    {
        "rank": 2,
        "slug": "aws",
        "name": "AWS free plan",
        "spec": "t3.micro class, 6 months",
        "egress_gib_month": 100,
        "expiry": "6 months",
        "role_fit": ["entry", "relay"],
        "provision": ["aws", "relay"],
        "notes": "Good entry/relay; too little egress for an exit.",
    },
    {
        "rank": 3,
        "slug": "gcp",
        "name": "GCP e2-micro free tier",
        "spec": "e2-micro, 1 GB/month egress",
        "egress_gib_month": 1,
        "expiry": "none (always free, US regions)",
        "role_fit": [],
        "provision": None,
        "notes": "Directory beacon duty only; does NOT meet the relay minimum and is not counted.",
    },
    {
        "rank": 4,
        "slug": "host",
        "name": "Your own server / VPS / home box",
        "spec": "anything reachable",
        "egress_gib_month": 0,
        "expiry": "n/a",
        "role_fit": ["entry", "relay", "exit"],
        "provision": ["host", "add"],
        "notes": "Registered over SSH; egress is your own plan's.",
    },
]
MIN_RELAY_EGRESS_GIB_MONTH = 50  # below this a node cannot carry relay duty + cover
DEFAULT_COVER_BUDGET_MIB_DAY = 2048  # fits OCI Always Free with relay headroom


def member_id(public_key_bytes: bytes) -> str:
    """!xxxxxxxx, truncated SHA-256 of a public key (mirrors src/mesh/identity.rs)."""
    return "!" + hashlib.sha256(public_key_bytes).hexdigest()[:8]


def load_operator_key(path: Path | None = None) -> bytes:
    """The member's public identity: the raw ML-DSA-65 public key of the operator that
    `cypherpunk init` made, read from the vault's operator-mldsa65.pub, or from the operator.pub
    JSON (schema 2 or 3) that `cypherpunk init` writes into the bundles.

    The matching secret stays sealed under the hardware token; this file is
    public. Refuse anything that is not a private, user-owned file.
    """
    p = path or OPERATOR_KEY
    st = p.lstat()
    if not p.is_file() or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
        raise SystemExit(f"refusing {p}: must be a regular file owned by you, mode 0600")
    raw = p.read_bytes()
    if raw.lstrip().startswith(b"{"):
        doc = json.loads(raw)
        if doc.get("schema") not in (2, 3) or "mldsa65" not in doc:
            raise SystemExit(f"refusing {p}: not an operator public file")
        raw = base64.b64decode(doc["mldsa65"], validate=True)
    if len(raw) != MLDSA65_PUBLIC:
        raise SystemExit(f"refusing {p}: not an ML-DSA-65 public key")
    return raw


def _mldsa():
    """ML-DSA-65 from the hash-locked environment (cryptography 49/50: `mldsa`). The module
    was named `ml_dsa` here until 20 November 2026, which the pinned library never had:
    every real verification raised SystemExit, hidden by tests that stubbed it out."""
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey

        return MLDSA65PrivateKey, MLDSA65PublicKey
    except Exception as e:  # pragma: no cover - environment dependent
        raise SystemExit(
            "ML-DSA-65 unavailable: run inside the hash-locked environment "
            "(cryptography 49); see tools/hardware-requirements.txt"
        ) from e


def canonical(descriptor: dict) -> bytes:
    """Canonical serialization of every descriptor field except the signature."""
    body = {k: v for k, v in descriptor.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_descriptor(descriptor: dict, private_key) -> dict:
    """Return the descriptor with its signature over the canonical encoding."""
    sig = private_key.sign(canonical(descriptor))
    return {**descriptor, "signature": base64.b64encode(sig).decode()}


def verify_descriptor(descriptor: dict) -> bool:
    """Verify a descriptor at ingestion, before it may enter the directory."""
    _, MLDSAPublicKey = _mldsa()
    try:
        pub = MLDSAPublicKey.from_public_bytes(base64.b64decode(descriptor["node_public_key"]))
        pub.verify(base64.b64decode(descriptor["signature"]), canonical(descriptor))
        return member_id(base64.b64decode(descriptor["node_public_key"])) == descriptor["node_id"]
    except Exception:
        return False


STREAMING_KEYS = {"service", "region", "result", "checked", "transport_profile"}

# The exit's advertised v6 egress (IPV6_TUNNELING_DESIGN.md section 3):
# "both" carries native v6 payloads, "v6" is v6-only, "v4" is v4-only even
# though the operator runs v6 locally (a routing fact, not a capability).
V6_EGRESS = ("both", "v4", "v6")


def _is_global_v6_prefix(prefix) -> bool:
    """A globally routable (2000::/3) /64 - the same scope rule the leak
    suite pins (tools/ipv6_leak_suite.py is_global_v6). An exit may only
    advertise a prefix the tunnel could actually egress from; a ULA or
    link-local prefix here would be a lie the chain planner refuses."""
    import socket as _socket

    if not isinstance(prefix, str) or len(prefix) > 64 or not prefix.endswith("/64"):
        return False
    try:
        packed = _socket.inet_pton(_socket.AF_INET6, prefix[:-3])
    except (OSError, ValueError):
        return False
    return (packed[0] & 0xE0) == 0x20  # 2000::/3: the top three bits are 001


def v6_egress(descriptor: dict) -> str:
    """The exit's advertised v6 egress; "none" when the field is absent (the
    honest default: an exit that never says, egresses v4 only)."""
    v6 = descriptor.get("v6") if isinstance(descriptor, dict) else None
    return v6["egress"] if isinstance(v6, dict) and v6.get("egress") in V6_EGRESS else "none"


def validate(descriptor: dict, now: float | None = None) -> list[str]:
    """Structural checks mirroring Descriptor::validate in src/mesh/descriptor.rs."""
    now = time.time() if now is None else now
    errors = []
    if descriptor.get("schema") != SCHEMA:
        errors.append("unsupported descriptor schema")
    if not descriptor.get("roles"):
        errors.append("a node must offer at least one role")
    if descriptor.get("expires", 0) <= now:
        errors.append("descriptor expired")
    if descriptor.get("expires", 0) > descriptor.get("published", 0) + DESCRIPTOR_TTL_SECONDS:
        errors.append("descriptor lifetime above the TTL")
    if descriptor.get("published", 0) > now + 3600:
        errors.append("descriptor from the future")
    c = descriptor.get("country", "")
    if len(c) != 2 or not c.isupper():
        errors.append("country must be ISO alpha-2 uppercase")
    # The exit_policy field (PATH_SELECTION_DESIGN.md section 2): absent is
    # the default refuse-everything posture; present, its structure is
    # checked here so an invalid policy cannot be signed into a descriptor.
    if "exit_policy" in descriptor:
        # Fail closed: a policy that cannot be checked is never signed (the installed
        # layout ships all of tools/, so the import is always there).
        try:
            import exit_policy
        except ImportError:
            errors.append("exit_policy: present but the validator is not installed")
        else:
            for e in exit_policy.validate_policy(descriptor.get("exit_policy")):
                errors.append(f"exit_policy: {e}")
    # Dated streaming measurements (tools/stream_check.py), the same rules as
    # Descriptor::validate: one row per service, a known result, a date.
    if "streaming" in descriptor:
        rows = descriptor["streaming"]
        if not isinstance(rows, list) or len(rows) > 64:
            errors.append("streaming must be a list of at most 64 rows")
            rows = []
        seen = set()
        for i, row in enumerate(rows):
            if not isinstance(row, dict) or set(row) != STREAMING_KEYS:
                errors.append(f"streaming row {i}: exactly the keys {sorted(STREAMING_KEYS)}")
                continue
            service = row["service"]
            if not isinstance(service, str) or not 0 < len(service) <= 64 or service in seen:
                errors.append(f"streaming row {i}: one row per named service")
            seen.add(service)
            if row["result"] not in ("eligible", "blocked", "unknown"):
                errors.append(f"streaming row {i}: result must be eligible, blocked or unknown")
            if not isinstance(row["checked"], str) or not 0 < len(row["checked"]) <= 40:
                errors.append(f"streaming row {i}: must be dated")
            if not isinstance(row["transport_profile"], str) or len(row["transport_profile"]) > 64:
                errors.append(f"streaming row {i}: transport profile too long")
            if row["region"] is not None and (not isinstance(row["region"], str) or len(row["region"]) > 64):
                errors.append(f"streaming row {i}: region too long")
    # The exit's IPv6 egress (IPV6_TUNNELING_DESIGN.md section 3, stage 1): a
    # family-honest descriptor. Absent is the honest default - the exit
    # egresses v4 only, exactly today's posture - so an absent field never
    # widens what a chain may rely on.
    if "v6" in descriptor:
        v6 = descriptor["v6"]
        if not (
            isinstance(v6, dict)
            and set(v6) == {"prefix", "egress"}
            and v6.get("egress") in V6_EGRESS
            and _is_global_v6_prefix(v6.get("prefix"))
        ):
            errors.append("v6: {prefix: a global 2000::/3 /64, egress: both|v4|v6}")
    return errors


# ---------------------------------------------------------------- directory


def directory_path() -> Path:
    """The local directory file."""
    return MESH_DIR / "directory.json"


def load_directory(now: float | None = None) -> list[dict]:
    """Verified, unexpired descriptors from the local directory."""
    p = directory_path()
    if not p.exists():
        return []
    doc = json.loads(p.read_text())
    out = []
    for d in doc.get("descriptors", []):
        if not validate(d, now):
            out.append(d)
    return out


def ranked(nodes: list[dict], role: str, group: str) -> list[dict]:
    """Nodes offering `role` in `group`, best first."""
    v = [d for d in nodes if role in d.get("roles", []) and d.get("group", "public") == group]
    return sorted(
        v,
        key=lambda d: (
            -d["health"]["uptime_30d"],
            d["health"]["latency_ms_p50"],
            -d["capacity"]["cover_budget_mib_day"],
            d["node_id"],
        ),
    )


# Parent jurisdiction of each provider (the US CLOUD Act reaches US providers wherever
# the server stands): the catalog's table. Mirrors legal_parent in src/mesh/directory.rs.
PROVIDER_PARENT = providers.LEGAL_PARENT


def legal_parent(provider: str, country: str) -> str:
    """The legal sphere a node answers to: its provider's parent, else its own country."""
    return PROVIDER_PARENT.get(provider, country.upper())


def select_chain(
    nodes: list[dict],
    hops: int,
    group: str = "public",
    exit_country: str | None = None,
    prefer: str | None = None,
    allow_weaker_diversity: bool = False,
    own_operator: str | None = None,
    allow_same_jurisdiction: bool = False,
    dual_stack: bool = False,
) -> list[dict]:
    """Diversity first: every hop a distinct operator, provider and country; the
    member's own node as the entry; the exit in another legal sphere than the entry.
    Mirrors NodeDb::select_chain in src/mesh/directory.rs.

    `dual_stack` (IPV6_TUNNELING_DESIGN.md stage 1) requires the exit to
    advertise v6 egress (v6.egress "both" or "v6"): a v4-only exit REFUSES a
    dual-stack chain - loudly, never by silently falling back to v4-only,
    which is the design's own no-silent-fallback rule."""
    if not 1 <= hops <= 3:
        raise SystemExit("chains have 1 to 3 hops")
    if dual_stack:
        exits = [d for d in nodes if "exit" in d.get("roles", []) and d.get("group", "public") == group]
        capable = [d for d in exits if v6_egress(d) in ("both", "v6")]
        if not capable:
            raise SystemExit(
                "no exit in group `%s` advertises v6 egress; a dual-stack chain is refused "
                "rather than silently built v4-only (IPV6_TUNNELING_DESIGN section 4)" % group
            )
        capable_ids = {d["node_id"] for d in capable}
        nodes = [
            d
            for d in nodes
            if "exit" not in d.get("roles", []) or d.get("group", "public") != group or d["node_id"] in capable_ids
        ]
    roles = {1: ["exit"], 2: ["entry", "exit"], 3: ["entry", "relay", "exit"]}[hops]
    chosen, ops, provs, cts = [], set(), set(), set()
    for i, role in enumerate(roles):
        candidates = ranked(nodes, role, group)
        if prefer:
            candidates.sort(key=lambda d: 0 if d["node_id"] == prefer else 1)
        if i == 0 and hops > 1 and own_operator:
            candidates.sort(key=lambda d: 0 if d["operator"] == own_operator else 1)
        entry_sphere = legal_parent(chosen[0]["provider"], chosen[0]["country"]) if chosen else None
        is_exit = i == len(roles) - 1
        pick = None
        for d in candidates:
            if d["operator"] in ops or any(c["node_id"] == d["node_id"] for c in chosen):
                continue
            if is_exit and exit_country and d["country"] != exit_country:
                continue
            if (
                is_exit
                and not allow_same_jurisdiction
                and entry_sphere is not None
                and legal_parent(d["provider"], d["country"]) == entry_sphere
            ):
                continue
            if not allow_weaker_diversity and (d["provider"] in provs or d["country"] in cts):
                continue
            pick = d
            break
        if pick is None:
            raise SystemExit(
                f"no {role} node in group `{group}` satisfies the diversity rule; widen the mesh or relax constraints"
            )
        chosen.append(pick)
        ops.add(pick["operator"])
        provs.add(pick["provider"])
        cts.add(pick["country"])
    return chosen


# ------------------------------------------------------------------ tokens


def token_store_path() -> Path:
    """The local credit store file."""
    return MESH_DIR / "tokens.json"


def load_tokens() -> dict:
    """The local credit store (empty when none exists yet)."""
    p = token_store_path()
    if not p.exists():
        return {"schema": 1, "grants": [], "spent": []}
    return json.loads(p.read_text())


def current_epoch(now: float | None = None) -> int:
    """The daily credit epoch for `now` (default: the current time)."""
    return int((time.time() if now is None else now) // 86400)


def quota_view(now: float | None = None) -> dict:
    """Token balance for the current epoch.

    Private-group credits are HMAC-based (a group trusts its members); the
    public pool uses blind-RSA credits in the control plane
    (tools/mesh_tokens.py) while the Rust data plane stays fail-closed until
    the scheme is reviewed and vendored (src/mesh/tokens.rs). The 22 November
    membership-and-credit review added the classical/PQ labels both pools
    carry wherever they are stated (docs/PQ_INVENTORY.md exceptions 1 and 6).
    """
    t = load_tokens()
    epoch = current_epoch(now)
    fresh = [g for g in t["grants"] if g["epoch"] == epoch]
    spent = [s for s in t["spent"] if s["epoch"] == epoch]
    pending = sum(g["epoch"] == epoch + 1 for g in t["grants"])
    return {
        "epoch": epoch,
        "earned_today": len(fresh),
        "spent_today": len(spent),
        "balance": len(fresh) - len(spent),
        "pending_next_epoch": pending,
        "next_epoch_utc": time.strftime("%d %b %Y · %H:%M UTC", time.gmtime((epoch + 1) * 86400)),
        "public_redemption_enabled": False,
        "public_pool": "blind-RSA credits via tools/mesh_tokens.py (control plane); "
        "data-plane redemption stays fail-closed until vendored in Rust; "
        "classical unforgeability, unlinkability survives a quantum adversary "
        "(PQ_INVENTORY exception 1)",
        "private_groups": "VOPRF credits via tools/mesh_voprf.py; classical "
        "unforgeability, unlinkability survives a quantum adversary (PQ_INVENTORY "
        "exception 6)",
    }


# ------------------------------------------------------------------ offer


def offer_plan() -> list[dict]:
    """Rows ranking the free tiers for contributing a node."""
    rows = []
    for t in FREE_TIERS:
        fit = (
            "relay-capable"
            if t["egress_gib_month"] >= MIN_RELAY_EGRESS_GIB_MONTH
            else ("beacon only" if t["egress_gib_month"] > 0 else "your own plan")
        )
        rows.append(
            {
                "label": t["slug"],
                "value": f"{t['name']} - {t['spec']}; ~{t['egress_gib_month']} GiB/mo free egress "
                f"({t['expiry']}); fit: {', '.join(t['role_fit']) or fit}; {t['notes']}",
            }
        )
    return rows


def cmd_offer(args) -> dict:
    """`cypherpunk mesh offer`: show the plan, or provision with --apply."""
    if args.guided or not args.apply:
        return {
            "ok": True,
            "rows": offer_plan()
            + [
                {
                    "label": "cover budget",
                    "value": f"{DEFAULT_COVER_BUDGET_MIB_DAY} MiB/day "
                    "fits every relay-capable tier; exit requires an explicit --role exit "
                    "and shows provider-ToS and abuse guidance first.",
                },
                {
                    "label": "private",
                    "value": "--private keeps the node out of the mesh directory; it is then usable only by you.",
                },
            ],
        }
    tier = next((t for t in FREE_TIERS if t["slug"] == args.provider), None)
    if tier is None or tier["provision"] is None:
        return {"ok": False, "error": "UnknownProvider"}
    if args.role == "exit" and not args.i_understand_exit_risk:
        return {
            "ok": False,
            "error": "ExitRequiresAcknowledgement",
            "hint": "an exit sees destinations and draws abuse complaints; re-run with "
            "--i-understand-exit-risk after reading `cypherpunk help mesh-exit`",
        }
    name = args.name or f"cpvpn-mesh-{tier['slug']}"
    cmd = [CLOUD, *tier["provision"], "--apply", "--name", name, "--yes"]
    if args.dry_run:
        return {"ok": True, "rows": [{"label": "plan", "value": " ".join(cmd)}]}
    if not args.yes:
        return {"ok": False, "error": "NeedsConfirmation"}
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {"ok": False, "error": "ProvisioningFailed", "stderr": proc.stderr[-2000:]}
    descriptor = build_descriptor(args, tier, name)
    return {"ok": True, "rows": [{"label": "node", "value": json.dumps(descriptor)}], "descriptor": descriptor}


def build_descriptor(args, tier: dict, name: str) -> dict:
    """A descriptor for the newly provisioned node, signed with the operator key.

    The node key is the server's own ML-DSA-65 key from its enrollment bundle;
    until the enroll flow returns it through cpvpn-cloud, the descriptor carries
    the operator key as a placeholder and is marked unpublished.
    """
    op_key = load_operator_key()
    now = int(time.time())
    return {
        "schema": SCHEMA,
        "node_id": member_id(op_key),
        "node_public_key": base64.b64encode(op_key).decode(),
        "wg_public_key": "",
        "cloak_endpoint": "",
        "roles": [args.role] if args.role != "entry" else ["entry", "relay"],
        "provider": tier["slug"],
        "country": args.country,
        "capacity": {
            "egress_gib_month": tier["egress_gib_month"],
            "cover_budget_mib_day": args.cover_budget_mib_day,
        },
        "health": {"uptime_30d": 1.0, "latency_ms_p50": 0},
        "group": "public" if not args.private else f"private-{member_id(op_key)[1:]}",
        "operator": member_id(op_key),
        "published": now,
        "expires": now + DESCRIPTOR_TTL_SECONDS,
        "signature": "",
        "name": name,
        "unpublished": True,
    }


# ------------------------------------------------------------------ publish


def cmd_publish(args) -> dict:
    """Sign the local node descriptor and gossip it (TTL 3, dup-suppressed).

    Beacons store-and-forward descriptors for offline peers and enforce
    anti-amplification: descriptors never trigger data-plane traffic, and are
    rate-limited per member.
    """
    node_desc = MESH_DIR / "node.json"
    if not node_desc.exists():
        return {"ok": False, "error": "NoNode", "hint": "run cypherpunk mesh offer first"}
    d = json.loads(node_desc.read_text())
    if getattr(args, "gateway_key", None):
        d = attach_gateway(d, args.gateway_key)
    now = int(time.time())
    d["published"] = now
    d["expires"] = now + DESCRIPTOR_TTL_SECONDS
    errors = validate(d, now)
    if errors:
        return {"ok": False, "error": "InvalidDescriptor", "hint": "; ".join(errors)}
    if args.dry_run:
        return {
            "ok": True,
            "rows": [
                {
                    "label": "plan",
                    "value": f"sign + gossip {d['node_id']} to group `{d['group']}` (ttl {GOSSIP_HOP_LIMIT})",
                }
            ],
        }
    # The operator ML-DSA key is sealed under the hardware credential and is
    # only unsealed in memory for one signing operation, exactly as in
    # `cypherpunk init`: keyguard mesh-sign does one PIN + touch, signs the
    # canonical descriptor, and returns it as the last JSON stdout line,
    # together with the FIDO2 membership assertion over the same bytes.
    if not OPERATOR_ENVELOPE.exists():
        return {
            "ok": False,
            "error": "NoSealedOperatorKey",
            "hint": f"no sealed operator key at {OPERATOR_ENVELOPE}: `cypherpunk init --vault {VAULT}` creates it "
            "on its first signature (or point CPVPN_MESH_ENVELOPE at one made by keyguard.py mesh-seal)",
        }
    MESH_DIR.mkdir(parents=True, exist_ok=True)
    tmp = MESH_DIR / ".publish.tmp"
    tmp.write_text(json.dumps(d))
    os.chmod(tmp, 0o600)
    proc = subprocess.run(
        [
            sys.executable,
            KEYGUARD,
            "mesh-sign",
            "--vault",
            str(VAULT),
            "--envelope",
            str(OPERATOR_ENVELOPE),
            "--role",
            OPERATOR_ROLE,
            "--cert",
            str(OPERATOR_KEY),
            "--descriptor",
            str(tmp),
        ],
        capture_output=True,
        text=True,
    )
    tmp.unlink(missing_ok=True)
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "HardwareSignRefused",
            "hint": "the hardware token refused or was absent; nothing was published",
        }
    try:
        out = parse_last_json(proc.stdout)
        signed = out["descriptor"]
    except Exception:
        return {"ok": False, "error": "SignerOutputInvalid"}
    # Fail-closed self-check: a descriptor we cannot verify never leaves us.
    if validate(signed, now) or not verify_descriptor(signed):
        return {
            "ok": False,
            "error": "SelfCheckFailed",
            "hint": "the signed descriptor did not verify; refusing to gossip it",
        }
    if out.get("assertion"):
        proof = MESH_DIR / "membership-proof.json"
        proof.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "member": d["node_id"],
                    "public_key": out.get("public_key"),
                    "assertion": out["assertion"],
                    "challenge_sha256": out.get("challenge_sha256"),
                }
            )
        )
        os.chmod(proof, 0o600)
    node_desc.write_text(json.dumps(signed))
    os.chmod(node_desc, 0o600)
    g = gossip_descriptor(signed)
    return {
        "ok": True,
        "rows": [
            {"label": "node", "value": f"{d['node_id']} signed (hardware, one PIN + touch)"},
            {"label": "gossip", "value": f"{g['sent']}/{g['beacons']} beacons accepted"},
        ],
        "gossip": g,
    }


def parse_last_json(stdout: str) -> dict:
    """The cypherpunk helper contract: the LAST stdout line that starts with '{' is
    the JSON result; earlier lines are human-facing logs."""
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise ValueError("no JSON result line")


def gossip_descriptor(descriptor: dict, hop: int = 0) -> dict:
    """POST a signed descriptor to every configured beacon; each beacon
    validates, rate-limits and store-and-forwards with TTL 3 and duplicate
    suppression (tools/mesh_beacon.py). Unreachable beacons are skipped,
    never fatal."""
    cfg = MESH_DIR / "beacons.json"
    if not cfg.exists():
        return {"sent": 0, "beacons": 0, "hint": f'no beacons configured; write ["https://host:8787"] to {cfg}'}
    beacons = [beacon_entry(u) for u in json.loads(cfg.read_text())]
    body = json.dumps({"descriptor": descriptor, "hop": hop}).encode()
    sent = 0
    for entry in beacons:
        try:
            status, doc = beacon_call(entry, "POST", "/gossip", body)
            sent += 1 if status == 200 and doc.get("ok") else 0
        except (OSError, ValueError):
            continue  # an unreachable beacon is skipped, never fatal
    return {"sent": sent, "beacons": len(beacons)}


# Key consistency for oblivious routes (RFC 9458 section 7). Unlinkability through a
# gateway holds only if every member encrypts to the same gateway key
# (formal/ohttp/ohttp_unlinkability.pv; its per-member-key mutant links). A gateway that
# handed each member its own key would link their requests, so a member uses an oblivious
# route only after beacons of other operators have shown it the gateway operator's own
# signed descriptor naming that same key. Two different keys signed by one operator are
# equivocation, and both signed descriptors are the proof.
GATEWAY_FIELD = "ohttp_gateway"
MIN_GATEWAY_WITNESSES = 2


class GatewayKeyRefused(ValueError):
    """An oblivious route whose gateway key is not shown to be everyone's."""


def attach_gateway(descriptor: dict, gateway_key: Path) -> dict:
    """Name this beacon's oblivious gateway key in its descriptor, so the operator's
    signature commits to it and gossip shows every member the same one."""
    import ohttp

    _, public = ohttp.load_private(gateway_key.read_bytes())
    return {**descriptor, GATEWAY_FIELD: {"key_id": 1, "public": base64.b64encode(public).decode()}}


def gateway_checks_path() -> Path:
    """Verified gateway keys, by gateway operator."""
    return MESH_DIR / "gateway-checks.json"


def gateway_claims(entry: dict, batches) -> dict:
    """{(key_id, public): {witness, ...}}: the gateway keys that the route's gateway
    operator signed, as seen through beacons other than that gateway. `batches` is
    [(source, descriptors)], one per beacon answered."""
    claims = {}
    for source, descriptors in batches:
        if source == entry["gateway_operator"]:
            continue  # the gateway cannot vouch for itself
        for d in descriptors:
            if d.get("node_id") != entry["gateway_operator"] or GATEWAY_FIELD not in d:
                continue
            if validate(d) or not verify_descriptor(d):
                continue
            g = d[GATEWAY_FIELD]
            claims.setdefault((int(g["key_id"]), g["public"]), set()).add(source)
    return claims


def check_gateway_key(entry: dict, batches, minimum: int = MIN_GATEWAY_WITNESSES) -> list:
    """The witnesses to an oblivious route's gateway key; raises GatewayKeyRefused."""
    claims = gateway_claims(entry, batches)
    if len(claims) > 1:
        raise GatewayKeyRefused(
            "gateway operator %s signed %d different keys: equivocation" % (entry["gateway_operator"], len(claims))
        )
    mine = (int(entry["key_id"]), entry["gateway_public"])
    if claims and mine not in claims:
        raise GatewayKeyRefused("this route's gateway key is not the one its operator published")
    witnesses = sorted(claims.get(mine, ()))
    if len(witnesses) < minimum:
        raise GatewayKeyRefused(
            "only %d other beacon(s) vouch for this gateway key; %d are needed" % (len(witnesses), minimum)
        )
    return witnesses


def gateway_verified(entry: dict, now: float | None = None) -> bool:
    """Whether this route's gateway key was verified within the descriptor lifetime."""
    path = gateway_checks_path()
    if not path.exists():
        return False
    record = json.loads(path.read_text()).get(entry["gateway_operator"])
    now = time.time() if now is None else now
    return bool(
        record
        and record["key"] == [int(entry["key_id"]), entry["gateway_public"]]
        and now - record["checked"] <= DESCRIPTOR_TTL_SECONDS
    )


# The relay's clock, per relay URL: (offset to add to this host's clock, when measured).
# Sealed requests carry a timestamp the gateway sees; taken from the relay, which already
# knows this member and sees only ciphertext, it reveals nothing to the gateway that the
# relay's own address does not, and no third party is asked the time (docs: ohttp.py).
RELAY_CLOCK_SECONDS = 3600
_relay_clock: dict = {}


def _date_offset(headers, before, after):
    import email.utils

    date = headers.get("Date")
    if not date:
        raise ValueError("the relay sent no Date")
    return email.utils.parsedate_to_datetime(date).timestamp() - (before + after) / 2


def relay_clock(relay: str) -> float:
    """This host's time on the relay's clock: GET /time when the last reading is old."""
    offset, at = _relay_clock.get(relay, (None, 0.0))
    if offset is None or time.monotonic() - at > RELAY_CLOCK_SECONDS:
        before = time.time()
        req = urllib.request.Request(relay + "/time", method="GET")  # noqa: S310 (scheme checked by beacon_url)
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (as above)
            offset = _date_offset(r.headers, before, time.time())
        _relay_clock[relay] = (offset, time.monotonic())
    return time.time() + offset


def beacon_entry(entry):
    """A configured beacon: a direct http(s) URL, or an oblivious route
    {"relay": URL, "gateway_public": B64, "key_id": N, "relay_operator": "!..",
    "gateway_operator": "!.."} whose relay and gateway belong to different operators."""
    if isinstance(entry, str):
        return beacon_url(entry)
    if not isinstance(entry, dict) or set(entry) != {
        "relay",
        "gateway_public",
        "key_id",
        "relay_operator",
        "gateway_operator",
    }:
        raise ValueError("a beacon is a URL or an oblivious route")
    if entry["relay_operator"] == entry["gateway_operator"]:
        raise ValueError("an oblivious route needs a relay and a gateway of different operators")
    import ohttp

    ohttp.load_public(base64.b64decode(entry["gateway_public"], validate=True))
    return dict(entry, relay=beacon_url(entry["relay"]))


def beacon_call(entry, method, path, body=b""):
    """(status, document) of one beacon request: direct, or sealed through a relay so
    the beacon never sees this member's address and the relay never sees the request."""
    if isinstance(entry, str):
        req = urllib.request.Request(  # noqa: S310 (scheme checked by beacon_url)
            entry + path,
            data=body if method == "POST" else None,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (scheme checked by beacon_url)
            return r.status, json.loads(r.read())
    if (method, path) != ("GET", "/descriptors") and not gateway_verified(entry):
        # Unverified, a route may only fetch the public directory (which is how its key
        # gets verified): anything else could be linked by a gateway that gave this member
        # its own key. `cypherpunk mesh nodes --fetch` checks the key against other beacons.
        raise GatewayKeyRefused("this oblivious route's gateway key is not verified yet; fetch descriptors first")
    import ohttp

    wire, reply = ohttp.encapsulate(
        base64.b64decode(entry["gateway_public"]),
        int(entry["key_id"]),
        method,
        path,
        body,
        now=relay_clock(entry["relay"]),
    )
    req = urllib.request.Request(  # noqa: S310 (scheme checked by beacon_url)
        entry["relay"] + "/relay", data=wire, headers={"Content-Type": "message/ohttp-req"}
    )
    before = time.time()
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (scheme checked by beacon_url)
        status, answer = ohttp.decapsulate(r.read(), reply)
        try:  # every answer refreshes the relay's clock
            _relay_clock[entry["relay"]] = (_date_offset(r.headers, before, time.time()), time.monotonic())
        except ValueError:
            pass
    return status, json.loads(answer)


def beacon_url(url) -> str:
    """A configured beacon URL, http(s) only (never file: or a custom scheme)."""
    if not isinstance(url, str) or urllib.parse.urlsplit(url).scheme not in ("https", "http"):
        raise ValueError("beacon URLs must be http(s): %r" % (url,))
    return url.rstrip("/")


def fetch_from_beacons() -> int:
    """Pull fresh descriptors from configured beacons into the directory."""
    cfg = MESH_DIR / "beacons.json"
    if not cfg.exists():
        return 0
    beacons = [beacon_entry(u) for u in json.loads(cfg.read_text())]
    added = 0
    directory = {d["node_id"]: d for d in load_directory()}
    answered = []
    for entry in beacons:
        try:
            _, batch = beacon_call(entry, "GET", "/descriptors")
        except (OSError, ValueError):
            continue  # an unreachable beacon is skipped, never fatal
        answered.append((entry, batch.get("descriptors", [])))
    # Each oblivious route's gateway key, checked against what the other beacons show.
    batches = [(e["gateway_operator"] if isinstance(e, dict) else e, ds) for e, ds in answered]
    path = gateway_checks_path()
    checks = json.loads(path.read_text()) if path.exists() else {}
    for entry, _ in answered:
        if not isinstance(entry, dict):
            continue
        try:
            witnesses = check_gateway_key(entry, batches)
        except GatewayKeyRefused as e:
            checks.pop(entry["gateway_operator"], None)
            print("oblivious route refused: %s" % e, file=sys.stderr)
            continue
        checks[entry["gateway_operator"]] = dict(
            key=[int(entry["key_id"]), entry["gateway_public"]], witnesses=witnesses, checked=int(time.time())
        )
    # Descriptors are signed one by one, so they are kept whichever beacon carried them.
    for _entry, descriptors in answered:
        for d in descriptors:
            if d.get("node_id") in directory:
                continue  # duplicate suppression
            if validate(d) or not verify_descriptor(d):
                continue  # unverified descriptors never enter the directory
            directory[d["node_id"]] = d
            added += 1
    MESH_DIR.mkdir(parents=True, exist_ok=True)
    checks_tmp = path.with_suffix(".tmp")
    checks_tmp.write_text(json.dumps(checks))
    os.chmod(checks_tmp, 0o600)
    checks_tmp.replace(path)
    tmp = directory_path().with_suffix(".tmp")
    tmp.write_text(json.dumps({"schema": SCHEMA, "descriptors": list(directory.values())}))
    os.chmod(tmp, 0o600)
    tmp.replace(directory_path())
    return added


# ------------------------------------------------------------------- cmds


def cmd_identity(_args) -> dict:
    """`cypherpunk mesh identity`: this member's ID and key."""
    mid = member_id(load_operator_key())
    return {
        "ok": True,
        "rows": [
            {"label": "member", "value": mid},
            {"label": "identity", "value": "your hardware device key (operator.pub); no account exists anywhere"},
        ],
        "member": mid,
    }


# A provider (or legal sphere) hosting more than this share of the mesh could watch a large
# part of every path's traffic, whatever the per-path diversity rule picks.
CONCENTRATION_LIMIT = 1 / 3


def concentration(nodes: list[dict]) -> list[dict]:
    """The largest provider's and legal sphere's share of the mesh's nodes, as rows; a
    share over CONCENTRATION_LIMIT is marked."""
    rows = []
    if not nodes:
        return rows
    for label, key in (
        ("provider", lambda d: d["provider"]),
        ("legal sphere", lambda d: legal_parent(d["provider"], d["country"])),
    ):
        counts: dict[str, int] = {}
        for d in nodes:
            counts[key(d)] = counts.get(key(d), 0) + 1
        top, n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
        share = n / len(nodes)
        note = (
            " - over %d%%: it sees much of every path" % round(100 * CONCENTRATION_LIMIT)
            if share > CONCENTRATION_LIMIT
            else ""
        )
        rows.append({"label": "largest " + label, "value": f"{top}: {n} of {len(nodes)} nodes ({share:.0%}){note}"})
    return rows


def cmd_nodes(args) -> dict:
    """`cypherpunk mesh nodes`: the directory (optionally fetched from beacons first)."""
    if args.fetch:
        fetch_from_beacons()
    nodes = load_directory()
    rows = [
        {
            "label": d["node_id"],
            "value": f"{'+'.join(d['roles'])}  {d['provider']}  {d['country']}  "
            f"{d['health']['latency_ms_p50']} ms  up {d['health']['uptime_30d']:.1%}  "
            f"cover {d['capacity']['cover_budget_mib_day']} MiB/d  by {d['operator']}",
        }
        for d in nodes
    ]
    return {
        "ok": True,
        "rows": (rows + concentration(nodes))
        or [{"label": "empty", "value": "no descriptors yet; cypherpunk mesh nodes --fetch, or offer your first node"}],
    }


def cmd_chain(args) -> dict:
    """`cypherpunk mesh chain`: pick a diverse chain from the directory."""
    try:
        own = member_id(load_operator_key())
    except (OSError, ValueError):
        own = None  # no identity here yet: no own-entry preference
    chain = select_chain(
        load_directory(),
        args.hops,
        group=args.group,
        exit_country=args.exit_country,
        prefer=args.prefer,
        allow_weaker_diversity=args.allow_weaker_diversity,
        own_operator=own,
        allow_same_jurisdiction=args.allow_same_jurisdiction,
    )
    rows = [
        {
            "label": f"hop {i + 1}",
            "value": f"{d['node_id']}  {d['roles'][0]}  {d['provider']} {d['country']}"
            f" (legal sphere {legal_parent(d['provider'], d['country'])})  {d['cloak_endpoint']}"
            + ("  your own node" if own and d["operator"] == own else ""),
        }
        for i, d in enumerate(chain)
    ]
    if args.dry_run or not args.apply:
        return {"ok": True, "rows": rows}
    # Enrollment itself goes through the existing flow: request/init/enroll,
    # one PIN + touch, keys never leave devices. The mesh planner emits the
    # plan; cypherpunk init consumes it.
    plan = MESH_DIR / "chain-plan.json"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text(json.dumps({"schema": SCHEMA, "chain": chain}))
    os.chmod(plan, 0o600)
    return {"ok": True, "rows": rows + [{"label": "plan", "value": str(plan)}]}


def cmd_quota(_args) -> dict:
    """`cypherpunk mesh quota` / `cypherpunk credits`: compact wallet and pool dashboard."""
    try:
        q = quota_view()
    except (OSError, TypeError, ValueError, KeyError):
        return {"ok": False, "error": "Credit store unreadable", "message": "Check the local mesh credit store."}
    import shared_cli

    shared = shared_cli.shared_summary()
    held_total = q["balance"] + shared["shared_active_credits"] if q["balance"] >= 0 else q["balance"]
    pending_total = q["pending_next_epoch"] + shared["shared_pending_credits"]
    pool_badge = "Public pool disabled · Self-hosted active"
    return {
        "ok": True,
        "credit_dashboard": True,
        "pool_badge": pool_badge,
        "held_total": held_total,
        "pending_total": pending_total,
        "rows": [
            {"label": "Held", "value": str(held_total) if held_total >= 0 else "Unavailable · inconsistent store"},
            {"label": "Pending", "value": str(pending_total)},
            {"label": "Earned today", "value": f"{q['earned_today']} mesh"},
            {"label": "Spent today", "value": f"{q['spent_today']} mesh"},
            {
                "label": "Shared wallet",
                "value": f"{shared['shared_active_pairs']} usable pairs · {shared['shared_pending_pairs']} pending (Nitrokey)",
            },
            {"label": "Next epoch", "value": q["next_epoch_utc"]},
            {"label": "Pool mode", "value": pool_badge},
            {"label": "Upstream", "value": shared["upstream_state"]},
            {"label": "Token crypto", "value": shared["token_verification"]},
            {"label": "Identity note", "value": shared["identity_notice"]},
        ],
        **q,
        **shared,
    }


def cmd_shared(args) -> dict:
    """`cypherpunk shared <import|status|connect|disconnect>`."""
    import shared_cli

    table = {
        "import": shared_cli.cmd_import,
        "status": shared_cli.cmd_status,
        "connect": shared_cli.cmd_connect,
        "disconnect": shared_cli.cmd_disconnect,
    }
    return table[args.shared_cmd](args)


def main() -> int:
    """Command-line entry point."""
    p = argparse.ArgumentParser(prog="cpvpn-mesh")
    p.add_argument("--json", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("identity")
    sp = sub.add_parser("nodes")
    sp.add_argument("--fetch", action="store_true")

    sp = sub.add_parser("chain")
    sp.add_argument("--hops", type=int, default=2)
    sp.add_argument("--group", default="public")
    sp.add_argument("--exit-country")
    sp.add_argument("--prefer")
    sp.add_argument("--allow-weaker-diversity", action="store_true")
    sp.add_argument("--allow-same-jurisdiction", action="store_true")
    sp.add_argument("--apply", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--yes", action="store_true")

    sp = sub.add_parser("offer")
    sp.add_argument("--guided", action="store_true")
    sp.add_argument("--apply", action="store_true")
    sp.add_argument("--provider", default="oci")
    sp.add_argument("--role", choices=["entry", "relay", "exit"], default="relay")
    sp.add_argument("--country", default="DE")
    sp.add_argument("--name")
    sp.add_argument(
        "--private", action="store_true", help="keep the node out of the mesh directory (usable only by you)"
    )
    sp.add_argument("--cover-budget-mib-day", type=int, default=DEFAULT_COVER_BUDGET_MIB_DAY)
    sp.add_argument("--i-understand-exit-risk", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--yes", action="store_true")

    sp = sub.add_parser("publish")
    sp.add_argument("--publish", action="store_true")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--yes", action="store_true")
    sp.add_argument(
        "--gateway-key",
        type=Path,
        help="this beacon's oblivious gateway key (mesh_beacon --gateway-key): its public half is signed into the descriptor",
    )

    sub.add_parser("quota", aliases=["credits"])

    sp = sub.add_parser("shared")
    shared_sub = sp.add_subparsers(dest="shared_cmd", required=True)
    shared_sub.add_parser("status")
    shared_sub.add_parser("connect")
    shared_sub.add_parser("disconnect")
    imp = shared_sub.add_parser("import")
    imp.add_argument("--pool", required=True)
    imp.add_argument("--pinned-key", required=True)
    imp.add_argument("--batch", required=True)
    imp.add_argument("--witness-keys", help="JSON map of pinned witness IDs to base64 ML-DSA-65 public keys")
    imp.add_argument(
        "--witness-quorum", type=int, default=0, help="minimum witness signatures required on pool manifest"
    )
    imp.add_argument("--vault")
    imp.add_argument("--allow-current-epoch", action="store_true")

    args = p.parse_args()
    handlers = {
        "identity": cmd_identity,
        "nodes": cmd_nodes,
        "chain": cmd_chain,
        "offer": cmd_offer,
        "publish": cmd_publish,
        "quota": cmd_quota,
        "credits": cmd_quota,
        "shared": cmd_shared,
    }
    try:
        result = handlers[args.cmd](args)
    except SystemExit as e:
        result = {"ok": False, "error": "Refused", "hint": str(e)}
    if args.json:
        print(json.dumps(result))
    else:
        for row in result.get("rows", []):
            print(f"  {row['label']:<12} {row['value']}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
