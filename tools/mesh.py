#!/usr/bin/env python3
"""avpn-mesh: the AVPN/Mesh community tool (installed as /opt/advanced-vpn/bin/avpn-mesh).

Runs as the user, never as root: it uses the user's own cloud sign-ins (via
avpn-cloud / tools/cloud.py) and the user's own hardware token.

There is no account. A member IS their hardware device: the member ID is the
truncated SHA-256 of the operator public key produced by `avpn init` (the
ML-DSA-65 operator key sealed under the device's FIDO2 credential - Nitrokey
preferred, any capable token works). Descriptors are signed with that key.

Subcommands: identity, nodes, chain, offer, publish, quota.
All commands accept --json (default in this launcher): the last stdout line
is one JSON object, the contract src/bin/avpn/mesh.rs parses.
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
MESH_DIR = Path(os.environ.get("AVPN_MESH_DIR", Path.home() / ".config" / "advanced-vpn" / "mesh"))
CLOUD = os.environ.get("AVPN_CLOUD", "/opt/advanced-vpn/bin/avpn-cloud")
OPERATOR_KEY = Path(os.environ.get("AVPN_OPERATOR_KEY", Path.home() / ".config" / "advanced-vpn" / "operator.pub"))
KEYGUARD = os.environ.get("AVPN_KEYGUARD", "/opt/advanced-vpn/tools/keyguard.py")
VAULT = Path(os.environ.get("AVPN_VAULT", Path.home() / ".config" / "advanced-vpn" / "vault"))
OPERATOR_ENVELOPE = Path(
    os.environ.get("AVPN_MESH_ENVELOPE", Path.home() / ".config" / "advanced-vpn" / "mesh" / "operator-key.sealed.json")
)

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


def load_operator_key() -> bytes:
    """The member's public identity: operator.pub written by `avpn init`.

    The matching secret stays sealed under the hardware token; this file is
    public. Refuse anything that is not a private, user-owned file.
    """
    p = OPERATOR_KEY
    st = p.lstat()
    if not p.is_file() or st.st_uid != os.geteuid() or (st.st_mode & 0o077):
        raise SystemExit(f"refusing {p}: must be a regular file owned by you, mode 0600")
    return p.read_bytes().strip()


def _mldsa():
    """ML-DSA-65 from the hash-locked environment (cryptography >= 43)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ml_dsa import MLDSAPrivateKey, MLDSAPublicKey

        return MLDSAPrivateKey, MLDSAPublicKey
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
) -> list[dict]:
    """Diversity first: every hop a distinct operator, provider and country; the
    member's own node as the entry; the exit in another legal sphere than the entry.
    Mirrors NodeDb::select_chain in src/mesh/directory.rs."""
    if not 1 <= hops <= 3:
        raise SystemExit("chains have 1 to 3 hops")
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
    the scheme is reviewed and vendored (src/mesh/tokens.rs).
    """
    t = load_tokens()
    epoch = current_epoch(now)
    fresh = [g for g in t["grants"] if g["epoch"] == epoch]
    spent = [s for s in t["spent"] if s["epoch"] == epoch]
    return {
        "epoch": epoch,
        "earned_today": len(fresh),
        "spent_today": len(spent),
        "balance": len(fresh) - len(spent),
        "public_pool": "blind-RSA credits via tools/mesh_tokens.py (control plane); "
        "data-plane redemption stays fail-closed until vendored in Rust",
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
    """`avpn mesh offer`: show the plan, or provision with --apply."""
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
            "--i-understand-exit-risk after reading `avpn help mesh-exit`",
        }
    name = args.name or f"avpn-mesh-{tier['slug']}"
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
    until the enroll flow returns it through avpn-cloud, the descriptor carries
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
        return {"ok": False, "error": "NoNode", "hint": "run avpn mesh offer first"}
    d = json.loads(node_desc.read_text())
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
    # `avpn init`: keyguard mesh-sign does one PIN + touch, signs the
    # canonical descriptor, and returns it as the last JSON stdout line,
    # together with the FIDO2 membership assertion over the same bytes.
    if not OPERATOR_ENVELOPE.exists():
        return {
            "ok": False,
            "error": "NoSealedOperatorKey",
            "hint": f"seal the operator key once: keyguard.py mesh-seal --vault {VAULT} "
            f"--key <operator.key> --cert {OPERATOR_KEY} --envelope {OPERATOR_ENVELOPE} "
            "--remove-plaintext",
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
                    "credential": out.get("credential"),
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
    """The avpn helper contract: the LAST stdout line that starts with '{' is
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
    import ohttp

    wire, reply = ohttp.encapsulate(base64.b64decode(entry["gateway_public"]), int(entry["key_id"]), method, path, body)
    req = urllib.request.Request(  # noqa: S310 (scheme checked by beacon_url)
        entry["relay"] + "/relay", data=wire, headers={"Content-Type": "message/ohttp-req"}
    )
    with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (scheme checked by beacon_url)
        status, answer = ohttp.decapsulate(r.read(), reply)
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
    for entry in beacons:
        try:
            _, batch = beacon_call(entry, "GET", "/descriptors")
        except (OSError, ValueError):
            continue  # an unreachable beacon is skipped, never fatal
        for d in batch.get("descriptors", []):
            if d.get("node_id") in directory:
                continue  # duplicate suppression
            if validate(d) or not verify_descriptor(d):
                continue  # unverified descriptors never enter the directory
            directory[d["node_id"]] = d
            added += 1
    MESH_DIR.mkdir(parents=True, exist_ok=True)
    tmp = directory_path().with_suffix(".tmp")
    tmp.write_text(json.dumps({"schema": SCHEMA, "descriptors": list(directory.values())}))
    os.chmod(tmp, 0o600)
    tmp.replace(directory_path())
    return added


# ------------------------------------------------------------------- cmds


def cmd_identity(_args) -> dict:
    """`avpn mesh identity`: this member's ID and key."""
    mid = member_id(load_operator_key())
    return {
        "ok": True,
        "rows": [
            {"label": "member", "value": mid},
            {"label": "identity", "value": "your hardware device key (operator.pub); no account exists anywhere"},
        ],
        "member": mid,
    }


def cmd_nodes(args) -> dict:
    """`avpn mesh nodes`: the directory (optionally fetched from beacons first)."""
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
        "rows": rows
        or [{"label": "empty", "value": "no descriptors yet; avpn mesh nodes --fetch, or offer your first node"}],
    }


def cmd_chain(args) -> dict:
    """`avpn mesh chain`: pick a diverse chain from the directory."""
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
    # plan; avpn init consumes it.
    plan = MESH_DIR / "chain-plan.json"
    plan.parent.mkdir(parents=True, exist_ok=True)
    plan.write_text(json.dumps({"schema": SCHEMA, "chain": chain}))
    os.chmod(plan, 0o600)
    return {"ok": True, "rows": rows + [{"label": "plan", "value": str(plan)}]}


def cmd_quota(_args) -> dict:
    """`avpn mesh quota`: credits held and spent this epoch."""
    q = quota_view()
    return {
        "ok": True,
        "rows": [
            {"label": "epoch", "value": str(q["epoch"])},
            {"label": "earned", "value": f"{q['earned_today']} credits (relaying for the mesh)"},
            {"label": "spent", "value": f"{q['spent_today']} credits (chains through others)"},
            {"label": "balance", "value": str(q["balance"])},
            {"label": "public pool", "value": q["public_pool"]},
        ],
        **q,
    }


def main() -> int:
    """Command-line entry point."""
    p = argparse.ArgumentParser(prog="avpn-mesh")
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

    sub.add_parser("quota")

    args = p.parse_args()
    handlers = {
        "identity": cmd_identity,
        "nodes": cmd_nodes,
        "chain": cmd_chain,
        "offer": cmd_offer,
        "publish": cmd_publish,
        "quota": cmd_quota,
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
