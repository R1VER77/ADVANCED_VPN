"""Shared-access pilot CLI actions (`cypherpunk shared import|status|connect|disconnect`)."""

import base64
import json
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives.asymmetric import mldsa

from shared_admission import AdmissionError, EPOCH_SECONDS
from shared_pool import SharedPool
from shared_session import upstream_is_ready
from shared_wallet import CreditWallet, PAIRS_PER_BATCH


CRYPTO_DISCLOSURE = "Classical RSA-PSS verification (RFC 9578); unlinkability holds against quantum observers"
PQ_STAMPED_DISCLOSURE = "Composite RFC 9578 RSA-PSS + ML-DSA-87 + SLH-DSA-SHA2-128f + Ed25519 (multi-family PQ)"
IDENTITY_NOTICE = "Logins, cookies, and browser fingerprints can still link sessions across fresh VPN credits"
UPSTREAM_NOTICE = "Upstream operator sees your source address; admission and VPN traffic block if upstream drops"


def shared_dir() -> Path:
    """Private per-user directory holding sealed shared-access wallets and aggregate index."""
    override = os.environ.get("CPVPN_SHARED_DIR")
    return Path(override) if override else (Path.home() / ".config/cypherpunk-vpn/shared")


def _preferences_path() -> Path:
    override = os.environ.get("CPVPN_PREFERENCES")
    return Path(override) if override else Path("/etc/cypherpunk-vpn/enrolled/preferences.json")


def configured_upstream() -> str | None:
    """Return the configured upstream interface name if readable, without exposing addresses."""
    env = os.environ.get("CPVPN_UPSTREAM_INTERFACE")
    if env:
        return env.strip() or None
    path = _preferences_path()
    try:
        if path.exists():
            data = json.loads(path.read_text())
            value = data.get("upstream_interface")
            if isinstance(value, str) and value.strip():
                return value.strip()
    except (OSError, ValueError):
        pass
    return None


def _index_path() -> Path:
    return shared_dir() / "index.json"


def load_index() -> dict:
    """Load the non-secret batch index (counts and epochs only; no tokens or order IDs)."""
    path = _index_path()
    if not path.exists():
        return {"schema": 1, "batches": []}
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("batches"), list):
        raise AdmissionError("shared credit index is unreadable")
    return data


def save_index(data: dict):
    """Write the private batch index atomically with owner-only permissions."""
    root = shared_dir()
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    target = _index_path()
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, target)


def shared_summary(now: float | None = None) -> dict:
    """Aggregate shared-wallet counts, upstream state, and privacy notices."""
    current = int((time.time() if now is None else now) // EPOCH_SECONDS)
    try:
        index = load_index()
        batches = index["batches"]
    except (OSError, ValueError, AdmissionError):
        batches = []
    active_pairs = sum(int(b.get("remaining_pairs", 0)) for b in batches if b.get("epoch") == current)
    pending_pairs = sum(int(b.get("remaining_pairs", 0)) for b in batches if b.get("epoch") == current + 1)
    pq_stamped_pairs = sum(
        int(b.get("remaining_pairs", 0))
        for b in batches
        if b.get("epoch") in (current, current + 1) and b.get("pq_stamped")
    )
    upstream = configured_upstream()
    upstream_up = bool(upstream and upstream_is_ready(upstream))
    if upstream is None:
        upstream_state = "Not configured (required for shared access)"
    elif upstream_up:
        upstream_state = f"{upstream} · up (sees source IP)"
    else:
        upstream_state = f"{upstream} · down (fail-closed)"
    return {
        "shared_access_enabled": False,
        "shared_active_pairs": active_pairs,
        "shared_pending_pairs": pending_pairs,
        "shared_pq_stamped_pairs": pq_stamped_pairs,
        "shared_active_credits": active_pairs * 2,
        "shared_pending_credits": pending_pairs * 2,
        "upstream_interface": upstream,
        "upstream_ready": upstream_up,
        "upstream_state": upstream_state,
        "token_verification": PQ_STAMPED_DISCLOSURE
        if (pq_stamped_pairs > 0 and pq_stamped_pairs == active_pairs + pending_pairs)
        else CRYPTO_DISCLOSURE,
        "identity_notice": IDENTITY_NOTICE,
        "upstream_notice": UPSTREAM_NOTICE,
    }


def _load_witness_keys(raw: str | dict | None) -> dict[str, mldsa.MLDSA65PublicKey] | None:
    if raw is None:
        return None
    mapping = json.loads(Path(raw).read_text()) if isinstance(raw, (str, Path)) else raw
    if not isinstance(mapping, dict) or not mapping:
        raise AdmissionError("witness keys file must be a non-empty JSON object")
    return {str(wid): _load_pinned_key(str(val)) for wid, val in mapping.items()}


def _load_pinned_key(raw: str) -> mldsa.MLDSA65PublicKey:
    text = raw.strip()
    if len(text) < 256 and "\n" not in text and Path(text).exists():
        text = Path(text).read_text().strip()
    try:
        key = mldsa.MLDSA65PublicKey.from_public_bytes(base64.b64decode(text, validate=True))
    except ValueError:
        from cryptography.hazmat.primitives import serialization

        try:
            loaded = serialization.load_der_public_key(base64.b64decode(text, validate=True))
        except ValueError:
            raise AdmissionError("invalid pinned pool operator key") from None
        if not isinstance(loaded, mldsa.MLDSA65PublicKey):
            raise AdmissionError("pinned pool operator key must be ML-DSA-65") from None
        return loaded
    return key


def cmd_import(args) -> dict:
    """`cypherpunk shared import`: verify a signed pool + fixed-size batch and seal with Nitrokey."""
    now = int(time.time()) if getattr(args, "now", None) is None else int(args.now)
    current_epoch = now // EPOCH_SECONDS
    try:
        manifest = json.loads(Path(args.pool).read_text())
        pinned = _load_pinned_key(args.pinned_key)
        witness_keys = _load_witness_keys(getattr(args, "witness_keys", None))
        witness_quorum = int(getattr(args, "witness_quorum", 0) or 0)
        pool = SharedPool.verify(
            manifest,
            pinned,
            now,
            witness_keys=witness_keys,
            witness_quorum=witness_quorum,
        )
        entry_cohort, exit_cohort = pool.cohorts
        if not getattr(args, "allow_current_epoch", False) and entry_cohort.epoch != current_epoch + 1:
            raise AdmissionError("imported shared credits must activate in the next UTC epoch")
        raw_batch = json.loads(Path(args.batch).read_text())
        # Keep sponsor and order identifiers at issuance: read only the blind token pairs (and optional PQ stamps).
        raw_pairs = raw_batch["pairs"] if isinstance(raw_batch, dict) else raw_batch
        raw_stamps = raw_batch.get("pq_stamps") if isinstance(raw_batch, dict) else None
        if not isinstance(raw_pairs, list) or len(raw_pairs) != PAIRS_PER_BATCH:
            raise AdmissionError("shared credit batch must contain exactly 4 entry/exit pairs")
        pairs = [tuple(bytes.fromhex(tok) for tok in pair) for pair in raw_pairs]
        root = shared_dir()
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        wallet_name = f"batch-{entry_cohort.pool_name}-{entry_cohort.epoch}.json"
        wallet_path = root / wallet_name
        vault_path = Path(args.vault) if getattr(args, "vault", None) else (root / "nitrokey.vault")
        wallet = CreditWallet(wallet_path, vault_path, entry_cohort, exit_cohort)
        wallet.import_batch(pairs, pq_stamps=raw_stamps)
        pq_stamped = raw_stamps is not None
        index = load_index()
        index["batches"].append(
            {
                "pool": entry_cohort.pool_name,
                "issuer": entry_cohort.issuer_name,
                "epoch": entry_cohort.epoch,
                "remaining_pairs": PAIRS_PER_BATCH,
                "wallet": wallet_name,
                "pq_stamped": pq_stamped,
                "witness_quorum": witness_quorum,
            }
        )
        save_index(index)
    except (AdmissionError, KeyError, OSError, TypeError, ValueError) as err:
        return {"ok": False, "error": "SharedImportFailed", "message": str(err)}
    activates = time.strftime("%d %b %Y · %H:%M UTC", time.gmtime(entry_cohort.epoch * EPOCH_SECONDS))
    disclosure = PQ_STAMPED_DISCLOSURE if pq_stamped else CRYPTO_DISCLOSURE
    return {
        "ok": True,
        "shared_dashboard": True,
        "pool": entry_cohort.pool_name,
        "epoch": entry_cohort.epoch,
        "imported_pairs": PAIRS_PER_BATCH,
        "imported_credits": PAIRS_PER_BATCH * 2,
        "pq_stamped": pq_stamped,
        "witness_quorum": witness_quorum,
        "activates_utc": activates,
        "token_verification": disclosure,
        "rows": [
            {"label": "Pool", "value": entry_cohort.pool_name},
            {
                "label": "Sealed",
                "value": f"{PAIRS_PER_BATCH} pairs ({PAIRS_PER_BATCH * 2} credits) · Nitrokey protected",
            },
            {"label": "Activates", "value": activates},
            {"label": "Token crypto", "value": disclosure},
            {"label": "Public pool", "value": "Disabled pending protocol review"},
        ],
    }


def cmd_status(_args) -> dict:
    """`cypherpunk shared status`: show shared-access state, credits, upstream, and privacy limits."""
    now = time.time()
    epoch = int(now // EPOCH_SECONDS)
    next_utc = time.strftime("%d %b %Y · %H:%M UTC", time.gmtime((epoch + 1) * EPOCH_SECONDS))
    summary = shared_summary(now)
    return {
        "ok": True,
        "shared_dashboard": True,
        "epoch": epoch,
        "next_epoch_utc": next_utc,
        **summary,
        "rows": [
            {"label": "Shared access", "value": "Disabled (pilot pending protocol review)"},
            {
                "label": "Usable credits",
                "value": f"{summary['shared_active_credits']} ({summary['shared_active_pairs']} pairs)",
            },
            {
                "label": "Pending next epoch",
                "value": f"{summary['shared_pending_credits']} ({summary['shared_pending_pairs']} pairs)",
            },
            {"label": "Next epoch", "value": next_utc},
            {"label": "Upstream", "value": summary["upstream_state"]},
            {"label": "Token crypto", "value": CRYPTO_DISCLOSURE},
            {"label": "Identity note", "value": IDENTITY_NOTICE},
        ],
    }


def cmd_connect(_args) -> dict:
    """`cypherpunk shared connect`: fail closed while public shared access is disabled."""
    summary = shared_summary()
    return {
        "ok": False,
        "error": "SharedAccessDisabled",
        "message": "Shared access is disabled pending protocol review. Self-hosted profiles and kill switch are unchanged.",
        "upstream_state": summary["upstream_state"],
        "token_verification": CRYPTO_DISCLOSURE,
        "hints": [
            "Public shared-pool connections stay disabled until protocol review and independent-operator gates pass.",
            f"Required upstream: {summary['upstream_state']}.",
            "Use `cypherpunk shared status` to check sealed credits and readiness, or `cypherpunk connect` for your self-hosted chain.",
        ],
    }


def cmd_disconnect(_args) -> dict:
    """`cypherpunk shared disconnect`: confirm no shared pilot session is active; keep kill switch."""
    return {
        "ok": True,
        "shared_dashboard": True,
        "disconnected": True,
        "kill_switch": "preserved",
        "rows": [
            {"label": "Shared session", "value": "Disconnected (no active shared peers)"},
            {"label": "Kill switch", "value": "Preserved"},
        ],
    }
