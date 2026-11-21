#!/usr/bin/env python3
"""The blind-voucher issuance engine (REVENUE_ARCHITECTURE.md Model 1).

Model 1's flow, made operational: a user buys an UNLINKED cryptographic
voucher out-of-band (self-hosted BTCPayServer for Monero/Lightning, or a
physical scratch-off card) and redeems it for mesh rate-class bandwidth.
The payment rail never learns the network identity; the mesh never
learns the payment. The bridge between them is the same Chaum blind
RSA-FDH primitive the mesh credits use (`tools/mesh_tokens.py`), so the
whole engine is one well-understood construction:

  1. The buyer draws a random 256-bit voucher secret, blinds its FDH,
     and submits the blinded value with the payment reference.
  2. The mint (the only new piece: a small, self-hosted service) sees
     the payment settle (BTCPay webhook, HMAC-authenticated, replay-
     protected) and blind-signs for the tier the payment bought.
  3. The buyer unblinds and holds (secret, signature, tier): valid
     under the mint's published epoch key, unlinkable to the payment.
  4. Redemption presents the pair at any relay carrying the mint's
     public key; verification is public (RSA), the tier maps to a
     rate class, and the double-spend ledger is the mesh's own.

Tiers (REVENUE_ARCHITECTURE section 2, Model 1): standard $5, fast
$10, line $25 — priced per month, each mapping to the landed rate
classes (tools/rates.py) with the cover-traffic cost that class burns
published alongside (cost honesty, the gap #3 discipline).

What is deliberately NOT here:

- No payment processing. BTCPayServer is a separate self-hosted
  program; this engine consumes its webhook (verified with the store's
  HMAC secret) and nothing else. The sandbox tests mock the webhook
  CALL, not the verification — the HMAC check, replay window, tier
  lookup and issuance are fully exercised.
- No custodial money transmission (boundary rule 2): the mint signs
  vouchers; it never holds, routes or takes a cut of anything.
- No account, no IP logging, no identity: the mint's records are the
  voucher digests required to refuse double-spends, exactly like the
  mesh ledger, nothing else.
- Quantum honesty (COMPARISON.md note 8): blind RSA is classical; a
  quantum adversary could forge vouchers without breaking any tunnel.
  The lattice blind-signature migration the credits await covers this
  engine too; until then the mint key's monthly rotation bounds the
  exposure window.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

import mesh_tokens as mt

SCHEMA = 1
# Model 1's monthly epoch: "Issuer keys rotate every 30 days"
# (REVENUE_ARCHITECTURE section 2, Model 1).
EPOCH_SECONDS = 86400 * 30
LIVE_EPOCHS = 2

# The tier table: price, rate class and the monthly cover cost that
# class burns on the chain's smallest-allowance hop (cost honesty: the
# price and the cost sit in the same row, computed from tools/rates.py
# at table-build time by `--refresh-costs`).
TIERS = {
    "standard": {"price_usd": 5, "rate": "standard"},
    "fast": {"price_usd": 10, "rate": "fast"},
    "line": {"price_usd": 25, "rate": "line"},
}


class VoucherError(Exception):
    """Base class for voucher failures."""


class PaymentNotSettled(VoucherError):
    """The webhook does not name a settled payment for a known tier."""


class WebhookAuthError(VoucherError):
    """The webhook's HMAC does not verify (wrong secret or tampering)."""


class ReplayDetected(VoucherError):
    """This webhook notification was already consumed."""


class TierError(VoucherError):
    """The named tier does not exist."""


def current_epoch(now: float | None = None) -> int:
    """The monthly voucher epoch at `now`."""
    return int((time.time() if now is None else now) // EPOCH_SECONDS)


def tier_for_price(cents: int) -> str:
    """The tier a settled payment of `cents` bought (exact match only;
    overpayment is not auto-upgraded — the mint never guesses)."""
    for name, tier in TIERS.items():
        if tier["price_usd"] * 100 == cents:
            return name
    raise TierError(f"no tier costs {cents / 100:.2f} USD")


# ------------------------------------------------------------------ mint


class Mint:
    """The issuance side: blind-signs for settled payments.

    Holds the monthly issuer key (an ordinary RSA-3072 key, as the mesh
    credits use; hardware-sealing it goes through tools/keyguard.py
    exactly like descriptor signing) and the webhook bookkeeping the
    replay protection needs. It keeps NO identity records: the payment
    references live in the replay set until their epoch passes, then
    they are gone."""

    def __init__(self, private_key=None, webhook_secret: bytes = b""):
        self.key = private_key or mt.generate_issuer_key()
        self.webhook_secret = webhook_secret or secrets.token_bytes(32)
        self._seen_webhooks: dict[str, int] = {}  # payment_id -> epoch seen

    def public_key_bytes(self) -> bytes:
        """The mint's public key for relays (PEM, published monthly)."""
        from cryptography.hazmat.primitives import serialization

        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def epoch_public(self, epoch: int):
        """The issuer key for an epoch (this implementation: one key,
        epoch-labelled; a per-epoch key set drops in exactly where this
        method is)."""
        return self.key.public_key()

    # ---- webhook

    def verify_webhook(self, body: bytes, signature_hex: str, now: float | None = None) -> dict:
        """Authenticate a BTCPay webhook notification and extract the
        settled payment. HMAC-SHA256 over the raw body with the store
        secret (BTCPay's convention), then the replay check on the
        payment id."""
        expected = hmac.new(self.webhook_secret, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature_hex or ""):
            raise WebhookAuthError("webhook HMAC does not verify")
        try:
            notice = json.loads(body)
        except json.JSONDecodeError as e:
            raise WebhookAuthError(f"webhook body is not JSON: {e}") from e
        if notice.get("type") != "InvoiceSettled":
            raise PaymentNotSettled(f"webhook type {notice.get('type')!r} is not a settlement")
        payment_id = str(notice.get("payment_id") or notice.get("invoiceId") or "")
        if not payment_id:
            raise PaymentNotSettled("the settlement names no payment id")
        epoch = current_epoch(now)
        if self._seen_webhooks.get(payment_id) is not None:
            raise ReplayDetected(payment_id)
        self._seen_webhooks[payment_id] = epoch
        return notice

    # ---- issuance

    def issue(self, blinded: int, tier: str, now: float | None = None) -> dict:
        """Blind-sign one voucher for a paid tier. The mint sees only
        the blinded value; it can neither derive the voucher secret nor
        recognize it later."""
        if tier not in TIERS:
            raise TierError(tier)
        blind_signature = mt.sign_blinded(self.key, blinded)
        return {
            "schema": SCHEMA,
            "epoch": current_epoch(now),
            "tier": tier,
            "blind_signature": blind_signature.to_bytes((mt.KEY_BITS + 7) // 8, "big").hex(),
            "issuer": mt.issuer_id(self.key.public_key()),
        }


# ---------------------------------------------------------------- buyer


class Buyer:
    """The purchase side: draw a secret, blind, unblind, hold the pair.

    Nothing here touches the network — the three messages (blinded
    value out, blind signature back, voucher pair at redemption) are
    carried by whatever rails the buyer uses."""

    def __init__(self):
        self.secret = mt.new_token()

    def blinded(self):
        """(blinded, unblinder) to send the mint with the payment. The
        unblinder stays with the buyer until the signature returns."""
        return mt.blind(self.secret, _mint_key_for_blinding())

    def finish(self, blind_signature: int, unblinder: int, epoch: int, tier: str) -> dict:
        """Unblind into the spendable voucher (refuses an unverifiable
        signature, never spends it — the RFC 9474 Finalize rule the
        mesh credits already apply)."""
        signature = mt.unblind(blind_signature, unblinder, _mint_key_for_blinding(), self.secret)
        return {
            "schema": SCHEMA,
            "epoch": epoch,
            "tier": tier,
            "secret": self.secret.hex(),
            "signature": signature.to_bytes((mt.KEY_BITS + 7) // 8, "big").hex(),
            "issuer": mt.issuer_id(_mint_key_for_blinding()),
        }


# The buyer needs the mint's public key to blind against; the tests
# inject it, production fetches it from the mint's published page.
_MINT_KEY_HOLDER: dict = {}


def _mint_key_for_blinding():
    if "key" not in _MINT_KEY_HOLDER:
        raise VoucherError("set the mint public key before blinding (set_mint_key_for_tests / fetch the published key)")
    return _MINT_KEY_HOLDER["key"]


def set_mint_key_for_tests(public_key) -> None:
    """Point the Buyer at a mint public key (the published PEM in
    production; a test fixture here)."""
    _MINT_KEY_HOLDER["key"] = public_key


# ---------------------------------------------------------------- relay


def redeem_voucher(voucher: dict, mint_public_key, ledger: mt.Ledger, now: float | None = None) -> dict:
    """Relay-side redemption: public verification, tier validity and
    the double-spend ledger (the mesh's own Ledger)."""
    if voucher.get("schema") != SCHEMA:
        raise VoucherError("unsupported voucher schema")
    tier = voucher.get("tier")
    if tier not in TIERS:
        raise TierError(tier)
    secret = bytes.fromhex(voucher.get("secret", ""))
    signature = int.from_bytes(bytes.fromhex(voucher.get("signature", "")), "big")
    grant = {
        "epoch": voucher["epoch"],
        "token": secret.hex(),
        "issuer": mt.issuer_id(mint_public_key),
    }
    spend = {"grant": grant, "redemption": voucher["signature"]}
    # mt.verify checks the RSA-FDH signature under the mint's public key.
    if not mt.verify(secret, signature, mint_public_key):
        raise mt.InvalidSignature("voucher does not verify under the mint key")
    # Epoch validity: the voucher epoch label must be live (monthly).
    now_epoch = current_epoch(now)
    if not now_epoch - LIVE_EPOCHS < voucher["epoch"] <= now_epoch:
        raise mt.Expired("this voucher's epoch is no longer live")
    # Double-spend: the digest of the secret.
    digest = mt.token_digest(secret)
    if ledger.seen(grant["issuer"], digest):
        raise mt.DoubleSpend("this voucher was already redeemed")
    result = ledger.redeem(spend, mint_public_key, epoch=voucher["epoch"])
    result["tier"] = tier
    result["rate_class"] = TIERS[tier]["rate"]
    return result


# ---------------------------------------------------------- scratch cards


def scratch_batch(mint: Mint, tier: str, count: int, batch_id: str | None = None) -> dict:
    """A batch of physical scratch-off vouchers (the retail rail):
    per-card random codes whose FDH the mint signs for the tier.

    A card's code IS the voucher secret, so the printed card and the
    digital voucher share one redemption path: scratch → (code,
    signature, tier) → relay. The batch record returned to the printer
    carries per-card digests (NOT the codes) so the fulfilment house
    cannot redeem what it prints — the same digest-only discipline as
    the ledger."""
    if tier not in TIERS:
        raise TierError(tier)
    batch_id = batch_id or secrets.token_hex(8)
    cards = []
    for _ in range(count):
        secret = mt.new_token()
        blinded, unblinder = mt.blind(secret, mint.key.public_key())
        sig = mt.unblind(
            mt.sign_blinded(mint.key, blinded),
            unblinder,
            mint.key.public_key(),
            secret,
        )
        cards.append(
            {
                "code": secret.hex(),
                "signature": sig.to_bytes((mt.KEY_BITS + 7) // 8, "big").hex(),
                "digest": mt.token_digest(secret),
            }
        )
    return {
        "schema": SCHEMA,
        "batch_id": batch_id,
        "tier": tier,
        "epoch": current_epoch(),
        # The printer gets digests only; the codes go to the card stock.
        "printer_view": [{"digest": c["digest"]} for c in cards],
        "cards": cards,  # the operator's sealed copy, 0600, for support
    }


def refresh_tier_costs() -> dict:
    """Publish the cover-traffic cost each tier burns per month beside
    its price (cost honesty): the standard rate-class math from
    tools/rates.py applied to each tier's class at 8 h/day, 2 links."""
    import rates

    out = {}
    for name, tier in TIERS.items():
        out[name] = {
            "price_usd": tier["price_usd"],
            "rate": tier["rate"],
            "pps": rates.RATE_CLASSES[tier["rate"]],
            "cover_cost_gib_month": round(rates.rate_cost_gib(tier["rate"], 8, links=2), 1),
        }
    return out
