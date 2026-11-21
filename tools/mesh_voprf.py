#!/usr/bin/env python3
"""VOPRF credits for the mesh's private groups (RFC 9497, ristretto255-SHA512).

Why this module exists, and the boundary it does not cross
-----------------------------------------------------------
The public pool's credits are Chaum blind RSA (`tools/mesh_tokens.py`)
because PUBLIC redemption must verify against the issuer's published
public key alone: any node holding the ledger can check an RSA signature
without the issuer's secret. A VOPRF cannot offer that — verifying a
redemption requires re-deriving the evaluation, which needs the private
key. That is why `src/mesh/tokens.rs` stays fail-closed for the public
pool until a reviewed constant-time Rust VOPRF crate is vendored, and
why this module does not change that gate.

Where a VOPRF is the right primitive is the PRIVATE GROUP (MESH_DESIGN
section 5): a group already shares a key (its credits are HMAC-based
today, which means the group's issuer sees everything). Moving the
group's credits to a VOPRF gives the members what the HMAC scheme
cannot: the group cannot link a redemption to the issuance it served,
because at issuance it sees only the blinded element and at redemption
it sees only the token input — the VOPRF's unlinkability, exactly the
Privacy Pass / private-token architecture where issuer and verifier are
the same entity (the group).

Construction (the private-token shape):
  1. EARN: the member blinds a fresh random 32-byte input and sends the
     blinded element to a group node (the issuer). The node evaluates
     under the group's epoch key and returns the evaluation with a DLEQ
     batch proof. The member verifies the proof against the group's
     public key (published in the group descriptor), unblinds, and holds
     a credit = (input, token_value = sk*H(input)) known only to itself.
  2. SPEND: the member presents (input, authenticator =
     HMAC-SHA512-256(key = derive(token_value), msg = epoch || binding))
     to a group node. The node recomputes token_value = sk*H(input) (it
     holds the group key), verifies the authenticator, and records the
     token digest in the double-spend ledger — the same ledger shape
     `mesh_tokens.Ledger` uses, so the audit and revocation semantics
     carry over.
  3. UNLINKABILITY: the issuer saw Blind(input) at earn time; it sees
     input at spend time; the VOPRF's blind makes the two unlinkable
     (RFC 9497 section 7.1) — unlike the HMAC scheme where the issuer
     computes the same value both times.

The Rust data plane remains the authority on what the wire accepts; the
wire shapes here (grant/spend dictionaries with hex fields) mirror
`src/mesh/tokens.rs` TokenGrant/TokenSpend for the day the reviewed
crate lands and the private-group flow moves into the tunnel itself.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import voprf

SCHEMA = 2
TOKEN_INPUT_BYTES = 32
EPOCH_SECONDS = 86400
# One day of grace: a credit earned under epoch k's key redeems until the
# end of epoch k+1, matching mesh_tokens.LIVE_EPOCHS.
LIVE_EPOCHS = 2

DOMAIN = b"avpn-group-credit/v2"


class CreditError(Exception):
    """Base class for VOPRF credit failures."""


class InvalidAuthenticator(CreditError):
    """The redemption's HMAC does not verify (wrong key, wrong binding)."""


class DoubleSpend(CreditError):
    """This token digest was already redeemed."""


class Expired(CreditError):
    """A credit under an epoch key that is no longer live."""


class UntrustedGroup(CreditError):
    """The spend names an issuer whose epoch key is not published."""


def current_epoch(now: float | None = None) -> int:
    """The credit epoch at `now` (default: the current time)."""
    import time

    return int((time.time() if now is None else now) // EPOCH_SECONDS)


def group_epoch_key(group_seed: bytes, epoch: int):
    """The group's deterministic VOPRF key for an epoch, derived exactly
    as RFC 9497 DeriveKeyPair with the epoch in the KeyInfo, so every
    group node derives the same key from the shared seed (the seed is the
    group's existing shared secret material; it never leaves the group)."""
    if len(group_seed) != 32:
        raise ValueError("the group seed is 32 bytes")
    sk, pk = voprf.derive_key_pair(group_seed, DOMAIN + b"|key|" + str(epoch).encode(), voprf.MODE_VOPRF)
    return sk, pk


def issuer_id(public_key_encoded: bytes) -> str:
    """!xxxxxxxx, the member-ID shape (SHA-256 of the encoded key)."""
    return "!" + hashlib.sha256(DOMAIN + b"|id|" + public_key_encoded).hexdigest()[:8]


def token_digest(token_value_encoded: bytes) -> str:
    """The ledger key; the ledger stores the digest, never the token."""
    return hashlib.sha256(DOMAIN + b"|spent|" + token_value_encoded).hexdigest()


def _derive_key(token_value_encoded: bytes) -> bytes:
    """The HMAC key derived from the unblinded token value."""
    return hashlib.sha256(DOMAIN + b"|auth|" + token_value_encoded).digest()


# ------------------------------------------------------------------ member


class Member:
    """The earning and spending side of a group member."""

    def __init__(self, group_pk_encoded: bytes):
        self._client = voprf.Client(group_pk_encoded, voprf.MODE_VOPRF)
        self.group_pk = group_pk_encoded

    def request(self, token_input: bytes | None = None) -> tuple[dict, dict]:
        """The earn request to send a group node, plus the local secret.

        Only `blinded` goes on the wire; the input and the blind stay
        with the member and never leave this machine."""
        if token_input is None:
            token_input = secrets.token_bytes(TOKEN_INPUT_BYTES)
        if len(token_input) != TOKEN_INPUT_BYTES:
            raise ValueError("a token input is exactly 32 bytes")
        blind, blinded = self._client.blind(token_input)
        wire = {"schema": SCHEMA, "blinded": blinded.hex()}
        secret = {
            "input": token_input.hex(),
            "blind": blind.to_bytes(32, "little").hex(),
            "blinded": blinded.hex(),
        }
        return wire, secret

    def finish(self, secret: dict, response: dict) -> dict:
        """Combine the issuer's response with the local secret into a credit.

        The response carries the evaluated element and the DLEQ proof;
        the proof is verified against the group key before the credit is
        kept (an unverifiable evaluation is refused, never spent)."""
        token_input = bytes.fromhex(secret["input"])
        blind = int.from_bytes(bytes.fromhex(secret["blind"]), "little")
        blinded = bytes.fromhex(secret["blinded"])
        evaluated = bytes.fromhex(response["evaluated"])
        proof = (
            int.from_bytes(bytes.fromhex(response["proof_c"]), "little"),
            int.from_bytes(bytes.fromhex(response["proof_s"]), "little"),
        )
        # finalize() verifies the DLEQ proof and unblinds; the resulting
        # PRF output is checked into the credit's identity, and the token
        # value (the unblinded element) is what redemption re-derives.
        output = self._client.finalize(token_input, blind, evaluated, blinded, proof)
        token_value = voprf.encode(voprf.scalar_mult(pow(blind, -1, voprf.L), voprf.decode(evaluated)))
        if hashlib.sha512(b"\x00\x20" + token_input + b"\x00\x20" + token_value + b"Finalize").digest() != output:
            raise ValueError("finalize/token mismatch")
        return {
            "schema": SCHEMA,
            "epoch": response["epoch"],
            "issuer": response["issuer"],
            "input": token_input.hex(),
            "token": token_value.hex(),
        }

    def spend(self, credit: dict, binding: str, now: float | None = None) -> dict:
        """The redemption message for a chain request through a group node.

        `binding` is the request identifier this spend pays for (the
        chain id and the requesting member's pseudonym for the epoch):
        replaying the spend on another request fails the HMAC, and the
        node records the digest so the same credit cannot pay twice."""
        epoch = credit["epoch"]
        token_value = bytes.fromhex(credit["token"])
        msg = DOMAIN + b"|spend|" + str(epoch).encode() + b"|" + binding.encode()
        auth = hmac.new(_derive_key(token_value), msg, hashlib.sha512).digest()[:32]
        return {
            "schema": SCHEMA,
            "grant": {
                "epoch": epoch,
                "issuer": credit["issuer"],
                "input": credit["input"],
            },
            "redemption": auth.hex(),
        }


# ------------------------------------------------------------------- node


class GroupNode:
    """The issuer/verifier side: a group node holding the group seed.

    In a private group every node may hold the shared seed (that is the
    existing group trust model); the VOPRF adds blind issuance so the
    nodes cannot tell which member earned which credit, and verification
    by re-derivation so redemptions need no issuer-side state beyond the
    double-spend ledger."""

    def __init__(self, group_seed: bytes, ledger_path=None):
        self.seed = group_seed
        self._ledger = Ledger(ledger_path) if ledger_path is not None else None

    def _keys(self, epoch: int):
        return group_epoch_key(self.seed, epoch)

    def public_key(self, now: float | None = None) -> bytes:
        """The group's current epoch public key (encoded), for members."""
        _, pk = self._keys(current_epoch(now))
        return pk

    def _client_for(self, epoch: int):
        sk, pk = self._keys(epoch)
        return voprf.Client(pk, voprf.MODE_VOPRF), sk

    def issue(self, request: dict, now: float | None = None) -> dict:
        """Answer an earn request: evaluate under the current epoch key
        and return the evaluation with a fresh DLEQ proof."""
        epoch = current_epoch(now)
        blinded = bytes.fromhex(request["blinded"])
        _, sk = self._client_for(epoch)
        server = voprf.Server(sk, voprf.MODE_VOPRF)
        evaluated, proof = server.blind_evaluate(blinded)
        return {
            "schema": SCHEMA,
            "epoch": epoch,
            "issuer": issuer_id(voprf.encode(server.pk)),
            "evaluated": evaluated.hex(),
            "proof_c": proof[0].to_bytes(32, "little").hex(),
            "proof_s": proof[1].to_bytes(32, "little").hex(),
        }

    def redeem(self, spend: dict, binding: str, now: float | None = None) -> dict:
        """Verify and record a redemption: re-derive the token under the
        named epoch's key, check the HMAC, refuse any digest the ledger
        has already seen (fail-closed on every error)."""
        now_epoch = current_epoch(now)
        grant = spend.get("grant", {})
        epoch = int(grant.get("epoch", -1))
        if not now_epoch - LIVE_EPOCHS < epoch <= now_epoch:
            raise Expired("this credit's epoch key is no longer live")
        token_input = bytes.fromhex(grant.get("input", ""))
        if len(token_input) != TOKEN_INPUT_BYTES:
            raise CreditError("a token input is exactly 32 bytes")
        auth = bytes.fromhex(spend.get("redemption", ""))
        client, sk = self._client_for(epoch)
        server = voprf.Server(sk, voprf.MODE_VOPRF)
        if issuer_id(voprf.encode(server.pk)) != grant.get("issuer"):
            raise UntrustedGroup("the spend names a different group key")
        # Re-derive: token_value = sk * H(input). The member proved it
        # holds the same value by the HMAC over the binding.
        token_value = server.evaluate_element(token_input)
        msg = DOMAIN + b"|spend|" + str(epoch).encode() + b"|" + binding.encode()
        expected = hmac.new(_derive_key(token_value), msg, hashlib.sha512).digest()[:32]
        if not hmac.compare_digest(auth, expected):
            raise InvalidAuthenticator("the redemption does not verify for this binding")
        digest = token_digest(token_value)
        if self._ledger is not None:
            self._ledger.record(grant["issuer"], digest)
        return {"ok": True, "issuer": grant["issuer"], "digest": digest}


class Ledger:
    """The group's double-spend ledger (the mesh_tokens.Ledger shape).

    Kept minimal here: a digest set per issuer, written atomically, so a
    credit redeemed anywhere in the group is refused everywhere after the
    record propagates with the descriptor gossip."""

    def __init__(self, path):
        from pathlib import Path

        self.path = Path(path)
        self._spent = {}
        self._load()

    def _load(self):
        import json

        if self.path.exists():
            doc = json.loads(self.path.read_text())
            if doc.get("schema") != SCHEMA:
                raise CreditError("unsupported ledger schema")
            self._spent = {k: set(v) for k, v in doc.get("spent", {}).items()}

    def record(self, issuer: str, digest: str) -> None:
        """Record a spend or raise DoubleSpend (fail-closed)."""
        if digest in self._spent.get(issuer, set()):
            raise DoubleSpend("this credit was already spent")
        self._spent.setdefault(issuer, set()).add(digest)
        self._flush()

    def _flush(self):
        import json
        import os
        import tempfile

        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"schema": SCHEMA, "spent": {k: sorted(v) for k, v in self._spent.items()}}
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(doc, indent=1) + "\n")
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise
