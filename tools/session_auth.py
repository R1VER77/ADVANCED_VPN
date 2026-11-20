"""Hardware session authorization (docs/HARDWARE_BOUND_SESSIONS.md).

At connect the client's FIDO2 key signs, after a touch and its PIN, a short statement: the
SHA-256 of each TLS layer's public key and a validity window of at most 12 hours. The
statement and the key's WebAuthn assertion travel in each fresh leaf certificate as a
non-critical extension. Every hop that pins the client's device key (`peer_device` in its
runtime configuration) refuses a leaf without a valid one (`src/tls.rs`, `authenticated`).
Identity keys copied off the computer therefore stop working when the current statement
expires: the hardware has to sign again.

This module builds the statement and the extension, converts the enrolled credential's
COSE key into the form the Rust verifier takes, and verifies a leaf exactly as the Rust
side does (the reference for `tools/testdata/session_auth.json`).
"""

import base64
import hashlib
import json

# A private OID arc derived from a UUID (ITU-T X.667: 2.25.<UUID as an integer>), so no
# registration is needed and it cannot collide with a registered extension.
OID = "2.25.304735596916668360143454144096617811569"
VERSION = "advanced-vpn/session/v1"
RP = "advanced-vpn.local"
ORIGIN = "https://" + RP
MAX_SECONDS = 43200  # 12 h, the client's leaf lifetime
SKEW = 600  # the leaf profile's tolerance, src/tls.rs certificate_lifetime
UP_UV = 0x05  # authenticator data flags: user present, user verified
COSE_ES256, COSE_EDDSA = -7, -8


def canonical(value) -> bytes:
    """The one byte form of a JSON value: sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def spki_sha256(spki_der: bytes) -> str:
    """Hex SHA-256 of a SubjectPublicKeyInfo, the form every pin uses."""
    return hashlib.sha256(spki_der).hexdigest()


def authorization(layers: dict, not_before: int, not_after: int) -> bytes:
    """The statement the key signs: {lane: SPKI SHA-256 hex}, and the window, in seconds."""
    if not layers or not all(isinstance(v, str) and len(v) == 64 for v in layers.values()):
        raise ValueError("a session names every layer's public-key hash")
    if not 0 < not_after - not_before <= MAX_SECONDS:
        raise ValueError("a session lasts at most 12 hours")
    return canonical(dict(v=VERSION, layers=dict(layers), not_before=int(not_before), not_after=int(not_after)))


def device_key(cose_b64: str) -> dict:
    """The enrolled credential's public key as the Rust verifier takes it: ES256 as an
    uncompressed P-256 point, EdDSA as the raw Ed25519 key. Other algorithms are refused:
    a key that cannot authorize sessions is named at enrollment, not silently exempted."""
    from fido2 import cbor

    key = cbor.decode(base64.b64decode(cose_b64, validate=True))
    alg = key.get(3)
    if alg == COSE_ES256 and key.get(1) == 2 and key.get(-1) == 1:
        x, y = key[-2], key[-3]
        if len(x) != 32 or len(y) != 32:
            raise ValueError("bad P-256 key")
        return dict(alg="es256", public_hex=(b"\x04" + x + y).hex())
    if alg == COSE_EDDSA and key.get(1) == 1 and key.get(-1) == 6:
        if len(key[-2]) != 32:
            raise ValueError("bad Ed25519 key")
        return dict(alg="eddsa", public_hex=key[-2].hex())
    raise ValueError(
        "this key's credential algorithm (COSE %r) cannot authorize sessions; "
        "hardware-bound sessions need ES256 or EdDSA" % (alg,)
    )


def extension_value(statement: bytes, assertion: dict) -> bytes:
    """The extension's contents: the statement and the assertion, hex-encoded JSON."""
    unb64 = lambda v: base64.b64decode(v, validate=True)  # noqa: E731
    return canonical(
        dict(
            authorization=statement.hex(),
            authenticator_data=unb64(assertion["authenticator_data"]).hex(),
            client_data=unb64(assertion["client_data"]).hex(),
            signature=unb64(assertion["signature"]).hex(),
        )
    )


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def verify_leaf(device: dict, leaf_der: bytes, now: float) -> dict:
    """Check a peer's leaf as src/tls.rs does: the extension's assertion is by `device`,
    with touch and PIN, over this statement; the statement names this leaf's public key;
    now, and the leaf's whole validity, lie inside the statement's window of at most 12 h.
    Returns the statement; raises ValueError otherwise."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except x509.InvalidVersion as e:  # found by tools/test_parser_fuzz.py
        raise ValueError("invalid certificate") from e
    try:
        raw = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(OID)).value.value
    except x509.ExtensionNotFound as e:
        raise ValueError("no hardware session authorization") from e
    try:
        ext = json.loads(raw)
        if set(ext) != {"authorization", "authenticator_data", "client_data", "signature"}:
            raise ValueError
        statement, auth, client_data, signature = (
            bytes.fromhex(ext[k]) for k in ("authorization", "authenticator_data", "client_data", "signature")
        )
        s = json.loads(statement)
        if set(s) != {"v", "layers", "not_before", "not_after"} or s["v"] != VERSION:
            raise ValueError
        not_before, not_after = int(s["not_before"]), int(s["not_after"])
        c = json.loads(client_data)
    except (ValueError, TypeError, KeyError) as e:
        raise ValueError("malformed session authorization") from e
    if canonical(s) != statement:
        raise ValueError("malformed session authorization")
    if len(auth) < 37 or auth[:32] != hashlib.sha256(RP.encode()).digest():
        raise ValueError("wrong relying party")
    if auth[32] & UP_UV != UP_UV:
        raise ValueError("touch and PIN required")
    if c.get("type") != "webauthn.get" or c.get("origin") != ORIGIN:
        raise ValueError("wrong client data")
    if c.get("challenge") != _b64url(hashlib.sha256(statement).digest()):
        raise ValueError("assertion is for another statement")
    signed = auth + hashlib.sha256(client_data).digest()
    public = bytes.fromhex(device["public_hex"])
    try:
        if device["alg"] == "es256":
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public).verify(
                signature, signed, ec.ECDSA(hashes.SHA256())
            )
        elif device["alg"] == "eddsa":
            ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signature, signed)
        else:
            raise ValueError("unknown device key algorithm")
    except InvalidSignature as e:
        raise ValueError("not signed by the enrolled key") from e
    from cryptography.exceptions import UnsupportedAlgorithm

    try:
        spki = leaf.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except UnsupportedAlgorithm as e:  # found by tools/test_parser_fuzz.py
        raise ValueError("the authorization does not name this key") from e
    if spki_sha256(spki) not in s["layers"].values():
        raise ValueError("the authorization does not name this key")
    if not 0 < not_after - not_before <= MAX_SECONDS:
        raise ValueError("a session lasts at most 12 hours")
    if not not_before <= now < not_after:
        raise ValueError("session authorization expired or not yet valid")
    nb, na = leaf.not_valid_before_utc.timestamp(), leaf.not_valid_after_utc.timestamp()
    if nb < not_before or na > not_after:
        raise ValueError("the leaf outlives its authorization")
    return s
