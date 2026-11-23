#!/usr/bin/env python3
"""Write tools/testdata/session_auth.json: leaves carrying hardware session authorizations,
for tools/session_auth.py and src/session_auth.rs to agree on.

Each vector is a real ML-DSA-65 leaf with the extension, signed by a software ES256 or
Ed25519 key in exactly the byte layout a FIDO2 key produces (authenticator data, client
data JSON, signature over both); the refused ones each break one check. Run it again only
when the format changes, and commit the result.
"""

import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent))
import session_auth as sa  # noqa: E402

OUT = Path(__file__).resolve().parent / "testdata" / "session_auth.json"
NOW = 1795000000  # the verifiers' clock in every vector


class SoftKey:
    """A software stand-in for a FIDO2 credential, producing WebAuthn assertions."""

    def __init__(self, alg):
        self.alg = alg
        self.key = ec.generate_private_key(ec.SECP256R1()) if alg == "es256" else ed25519.Ed25519PrivateKey.generate()

    def device(self):
        """The key as a hop pins it (`peer_device`)."""
        p = self.key.public_key()
        if self.alg == "es256":
            raw = p.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        else:
            raw = p.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return dict(alg=self.alg, public_hex=raw.hex())

    def assert_(self, statement, rp=sa.RP, flags=sa.UP_UV, challenge=None, typ="webauthn.get", origin=sa.ORIGIN):
        """A WebAuthn assertion over SHA-256(statement); the keywords break one field each."""
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + (42).to_bytes(4, "big")
        digest = hashlib.sha256(statement if challenge is None else challenge).digest()
        client = json.dumps(
            dict(type=typ, challenge=base64.urlsafe_b64encode(digest).rstrip(b"=").decode(), origin=origin),
            separators=(",", ":"),
        ).encode()
        signed = auth + hashlib.sha256(client).digest()
        sig = self.key.sign(signed, ec.ECDSA(hashes.SHA256())) if self.alg == "es256" else self.key.sign(signed)
        b64 = lambda v: base64.b64encode(v).decode()  # noqa: E731
        return dict(authenticator_data=b64(auth), client_data=b64(client), signature=b64(sig))


def spki(key):
    """DER SubjectPublicKeyInfo of a private key's public half."""
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def leaf(identity, not_before, not_after, value=None):
    """A self-signed leaf for `identity`, with the extension when `value` is given."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client-inner.cypherpunk-vpn.internal")])
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(identity.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.fromtimestamp(not_before, dt.timezone.utc))
        .not_valid_after(dt.datetime.fromtimestamp(not_after, dt.timezone.utc))
    )
    if value is not None:
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(sa.OID), value), False)
    return b.sign(identity, None).public_bytes(serialization.Encoding.DER)


def main():
    """Write every vector."""
    identity, other_identity = mldsa.MLDSA65PrivateKey.generate(), mldsa.MLDSA65PrivateKey.generate()
    layers = {"inner": sa.spki_sha256(spki(identity)), "outer": "ab" * 32}
    nb, na = NOW - 300, NOW - 300 + sa.MAX_SECONDS
    statement = sa.authorization(layers, nb, na)
    vectors = []

    def add(name, device, der, error=None):
        vectors.append(dict(name=name, device=device, leaf=der.hex(), error=error))

    for alg in ("es256", "eddsa"):
        k = SoftKey(alg)
        good = sa.extension_value(statement, k.assert_(statement))
        add("accepted_" + alg, k.device(), leaf(identity, nb, na, good))
    k = SoftKey("es256")
    dev = k.device()
    ok = k.assert_(statement)
    add("no_extension", dev, leaf(identity, nb, na), "no hardware session authorization")
    add(
        "wrong_relying_party",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, k.assert_(statement, rp="evil.example"))),
        "wrong relying party",
    )
    add(
        "touch_only_no_pin",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, k.assert_(statement, flags=0x01))),
        "touch and PIN required",
    )
    add(
        "pin_only_no_touch",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, k.assert_(statement, flags=0x04))),
        "touch and PIN required",
    )
    add(
        "registration_not_assertion",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, k.assert_(statement, typ="webauthn.create"))),
        "wrong client data",
    )
    add(
        "wrong_origin",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, k.assert_(statement, origin="https://evil.example"))),
        "wrong client data",
    )
    other_statement = sa.authorization(layers, nb, na - 1)
    add(
        "assertion_for_another_statement",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, k.assert_(other_statement))),
        "assertion is for another statement",
    )
    tampered = dict(ok)
    sig = bytearray(base64.b64decode(tampered["signature"]))
    sig[-1] ^= 1
    tampered["signature"] = base64.b64encode(bytes(sig)).decode()
    add(
        "tampered_signature",
        dev,
        leaf(identity, nb, na, sa.extension_value(statement, tampered)),
        "not signed by the enrolled key",
    )
    add(
        "another_key",
        SoftKey("es256").device(),
        leaf(identity, nb, na, sa.extension_value(statement, ok)),
        "not signed by the enrolled key",
    )
    add(
        "statement_names_another_identity",
        dev,
        leaf(other_identity, nb, na, sa.extension_value(statement, ok)),
        "the authorization does not name this key",
    )
    expired = sa.authorization(layers, NOW - sa.MAX_SECONDS - 10, NOW - 10)
    add(
        "expired",
        dev,
        leaf(identity, NOW - sa.MAX_SECONDS - 10, NOW - 10, sa.extension_value(expired, k.assert_(expired))),
        "session authorization expired or not yet valid",
    )
    future = sa.authorization(layers, NOW + 60, NOW + 3600)
    add(
        "not_yet_valid",
        dev,
        leaf(identity, NOW + 60, NOW + 3600, sa.extension_value(future, k.assert_(future))),
        "session authorization expired or not yet valid",
    )
    add(
        "leaf_outlives_authorization",
        dev,
        leaf(identity, nb, na + 3600, sa.extension_value(statement, ok)),
        "the leaf outlives its authorization",
    )
    too_long = sa.canonical(dict(v=sa.VERSION, layers=layers, not_before=nb, not_after=nb + sa.MAX_SECONDS + 1))
    add(
        "window_over_12h",
        dev,
        leaf(identity, nb, nb + sa.MAX_SECONDS + 1, sa.extension_value(too_long, k.assert_(too_long))),
        "a session lasts at most 12 hours",
    )
    loose = json.dumps(json.loads(statement), indent=1).encode()  # same content, not the canonical bytes
    add(
        "non_canonical_statement",
        dev,
        leaf(identity, nb, na, sa.extension_value(loose, k.assert_(loose))),
        "malformed session authorization",
    )
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(dict(now=NOW, oid=sa.OID, vectors=vectors), indent=1) + "\n")
    print("%d vectors -> %s" % (len(vectors), OUT))


def handshake_leaf(cert_path, key_path, out_path, mode):
    """For src/crypto_tests.rs: turn a provisioned client identity into a managed one (its
    own self-signed certificate as the hop's root, pinned by public key, as `cypherpunk init`
    does) and rotate its leaf. Modes, by what the leaf carries:

    - `authorized`: the identity key, re-signed, with a statement by the pinned device key;
    - `plain`: the identity key, no statement; `other`: a statement by another device key;
    - `session`: a fresh session key certified by the identity (phase 2), statement naming it;
    - `session-other-identity`: a session key certified by a different ML-DSA-65 key;
    - `session-names-identity`: a session key whose statement names the identity instead;
    - `session-extra-root`: the hop also trusts a second identity under the same name, and
      that one certified the session key (the pin must still decide).

    Prints {device, root, spki_sha256, key} for the hop to pin and the client to use."""
    import time

    original = x509.load_der_x509_certificate(Path(cert_path).read_bytes())
    identity = serialization.load_der_private_key(Path(key_path).read_bytes(), password=None)
    now = int(time.time())
    nb, na = now - 300, now - 300 + sa.MAX_SECONDS
    leaf_key, issuer_key, named = identity, identity, identity
    if mode.startswith("session"):
        leaf_key = mldsa.MLDSA65PrivateKey.generate()
        named = identity if mode == "session-names-identity" else leaf_key
        if mode in ("session-other-identity", "session-extra-root"):
            issuer_key = mldsa.MLDSA65PrivateKey.generate()
    statement = sa.authorization({"outer": sa.spki_sha256(spki(named))}, nb, na)
    pinned, signer = SoftKey("es256"), SoftKey("es256")
    if mode != "other":
        signer = pinned
    b = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.fromtimestamp(nb, dt.timezone.utc))
        .not_valid_after(dt.datetime.fromtimestamp(na, dt.timezone.utc))
    )
    if mode != "plain":
        value = sa.extension_value(statement, signer.assert_(statement))
        b = b.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(sa.OID), value), False)
    for extension in original.extensions:
        b = b.add_extension(extension.value, extension.critical)
    Path(out_path).write_bytes(b.sign(issuer_key, None).public_bytes(serialization.Encoding.DER))
    Path(out_path).chmod(0o600)
    key = Path(str(out_path) + ".key")
    key.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    key.chmod(0o600)

    def self_signed(key):
        return (
            x509.CertificateBuilder()
            .subject_name(original.subject)
            .issuer_name(original.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.fromtimestamp(nb, dt.timezone.utc))
            .not_valid_after(dt.datetime.fromtimestamp(nb + 86400, dt.timezone.utc))
            .sign(key, None)
            .public_bytes(serialization.Encoding.DER)
        )

    root = Path(str(out_path) + ".root")
    root.write_bytes(self_signed(identity) + (self_signed(issuer_key) if mode == "session-extra-root" else b""))
    root.chmod(0o600)
    print(
        json.dumps(
            dict(device=pinned.device(), root=str(root), spki_sha256=sa.spki_sha256(spki(identity)), key=str(key))
        )
    )


if __name__ == "__main__":
    if sys.argv[1:2] == ["leaf"]:
        handshake_leaf(*sys.argv[2:6])
    else:
        main()
