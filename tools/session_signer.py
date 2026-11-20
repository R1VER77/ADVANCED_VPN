#!/usr/bin/env python3
"""Short-lived signer for hardware-bound sessions (docs/HARDWARE_BOUND_SESSIONS.md, phase 2).

The long-term ML-DSA-65 identities never enter the VPN's long-running processes. For each
session the supervisor makes fresh session keys and runs this program with their public
keys. It hardens itself, asks the hardware key for one touch and its PIN (which both
signs the session statement and returns the vault's hmac-secret), unseals only what it was
asked for, certifies each session key with its layer's identity, prints the leaves and
exits: the identity exists in plaintext for those seconds, in this process alone, and the
kernel reclaims the memory when it ends.

Request (JSON on the descriptor given by --request-fd, else stdin): {"state": DIR, "lanes":
{lane: session SPKI hex}, "carry": [names]}. The supervisor uses --request-fd so that stdin
and stderr stay its own: the PIN prompt needs the terminal, the touch prompt must be seen.
A refusal is {"error": "..."} on stdout (and on stderr), with a non-zero exit.
`carry` names keys the data plane still takes long-term (the WireGuard key and its siblings
until phase 2's per-session carrier); they are returned as they are today.
Reply (JSON on stdout): {"leaves": {lane: DER hex}, "carry": {name: hex}, "not_before",
"not_after", "hardening": {...}}.
"""

import ctypes
import datetime as dt
import hashlib
import json
from pathlib import Path
import resource
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

PR_SET_DUMPABLE = 4
MCL_CURRENT, MCL_FUTURE = 1, 2


def harden() -> dict:
    """No core dumps, no ptrace by same-user processes, memory kept out of swap where the
    kernel allows it. Returns what took effect; only the first two are required."""
    libc = ctypes.CDLL(None, use_errno=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "could not make the signer undumpable")
    locked = libc.mlockall(MCL_CURRENT | MCL_FUTURE) == 0
    return dict(core_dumps=False, dumpable=False, memory_locked=locked)


def certify(state: Path, lane: str, identity_der: bytes, session_spki: bytes, window, extension: bytes) -> bytes:
    """A leaf for the session key, issued under the layer's identity: same name and
    extensions as the identity certificate, the session's window, and the authorization."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    import session_auth
    from keyguard import read_private
    from provision import digest_for

    original = x509.load_der_x509_certificate(read_private(state / (lane + "-cert.der")))
    identity = serialization.load_der_private_key(identity_der, password=None)
    if identity.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) != original.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ):
        raise ValueError("identity key mismatch")
    b = (
        x509.CertificateBuilder()
        .subject_name(original.subject)
        .issuer_name(original.subject)
        .public_key(serialization.load_der_public_key(session_spki))
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.fromtimestamp(window[0], dt.timezone.utc))
        .not_valid_after(dt.datetime.fromtimestamp(window[1], dt.timezone.utc))
        .add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(session_auth.OID), extension), False)
    )
    for e in original.extensions:
        b = b.add_extension(e.value, e.critical)
    return b.sign(identity, digest_for(identity)).public_bytes(serialization.Encoding.DER)


def sign(state: Path, lanes: dict, carry=(), now=None) -> dict:
    """The signer's work, in this process: see the module docstring."""
    import session_auth
    from keyguard import hardware_assertion, read_private
    from managed_profile import load_keys

    protection = json.loads(read_private(state / "protection.json"))
    if protection["mode"] != "nitrokey":
        raise ValueError("sessions are hardware-signed only on a hardware-protected device")
    if not lanes or not set(lanes) <= {"outer", "middle", "inner"}:
        raise ValueError("a session names the device's layers")
    now = int(time.time() if now is None else now)
    window = (now - 300, now - 300 + session_auth.MAX_SECONDS)
    spki = {lane: bytes.fromhex(v) for lane, v in lanes.items()}
    statement = session_auth.authorization({lane: hashlib.sha256(v).hexdigest() for lane, v in spki.items()}, *window)
    secret, meta, assertion = hardware_assertion(Path(protection["vault"]), message=statement)
    keys = load_keys(state, sorted(lanes) + list(carry), secret, meta)
    extension = session_auth.extension_value(statement, assertion)
    leaves = {lane: certify(state, lane, keys.pop(lane), spki[lane], window, extension).hex() for lane in sorted(lanes)}
    return dict(
        leaves=leaves,
        carry={name: keys.pop(name).hex() for name in carry},
        not_before=window[0],
        not_after=window[1],
    )


def main(argv=None) -> int:
    """Read one request, sign it, reply, exit."""
    argv = sys.argv[1:] if argv is None else argv
    hardening = harden()
    # stdout carries only the reply: anything printed while signing (a library's touch
    # prompt) goes to stderr, where the person sees it.
    reply_out, sys.stdout = sys.stdout, sys.stderr
    try:
        return _main(argv, hardening, reply_out)
    finally:
        sys.stdout = reply_out


def _main(argv, hardening, out):
    import os

    try:
        if argv[:1] == ["--request-fd"] and len(argv) == 2:
            with os.fdopen(int(argv[1]), "rb") as f:
                request = json.loads(f.read())
        elif not argv:
            request = json.loads(sys.stdin.read())
        else:
            raise ValueError("usage: session_signer.py [--request-fd N]")
        if set(request) != {"state", "lanes", "carry"}:
            raise ValueError("unexpected signer request")
        reply = sign(Path(request["state"]), request["lanes"], request["carry"])
    except Exception as e:  # one refusal, its reason for the supervisor and the person
        reason = "%s: %s" % (type(e).__name__, e)
        print(reason, file=sys.stderr)
        out.write(json.dumps(dict(error=reason)))
        out.flush()
        return 1
    reply["hardening"] = hardening
    out.write(json.dumps(reply))
    out.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
