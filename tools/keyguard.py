#!/usr/bin/env python3
"""Nitrokey/FIDO2 envelopes and memory-only private-key handoff.

No PIN enrollment/reset, secret CLI arguments or software fallback. Requires a
preconfigured FIDO2 PIN. Keeps long-lived private material off the relay host.
"""

import argparse
import base64
import contextlib
import contextvars
from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import secrets
import stat
import subprocess
import sys
import time
from urllib.parse import unquote_to_bytes

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RP = "advanced-vpn.local"
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)


from sysexec import trusted_exe  # noqa: E402  (dependency-free; also used by install.py)


def read_private(path, limit=65536):
    """Read a small private file: regular, owned by this user, no group/other access, at most `limit` bytes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid != os.geteuid() or m.st_mode & 0o077 or m.st_size > limit:
            raise ValueError("invalid private file")
        data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file too large")
        return data


def atomic(path, data):
    """Write `data` to `path` atomically (exclusive temp file, fsync, rename), mode 0600."""
    tmp = path.with_name(path.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if path.is_symlink():
            raise ValueError("symlink target refused")
        os.replace(tmp, path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if tmp.exists():
            tmp.unlink()


ASK_PASSWORD = "/usr/bin/systemd-ask-password"
PINENTRY = "/usr/bin/pinentry-gnome3"
PIN_PROMPT = "ADVANCED VPN: FIDO2 PIN, then touch the Nitrokey when it flashes"
_PROMPT_CALLER = contextvars.ContextVar("cypherpunk_authenticated_prompt_caller", default=None)
_PROMPT_CANCEL = contextvars.ContextVar("cypherpunk_prompt_cancellation", default=None)


@contextlib.contextmanager
def authenticated_prompt(uid, cancel=None):
    """Root broker's authenticated bus caller; thread-local and never a WebView PIN."""
    if os.geteuid() != 0 or type(uid) is not int or uid <= 0:
        raise ValueError("a trusted non-root desktop caller is required")
    token = _PROMPT_CALLER.set(uid)
    cancellation = _PROMPT_CANCEL.set(cancel)
    try:
        yield
    finally:
        _PROMPT_CANCEL.reset(cancellation)
        _PROMPT_CALLER.reset(token)


class DialogUnavailable(RuntimeError):
    """The desktop PIN dialog could not be shown (no session, no display, no prompter)."""


def desktop_session():
    """(uid, gid, environment) for showing a dialog on the desktop of the person at
    this keyboard, or None. Run as yourself: your own session. Run as root through
    sudo: the invoking user's session (SUDO_UID), found from their /run/user
    directory, since sudo strips the display variables and root cannot use their
    session bus. Never over SSH: the dialog would open on another screen."""
    if os.environ.get("SSH_CONNECTION") or os.environ.get("AVPN_PIN_DIALOG") == "0":
        return None
    uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
    home = os.environ.get("HOME", "/")
    caller = _PROMPT_CALLER.get()
    if caller is not None:
        import pwd

        person = pwd.getpwuid(caller)
        uid, gid, home = str(person.pw_uid), str(person.pw_gid), person.pw_dir
    if os.geteuid() != 0 or not (uid.isdigit() and gid.isdigit()) or int(uid) == 0:
        # Not through sudo (yourself, or root with a display of its own): this session.
        if os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY"):
            return None, None, dict(os.environ)
        return None
    runtime = Path("/run/user") / uid
    env = {"PATH": "/usr/bin:/bin", "XDG_RUNTIME_DIR": str(runtime), "HOME": home}
    try:
        wayland = sorted(p.name for p in runtime.glob("wayland-[0-9]*") if not p.name.endswith(".lock"))
    except OSError:
        wayland = []
    if wayland:
        env["WAYLAND_DISPLAY"] = wayland[0]
    if Path("/tmp/.X11-unix/X0").exists():  # noqa: S108 - the X server's fixed socket, only checked
        env["DISPLAY"] = ":0"
    if not wayland and "DISPLAY" not in env:
        return None
    if (runtime / "bus").exists():
        env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=%s" % (runtime / "bus")
    return int(uid), int(gid), env


def pinentry():
    """PIN source, in order: a desktop dialog (pinentry-gnome3) on the session of the
    person at this keyboard, also under sudo; a terminal (no-echo prompt with a
    visible label); a systemd service without either, e.g. the whole-device unit at
    boot (systemd's password agents: boot console or `avpn unlock`). Anything else
    is refused; there is no unattended bypass. Cancelling the dialog stops; a dialog
    that cannot open falls back to the terminal.

    Desktop apps also run inside systemd scopes (INVOCATION_ID is set there), so
    the desktop check must come before the service check."""
    import sys

    session = desktop_session()
    if session and Path(PINENTRY).exists():
        try:
            return desktop_pinentry(session)
        except DialogUnavailable:
            pass
    if _PROMPT_CALLER.get() is not None:
        raise RuntimeError("trusted desktop prompt unavailable; use the local terminal unlock command")
    if sys.stdin.isatty():
        import getpass

        value = getpass.getpass("Nitrokey PIN (then touch the key when it flashes): ")
        if not value:
            raise RuntimeError("PIN unavailable")
        return value
    if os.environ.get("INVOCATION_ID") and Path(ASK_PASSWORD).exists():
        # No --keyname/--accept-cached: the PIN is never cached in the kernel keyring.
        r = subprocess.run(
            [
                ASK_PASSWORD,
                "--timeout=300",
                "--id=advanced-vpn:fido2-pin",
                "--icon=security-high",
                "--echo=no",
                PIN_PROMPT,
            ],
            capture_output=True,
            timeout=330,
        )
        value = r.stdout[:-1] if r.stdout.endswith(b"\n") else r.stdout
        if r.returncode or not value:
            raise RuntimeError("PIN prompt not answered")
        return value.decode()
    raise RuntimeError("no terminal, desktop session or systemd password agent for the PIN; run interactively")


def desktop_pinentry(session=None):
    """Ask for the FIDO2 PIN with the desktop pinentry dialog; never caches it.
    `session` is (uid, gid, env) from desktop_session(): under sudo the dialog runs
    as the invoking user, in their session."""
    uid, gid, env = session if session else (None, None, dict(os.environ))
    message = "SETTITLE ADVANCED VPN\nSETDESC Enter your Nitrokey PIN, then touch the key when it flashes.\nThis cannot reset or change the PIN.\nSETPROMPT PIN:\nGETPIN\nBYE\n"
    kw = dict(user=uid, group=gid, extra_groups=[]) if uid is not None else {}
    try:
        cancel = _PROMPT_CANCEL.get()
        if cancel is None:
            r = subprocess.run([PINENTRY], input=message.encode(), capture_output=True, timeout=180, env=env, **kw)
        else:
            # Own only this native prompt process. Cancellation never signals a
            # token-management service or unrelated PIN dialog.
            with subprocess.Popen(
                [PINENTRY], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, **kw
            ) as process:
                deadline = time.monotonic() + 180
                first = True
                try:
                    while True:
                        if cancel.is_set():
                            raise InterruptedError("native prompt cancelled")
                        if time.monotonic() >= deadline:
                            raise subprocess.TimeoutExpired(PINENTRY, 180)
                        data = message.encode() if first else None
                        first = False
                        try:
                            stdout, stderr = process.communicate(input=data, timeout=0.1)
                            r = subprocess.CompletedProcess([PINENTRY], process.returncode, stdout, stderr)
                            break
                        except subprocess.TimeoutExpired:
                            continue
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DialogUnavailable(str(e)) from e
    errors = [v for v in r.stdout.splitlines() if v.startswith(b"ERR ")]
    # Assuan error 83886179 is "Operation cancelled": the person said no; stop there.
    if any(b"83886179" in v or b"ancel" in v for v in errors):
        raise RuntimeError("PIN dialog cancelled")
    if r.returncode or errors:
        raise DialogUnavailable("PIN dialog could not be shown")
    values = [unquote_to_bytes(v[2:].decode()) for v in r.stdout.splitlines() if v.startswith(b"D ")]
    if len(values) != 1:
        raise RuntimeError("PIN unavailable")
    return values[0].decode()


# Firmware that advertises CTAP PIN/UV protocol 2 but refuses hmac-secret under it: its salt
# parser takes only protocol 1's 32/64-byte encrypted salts (tkey-fido2 7fdf8ea,
# fido2/src/ctap_extensions.c; docs/evidence/TKEY_QEMU_VPN_OPERATIONS_20261119.json). The client
# uses protocol 1 with it, as it already must with Trezor, Ledger and Solo 1, which offer only 1.
# Chosen up front by AAGUID, never as a fallback after a failure.
PIN_UV_PROTOCOL_1_ONLY = {"dbe42d66-22be-4624-8811-972a8e65367e": "Tillitis TKey FIDO2 app"}


def pin_protocols(info):
    """The PIN/UV protocols the client may negotiate with this key."""
    if str(info.aaguid) in PIN_UV_PROTOCOL_1_ONLY:
        return [p for p in info.pin_uv_protocols if p == 1]
    return list(info.pin_uv_protocols)


def eligible(info):
    """Whether a FIDO2 key can hold a vault: `hmac-secret`, and user verification by a
    PIN typed on this computer (`clientPin`) or on the key itself (`uv`, as on a Trezor,
    whose PIN is entered on its own screen). A key with neither is refused."""
    options = info.options or {}
    return "hmac-secret" in (info.extensions or []) and (options.get("clientPin") is True or options.get("uv") is True)


def holds(device, credential_id):
    """Whether `device` holds this credential: a silent lookup (no touch, no PIN, no
    signature kept), which is how a client picks among several keys."""
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2

    try:
        Ctap2(device).get_assertion(
            RP, os.urandom(32), [{"type": "public-key", "id": credential_id}], options={"up": False}
        )
    except CtapError as e:
        if e.code == CtapError.ERR.NO_CREDENTIALS:
            return False
        raise
    return True


def client(credential_id=None, require=None, exclude=None):
    """Open the one eligible hmac-secret FIDO2 device: the one holding `credential_id`
    when several are present, only keys `require(info)` accepts, and never one holding
    the credential `exclude`. A PIN typed on this
    computer comes from `pinentry` and is never retried; a key that verifies on the device
    asks there."""
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction
    from fido2.ctap2.extensions import HmacSecretExtension

    found = []
    for d in CtapHidDevice.list_devices():
        info = Ctap2(d).info
        if eligible(info) and (require is None or require(info)):
            found.append(d)
        else:
            d.close()
    if exclude is not None:
        kept = [d for d in found if not holds(d, exclude)]
        for d in found:
            if d not in kept:
                d.close()
        if found and not kept:
            raise RuntimeError("the only suitable key holds the operator's credential: use a separate key")
        found = kept
    if credential_id is not None and len(found) > 1:
        holding = [d for d in found if holds(d, credential_id)]
        for d in found:
            if d not in holding:
                d.close()
        found = holding
    if len(found) != 1:
        for d in found:
            d.close()
        raise RuntimeError("exactly one hmac-secret key with a PIN (or on-device verification) required")

    class Interaction(UserInteraction):
        attempted = False

        def request_pin(self, permissions, rp_id):
            if self.attempted:
                raise RuntimeError("no repeated PIN guesses")
            self.attempted = True
            return pinentry()

        def prompt_up(self):
            print("Touch your hardware key when it flashes.", flush=True)

        def request_uv(self, permissions, rp_id):
            # The key verifies the user itself (its own PIN pad or screen).
            print("Verify on your hardware key (enter its PIN there if it asks).", flush=True)
            return True

    device = found[0]
    c = Fido2Client(
        device,
        DefaultClientDataCollector("https://" + RP),
        user_interaction=Interaction(),
        extensions=[HmacSecretExtension(allow_hmac_secret=True)],
    )
    allowed = pin_protocols(c._backend.info)  # the client negotiates from this copy of GetInfo
    if allowed != list(c._backend.info.pin_uv_protocols):
        if not allowed:
            device.close()
            raise RuntimeError("this key offers no PIN/UV protocol it can use for hmac-secret")
        c._backend.info = replace(c._backend.info, pin_uv_protocols=allowed)
    return device, c


def enroll(vault):
    """Create a new vault: a non-resident FIDO2 credential (PIN required) with hmac-secret, plus its salt."""
    from fido2.server import Fido2Server

    vault.mkdir(mode=0o700, parents=False, exist_ok=False)
    device, c = client()
    try:
        # No attestation: nothing about the make, model or batch of the key is asked for.
        s = Fido2Server({"id": RP, "name": "ADVANCED VPN"}, attestation="none")
        options, state = s.register_begin(
            {"id": os.urandom(32), "name": "operator", "displayName": "VPN operator"},
            resident_key_requirement="discouraged",
            user_verification="required",
            extensions={"hmacCreateSecret": True},
        )
        if _PROMPT_CANCEL.get() is None:
            response = c.make_credential(replace(options.public_key, timeout=90000))
        else:
            response = c.make_credential(replace(options.public_key, timeout=90000), event=_PROMPT_CANCEL.get())
        auth = s.register_complete(state, response)
        if response.client_extension_results.hmac_create_secret is not True:
            raise RuntimeError("extension unavailable")
        # The credential ID must stay (the key needs it back to sign); the AAGUID (the model)
        # is not needed even here, so it is not kept.
        from fido2.webauthn import Aaguid, AttestedCredentialData

        kept = AttestedCredentialData.create(
            Aaguid(bytes(16)), auth.credential_data.credential_id, auth.credential_data.public_key
        )
        value = dict(schema=1, rp=RP, credential=b64(bytes(kept)), salt=b64(os.urandom(32)), counter=auth.counter)
        atomic(vault / "credential.json", json.dumps(value).encode())
    finally:
        device.close()


# An optional third operator half: a non-exportable ML-DSA-44 FIDO2 credential (COSE -48),
# on keys that offer one (Solo 2's Hacker build). Kept in its own record beside the vault's.
MLDSA44 = -48
PQ_SIGNER = "credential-mldsa44.json"


def offers_mldsa44(info):
    """Whether a key's GetInfo lists ML-DSA-44 (COSE -48) credentials."""
    return any(a.get("alg") == MLDSA44 for a in (info.algorithms or []))


def _pq_signer(vault):
    meta = json.loads(read_private(vault / PQ_SIGNER))
    if meta["schema"] != 1 or meta["rp"] != RP:
        raise ValueError("credential policy mismatch")
    return meta


def enroll_pq_signer(vault, operator_vault):
    """Create the operator's ML-DSA-44 FIDO2 credential in its own vault (PIN + touch), on
    a key that offers ML-DSA-44 (a Solo 2 Hacker) and is NOT the one holding the operator's
    credential: the operator stays on a locked key, and an unlocked one adds only this half.
    Refused unless the key returns exactly ML-DSA-44."""
    from fido2.server import Fido2Server
    from fido2.webauthn import Aaguid, AttestedCredentialData, PublicKeyCredentialParameters, PublicKeyCredentialType

    vault, operator_vault = vault.resolve(), operator_vault.resolve()
    if vault == operator_vault:
        raise ValueError("the ML-DSA-44 credential needs its own vault, apart from the operator's")
    meta = json.loads(read_private(operator_vault / "credential.json"))
    if meta["schema"] != 1 or meta["rp"] != RP:
        raise ValueError("credential policy mismatch")
    operator_credential = AttestedCredentialData(unb64(meta["credential"])).credential_id
    if vault.exists():
        raise ValueError("%s already exists" % vault)
    device, c = client(require=offers_mldsa44, exclude=operator_credential)
    try:
        if holds(device, operator_credential):
            raise RuntimeError("this key holds the operator's credential: use a separate key for ML-DSA-44")
        s = Fido2Server({"id": RP, "name": "ADVANCED VPN"}, attestation="none")
        s.allowed_algorithms = [PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=MLDSA44)]
        options, state = s.register_begin(
            {"id": os.urandom(32), "name": "operator", "displayName": "VPN operator (ML-DSA-44)"},
            resident_key_requirement="discouraged",
            user_verification="required",
        )
        response = c.make_credential(replace(options.public_key, timeout=90000))
        auth = s.register_complete(state, response)
        if auth.credential_data.public_key.ALGORITHM != MLDSA44:
            raise RuntimeError("the key returned another algorithm than ML-DSA-44")
        kept = AttestedCredentialData.create(
            Aaguid(bytes(16)), auth.credential_data.credential_id, auth.credential_data.public_key
        )
        value = dict(schema=1, rp=RP, credential=b64(bytes(kept)), counter=auth.counter)
        vault.mkdir(mode=0o700, parents=False, exist_ok=False)
        atomic(vault / PQ_SIGNER, json.dumps(value).encode())
    finally:
        device.close()


def pq_signer_public(vault):
    """The ML-DSA-44 credential's COSE public key, or None when the vault has none."""
    return public_key_of(_pq_signer(vault)["credential"]) if (vault / PQ_SIGNER).exists() else None


def pq_signer_assertion(vault, message):
    """One PIN + touch: the ML-DSA-44 credential's assertion over SHA-256(message)."""
    from fido2.server import Fido2Server
    from fido2.webauthn import AttestedCredentialData

    meta = _pq_signer(vault)
    credential = AttestedCredentialData(unb64(meta["credential"]))
    device, c = client(credential.credential_id)
    try:
        s = Fido2Server({"id": RP, "name": "ADVANCED VPN"})
        options, state = s.authenticate_begin(
            [credential], user_verification="required", challenge=hashlib.sha256(message).digest()
        )
        if not holds(device, credential.credential_id):
            raise RuntimeError("the connected key does not hold the operator's ML-DSA-44 credential")
        response = c.get_assertion(replace(options.public_key, timeout=90000)).get_response(0)
        s.authenticate_complete(state, [credential], response)
        counter = response.response.authenticator_data.counter
        if (counter or meta["counter"]) and counter <= meta["counter"]:
            raise RuntimeError("counter did not advance")
        meta["counter"] = counter
        atomic(vault / PQ_SIGNER, json.dumps(meta).encode())
        return dict(
            authenticator_data=b64(bytes(response.response.authenticator_data)),
            client_data=b64(bytes(response.response.client_data)),
            signature=b64(bytes(response.response.signature)),
        )
    finally:
        device.close()


def hardware_secret(vault):
    """The vault's hmac-secret and metadata (one PIN + touch)."""
    secret, meta, _ = hardware_assertion(vault)
    return secret, meta


def hardware_secrets(vault, salt2):
    """One PIN + touch, two hmac-secrets: the vault's (its stored salt) and one for `salt2`
    (32 bytes), which a deniable store's layer derives from its passphrase, so nothing on
    disk counts the layers (tools/padstore.py). Returns (secret, second, meta)."""
    secret, meta, _, second = hardware_assertion(vault, salt2=salt2)
    return secret, second, meta


def hardware_assertion(vault, message=None, salt2=None):
    """One PIN+touch: the hmac-secret (for sealed keys) and, when `message` is given,
    a non-exportable credential signature whose challenge is SHA-256(message). With
    `salt2`, a fourth value: the hmac-secret for that salt (see hardware_secrets)."""
    if salt2 is not None and len(salt2) != 32:
        raise ValueError("an hmac-secret salt is 32 bytes")
    from fido2.server import Fido2Server
    from fido2.webauthn import AttestedCredentialData

    meta = json.loads(read_private(vault / "credential.json"))
    if meta["schema"] != 1 or meta["rp"] != RP:
        raise ValueError("credential policy mismatch")
    credential = AttestedCredentialData(unb64(meta["credential"]))
    device, c = client(credential.credential_id)
    try:
        s = Fido2Server({"id": RP, "name": "ADVANCED VPN"})
        options, state = s.authenticate_begin(
            [credential],
            user_verification="required",
            challenge=hashlib.sha256(message).digest() if message is not None else None,
            extensions={
                "hmacGetSecret": dict(salt1=unb64(meta["salt"]), **({} if salt2 is None else {"salt2": salt2}))
            },
        )
        if _PROMPT_CANCEL.get() is None:
            response = c.get_assertion(replace(options.public_key, timeout=90000)).get_response(0)
        else:
            response = c.get_assertion(
                replace(options.public_key, timeout=90000), event=_PROMPT_CANCEL.get()
            ).get_response(0)
        s.authenticate_complete(state, [credential], response)
        assertion = dict(
            authenticator_data=b64(bytes(response.response.authenticator_data)),
            client_data=b64(bytes(response.response.client_data)),
            signature=b64(bytes(response.response.signature)),
        )
        counter = response.response.authenticator_data.counter
        if (counter or meta["counter"]) and counter <= meta["counter"]:
            raise RuntimeError("counter did not advance")
        ext = response.client_extension_results.hmac_get_secret
        if ext is None or len(ext.output1) != 32:
            raise RuntimeError("hardware secret missing")
        if salt2 is not None and (ext.output2 is None or len(ext.output2) != 32):
            raise RuntimeError("second hardware secret missing")
        meta["counter"] = counter
        atomic(vault / "credential.json", json.dumps(meta).encode())
        if salt2 is not None:
            return ext.output1, meta, assertion, ext.output2
        return ext.output1, meta, assertion
    finally:
        device.close()


def public_key_of(credential_b64):
    """The one thing a verifier needs of a credential: its COSE public key (CBOR), alone.
    Nothing about the device has a place in it: no AAGUID (the make and model), no
    credential ID, no attestation. It is built from the key, not scrubbed from a record."""
    from fido2 import cbor
    from fido2.webauthn import AttestedCredentialData

    return b64(cbor.encode(dict(AttestedCredentialData(unb64(credential_b64)).public_key)))


def credential_public(vault):
    """What this device publishes about its credential: the COSE public key only."""
    meta = json.loads(read_private(vault / "credential.json"))
    if meta["schema"] != 1 or meta["rp"] != RP:
        raise ValueError("credential policy mismatch")
    return public_key_of(meta["credential"])


def _verifying_key(public_b64):
    """The COSE key from a published public key, or (bundles signed before v0.10) from a
    full credential record, of which only the key is read."""
    from fido2 import cbor
    from fido2.cose import CoseKey
    from fido2.webauthn import AttestedCredentialData

    raw = unb64(public_b64)
    try:
        key = cbor.decode(raw)
    except Exception:  # not a CBOR map: the older full credential record
        key = None
    if isinstance(key, dict):
        return CoseKey.parse(key)
    return AttestedCredentialData(raw).public_key


def verify_assertion(public_b64, message, assertion):
    """Offline WebAuthn assertion check: RP, user presence AND verification (PIN),
    challenge == SHA-256(message), signature by the credential's public key."""
    from fido2.webauthn import AuthenticatorData, CollectedClientData

    public = _verifying_key(public_b64)
    auth = AuthenticatorData(unb64(assertion["authenticator_data"]))
    client_data = CollectedClientData(unb64(assertion["client_data"]))
    if auth.rp_id_hash != hashlib.sha256(RP.encode()).digest():
        raise ValueError("wrong relying party")
    if not (auth.is_user_present() and auth.is_user_verified()):
        raise ValueError("PIN and touch required")
    if client_data.type != "webauthn.get" or client_data.origin != "https://" + RP:
        raise ValueError("wrong client data")
    if client_data.challenge != hashlib.sha256(message).digest():
        raise ValueError("signature is for another message")
    public.verify(bytes(auth) + client_data.hash, unb64(assertion["signature"]))


# Hybrid X25519 + ML-KEM-768 public-key encryption (both secrets feed HKDF).
KEM_PUBLIC = 32 + 1184


def kem_keypair():
    """A new hybrid X25519 + ML-KEM-768 key pair: (96-byte private, public)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

    a = x25519.X25519PrivateKey.generate()
    b = mlkem.MLKEM768PrivateKey.generate()
    raw = serialization.Encoding.Raw
    private = (
        a.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()) + b.private_bytes_raw()
    )
    public = a.public_key().public_bytes(raw, serialization.PublicFormat.Raw) + b.public_key().public_bytes(
        raw, serialization.PublicFormat.Raw
    )
    return private, public


def _kem_key(classical, pq, context, eph, ct, recipient):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"advanced-vpn/hybrid-kem/v1|" + context + b"|" + hashlib.sha256(eph + ct + recipient).digest(),
    ).derive(classical + pq)


def kem_seal(recipient, plaintext, context):
    """Encrypt `plaintext` to a hybrid public key, bound to `context` (both shared secrets feed the KDF)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

    if len(recipient) != KEM_PUBLIC:
        raise ValueError("wrong recipient key")
    e = x25519.X25519PrivateKey.generate()
    eph = e.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    classical = e.exchange(x25519.X25519PublicKey.from_public_bytes(recipient[:32]))
    pq, ct = mlkem.MLKEM768PublicKey.from_public_bytes(recipient[32:]).encapsulate()
    nonce = os.urandom(12)
    key = _kem_key(classical, pq, context, eph, ct, recipient)
    return dict(
        schema=1,
        ephemeral=b64(eph),
        mlkem=b64(ct),
        nonce=b64(nonce),
        ciphertext=b64(AESGCM(key).encrypt(nonce, plaintext, context)),
    )


def kem_open(private, value, context):
    """Decrypt a hybrid envelope with the private key; fails on any context or key mismatch."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

    if value.get("schema") != 1 or len(private) != 96:
        raise ValueError("wrong hybrid envelope")
    a = x25519.X25519PrivateKey.from_private_bytes(private[:32])
    b = mlkem.MLKEM768PrivateKey.from_seed_bytes(private[32:])
    raw = serialization.Encoding.Raw
    recipient = a.public_key().public_bytes(raw, serialization.PublicFormat.Raw) + b.public_key().public_bytes(
        raw, serialization.PublicFormat.Raw
    )
    eph = unb64(value["ephemeral"])
    ct = unb64(value["mlkem"])
    key = _kem_key(
        a.exchange(x25519.X25519PublicKey.from_public_bytes(eph)), b.decapsulate(ct), context, eph, ct, recipient
    )
    return AESGCM(key).decrypt(unb64(value["nonce"]), unb64(value["ciphertext"]), context)


def tpm2_usable():
    """True only when systemd can really use the TPM2 (device, driver and TSS2 libraries)."""
    try:
        exe = trusted_exe("systemd-analyze")
    except FileNotFoundError:
        return False
    return subprocess.run([exe, "has-tpm2"], capture_output=True, timeout=15).returncode == 0


def creds_encrypt(name, data, path, key="host"):
    """At-rest protection without a hardware token. `key` is chosen once at request
    time: 'host+tpm2' when a usable TPM2 exists (fails loudly if it later does not),
    otherwise 'host'. Never 'auto', which silently drops the TPM when libraries are
    missing. The credential name is authenticated."""
    if key not in ("host", "host+tpm2"):
        raise ValueError("unsupported credential key")
    r = subprocess.run(
        [trusted_exe("systemd-creds"), "encrypt", "--with-key=" + key, "--name=" + name, "-", str(path)],
        input=data,
        capture_output=True,
        timeout=30,
    )
    if r.returncode:
        raise RuntimeError("systemd-creds encrypt failed")
    path.chmod(0o600)


def creds_decrypt(name, path):
    """Decrypt a systemd credential `name` from `path`."""
    r = subprocess.run(
        [trusted_exe("systemd-creds"), "decrypt", "--name=" + name, str(path), "-"], capture_output=True, timeout=30
    )
    if r.returncode:
        raise RuntimeError("systemd-creds decrypt failed")
    return r.stdout


def b64(value):
    """Base64-encode bytes to str."""
    return base64.b64encode(value).decode()


def unb64(value):
    """Strictly decode base64 (rejects non-alphabet characters)."""
    return base64.b64decode(value, validate=True)


def aad(role, cert, meta):
    """Associated data binding an envelope to its role, certificate and vault credential."""
    return json.dumps(
        dict(
            schema=1,
            domain="advanced-vpn/key-envelope",
            rp=RP,
            role=role,
            certificate_sha256=hashlib.sha256(cert).hexdigest(),
            credential_sha256=hashlib.sha256(unb64(meta["credential"])).hexdigest(),
        ),
        sort_keys=True,
    ).encode()


def wrapping_key(secret, meta):
    """Derive the AES-256-GCM wrapping key from the hmac-secret and the vault salt."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=unb64(meta["salt"]), info=b"advanced-vpn/key-envelope/v1"
    ).derive(secret)


def seal_bytes(secret, meta, role, cert, key):
    """Seal `key` under the hardware secret, bound to `role` and `cert`."""
    nonce = os.urandom(12)
    header = aad(role, cert, meta)
    return dict(
        schema=1,
        aad=b64(header),
        nonce=b64(nonce),
        ciphertext=b64(AESGCM(wrapping_key(secret, meta)).encrypt(nonce, key, header)),
    )


def open_bytes(secret, meta, role, cert, value):
    """Open a sealed key; fails unless role, certificate and vault all match."""
    header = aad(role, cert, meta)
    if value["schema"] != 1 or unb64(value["aad"]) != header:
        raise ValueError("envelope binding mismatch")
    return AESGCM(wrapping_key(secret, meta)).decrypt(unb64(value["nonce"]), unb64(value["ciphertext"]), header)


def memory_fd(key):
    """An immutable, sealed memfd holding `key`, for handing secrets to the data plane without files."""
    # Some portable Python builds omit the os wrapper despite Linux/glibc support.
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    create = libc.memfd_create
    create.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    create.restype = ctypes.c_int
    fd = create(b"avpn-key", 3)  # Linux MFD_CLOEXEC | MFD_ALLOW_SEALING
    if fd < 0:
        raise OSError(ctypes.get_errno(), "memfd_create refused")
    os.write(fd, key)
    os.lseek(fd, 0, os.SEEK_SET)
    fcntl.fcntl(fd, F_ADD_SEALS, 15)  # SEAL_SEAL | SHRINK | GROW | WRITE
    os.set_inheritable(fd, True)
    return fd


MESH_ROLE = "mesh-operator"


def mesh_seal(vault, key_path, cert_path, envelope_path, remove_plaintext=False):
    """Seal the mesh operator signing key under the hardware credential.

    The envelope is bound to role 'mesh-operator' and to the operator public
    key as its certificate, exactly like the role envelopes of `seal`: the key
    can only come back out of the same vault, for the same role, against the
    same public key. Refuses to overwrite an existing envelope."""
    if envelope_path.exists():
        raise ValueError("envelope exists")
    secret, meta = hardware_secret(vault)
    cert = read_private(cert_path)
    key = read_private(key_path, 16384)
    envelope = seal_bytes(secret, meta, MESH_ROLE, cert, key)
    if open_bytes(secret, meta, MESH_ROLE, cert, envelope) != key:
        raise RuntimeError("envelope verification failed")
    atomic(envelope_path, json.dumps(envelope).encode())
    if remove_plaintext:
        key_path.unlink()


def mesh_sign(vault, envelope_path, cert_path, descriptor_path, role=None):
    """One PIN + touch: unseal the mesh operator key in memory, sign the
    canonical descriptor, and print the signed descriptor as the last stdout
    line (the avpn helper JSON contract).

    Also emits the FIDO2 assertion over SHA-256(canonical descriptor): the
    hardware-bound membership proof (a member IS their device - Nitrokey
    preferred, any hmac-secret token works), verifiable offline with
    verify_assertion(). The key is scrubbed best-effort before returning."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    from mesh import canonical

    envelope = json.loads(read_private(envelope_path))
    cert = read_private(cert_path)
    descriptor = json.loads(read_private(descriptor_path))
    message = canonical(descriptor)
    secret, meta, assertion = hardware_assertion(vault, message)
    # The operator's own key (`avpn init --vault`, role operator-mldsa65) or a separately
    # sealed mesh key (mesh-seal, role mesh-operator).
    if role not in (None, MESH_ROLE, "operator-mldsa65"):
        raise ValueError("unknown mesh signing role")
    key = open_bytes(secret, meta, role or MESH_ROLE, cert, envelope)
    try:
        # The sealed key is the 32-byte ML-DSA-65 seed, or a PKCS#8 key.
        if len(key) == 32:
            priv = MLDSA65PrivateKey.from_seed_bytes(key)
        else:
            priv = serialization.load_der_private_key(key, password=None)
            if not isinstance(priv, MLDSA65PrivateKey):
                raise ValueError("the mesh operator key is not ML-DSA-65")
        descriptor["signature"] = b64(priv.sign(message))
    finally:
        key = b"\x00" * len(key)  # best-effort scrub; CPython gives no guarantee
    print(
        json.dumps(
            {
                "descriptor": descriptor,
                "public_key": public_key_of(meta["credential"]),
                "assertion": assertion,
                "challenge_sha256": hashlib.sha256(message).hexdigest(),
            }
        )
    )


def main():
    """Command-line entry point for vault and key-envelope operations."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    import ctypes

    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["enroll", "enroll-pq-signer", "seal", "run", "mesh-seal", "mesh-sign"])
    p.add_argument("--vault", type=Path, required=True)
    p.add_argument("--operator-vault", type=Path, help="with enroll-pq-signer: the operator's (locked key's) vault")
    p.add_argument("--config", type=Path)
    p.add_argument("--binary", type=Path)
    p.add_argument("--check", action="store_true")
    p.add_argument("--remove-plaintext", action="store_true")
    p.add_argument("--recovery-recipient", type=Path)
    p.add_argument("--verify-recovery-with", type=Path)
    p.add_argument("--age", type=Path)
    p.add_argument("--key", type=Path, help="with mesh-seal: the operator signing key to seal")
    p.add_argument("--cert", type=Path, help="with mesh-seal/mesh-sign: the operator public key")
    p.add_argument("--envelope", type=Path, help="with mesh-seal/mesh-sign: the sealed-key envelope")
    p.add_argument("--descriptor", type=Path, help="with mesh-sign: the descriptor JSON to sign")
    p.add_argument(
        "--role", help="with mesh-sign: the envelope's role, operator-mldsa65 (avpn init) or mesh-operator (mesh-seal)"
    )
    a = p.parse_args()
    if a.action == "enroll":
        enroll(a.vault)
        print("New hardware credential enrolled; existing credentials and PIN unchanged.")
        return
    if a.action == "enroll-pq-signer":
        if a.operator_vault is None:
            raise ValueError("enroll-pq-signer needs --operator-vault (the locked key's vault)")
        enroll_pq_signer(a.vault, a.operator_vault)
        print("ML-DSA-44 operator credential added: operator signatures now carry three halves.")
        return
    if a.action == "mesh-seal":
        if not (a.key and a.cert and a.envelope):
            raise ValueError("mesh-seal needs --key, --cert and --envelope")
        mesh_seal(a.vault, a.key, a.cert, a.envelope, a.remove_plaintext)
        print("Mesh operator key sealed under the hardware credential.")
        return
    if a.action == "mesh-sign":
        if not (a.envelope and a.cert and a.descriptor):
            raise ValueError("mesh-sign needs --envelope, --cert and --descriptor")
        mesh_sign(a.vault, a.envelope, a.cert, a.descriptor, a.role)
        return
    if not a.config:
        raise ValueError("configuration required")
    config = json.loads(read_private(a.config))
    identities = {r: config[r] for r in ["outer", "inner", "wireguard"] if config.get(r)}
    if not identities:
        raise ValueError("no identities")
    if a.action == "seal" and (not a.age or not a.recovery_recipient):
        raise ValueError("explicit age binary and recovery recipient required")
    if a.action == "seal" and a.remove_plaintext and not a.verify_recovery_with:
        raise ValueError("recovery decryption verification required before removing plaintext")
    keys = {r: read_private(Path(i["key"]), 16384) for r, i in identities.items()} if a.action == "seal" else {}
    if a.action == "seal":
        for role in identities:
            if a.config.with_name(role + "-key.sealed.json").exists():
                raise ValueError("envelope exists")
        if a.config.with_name(a.config.stem + ".recovery.age").exists():
            raise ValueError("recovery file exists")
    secret, meta = hardware_secret(a.vault)
    if a.action == "seal":
        recovery = a.config.with_name(a.config.stem + ".recovery.age")
        if recovery.exists():
            raise ValueError("recovery file exists")
        # Encrypted recovery is written and age authenticates it on later recovery; no identity is uploaded.
        body = json.dumps(dict(schema=1, keys={r: b64(k) for r, k in keys.items()})).encode()
        subprocess.run(
            [str(a.age), "-R", str(a.recovery_recipient), "-o", str(recovery)],
            input=body,
            check=True,
            capture_output=True,
            timeout=30,
        )
        if a.verify_recovery_with:
            verified = subprocess.run(
                [str(a.age), "-d", "-i", str(a.verify_recovery_with), str(recovery)],
                check=True,
                capture_output=True,
                timeout=30,
            )
            if verified.stdout != body:
                raise RuntimeError("recovery did not verify")
    if a.action == "seal":
        for role, i in identities.items():
            path = a.config.with_name(role + "-key.sealed.json")
            if path.exists():
                raise ValueError("envelope exists")
            envelope = seal_bytes(secret, meta, role, read_private(Path(i["cert"])), keys[role])
            if open_bytes(secret, meta, role, read_private(Path(i["cert"])), envelope) != keys[role]:
                raise RuntimeError("envelope verification failed")
            atomic(path, json.dumps(envelope).encode())
        if a.remove_plaintext:
            for i in identities.values():
                Path(i["key"]).unlink()
        print(
            "Hardware envelopes verified; encrypted recovery retained. Flash wear/old-block erasure is not guaranteed."
        )
    else:
        if not a.binary or not a.binary.is_absolute():
            raise ValueError("absolute binary path required")
        fds = []
        command = [str(a.binary), "--config", str(a.config)]
        try:
            for role, i in identities.items():
                value = json.loads(read_private(a.config.with_name(role + "-key.sealed.json")))
                key = open_bytes(secret, meta, role, read_private(Path(i["cert"])), value)
                fd = memory_fd(key)
                fds.append(fd)
                command += ["--key-fd", role + "=" + str(fd)]
            if a.check:
                command += ["--check"]
            os.execv(command[0], command)
        finally:
            for fd in fds:
                os.close(fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(
            "Hardware operation refused: " + type(e).__name__ + ". No reset or software fallback.",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1) from None  # no key-handling details on stderr
