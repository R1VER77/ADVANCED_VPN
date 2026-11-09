#!/usr/bin/env python3
"""Nitrokey/FIDO2 envelopes and memory-only private-key handoff.

No PIN enrollment/reset, secret CLI arguments or software fallback. Requires a
preconfigured FIDO2 PIN. Keeps long-lived private material off the relay host.
"""

import argparse
import base64
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
    finally:
        if tmp.exists():
            tmp.unlink()


ASK_PASSWORD = "/usr/bin/systemd-ask-password"
PINENTRY = "/usr/bin/pinentry-gnome3"
PIN_PROMPT = "ADVANCED VPN: FIDO2 PIN, then touch the Nitrokey when it flashes"


def pinentry():
    """PIN source, in order: a terminal (no-echo prompt); a desktop session
    (pinentry-gnome3); a systemd service without a desktop, e.g. the whole-device
    unit at boot (systemd's password agents: boot console or `avpn unlock`).
    Anything else is refused; there is no unattended bypass.

    Desktop apps also run inside systemd scopes (INVOCATION_ID is set there), so
    the desktop check must come before the service check."""
    import sys

    if sys.stdin.isatty():
        import getpass

        value = getpass.getpass("ADVANCED VPN: FIDO2 PIN (cannot be reset or changed here): ")
        if not value:
            raise RuntimeError("PIN unavailable")
        return value
    if (os.environ.get("WAYLAND_DISPLAY") or os.environ.get("DISPLAY")) and Path(PINENTRY).exists():
        return desktop_pinentry()
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


def desktop_pinentry():
    """Ask for the FIDO2 PIN with the desktop pinentry dialog; never caches it."""
    message = "SETTITLE ADVANCED VPN hardware authorization\nSETDESC Enter the existing FIDO2 PIN. This operation cannot reset or change it.\nSETPROMPT FIDO2 PIN:\nGETPIN\nBYE\n"
    r = subprocess.run([PINENTRY], input=message.encode(), capture_output=True, timeout=180)
    if r.returncode or any(v.startswith(b"ERR ") for v in r.stdout.splitlines()):
        raise RuntimeError("PIN dialog stopped")
    values = [unquote_to_bytes(v[2:].decode()) for v in r.stdout.splitlines() if v.startswith(b"D ")]
    if len(values) != 1:
        raise RuntimeError("PIN unavailable")
    return values[0].decode()


def client():
    """Open the one PIN-configured hmac-secret FIDO2 device; PIN via `pinentry`, never retried."""
    from fido2.hid import CtapHidDevice
    from fido2.ctap2 import Ctap2
    from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction
    from fido2.ctap2.extensions import HmacSecretExtension

    found = []
    for d in CtapHidDevice.list_devices():
        info = Ctap2(d).info
        if "hmac-secret" in info.extensions and info.options.get("clientPin") is True:
            found.append(d)
        else:
            d.close()
    if len(found) != 1:
        for d in found:
            d.close()
        raise RuntimeError("exactly one PIN-configured hmac-secret device required")

    class Interaction(UserInteraction):
        attempted = False

        def request_pin(self, permissions, rp_id):
            if self.attempted:
                raise RuntimeError("no repeated PIN guesses")
            self.attempted = True
            return pinentry()

        def prompt_up(self):
            print("Touch your hardware key when it flashes.", flush=True)

    device = found[0]
    return device, Fido2Client(
        device,
        DefaultClientDataCollector("https://" + RP),
        user_interaction=Interaction(),
        extensions=[HmacSecretExtension(allow_hmac_secret=True)],
    )


def enroll(vault):
    """Create a new vault: a non-resident FIDO2 credential (PIN required) with hmac-secret, plus its salt."""
    from fido2.server import Fido2Server

    vault.mkdir(mode=0o700, parents=False, exist_ok=False)
    device, c = client()
    try:
        s = Fido2Server({"id": RP, "name": "ADVANCED VPN"})
        options, state = s.register_begin(
            {"id": os.urandom(32), "name": "operator", "displayName": "VPN operator"},
            resident_key_requirement="discouraged",
            user_verification="required",
            extensions={"hmacCreateSecret": True},
        )
        response = c.make_credential(replace(options.public_key, timeout=90000))
        auth = s.register_complete(state, response)
        if response.client_extension_results.hmac_create_secret is not True:
            raise RuntimeError("extension unavailable")
        value = dict(
            schema=1, rp=RP, credential=b64(bytes(auth.credential_data)), salt=b64(os.urandom(32)), counter=auth.counter
        )
        atomic(vault / "credential.json", json.dumps(value).encode())
    finally:
        device.close()


def hardware_secret(vault):
    """The vault's hmac-secret and metadata (one PIN + touch)."""
    secret, meta, _ = hardware_assertion(vault)
    return secret, meta


def hardware_assertion(vault, message=None):
    """One PIN+touch: the hmac-secret (for sealed keys) and, when `message` is given,
    a non-exportable credential signature whose challenge is SHA-256(message)."""
    from fido2.server import Fido2Server
    from fido2.webauthn import AttestedCredentialData

    meta = json.loads(read_private(vault / "credential.json"))
    if meta["schema"] != 1 or meta["rp"] != RP:
        raise ValueError("credential policy mismatch")
    credential = AttestedCredentialData(unb64(meta["credential"]))
    device, c = client()
    try:
        s = Fido2Server({"id": RP, "name": "ADVANCED VPN"})
        options, state = s.authenticate_begin(
            [credential],
            user_verification="required",
            challenge=hashlib.sha256(message).digest() if message is not None else None,
            extensions={"hmacGetSecret": {"salt1": unb64(meta["salt"])}},
        )
        response = c.get_assertion(replace(options.public_key, timeout=90000)).get_response(0)
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
        meta["counter"] = counter
        atomic(vault / "credential.json", json.dumps(meta).encode())
        return ext.output1, meta, assertion
    finally:
        device.close()


def credential_public(vault):
    """Public part of the vault credential (contains the COSE public key)."""
    meta = json.loads(read_private(vault / "credential.json"))
    if meta["schema"] != 1 or meta["rp"] != RP:
        raise ValueError("credential policy mismatch")
    return meta["credential"]


def verify_assertion(credential_b64, message, assertion):
    """Offline WebAuthn assertion check: RP, user presence AND verification (PIN),
    challenge == SHA-256(message), signature by the credential's public key."""
    from fido2.webauthn import AttestedCredentialData, AuthenticatorData, CollectedClientData

    public = AttestedCredentialData(unb64(credential_b64)).public_key
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


def main():
    """Command-line entry point for vault and key-envelope operations."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    import ctypes

    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["enroll", "seal", "run"])
    p.add_argument("--vault", type=Path, required=True)
    p.add_argument("--config", type=Path)
    p.add_argument("--binary", type=Path)
    p.add_argument("--check", action="store_true")
    p.add_argument("--remove-plaintext", action="store_true")
    p.add_argument("--recovery-recipient", type=Path)
    p.add_argument("--verify-recovery-with", type=Path)
    p.add_argument("--age", type=Path)
    a = p.parse_args()
    if a.action == "enroll":
        enroll(a.vault)
        print("New hardware credential enrolled; existing credentials and PIN unchanged.")
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
