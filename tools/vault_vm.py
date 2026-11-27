"""Tor-Browser-style 3-tier security level detection and hardwareless `vault-vm` key protection.

Provides a seamless, user-friendly setup experience across three clear security tiers:
1. `standard` — Hardwareless Vault-VM / Isolated Software Vault (zero dongle required;
   scrypt + AES-256-GCM encrypted vault, short-lived undumpable `session_signer` or Qubes
   `qrexec` / KVM `AF_UNIX` signing VM boundary; protects long-term identities against
   VPN process/VM compromise without hardware PIN retry lockout).
2. `safer` — Hardware-Bound Sessions (auto-detects connected Nitrokey / FIDO2 hmac-secret
   key; physical PIN + touch required for every session and shared-credit withdrawal).
3. `safest` — Split Vault-VM + Hardware Token + Strict Hardening (requires hardware key
   plus VM isolation: Qubes `qrexec` or KVM `AF_UNIX` signing VM, strict NTS, constant-rate
   wire-clock opt-in, and ephemeral browser isolation).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import keyguard


VAULT_VM_SCHEMA = 1
VAULT_VM_AAD = b"cypherpunk-vpn/vault-vm/v1"
VAULT_VM_SCRYPT_N = 1 << 17
VAULT_VM_SCRYPT_R = 8
VAULT_VM_SCRYPT_P = 1
MIN_PASSPHRASE_LEN = 12


class VaultVmError(ValueError):
    """Raised when a vault-vm operation or tier requirement fails closed."""


@dataclass(frozen=True)
class SecurityEnvironment:
    """Detected local hardware and VM isolation capabilities (no device serials retained)."""

    hardware_keys: tuple[str, ...]
    tpm2_usable: bool
    qubes_available: bool
    kvm_available: bool
    signing_vm_configured: bool

    @property
    def has_hardware_key(self) -> bool:
        """Return True if at least one supported FIDO2/Nitrokey device is connected."""
        return len(self.hardware_keys) > 0

    @property
    def has_vm_isolation(self) -> bool:
        """Return True if Qubes qrexec, KVM, or an explicit signing VM transport is present."""
        return self.qubes_available or self.kvm_available or self.signing_vm_configured


def detect_hardware_keys() -> tuple[str, ...]:
    """Probe connected FIDO2/CTAP2 USB HID keys without recording serials or AAGUIDs."""
    try:
        from fido2.hid import CtapHidDevice

        found = []
        for dev in CtapHidDevice.list_devices():
            label = getattr(dev.descriptor, "product_name", None) or "FIDO2 hardware key"
            found.append(str(label).strip() or "FIDO2 hardware key")
        return tuple(found)
    except Exception:
        return ()


def detect_security_environment() -> SecurityEnvironment:
    """Inspect local hardware keys, TPM2, Qubes qrexec, and KVM availability."""
    hw = detect_hardware_keys()
    try:
        tpm2 = bool(keyguard.tpm2_usable())
    except Exception:
        tpm2 = False
    qubes = Path("/etc/qubes-release").exists() and Path("/usr/bin/qrexec-client-vm").exists()
    kvm = Path("/dev/kvm").exists()
    vm_env = bool(os.environ.get("CPVPN_SIGNING_VM", "").strip())
    return SecurityEnvironment(
        hardware_keys=hw,
        tpm2_usable=tpm2,
        qubes_available=qubes,
        kvm_available=kvm,
        signing_vm_configured=vm_env,
    )


def evaluate_tiers(env: SecurityEnvironment) -> dict:
    """Evaluate all three security tiers against `env` and choose the strongest seamless recommendation."""
    standard = {
        "id": "standard",
        "name": "Standard (Hardwareless Vault-VM)",
        "available": True,
        "requires_hardware": False,
        "protection_mode": "vault-vm",
        "transport": "qrexec" if env.qubes_available else "local-isolated",
        "summary": "No hardware token required. Long-term keys stay sealed in an isolated vault and never enter VPN daemons.",
        "boundary": "Protects against VPN process/VM compromise; no hardware-enforced PIN retry lockout against offline disk seizure.",
        "missing": [],
    }
    safer_missing = [] if env.has_hardware_key else ["Connect a supported Nitrokey 3 or FIDO2 hmac-secret key"]
    safer = {
        "id": "safer",
        "name": "Safer (Hardware-Bound Sessions)",
        "available": env.has_hardware_key,
        "requires_hardware": True,
        "protection_mode": "nitrokey",
        "transport": "local-signer",
        "summary": "Physical Nitrokey/FIDO2 PIN + touch required for every session and shared credit withdrawal.",
        "boundary": "Defeats offline disk theft and silent background signing; local CTAP PIN channel uses P-256 per CTAP 2.3.",
        "missing": safer_missing,
    }
    safest_missing = list(safer_missing)
    if not env.has_vm_isolation:
        safest_missing.append("Requires Qubes OS qrexec, KVM (/dev/kvm), or CPVPN_SIGNING_VM isolation")
    safest = {
        "id": "safest",
        "name": "Safest (Split Vault-VM + Hardware Token + Strict Hardening)",
        "available": env.has_hardware_key and env.has_vm_isolation,
        "requires_hardware": True,
        "protection_mode": "nitrokey",
        "transport": "qrexec" if env.qubes_available else ("unix-vm" if env.has_vm_isolation else "unavailable"),
        "summary": "Hardware key attached only to an offline signing VM, plus strict NTS, constant-rate wire clock, and ephemeral browser profiles.",
        "boundary": "Defeats VPN-VM root compromise, offline disk theft, and silent signing; hypervisor/dom0 remains in trust boundary.",
        "missing": safest_missing,
    }
    recommended = "safest" if safest["available"] else ("safer" if safer["available"] else "standard")
    return {
        "recommended": recommended,
        "detected": {
            "hardware_keys_count": len(env.hardware_keys),
            "hardware_keys": list(env.hardware_keys),
            "tpm2_usable": env.tpm2_usable,
            "qubes_available": env.qubes_available,
            "kvm_available": env.kvm_available,
            "signing_vm_configured": env.signing_vm_configured,
        },
        "tiers": [standard, safer, safest],
    }


def select_tier(tier_id: str, env: SecurityEnvironment | None = None) -> dict:
    """Validate that `tier_id` (`standard`, `safer`, `safest`) is supported on this host; fail closed otherwise."""
    report = evaluate_tiers(env or detect_security_environment())
    by_id = {t["id"]: t for t in report["tiers"]}
    if tier_id not in by_id:
        raise VaultVmError(f"unknown security tier {tier_id!r}; choose standard, safer, or safest")
    chosen = by_id[tier_id]
    if not chosen["available"]:
        raise VaultVmError(f"security tier {tier_id!r} unavailable: {'; '.join(chosen['missing'])}")
    return chosen


def _derive_kek(passphrase: str, salt: bytes, *, n: int = VAULT_VM_SCRYPT_N) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE_LEN:
        raise VaultVmError(f"vault passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
    raw = bytearray(passphrase.encode("utf-8"))
    try:
        return Scrypt(salt=salt, length=32, n=n, r=VAULT_VM_SCRYPT_R, p=VAULT_VM_SCRYPT_P).derive(bytes(raw))
    finally:
        raw[:] = bytes(len(raw))


class VaultVmStore:
    """Hardwareless isolated software vault sealing master secret + Ed25519 session-consent key."""

    @staticmethod
    def enroll(vault_dir: Path, passphrase: str, *, scrypt_n: int = VAULT_VM_SCRYPT_N) -> dict:
        """Create a new passphrase-sealed software vault inside `vault_dir` (0700/0600)."""
        vault_dir = Path(vault_dir)
        vault_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(vault_dir, 0o700)
        vault_file = vault_dir / "vault-vm.json"
        if os.path.lexists(vault_file):
            raise VaultVmError("vault-vm already exists; refusing to overwrite")
        salt = os.urandom(32)
        nonce = os.urandom(12)
        master_secret = os.urandom(32)
        consent_priv = ed25519.Ed25519PrivateKey.generate()
        consent_priv_raw = consent_priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        consent_pub_raw = consent_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        plaintext = bytearray(
            json.dumps(
                {
                    "secret": base64.b64encode(master_secret).decode("ascii"),
                    "consent_private": base64.b64encode(consent_priv_raw).decode("ascii"),
                },
                separators=(",", ":"),
            ).encode("utf-8")
        )
        kek = bytearray(_derive_kek(passphrase, salt, n=scrypt_n))
        try:
            ct = AESGCM(bytes(kek)).encrypt(nonce, bytes(plaintext), VAULT_VM_AAD)
        finally:
            plaintext[:] = bytes(len(plaintext))
            kek[:] = bytes(len(kek))
        meta = {
            "schema": VAULT_VM_SCHEMA,
            "mode": "vault-vm",
            "kdf": "scrypt",
            "scrypt_n": scrypt_n,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ct).decode("ascii"),
            "consent_public": base64.b64encode(consent_pub_raw).decode("ascii"),
            "credential": base64.b64encode(hashlib.sha256(consent_pub_raw).digest()[:16]).decode("ascii"),
            "created": int(time.time()),
        }
        keyguard.atomic(vault_file, json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))
        return meta

    @staticmethod
    def authorize_session(vault_dir: Path, statement: bytes, passphrase: str) -> tuple[bytes, dict, dict]:
        """Unseal `vault-vm.json`, sign `statement` with the vault Ed25519 key, and return `(secret, meta, assertion)`."""
        vault_file = Path(vault_dir) / "vault-vm.json"
        doc = json.loads(keyguard.read_private(vault_file))
        if doc.get("schema") != VAULT_VM_SCHEMA or doc.get("mode") != "vault-vm":
            raise VaultVmError("invalid vault-vm format")
        salt = base64.b64decode(doc["salt"], validate=True)
        nonce = base64.b64decode(doc["nonce"], validate=True)
        ct = base64.b64decode(doc["ciphertext"], validate=True)
        scrypt_n = int(doc.get("scrypt_n", VAULT_VM_SCRYPT_N))
        kek = bytearray(_derive_kek(passphrase, salt, n=scrypt_n))
        plaintext = bytearray()
        try:
            plaintext.extend(AESGCM(bytes(kek)).decrypt(nonce, ct, VAULT_VM_AAD))
            inner = json.loads(plaintext.decode("utf-8"))
            secret = base64.b64decode(inner["secret"], validate=True)
            consent_priv = ed25519.Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(inner["consent_private"], validate=True)
            )
            sig = consent_priv.sign(b"cpvpn/vault-vm-consent/v1\0" + hashlib.sha3_512(statement).digest())
        except VaultVmError:
            raise
        except Exception:
            raise VaultVmError("incorrect vault passphrase or corrupted vault-vm") from None
        finally:
            kek[:] = bytes(len(kek))
            plaintext[:] = bytes(len(plaintext))
        assertion = {
            "mode": "vault-vm",
            "consent_public": doc["consent_public"],
            "signature": base64.b64encode(sig).decode("ascii"),
        }
        return secret, doc, assertion

    @staticmethod
    def verify_assertion(consent_public_b64: str, statement: bytes, assertion: dict) -> None:
        """Verify an offline `vault-vm` Ed25519 session-consent assertion."""
        if not isinstance(assertion, dict) or assertion.get("mode") != "vault-vm":
            raise VaultVmError("invalid vault-vm assertion")
        if assertion.get("consent_public") != consent_public_b64:
            raise VaultVmError("vault-vm consent key mismatch")
        pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(consent_public_b64, validate=True))
        sig = base64.b64decode(assertion["signature"], validate=True)
        try:
            pub.verify(sig, b"cpvpn/vault-vm-consent/v1\0" + hashlib.sha3_512(statement).digest())
        except Exception:
            raise VaultVmError("invalid vault-vm consent signature") from None
