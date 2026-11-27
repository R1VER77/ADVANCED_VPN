"""Hardware-resident carrier X25519 ECDH adapters + hybrid ML-KEM-1024 PSK derivation.

Scaffold for roadmap item 4 (per-session hardware-bound carrier keys):
- Durable X25519 private keys stay inside the hardware token (OpenPGP card PSO:DECIPHER
  for Nitrokey 3 / YubiKey 5 / CanoKey / Ledger, SLIP-0017 for Trezor, or a TKey device
  app) rather than being exported as raw bytes to host RAM.
- Each derived carrier PSK combines the token's X25519 ECDH shared secret with an
  ephemeral ML-KEM-1024 shared secret via `shared_pq.dual_hkdf_expand`
  (`HKDF-SHA-512 XOR HKDF-SHA3-512`), providing hybrid post-quantum forward secrecy even
  before hardware tokens offer native ML-KEM.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from shared_pq import dual_hkdf_expand


CARRIER_PSK_DOMAIN = b"cpvpn/hw-carrier-psk/v1\0"
MLKEM1024_PUBLIC_BYTES = 1568
OPENPGP_PSO_DECIPHER_HEADER = bytes([0x00, 0x2A, 0x80, 0x86])


class HardwareCarrierError(RuntimeError):
    """Refusal or failure during hardware-resident carrier key agreement."""


class CarrierKeyProvider(ABC):
    """Abstract interface for a hardware-resident X25519 carrier key."""

    is_hardware: bool = True

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """Return the 32-byte raw X25519 public key held by the token."""

    @abstractmethod
    def ecdh(self, peer_public: bytes) -> bytes:
        """Perform X25519 ECDH inside the token and return the 32-byte shared secret."""


def build_openpgp_x25519_decipher_apdu(peer_public: bytes) -> bytes:
    """Build an ISO 7816-4 / OpenPGP v3.4 PSO:DECIPHER APDU for X25519 ECDH (DEC slot)."""
    if len(peer_public) != 32 or not any(peer_public):
        raise HardwareCarrierError("invalid X25519 peer public key")
    # Cipher DO: 0xA6 (len 0x25) -> 0x7F49 (len 0x22) -> 0x86 (len 0x20) || 32-byte X25519 pub
    data = bytes([0xA6, 0x25, 0x7F, 0x49, 0x22, 0x86, 0x20]) + peer_public
    return OPENPGP_PSO_DECIPHER_HEADER + bytes([len(data)]) + data + b"\x00"


class OpenPgpCardEcdhProvider(CarrierKeyProvider):
    """OpenPGP v3.4 smartcard X25519 ECDH adapter (Nitrokey 3, YubiKey 5, CanoKey, Ledger)."""

    def __init__(self, public_key: bytes, transceive: Callable[[bytes], bytes]):
        if len(public_key) != 32 or not any(public_key):
            raise HardwareCarrierError("invalid OpenPGP X25519 public key")
        self._public = public_key
        self._transceive = transceive

    def public_key_bytes(self) -> bytes:
        """Return the 32-byte OpenPGP card DEC-slot X25519 public key."""
        return self._public

    def ecdh(self, peer_public: bytes) -> bytes:
        """Send PSO:DECIPHER APDU to the smartcard and verify SW=0x9000 + 32-byte shared secret."""
        apdu = build_openpgp_x25519_decipher_apdu(peer_public)
        resp = self._transceive(apdu)
        if len(resp) != 34 or resp[-2:] != b"\x90\x00":
            raise HardwareCarrierError("OpenPGP card PSO:DECIPHER failed or returned unexpected status")
        secret = resp[:32]
        if not any(secret):
            raise HardwareCarrierError("OpenPGP card returned all-zero shared secret")
        return secret


class Slip0017TrezorProvider(CarrierKeyProvider):
    """SLIP-0017 deterministic X25519 ECDH adapter for Trezor Safe 3/5/7 and Model T."""

    def __init__(
        self,
        public_key: bytes,
        identity_uri: str,
        ecdh_fn: Callable[[str, bytes], bytes],
    ):
        if len(public_key) != 32 or not any(public_key) or not identity_uri.startswith("cypherpunk-vpn://"):
            raise HardwareCarrierError("invalid SLIP-0017 Trezor configuration")
        self._public = public_key
        self._identity_uri = identity_uri
        self._ecdh_fn = ecdh_fn

    def public_key_bytes(self) -> bytes:
        """Return the 32-byte SLIP-0017 X25519 public key."""
        return self._public

    def ecdh(self, peer_public: bytes) -> bytes:
        """Invoke Trezor SLIP-0017 get_ecdh_session_key (curve25519) for `peer_public`."""
        if len(peer_public) != 32 or not any(peer_public):
            raise HardwareCarrierError("invalid X25519 peer public key")
        # Trezor returns 0x04 || 32-byte shared secret or raw 32-byte secret depending on transport.
        raw = self._ecdh_fn(self._identity_uri, peer_public)
        secret = raw[1:] if len(raw) == 33 and raw[0] == 0x04 else raw
        if len(secret) != 32 or not any(secret):
            raise HardwareCarrierError("invalid SLIP-0017 ECDH output")
        return secret


class TKeyCarrierAppProvider(CarrierKeyProvider):
    """Tillitis TKey framed X25519 device-app adapter (`0x43 0x01 || peer_pub` -> `0x43 0x00 || shared`)."""

    CMD_ECDH = b"\x43\x01"
    RSP_OK = b"\x43\x00"

    def __init__(self, public_key: bytes, exchange_fn: Callable[[bytes], bytes]):
        if len(public_key) != 32 or not any(public_key):
            raise HardwareCarrierError("invalid TKey X25519 public key")
        self._public = public_key
        self._exchange_fn = exchange_fn

    def public_key_bytes(self) -> bytes:
        """Return the 32-byte TKey device-app X25519 public key."""
        return self._public

    def ecdh(self, peer_public: bytes) -> bytes:
        """Send one framed X25519 ECDH command to the Tillitis TKey carrier app."""
        if len(peer_public) != 32 or not any(peer_public):
            raise HardwareCarrierError("invalid X25519 peer public key")
        reply = self._exchange_fn(self.CMD_ECDH + peer_public)
        if len(reply) != 34 or reply[:2] != self.RSP_OK or not any(reply[2:]):
            raise HardwareCarrierError("TKey carrier app ECDH failed")
        return reply[2:]


class SoftwareLabProvider(CarrierKeyProvider):
    """Non-hardware X25519 provider strictly for isolated unit/lab testing."""

    is_hardware = False

    def __init__(self, private_key: x25519.X25519PrivateKey | None = None):
        self._private = private_key or x25519.X25519PrivateKey.generate()

    def public_key_bytes(self) -> bytes:
        """Return the 32-byte lab X25519 public key."""
        return self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def ecdh(self, peer_public: bytes) -> bytes:
        """Compute X25519 ECDH in software (lab only)."""
        if len(peer_public) != 32 or not any(peer_public):
            raise HardwareCarrierError("invalid X25519 peer public key")
        return self._private.exchange(x25519.X25519PublicKey.from_public_bytes(peer_public))


@dataclass(frozen=True)
class HardwareCarrierSession:
    """Result of hybrid hardware-X25519 + ephemeral ML-KEM-1024 carrier PSK derivation."""

    psk: bytes
    mlkem_ciphertext: bytes
    hardware_backed: bool


def derive_hardware_carrier_psk(
    provider: CarrierKeyProvider,
    peer_x25519_public: bytes,
    peer_mlkem1024_public: bytes,
    *,
    context: bytes,
) -> HardwareCarrierSession:
    """Combine hardware-resident X25519 ECDH with ephemeral ML-KEM-1024 via dual HKDF-SHA512/SHA3-512."""
    if len(peer_x25519_public) != 32 or not any(peer_x25519_public):
        raise HardwareCarrierError("invalid peer X25519 public key")
    if len(peer_mlkem1024_public) != MLKEM1024_PUBLIC_BYTES:
        raise HardwareCarrierError("invalid peer ML-KEM-1024 public key")
    if not context:
        raise HardwareCarrierError("carrier session context binding is required")
    hw_secret = bytearray(provider.ecdh(peer_x25519_public))
    pq_secret_bytes, mlkem_ct = mlkem.MLKEM1024PublicKey.from_public_bytes(peer_mlkem1024_public).encapsulate()
    pq_secret = bytearray(pq_secret_bytes)
    ikm = bytearray(hw_secret) + bytearray(pq_secret)
    try:
        transcript = (
            CARRIER_PSK_DOMAIN
            + provider.public_key_bytes()
            + peer_x25519_public
            + peer_mlkem1024_public
            + mlkem_ct
            + context
        )
        psk = dual_hkdf_expand(ikm, transcript, b"cpvpn/hw-carrier/psk/v1", 32)
    finally:
        hw_secret[:] = bytes(len(hw_secret))
        pq_secret[:] = bytes(len(pq_secret))
        ikm[:] = bytes(len(ikm))
    return HardwareCarrierSession(psk=psk, mlkem_ciphertext=mlkem_ct, hardware_backed=provider.is_hardware)
