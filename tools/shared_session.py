"""Entry-first, exit-through-entry TLS 1.3 shared admission server and client."""

from contextlib import suppress
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
from threading import Lock, Thread
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x448, x25519

from shared_admission import AdmissionError, Cohort, ROLES, ReplayLedger, binding_message
from shared_carrier import SharedCarrier
from shared_pq import HybridPqIdentity, HybridPqPublic, dual_hkdf_expand


ADMISSION_FRAME_BYTES = 49152
MAX_PAYLOAD_BYTES = ADMISSION_FRAME_BYTES - 2
X448_PUBLIC_BYTES = 56
MLKEM1024_PUBLIC_BYTES = 1568
MLKEM1024_CIPHERTEXT_BYTES = 1568
SERVER_CONFIRM_DOMAIN = b"cpvpn/shared-server-confirm/v2\0"


def _wipe_bytearray(buf: bytearray):
    """Overwrite a mutable secret buffer with zeros in place."""
    buf[:] = bytes(len(buf))


def _transcript_bytes(
    role: str,
    hop_key_id: bytes,
    client_ephem: bytes,
    server_ephem: bytes,
    client_x448: bytes,
    server_x448: bytes,
    client_mlkem: bytes,
    server_mlkem_ct: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> bytes:
    return (
        b"cpvpn/shared-channel-pq/v2\0"
        + role.encode("ascii")
        + b"\0"
        + hop_key_id
        + client_ephem
        + server_ephem
        + client_x448
        + server_x448
        + client_mlkem
        + server_mlkem_ct
        + client_nonce
        + server_nonce
    )


def derive_channel_keys(
    shared_x25519: bytes,
    shared_x448: bytes,
    pq_secret: bytes,
    role: str,
    hop_key_id: bytes,
    client_ephem: bytes,
    server_ephem: bytes,
    client_x448: bytes,
    server_x448: bytes,
    client_mlkem: bytes,
    server_mlkem_ct: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]:
    """Derive 32-byte admission binding and WireGuard PSK from X25519 + X448 + ML-KEM-1024 via dual HKDF."""
    if (
        role not in ROLES
        or any(
            not isinstance(v, bytes) or len(v) != 32 or not any(v)
            for v in (shared_x25519, pq_secret, hop_key_id, client_ephem, server_ephem, client_nonce, server_nonce)
        )
        or any(
            not isinstance(v, bytes) or len(v) != X448_PUBLIC_BYTES or not any(v)
            for v in (shared_x448, client_x448, server_x448)
        )
        or not isinstance(client_mlkem, bytes)
        or len(client_mlkem) != MLKEM1024_PUBLIC_BYTES
        or not isinstance(server_mlkem_ct, bytes)
        or len(server_mlkem_ct) != MLKEM1024_CIPHERTEXT_BYTES
    ):
        raise AdmissionError("invalid channel key derivation inputs")
    transcript = _transcript_bytes(
        role,
        hop_key_id,
        client_ephem,
        server_ephem,
        client_x448,
        server_x448,
        client_mlkem,
        server_mlkem_ct,
        client_nonce,
        server_nonce,
    )
    ikm = bytearray(shared_x25519) + bytearray(shared_x448) + bytearray(pq_secret)
    try:
        binding = dual_hkdf_expand(ikm, transcript, b"cpvpn/shared-admission/channel/v2\0" + role.encode("ascii"), 32)
        psk = dual_hkdf_expand(ikm, transcript, b"cpvpn/shared-admission/psk/v2\0" + role.encode("ascii"), 32)
    finally:
        _wipe_bytearray(ikm)
    if binding == psk or not any(binding) or not any(psk):
        raise AdmissionError("invalid derived channel keys")
    return binding, psk


def _server_channel_handshake(
    conn: ssl.SSLSocket, role: str, hop_key_id: bytes, server_pq_identity: HybridPqIdentity
) -> tuple[bytes, bytes]:
    """Perform X25519 + X448 + ML-KEM-1024 KEX with multi-family PQ server confirmation."""
    hello = _recv_json(conn)
    if hello.get("op") != "hello":
        raise AdmissionError("expected channel hello")
    client_ephem = bytes.fromhex(hello["client_ephem"])
    client_x448 = bytes.fromhex(hello["client_x448"])
    client_mlkem = bytes.fromhex(hello["client_mlkem"])
    client_nonce = bytes.fromhex(hello["client_nonce"])
    if (
        len(client_ephem) != 32
        or len(client_x448) != X448_PUBLIC_BYTES
        or len(client_mlkem) != MLKEM1024_PUBLIC_BYTES
        or len(client_nonce) != 32
    ):
        raise AdmissionError("invalid channel hello")
    server_priv = x25519.X25519PrivateKey.generate()
    server_x448_priv = x448.X448PrivateKey.generate()
    try:
        server_ephem = server_priv.public_key().public_bytes_raw()
        server_x448 = server_x448_priv.public_key().public_bytes_raw()
        server_nonce = os.urandom(32)
        shared_x25519 = server_priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_ephem))
        shared_x448 = server_x448_priv.exchange(x448.X448PublicKey.from_public_bytes(client_x448))
        pq_secret, server_mlkem_ct = mlkem.MLKEM1024PublicKey.from_public_bytes(client_mlkem).encapsulate()
    finally:
        del server_priv, server_x448_priv
    transcript = _transcript_bytes(
        role,
        hop_key_id,
        client_ephem,
        server_ephem,
        client_x448,
        server_x448,
        client_mlkem,
        server_mlkem_ct,
        client_nonce,
        server_nonce,
    )
    server_confirm = server_pq_identity.sign(SERVER_CONFIRM_DOMAIN, transcript)
    _send_json(
        conn,
        {
            "ok": True,
            "server_ephem": server_ephem.hex(),
            "server_x448": server_x448.hex(),
            "server_mlkem_ct": server_mlkem_ct.hex(),
            "server_nonce": server_nonce.hex(),
            "server_confirm": server_confirm,
        },
    )
    try:
        return derive_channel_keys(
            shared_x25519,
            shared_x448,
            pq_secret,
            role,
            hop_key_id,
            client_ephem,
            server_ephem,
            client_x448,
            server_x448,
            client_mlkem,
            server_mlkem_ct,
            client_nonce,
            server_nonce,
        )
    finally:
        del shared_x25519, shared_x448, pq_secret


def _client_channel_handshake(
    conn: ssl.SSLSocket, role: str, hop_key_id: bytes, server_pq_public: HybridPqPublic
) -> tuple[bytes, bytes]:
    """Client half of X25519 + X448 + ML-KEM-1024 KEX with pinned multi-family PQ server auth."""
    client_priv = x25519.X25519PrivateKey.generate()
    client_x448_priv = x448.X448PrivateKey.generate()
    client_kem_priv = mlkem.MLKEM1024PrivateKey.generate()
    try:
        client_ephem = client_priv.public_key().public_bytes_raw()
        client_x448 = client_x448_priv.public_key().public_bytes_raw()
        client_mlkem = client_kem_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        client_nonce = os.urandom(32)
        _send_json(
            conn,
            {
                "op": "hello",
                "client_ephem": client_ephem.hex(),
                "client_x448": client_x448.hex(),
                "client_mlkem": client_mlkem.hex(),
                "client_nonce": client_nonce.hex(),
            },
        )
        reply = _recv_json(conn)
        if not reply.get("ok"):
            raise AdmissionError("channel hello rejected")
        server_ephem = bytes.fromhex(reply["server_ephem"])
        server_x448 = bytes.fromhex(reply["server_x448"])
        server_mlkem_ct = bytes.fromhex(reply["server_mlkem_ct"])
        server_nonce = bytes.fromhex(reply["server_nonce"])
        if (
            len(server_ephem) != 32
            or len(server_x448) != X448_PUBLIC_BYTES
            or len(server_mlkem_ct) != MLKEM1024_CIPHERTEXT_BYTES
            or len(server_nonce) != 32
        ):
            raise AdmissionError("invalid channel hello reply")
        transcript = _transcript_bytes(
            role,
            hop_key_id,
            client_ephem,
            server_ephem,
            client_x448,
            server_x448,
            client_mlkem,
            server_mlkem_ct,
            client_nonce,
            server_nonce,
        )
        # Verify ALL pinned multi-family PQ server confirmation signatures BEFORE deriving keys or sending credits.
        server_pq_public.verify(SERVER_CONFIRM_DOMAIN, transcript, reply.get("server_confirm"))
        shared_x25519 = client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(server_ephem))
        shared_x448 = client_x448_priv.exchange(x448.X448PublicKey.from_public_bytes(server_x448))
        pq_secret = client_kem_priv.decapsulate(server_mlkem_ct)
    finally:
        del client_priv, client_x448_priv, client_kem_priv
    try:
        return derive_channel_keys(
            shared_x25519,
            shared_x448,
            pq_secret,
            role,
            hop_key_id,
            client_ephem,
            server_ephem,
            client_x448,
            server_x448,
            client_mlkem,
            server_mlkem_ct,
            client_nonce,
            server_nonce,
        )
    finally:
        del shared_x25519, shared_x448, pq_secret


def disconnect_message(role: str, hop_key_id: bytes, channel_binding: bytes, carrier_key: bytes) -> bytes:
    """Bind an authenticated disconnect request to the live TLS channel and carrier key."""
    if role not in ROLES or any(len(v) != 32 or not any(v) for v in (hop_key_id, channel_binding, carrier_key)):
        raise AdmissionError("invalid disconnect binding")
    return b"cpvpn/shared-disconnect/v1\0" + role.encode("ascii") + b"\0" + hop_key_id + channel_binding + carrier_key


def cert_spki_sha256(cert_der: bytes) -> bytes:
    """Compute the pinned hop key identifier from a DER-encoded X.509 certificate."""
    from cryptography import x509

    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).digest()


def _send_json(conn: ssl.SSLSocket, payload: dict):
    """Send a fixed-size 16,384-byte padded frame so all admission messages look identical on the wire."""
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_PAYLOAD_BYTES:
        raise AdmissionError("admission message too large")
    pad = bytes(MAX_PAYLOAD_BYTES - len(data))
    conn.sendall(struct.pack("!H", len(data)) + data + pad)


def _recv_json(conn: ssl.SSLSocket) -> dict:
    """Receive one fixed-size 16,384-byte padded admission frame."""
    frame = _recv_exact(conn, ADMISSION_FRAME_BYTES)
    (size,) = struct.unpack("!H", frame[:2])
    if not 2 <= size <= MAX_PAYLOAD_BYTES:
        raise AdmissionError("invalid admission frame size")
    raw = frame[2 : 2 + size]
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AdmissionError("invalid admission message") from None
    if not isinstance(value, dict):
        raise AdmissionError("invalid admission message")
    return value


def _recv_exact(conn: ssl.SSLSocket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        piece = conn.recv(length - len(chunks))
        if not piece:
            raise AdmissionError("admission channel closed")
        chunks.extend(piece)
    return bytes(chunks)


def _load_mldsa_public(raw: bytes) -> mldsa.MLDSA65PublicKey:
    try:
        key = serialization.load_der_public_key(raw)
    except ValueError:
        raise AdmissionError("invalid session public key") from None
    if not isinstance(key, mldsa.MLDSA65PublicKey):
        raise AdmissionError("session key must be ML-DSA-65")
    return key


class AdmissionServer:
    """Pinned TLS 1.3 shared admission endpoint backed by ReplayLedger and SharedCarrier.

    Retains only aggregate counters and in-memory disconnect keys for live leases.
    Never logs client addresses, destinations, hardware IDs, or session timestamps.
    """

    def __init__(
        self,
        *,
        bind: tuple[str, int],
        cert_path: Path,
        key_path: Path,
        cohort: Cohort,
        ledger: ReplayLedger,
        carrier: SharedCarrier,
        server_wg_public: bytes,
        server_pq_identity: HybridPqIdentity | None = None,
    ):
        if len(server_wg_public) != 32 or not any(server_wg_public):
            raise AdmissionError("invalid carrier public key")
        self.cohort = cohort
        self.ledger = ledger
        self.carrier = carrier
        self.server_wg_public = server_wg_public
        self.server_pq_identity = server_pq_identity or HybridPqIdentity()
        self.server_pq_public = self.server_pq_identity.public
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        # Disable TLS 1.3 session tickets for strict per-connection forward secrecy and anti-tracking.
        self.context.options |= ssl.OP_NO_TICKET
        self.context.load_cert_chain(str(cert_path), str(key_path))
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        self.hop_key_id = hashlib.sha256(
            cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).digest()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(bind)
        self._sock.listen(64)
        self._sock.settimeout(0.5)
        self.address = self._sock.getsockname()
        self._stop = False
        self._lock = Lock()
        # In-memory map of active carrier_key -> (session_public_der, expiry) solely to authorize disconnect.
        self._sessions: dict[bytes, tuple[bytes, int]] = {}
        self._counters = {"admitted": 0, "rejected": 0, "disconnected": 0}
        self._thread = Thread(target=self._serve, daemon=True)

    def start(self):
        """Start serving pinned TLS 1.3 admission requests in the background."""
        self._thread.start()

    def stop(self):
        """Stop accepting new admission connections, wipe live session/PQ key state, and wait for shutdown."""
        self._stop = True
        with suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=3)
        with self._lock:
            self._sessions.clear()
        self.server_pq_identity.wipe()

    def metrics(self) -> dict[str, int]:
        """Return strictly aggregate health and capacity counters."""
        with self._lock:
            now = int(time.time())
            self._reap_sessions(now)
            return {
                "active_leases": self.carrier.leases.active_count(now),
                "admitted": self._counters["admitted"],
                "rejected": self._counters["rejected"],
                "disconnected": self._counters["disconnected"],
            }

    def _reap_sessions(self, now: int):
        for key in [k for k, (_, exp) in self._sessions.items() if exp <= now]:
            self._sessions.pop(key, None)

    def _serve(self):
        while not self._stop:
            try:
                client, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, raw_sock: socket.socket):
        conn = None
        try:
            raw_sock.settimeout(5)
            with self.context.wrap_socket(raw_sock, server_side=True) as tls_conn:
                conn = tls_conn
                if conn.version() != "TLSv1.3":
                    raise AdmissionError("TLS 1.3 required")
                channel_binding, psk = _server_channel_handshake(
                    conn, self.cohort.role, self.hop_key_id, self.server_pq_identity
                )
                req = _recv_json(conn)
                op = req.get("op")
                if op == "admit":
                    token = bytes.fromhex(req["token"])
                    carrier_key = bytes.fromhex(req["carrier_key"])
                    session_der = bytes.fromhex(req["session_key"])
                    proof = bytes.fromhex(req["proof"])
                    pq_stamp = req.get("pq_stamp")
                    session_pub = _load_mldsa_public(session_der)
                    assigned, expiry = self.carrier.install_lease(
                        self.cohort,
                        self.ledger,
                        token,
                        psk=psk,
                        hop_key_id=self.hop_key_id,
                        channel_binding=channel_binding,
                        carrier_key=carrier_key,
                        session_key=session_pub,
                        proof=proof,
                        pq_stamp=pq_stamp,
                    )
                    with self._lock:
                        self._reap_sessions(int(time.time()))
                        self._sessions[carrier_key] = (session_der, expiry)
                        self._counters["admitted"] += 1
                    _send_json(
                        conn,
                        {
                            "ok": True,
                            "address": assigned,
                            "expiry": expiry,
                            "server_public": self.server_wg_public.hex(),
                        },
                    )
                elif op == "disconnect":
                    carrier_key = bytes.fromhex(req["carrier_key"])
                    session_der = bytes.fromhex(req["session_key"])
                    proof = bytes.fromhex(req["proof"])
                    with self._lock:
                        self._reap_sessions(int(time.time()))
                        recorded = self._sessions.get(carrier_key)
                    if recorded is None or recorded[0] != session_der:
                        raise AdmissionError("unknown active lease")
                    session_pub = _load_mldsa_public(session_der)
                    try:
                        session_pub.verify(
                            proof,
                            disconnect_message(self.cohort.role, self.hop_key_id, channel_binding, carrier_key),
                        )
                    except InvalidSignature:
                        raise AdmissionError("invalid disconnect proof") from None
                    self.carrier.remove(carrier_key)
                    with self._lock:
                        self._sessions.pop(carrier_key, None)
                        self._counters["disconnected"] += 1
                    _send_json(conn, {"ok": True})
                else:
                    raise AdmissionError("unknown admission operation")
        except (AdmissionError, KeyError, ValueError, OSError, ssl.SSLError):
            with self._lock:
                self._counters["rejected"] += 1
            if conn is not None:
                with suppress(AdmissionError, OSError, ssl.SSLError):
                    _send_json(conn, {"ok": False, "error": "admission refused"})
        finally:
            with suppress(OSError):
                raw_sock.close()


@dataclass(frozen=True)
class HopEndpoint:
    """Pinned server-authenticated admission endpoint with mandatory multi-family PQ server auth."""

    host: str
    port: int
    server_name: str
    ca_path: Path
    hop_key_id: bytes
    server_pq_public: HybridPqPublic
    sni_override: str | None = None


@dataclass(frozen=True)
class HopGrant:
    """Ephemeral session state for one admitted shared hop."""

    role: str
    endpoint: HopEndpoint
    client_private: x25519.X25519PrivateKey | None
    session_private: mldsa.MLDSA65PrivateKey | None
    psk: bytes
    server_public: bytes
    assigned_address: str
    expiry: int
    channel_binding: bytes

    def wipe(self):
        """Destroy ephemeral session keys and derived secrets immediately upon teardown."""
        object.__setattr__(self, "client_private", None)
        object.__setattr__(self, "session_private", None)
        object.__setattr__(self, "psk", b"")
        object.__setattr__(self, "channel_binding", b"")


def _connect_pinned(endpoint: HopEndpoint, *, timeout: float = 5.0) -> ssl.SSLSocket:
    ctx = ssl.create_default_context(cafile=str(endpoint.ca_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    # Disable TLS 1.3 session tickets so every admission uses fresh ephemeral key agreement.
    ctx.options |= ssl.OP_NO_TICKET
    # When a cover SNI is used, authenticate strictly by pinned SPKI SHA-256.
    ctx.check_hostname = endpoint.sni_override is None
    raw = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    try:
        conn = ctx.wrap_socket(raw, server_hostname=endpoint.sni_override or endpoint.server_name)
    except BaseException:
        raw.close()
        raise
    if conn.version() != "TLSv1.3":
        conn.close()
        raise AdmissionError("TLS 1.3 required")
    peer_der = conn.getpeercert(binary_form=True)
    if not peer_der or cert_spki_sha256(peer_der) != endpoint.hop_key_id:
        conn.close()
        raise AdmissionError("hop certificate pin mismatch")
    return conn


def admit_hop(
    cohort: Cohort,
    endpoint: HopEndpoint,
    token: bytes,
    *,
    pq_stamp: dict | None = None,
    timeout: float = 5.0,
) -> HopGrant:
    """Redeem one blind credit over a fresh pinned PQ-authenticated TLS 1.3 channel with fresh keys."""
    session_private = mldsa.MLDSA65PrivateKey.generate()
    client_private = x25519.X25519PrivateKey.generate()
    carrier_key = client_private.public_key().public_bytes_raw()
    session_der = session_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with _connect_pinned(endpoint, timeout=timeout) as conn:
        channel_binding, psk = _client_channel_handshake(
            conn, cohort.role, endpoint.hop_key_id, endpoint.server_pq_public
        )
        proof = session_private.sign(binding_message(cohort, token, endpoint.hop_key_id, channel_binding, carrier_key))
        payload = {
            "op": "admit",
            "token": token.hex(),
            "carrier_key": carrier_key.hex(),
            "session_key": session_der.hex(),
            "proof": proof.hex(),
        }
        if pq_stamp is not None:
            payload["pq_stamp"] = pq_stamp
        _send_json(conn, payload)
        reply = _recv_json(conn)
        if not reply.get("ok"):
            raise AdmissionError("hop admission rejected")
        server_public = bytes.fromhex(reply["server_public"])
        if len(server_public) != 32 or not any(server_public):
            raise AdmissionError("invalid server carrier key")
        return HopGrant(
            role=cohort.role,
            endpoint=endpoint,
            client_private=client_private,
            session_private=session_private,
            psk=psk,
            server_public=server_public,
            assigned_address=str(reply["address"]),
            expiry=int(reply["expiry"]),
            channel_binding=channel_binding,
        )


def disconnect_hop(grant: HopGrant, *, timeout: float = 5.0):
    """Send an authenticated disconnect over a fresh pinned PQ-authenticated TLS 1.3 channel."""
    if grant.client_private is None or grant.session_private is None:
        raise AdmissionError("hop grant keys already wiped")
    carrier_key = grant.client_private.public_key().public_bytes_raw()
    session_der = grant.session_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with _connect_pinned(grant.endpoint, timeout=timeout) as conn:
        channel_binding, _ = _client_channel_handshake(
            conn, grant.role, grant.endpoint.hop_key_id, grant.endpoint.server_pq_public
        )
        proof = grant.session_private.sign(
            disconnect_message(grant.role, grant.endpoint.hop_key_id, channel_binding, carrier_key)
        )
        _send_json(
            conn,
            {
                "op": "disconnect",
                "carrier_key": carrier_key.hex(),
                "session_key": session_der.hex(),
                "proof": proof.hex(),
            },
        )
        reply = _recv_json(conn)
        if not reply.get("ok"):
            raise AdmissionError("hop disconnect rejected")


def upstream_is_ready(interface: str) -> bool:
    """Confirm that the configured upstream interface exists and is operational."""
    if not interface or "/" in interface or interface in (".", ".."):
        return False
    oper = Path("/sys/class/net") / interface / "operstate"
    flags = Path("/sys/class/net") / interface / "flags"
    if not oper.exists() or not flags.exists():
        return False
    state = oper.read_text().strip().lower()
    if state == "up":
        return True
    # TUN/WireGuard interfaces often report "unknown" when UP (IFF_UP = 0x1).
    return state == "unknown" and bool(int(flags.read_text().strip(), 16) & 0x1)


def _uniform_jitter(bounds: tuple[float, float]) -> float:
    low, high = bounds
    if low < 0 or high < low:
        raise AdmissionError("invalid jitter bounds")
    if high == 0:
        return 0.0
    span_ms = int(round((high - low) * 1000))
    return low + (secrets.randbelow(span_ms + 1) / 1000.0 if span_ms > 0 else 0.0)


class SharedSessionClient:
    """Coordinate entry-first, exit-through-entry shared admission with atomic rollback."""

    def __init__(
        self,
        *,
        entry_cohort: Cohort,
        exit_cohort: Cohort,
        entry_endpoint: HopEndpoint,
        exit_endpoint: HopEndpoint,
        upstream_interface: str,
        activate_entry,
        teardown_entry,
        activate_exit,
        teardown_exit,
        upstream_check=upstream_is_ready,
        hop_delay_range: tuple[float, float] = (0.4, 1.5),
        disconnect_tail_range: tuple[float, float] = (0.3, 1.0),
        silent_entry_disconnect: bool = True,
        sleep_fn=time.sleep,
    ):
        self.entry_cohort = entry_cohort
        self.exit_cohort = exit_cohort
        self.entry_endpoint = entry_endpoint
        self.exit_endpoint = exit_endpoint
        self.upstream_interface = upstream_interface
        self.activate_entry = activate_entry
        self.teardown_entry = teardown_entry
        self.activate_exit = activate_exit
        self.teardown_exit = teardown_exit
        self.upstream_check = upstream_check
        self.hop_delay_range = hop_delay_range
        self.disconnect_tail_range = disconnect_tail_range
        self.silent_entry_disconnect = silent_entry_disconnect
        self.sleep_fn = sleep_fn

    def connect(
        self,
        entry_token: bytes,
        exit_token: bytes,
        *,
        entry_pq_stamp: dict | None = None,
        exit_pq_stamp: dict | None = None,
    ) -> tuple[HopGrant, HopGrant]:
        """Admit entry via upstream, wait randomized cover delay, then admit exit through entry."""
        if not self.upstream_check(self.upstream_interface):
            raise AdmissionError("required upstream interface is unavailable; refusing direct fallback")
        entry_grant = admit_hop(self.entry_cohort, self.entry_endpoint, entry_token, pq_stamp=entry_pq_stamp)
        entry_local_up = False
        exit_grant = None
        try:
            self.activate_entry(entry_grant)
            entry_local_up = True
            delay = _uniform_jitter(self.hop_delay_range)
            if delay > 0:
                self.sleep_fn(delay)
            exit_grant = admit_hop(self.exit_cohort, self.exit_endpoint, exit_token, pq_stamp=exit_pq_stamp)
            self.activate_exit(exit_grant)
            return entry_grant, exit_grant
        except BaseException:
            if exit_grant is not None:
                with suppress(Exception):
                    self.teardown_exit(exit_grant)
                with suppress(Exception):
                    disconnect_hop(exit_grant)
                exit_grant.wipe()
            if entry_local_up:
                with suppress(Exception):
                    self.teardown_entry(entry_grant)
            with suppress(Exception):
                disconnect_hop(entry_grant)
            entry_grant.wipe()
            raise

    def disconnect(self, entry_grant: HopGrant, exit_grant: HopGrant):
        """Disconnect exit, tear down tunnels with zero wait on silent entry expiry, and wipe keys."""
        errors = []
        try:
            try:
                disconnect_hop(exit_grant)
            except Exception as err:
                errors.append(err)
            try:
                self.teardown_exit(exit_grant)
            except Exception as err:
                errors.append(err)
            if not self.silent_entry_disconnect:
                tail = _uniform_jitter(self.disconnect_tail_range)
                if tail > 0:
                    self.sleep_fn(tail)
            try:
                self.teardown_entry(entry_grant)
            except Exception as err:
                errors.append(err)
            if not self.silent_entry_disconnect:
                try:
                    disconnect_hop(entry_grant)
                except Exception as err:
                    errors.append(err)
        finally:
            exit_grant.wipe()
            entry_grant.wipe()
        if errors:
            raise AdmissionError("shared disconnect incomplete") from errors[0]
