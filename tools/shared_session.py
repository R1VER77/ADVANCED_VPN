"""Entry-first, exit-through-entry TLS 1.3 shared admission server and client."""

from contextlib import suppress
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
from threading import Lock, Thread
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared_admission import AdmissionError, Cohort, ROLES, ReplayLedger, binding_message
from shared_carrier import SharedCarrier


MAX_FRAME_BYTES = 16384


def derive_channel_keys(
    shared_secret: bytes,
    role: str,
    hop_key_id: bytes,
    client_ephem: bytes,
    server_ephem: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
) -> tuple[bytes, bytes]:
    """Derive distinct 32-byte admission binding and WireGuard PSK inside a pinned TLS 1.3 channel."""
    if role not in ROLES or any(
        not isinstance(v, bytes) or len(v) != 32 or not any(v)
        for v in (shared_secret, hop_key_id, client_ephem, server_ephem, client_nonce, server_nonce)
    ):
        raise AdmissionError("invalid channel key derivation inputs")
    salt = hashlib.sha256(
        b"cpvpn/shared-channel/v1\0"
        + role.encode("ascii")
        + b"\0"
        + hop_key_id
        + client_ephem
        + server_ephem
        + client_nonce
        + server_nonce
    ).digest()
    binding = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"cpvpn/shared-admission/channel/v1\0" + role.encode("ascii"),
    ).derive(shared_secret)
    psk = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"cpvpn/shared-admission/psk/v1\0" + role.encode("ascii"),
    ).derive(shared_secret)
    if binding == psk or not any(binding) or not any(psk):
        raise AdmissionError("invalid derived channel keys")
    return binding, psk


def _server_channel_handshake(conn: ssl.SSLSocket, role: str, hop_key_id: bytes) -> tuple[bytes, bytes]:
    """Perform an ephemeral X25519 + nonce exchange inside the pinned TLS 1.3 connection."""
    hello = _recv_json(conn)
    if hello.get("op") != "hello":
        raise AdmissionError("expected channel hello")
    client_ephem = bytes.fromhex(hello["client_ephem"])
    client_nonce = bytes.fromhex(hello["client_nonce"])
    if len(client_ephem) != 32 or len(client_nonce) != 32:
        raise AdmissionError("invalid channel hello")
    server_priv = x25519.X25519PrivateKey.generate()
    server_ephem = server_priv.public_key().public_bytes_raw()
    server_nonce = os.urandom(32)
    shared_secret = server_priv.exchange(x25519.X25519PublicKey.from_public_bytes(client_ephem))
    _send_json(conn, {"ok": True, "server_ephem": server_ephem.hex(), "server_nonce": server_nonce.hex()})
    return derive_channel_keys(
        shared_secret, role, hop_key_id, client_ephem, server_ephem, client_nonce, server_nonce
    )


def _client_channel_handshake(conn: ssl.SSLSocket, role: str, hop_key_id: bytes) -> tuple[bytes, bytes]:
    """Client half of the ephemeral X25519 + nonce channel exchange over pinned TLS 1.3."""
    client_priv = x25519.X25519PrivateKey.generate()
    client_ephem = client_priv.public_key().public_bytes_raw()
    client_nonce = os.urandom(32)
    _send_json(conn, {"op": "hello", "client_ephem": client_ephem.hex(), "client_nonce": client_nonce.hex()})
    reply = _recv_json(conn)
    if not reply.get("ok"):
        raise AdmissionError("channel hello rejected")
    server_ephem = bytes.fromhex(reply["server_ephem"])
    server_nonce = bytes.fromhex(reply["server_nonce"])
    if len(server_ephem) != 32 or len(server_nonce) != 32:
        raise AdmissionError("invalid channel hello reply")
    shared_secret = client_priv.exchange(x25519.X25519PublicKey.from_public_bytes(server_ephem))
    return derive_channel_keys(
        shared_secret, role, hop_key_id, client_ephem, server_ephem, client_nonce, server_nonce
    )


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
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_FRAME_BYTES:
        raise AdmissionError("admission message too large")
    conn.sendall(struct.pack("!I", len(data)) + data)


def _recv_json(conn: ssl.SSLSocket) -> dict:
    header = _recv_exact(conn, 4)
    (size,) = struct.unpack("!I", header)
    if not 2 <= size <= MAX_FRAME_BYTES:
        raise AdmissionError("invalid admission frame size")
    raw = _recv_exact(conn, size)
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
    ):
        if len(server_wg_public) != 32 or not any(server_wg_public):
            raise AdmissionError("invalid carrier public key")
        self.cohort = cohort
        self.ledger = ledger
        self.carrier = carrier
        self.server_wg_public = server_wg_public
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
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
        """Stop accepting new admission connections and wait for the listener thread."""
        self._stop = True
        with suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=3)

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
                channel_binding, psk = _server_channel_handshake(conn, self.cohort.role, self.hop_key_id)
                req = _recv_json(conn)
                op = req.get("op")
                if op == "admit":
                    token = bytes.fromhex(req["token"])
                    carrier_key = bytes.fromhex(req["carrier_key"])
                    session_der = bytes.fromhex(req["session_key"])
                    proof = bytes.fromhex(req["proof"])
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
    """Pinned server-authenticated admission endpoint for one hop."""

    host: str
    port: int
    server_name: str
    ca_path: Path
    hop_key_id: bytes


@dataclass(frozen=True)
class HopGrant:
    """Ephemeral session state for one admitted shared hop."""

    role: str
    endpoint: HopEndpoint
    client_private: x25519.X25519PrivateKey
    session_private: mldsa.MLDSA65PrivateKey
    psk: bytes
    server_public: bytes
    assigned_address: str
    expiry: int
    channel_binding: bytes


def _connect_pinned(endpoint: HopEndpoint, *, timeout: float = 5.0) -> ssl.SSLSocket:
    ctx = ssl.create_default_context(cafile=str(endpoint.ca_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    raw = socket.create_connection((endpoint.host, endpoint.port), timeout=timeout)
    try:
        conn = ctx.wrap_socket(raw, server_hostname=endpoint.server_name)
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


def admit_hop(cohort: Cohort, endpoint: HopEndpoint, token: bytes, *, timeout: float = 5.0) -> HopGrant:
    """Redeem one blind credit over a fresh pinned TLS 1.3 channel with fresh keys."""
    session_private = mldsa.MLDSA65PrivateKey.generate()
    client_private = x25519.X25519PrivateKey.generate()
    carrier_key = client_private.public_key().public_bytes_raw()
    session_der = session_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with _connect_pinned(endpoint, timeout=timeout) as conn:
        channel_binding, psk = _client_channel_handshake(conn, cohort.role, endpoint.hop_key_id)
        proof = session_private.sign(binding_message(cohort, token, endpoint.hop_key_id, channel_binding, carrier_key))
        _send_json(
            conn,
            {
                "op": "admit",
                "token": token.hex(),
                "carrier_key": carrier_key.hex(),
                "session_key": session_der.hex(),
                "proof": proof.hex(),
            },
        )
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
    """Send an authenticated disconnect over a fresh pinned TLS 1.3 channel to remove the peer."""
    carrier_key = grant.client_private.public_key().public_bytes_raw()
    session_der = grant.session_private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with _connect_pinned(grant.endpoint, timeout=timeout) as conn:
        channel_binding, _ = _client_channel_handshake(conn, grant.role, grant.endpoint.hop_key_id)
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

    def connect(self, entry_token: bytes, exit_token: bytes) -> tuple[HopGrant, HopGrant]:
        """Admit entry via upstream, bring up entry carrier, then admit exit through entry."""
        if not self.upstream_check(self.upstream_interface):
            raise AdmissionError("required upstream interface is unavailable; refusing direct fallback")
        entry_grant = admit_hop(self.entry_cohort, self.entry_endpoint, entry_token)
        entry_local_up = False
        exit_grant = None
        try:
            self.activate_entry(entry_grant)
            entry_local_up = True
            exit_grant = admit_hop(self.exit_cohort, self.exit_endpoint, exit_token)
            self.activate_exit(exit_grant)
            return entry_grant, exit_grant
        except BaseException:
            if exit_grant is not None:
                with suppress(Exception):
                    self.teardown_exit(exit_grant)
                with suppress(Exception):
                    disconnect_hop(exit_grant)
            if entry_local_up:
                with suppress(Exception):
                    self.teardown_entry(entry_grant)
            with suppress(Exception):
                disconnect_hop(entry_grant)
            raise

    def disconnect(self, entry_grant: HopGrant, exit_grant: HopGrant):
        """Remove exit then entry peers cleanly before tearing down local tunnels."""
        errors = []
        try:
            disconnect_hop(exit_grant)
        except Exception as err:
            errors.append(err)
        try:
            self.teardown_exit(exit_grant)
        except Exception as err:
            errors.append(err)
        try:
            self.teardown_entry(entry_grant)
        except Exception as err:
            errors.append(err)
        try:
            disconnect_hop(entry_grant)
        except Exception as err:
            errors.append(err)
        if errors:
            raise AdmissionError("shared disconnect incomplete") from errors[0]
