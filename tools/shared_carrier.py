"""Forward verified peer grants to the isolated GotaTun carrier via an inherited channel."""

from ipaddress import IPv4Address, IPv4Network
import secrets
import socket
import struct
from threading import Lock
import time

from shared_admission import AdmissionError, ROLES, admit


ROLE_RANGES = {
    "entry": IPv4Network("10.78.0.0/24"),
    "exit": IPv4Network("10.79.0.0/24"),
}
CLIENT_RANGE = ROLE_RANGES["entry"]


class LeaseAllocator:
    """Track active relay-local IPv4 leases for one shared carrier role."""

    def __init__(self, role: str = "entry"):
        if role not in ROLES:
            raise AdmissionError("invalid shared carrier role")
        self.role = role
        self.network = ROLE_RANGES[role]
        self._by_key: dict[bytes, tuple[IPv4Address, int]] = {}
        self._in_use: set[IPv4Address] = set()

    def _reap(self, now: int):
        expired = [key for key, (_, expiry) in self._by_key.items() if expiry <= now]
        for key in expired:
            address, _ = self._by_key.pop(key)
            self._in_use.discard(address)

    def reserve(self, carrier_key: bytes, expiry: int, *, address: IPv4Address | None = None, now: int | None = None):
        """Reserve an unused host address in `.2..254` for a fresh carrier key."""
        current = int(time.time()) if now is None else now
        self._reap(current)
        if carrier_key in self._by_key:
            raise AdmissionError("carrier key already holds an active lease")
        if address is not None:
            candidate = IPv4Address(address)
            if candidate not in self.network or not 2 <= candidate.packed[-1] <= 254:
                raise AdmissionError("invalid shared carrier address")
            if candidate in self._in_use:
                raise AdmissionError("shared carrier address is occupied")
        else:
            base = int(self.network.network_address)
            free = [IPv4Address(base + host) for host in range(2, 255) if IPv4Address(base + host) not in self._in_use]
            if not free:
                raise AdmissionError("shared carrier lease pool is full")
            # Uniform random selection prevents leaking occupancy or arrival order.
            candidate = secrets.choice(free)
        self._by_key[carrier_key] = (candidate, expiry)
        self._in_use.add(candidate)
        return candidate

    def release(self, carrier_key: bytes):
        """Release any lease held by `carrier_key`."""
        entry = self._by_key.pop(carrier_key, None)
        if entry is not None:
            self._in_use.discard(entry[0])

    def active_count(self, now: int | None = None) -> int:
        """Return only the aggregate count of live leases."""
        self._reap(int(time.time()) if now is None else now)
        return len(self._by_key)


class SharedCarrier:
    """Serialize admission updates. Close the channel if their outcome is ambiguous."""

    def __init__(self, control: socket.socket, *, role: str = "entry"):
        if role not in ROLES:
            raise AdmissionError("invalid shared carrier role")
        self.control = control
        self.control.settimeout(3)
        self.role = role
        self.network = ROLE_RANGES[role]
        self.leases = LeaseAllocator(role)
        self._lock = Lock()

    def _apply(self, message: bytes | bytearray):
        try:
            self.control.sendall(message)
            if self.control.recv(1) != b"\x00":
                raise OSError("invalid acknowledgment")
        except OSError:
            # The carrier stops on EOF. An uncertain update must never be
            # treated as a successfully installed or removed peer.
            self.control.close()
            raise AdmissionError("shared carrier update failed") from None

    def install_lease(self, cohort, ledger, token, *, psk, address=None, now: int | None = None, **binding):
        """Validate and consume the caller's credit, allocate a lease, and install the peer."""
        if cohort.role != self.role:
            raise AdmissionError(f"the shared WireGuard carrier accepts {self.role} credits only")
        if len(psk) != 32 or not any(psk) or psk == binding.get("channel_binding"):
            raise AdmissionError("shared carrier needs a separate exporter key")
        carrier_key = binding["carrier_key"]
        if len(carrier_key) != 32 or not any(carrier_key):
            raise AdmissionError("invalid carrier key")
        explicit = None
        if address is not None:
            explicit = IPv4Address(address)
            if explicit not in self.network or not 2 <= explicit.packed[-1] <= 254:
                raise AdmissionError("invalid shared carrier address")
        with self._lock:
            current = int(time.time()) if now is None else now
            expiry = admit(cohort, ledger, token, current, **binding)
            allocated = self.leases.reserve(carrier_key, expiry, address=explicit, now=current)
            frame = bytearray(b"\x01" + carrier_key + psk + allocated.packed + struct.pack("!Q", expiry))
            try:
                self._apply(frame)
            except BaseException:
                self.leases.release(carrier_key)
                raise
            finally:
                frame[:] = bytes(len(frame))
            return str(allocated), expiry

    def install(self, cohort, ledger, token, *, address, psk, now: int | None = None, **binding):
        """Validate and consume the caller's credit before touching the data plane.

        `address` comes from the supervisor's lease allocator. `psk` comes from
        a dedicated exporter on the authenticated hop connection.
        """
        _, expiry = self.install_lease(cohort, ledger, token, psk=psk, address=address, now=now, **binding)
        return expiry

    def remove(self, carrier_key: bytes):
        """Remove a peer before acknowledging disconnect to the caller."""
        if len(carrier_key) != 32 or not any(carrier_key):
            raise AdmissionError("invalid carrier key")
        with self._lock:
            self._apply(b"\x02" + carrier_key + bytes(44))
            self.leases.release(carrier_key)
