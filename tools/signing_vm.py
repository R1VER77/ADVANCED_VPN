"""Split signing-VM transports for hardware-bound sessions (Qubes qrexec & KVM/Unix socket).

Transports the exact single-JSON stdin/stdout contract of `tools/session_signer.py`
across a VM boundary so long-term ML-DSA-65 identities and the attached FIDO2 hardware
token remain strictly inside an isolated vault VM (docs/HARDWARE_BOUND_SESSIONS.md).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess

import session_auth


MAX_REPLY_BYTES = 262_144
QUBES_SERVICE = "cypherpunk.SessionSign"
QUBES_VM_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,31}$")
ALLOWED_LANES = frozenset({"outer", "middle", "inner"})


class SigningVmError(RuntimeError):
    """Fail-closed refusal from the split signing-VM transport."""


def validate_signer_request(state: str, lanes: dict[str, str], carry: tuple[str, ...] | list[str] = ()) -> dict:
    """Validate and canonicalize a session_signer request before crossing a VM boundary."""
    if not isinstance(state, str) or not state or "\x00" in state:
        raise SigningVmError("invalid vault state path")
    if not isinstance(lanes, dict) or not lanes or not set(lanes) <= ALLOWED_LANES:
        raise SigningVmError("invalid session lanes requested")
    for lane, spki_hex in lanes.items():
        if not isinstance(spki_hex, str) or not spki_hex:
            raise SigningVmError(f"missing SPKI hex for lane {lane}")
        try:
            raw = bytes.fromhex(spki_hex)
        except ValueError:
            raise SigningVmError(f"malformed SPKI hex for lane {lane}") from None
        if len(raw) < 32:
            raise SigningVmError(f"undersized SPKI for lane {lane}")
    carry_list = list(carry)
    if any(not isinstance(item, str) or not item for item in carry_list):
        raise SigningVmError("invalid carry key list")
    return {"state": state, "lanes": dict(lanes), "carry": carry_list}


def validate_signer_reply(request: dict, reply: dict) -> dict:
    """Strictly validate a signing-VM reply against the original request (fail closed)."""
    if not isinstance(reply, dict):
        raise SigningVmError("signing VM returned non-object reply")
    if "error" in reply:
        raise SigningVmError(f"signing VM refused request: {reply['error']}")
    required = {"leaves", "carry", "not_before", "not_after"}
    if not required <= set(reply):
        raise SigningVmError("signing VM reply missing required fields")
    leaves = reply["leaves"]
    if not isinstance(leaves, dict) or set(leaves) != set(request["lanes"]):
        raise SigningVmError("signing VM returned mismatched lane leaves")
    for lane, cert_hex in leaves.items():
        try:
            raw = bytes.fromhex(cert_hex)
        except (TypeError, ValueError):
            raise SigningVmError(f"malformed leaf certificate hex for {lane}") from None
        if len(raw) < 64:
            raise SigningVmError(f"undersized leaf certificate for {lane}")
    carry = reply["carry"]
    if not isinstance(carry, dict) or set(carry) != set(request["carry"]):
        raise SigningVmError("signing VM returned mismatched carry keys")
    not_before, not_after = reply["not_before"], reply["not_after"]
    if type(not_before) is not int or type(not_after) is not int:
        raise SigningVmError("invalid session validity timestamps")
    span = not_after - not_before
    if not (0 < span <= session_auth.MAX_SECONDS):
        raise SigningVmError("signing VM returned session window exceeding MAX_SECONDS")
    return reply


class QrexecTransport:
    """Invoke `session_signer.py` inside a Qubes OS vault VM over qrexec."""

    def __init__(
        self,
        vault_vm: str,
        *,
        service: str = QUBES_SERVICE,
        qrexec_bin: str = "/usr/bin/qrexec-client-vm",
        timeout: float = 120.0,
    ):
        if not QUBES_VM_NAME_RE.fullmatch(vault_vm):
            raise SigningVmError("invalid Qubes vault VM name")
        if not re.fullmatch(r"^[a-zA-Z0-9._+-]{1,64}$", service):
            raise SigningVmError("invalid qrexec service name")
        self.vault_vm = vault_vm
        self.service = service
        self.qrexec_bin = qrexec_bin
        self.timeout = timeout

    def argv(self) -> list[str]:
        """Exact non-shell argv passed to qrexec-client-vm."""
        return [self.qrexec_bin, self.vault_vm, self.service]

    def request(self, state: str, lanes: dict[str, str], carry=()) -> dict:
        """Send one session-signing request across qrexec and strictly validate the reply."""
        req = validate_signer_request(state, lanes, carry)
        payload = json.dumps(req, separators=(",", ":")).encode("utf-8")
        try:
            proc = subprocess.run(  # noqa: S603 - explicit trusted qrexec-client-vm binary
                self.argv(),
                input=payload,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            raise SigningVmError(f"qrexec transport failed: {err}") from None
        if len(proc.stdout) > MAX_REPLY_BYTES:
            raise SigningVmError("qrexec reply exceeded maximum allowed size")
        try:
            reply = json.loads(proc.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SigningVmError(f"qrexec returned invalid JSON (exit {proc.returncode})") from None
        if proc.returncode != 0:
            raise SigningVmError(reply.get("error", f"qrexec exited with {proc.returncode}"))
        return validate_signer_reply(req, reply)


class UnixSocketVmTransport:
    """Length-prefixed JSON transport over AF_UNIX (for KVM/Firecracker/QEMU signing VMs)."""

    def __init__(self, socket_path: Path, *, timeout: float = 120.0):
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def request(self, state: str, lanes: dict[str, str], carry=()) -> dict:
        """Send one length-prefixed request to the signing VM socket and validate the reply."""
        req = validate_signer_request(state, lanes, carry)
        body = json.dumps(req, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_REPLY_BYTES:
            raise SigningVmError("signing request too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(str(self.socket_path))
                sock.sendall(struct.pack("!I", len(body)) + body)
                hdr = _recv_exact(sock, 4)
                (size,) = struct.unpack("!I", hdr)
                if not 2 <= size <= MAX_REPLY_BYTES:
                    raise SigningVmError("invalid signing VM reply frame size")
                raw = _recv_exact(sock, size)
        except OSError as err:
            raise SigningVmError(f"signing VM socket error: {err}") from None
        try:
            reply = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SigningVmError("signing VM returned malformed JSON") from None
        return validate_signer_reply(req, reply)


def serve_unix_socket_once(socket_path: Path, handler, *, ready=None):
    """Serve a single length-prefixed signing request on `socket_path` (0600, lab/VM daemon)."""
    if socket_path.exists():
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        srv.listen(1)
        if ready is not None:
            ready.set()
        conn, _ = srv.accept()
        with conn:
            (size,) = struct.unpack("!I", _recv_exact(conn, 4))
            if not 2 <= size <= MAX_REPLY_BYTES:
                raise SigningVmError("invalid incoming request size")
            req = json.loads(_recv_exact(conn, size).decode("utf-8"))
            resp = json.dumps(handler(req), separators=(",", ":")).encode("utf-8")
            conn.sendall(struct.pack("!I", len(resp)) + resp)


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise SigningVmError("signing VM closed connection prematurely")
        buf.extend(chunk)
    return bytes(buf)
