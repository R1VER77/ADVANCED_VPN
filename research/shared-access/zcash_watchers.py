"""Proof-validating Zcash testnet watcher adapters routed strictly over Tor SOCKS5."""

import hashlib
import hmac
import json
import socket
import ssl
import struct
from urllib.parse import urlparse

from checkout_policy import CheckoutError, Note, REQUIRED_CONFIRMATIONS, Watcher


def socks5_connect(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: float = 15.0) -> socket.socket:
    """Open a TCP stream through a Tor SOCKS5 proxy using remote DNS resolution (ATYP=0x03)."""
    host_bytes = target_host.encode("ascii")
    if not 1 <= len(host_bytes) <= 255 or not 1 <= target_port <= 65535:
        raise CheckoutError("invalid SOCKS5 target")
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        greeting = _recv_exact(sock, 2)
        if greeting != b"\x05\x00":
            raise CheckoutError("Tor SOCKS5 handshake rejected")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", target_port)
        sock.sendall(req)
        head = _recv_exact(sock, 4)
        if head[0] != 5 or head[1] != 0:
            raise CheckoutError(f"Tor SOCKS5 connect failed (code {head[1]})")
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            (nlen,) = _recv_exact(sock, 1)
            _recv_exact(sock, nlen + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            raise CheckoutError("unexpected SOCKS5 address type")
        return sock
    except BaseException:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise CheckoutError("unexpected EOF from proxy or watcher")
        buf.extend(chunk)
    return bytes(buf)


def http_json_request(
    *,
    host: str,
    port: int,
    method: str,
    path: str,
    body: dict | None = None,
    use_tls: bool = False,
    server_name: str | None = None,
    cafile: str | None = None,
    socks_proxy: tuple[str, int] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict]:
    """Send a minimal HTTP/1.1 JSON request over Tor SOCKS5 or loopback."""
    raw_sock = (
        socks5_connect(socks_proxy[0], socks_proxy[1], host, port, timeout=timeout)
        if socks_proxy is not None
        else socket.create_connection((host, port), timeout=timeout)
    )
    conn = raw_sock
    try:
        raw_sock.settimeout(timeout)
        if use_tls:
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            conn = ctx.wrap_socket(raw_sock, server_hostname=server_name or host)
        payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        host_hdr = f"{host}:{port}" if port not in (80, 443) else host
        headers = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host_hdr}",
            "Connection: close",
            "Accept: application/json",
        ]
        if body is not None:
            headers.append("Content-Type: application/json")
            headers.append(f"Content-Length: {len(payload)}")
        conn.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + payload)
        chunks = bytearray()
        while True:
            piece = conn.recv(65536)
            if not piece:
                break
            chunks.extend(piece)
            if len(chunks) > 1_048_576:
                raise CheckoutError("response exceeded size limit")
        head, sep, body_bytes = bytes(chunks).partition(b"\r\n\r\n")
        if not sep:
            raise CheckoutError("malformed HTTP response")
        status_line = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace").split()
        if len(status_line) < 2 or not status_line[1].isdigit():
            raise CheckoutError("invalid HTTP status line")
        status = int(status_line[1])
        data = json.loads(body_bytes.decode("utf-8")) if body_bytes.strip() else {}
        if not isinstance(data, dict):
            raise CheckoutError("expected JSON object response")
        return status, data
    except (OSError, ssl.SSLError, ValueError) as err:
        raise CheckoutError(f"watcher or checkout transport failed: {err}") from None
    finally:
        conn.close()


def orchard_note_commitment(ivk: bytes, txid: bytes, block_hash: bytes, height: int, receiver: bytes, amount: int) -> bytes:
    """Deterministic Orchard note-decryption attestation bound to the checkout viewing key."""
    msg = (
        b"cpvpn/orchard-testnet-note/v1\0"
        + txid
        + block_hash
        + struct.pack("!QQ", height, amount)
        + receiver
    )
    return hmac.new(ivk, msg, hashlib.sha256).digest()


def make_http_watcher(
    *,
    operator: str,
    url: str,
    ivk: bytes,
    cafile: str | None = None,
    socks_proxy: tuple[str, int] | None = None,
) -> Watcher:
    """Create a proof-validating watcher adapter for one independent Zcash testnet operator."""
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise CheckoutError("invalid watcher URL")
    if parsed.scheme == "http" and not (parsed.hostname.endswith(".onion") or parsed.hostname == "127.0.0.1"):
        raise CheckoutError("watcher URL must use HTTPS or a Tor .onion service")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def lookup(txid: bytes, receiver: bytes) -> Note | None:
        status, data = http_json_request(
            host=parsed.hostname,
            port=port,
            method="POST",
            path=parsed.path or "/v1/orchard-note",
            body={"txid": txid.hex(), "receiver": receiver.hex()},
            use_tls=parsed.scheme == "https",
            cafile=cafile,
            socks_proxy=socks_proxy,
        )
        if status == 404 or not data.get("found"):
            return None
        if status != 200:
            raise CheckoutError("watcher query failed")
        if data.get("network") != "testnet" or data.get("pool") != "orchard":
            raise CheckoutError("non-testnet or non-shielded note rejected")
        got_txid = bytes.fromhex(data["txid"])
        block_hash = bytes.fromhex(data["block_hash"])
        got_receiver = bytes.fromhex(data["receiver"])
        height = int(data["height"])
        tip_height = int(data["tip_height"])
        amount = int(data["amount"])
        proof = bytes.fromhex(data["decryption_proof"])
        expected = orchard_note_commitment(ivk, got_txid, block_hash, height, got_receiver, amount)
        if not hmac.compare_digest(proof, expected):
            raise CheckoutError("invalid Orchard note decryption proof")
        if tip_height - height + 1 < REQUIRED_CONFIRMATIONS:
            raise CheckoutError("insufficient testnet confirmations")
        return Note(
            network="testnet",
            pool="orchard",
            txid=got_txid,
            block_hash=block_hash,
            height=height,
            tip_height=tip_height,
            receiver=got_receiver,
            amount=amount,
        )

    return Watcher(operator=operator, lookup=lookup)


def probe_lightwalletd_over_tor(host: str, port: int, socks_port: int, timeout: float = 15.0) -> dict:
    """Verify TLS reachability of an independent Zcash testnet lightwalletd host over Tor."""
    raw = socks5_connect("127.0.0.1", socks_port, host, port, timeout=timeout)
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return {
                "host": host,
                "port": port,
                "reachable": True,
                "tls_version": tls.version(),
                "alpn": tls.selected_alpn_protocol(),
            }
    finally:
        raw.close()
