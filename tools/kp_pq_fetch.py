#!/usr/bin/env python3
"""The mix lane's fetch service: a Katzenpost service-node plugin (protocol 2) that fetches
web pages for mixnet clients over post-quantum TLS only.

Katzenpost's own HTTP proxy uses Go's TLS defaults, which still allow TLS 1.2 and a
classical key exchange to the website. This plugin replaces it on the service node, as a
separate process (our code; Katzenpost stays unmodified), and is wire-compatible with
Katzenpost's unmodified `http-proxy-client`: requests are raw HTTP requests, replies a
CBOR map {"Payload": raw HTTP response}.

TLS policy, enforced by OpenSSL itself (this process re-executes itself under a private
OPENSSL_CONF): TLS 1.3 only, and X25519MLKEM768 as the only key-exchange group. A site
that cannot complete such a handshake is refused, never fetched classically:
  525  the site offers no TLS 1.3
  526  the site offers no post-quantum key exchange (or the handshake failed otherwise)
Every successful fetch therefore used hybrid post-quantum key exchange.

usage (as the service node's plugin Command): kp_pq_fetch.py [-key value ...]
"""

import ipaddress
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
from urllib.parse import urlsplit

PQ_GROUP = "X25519MLKEM768"
OPENSSL_POLICY = (
    "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\n"
    "system_default = system_default_sect\n[system_default_sect]\nMinProtocol = TLSv1.3\n"
    "Groups = %s\n" % PQ_GROUP
)
FETCH_TIMEOUT = 20


def policy_env():
    """Re-exec under the post-quantum OpenSSL policy unless already running under it."""
    if os.environ.get("AVPN_PQ_FETCH_POLICY") == "1":
        return
    conf = Path(tempfile.mkdtemp(prefix="avpn-pqfetch-")) / "openssl.cnf"
    conf.write_text(OPENSSL_POLICY)
    env = dict(os.environ, OPENSSL_CONF=str(conf), AVPN_PQ_FETCH_POLICY="1")
    # orig_argv keeps the interpreter's own options (a script path, -m or -c) intact.
    os.execve(sys.executable, [sys.executable, *sys.orig_argv[1:]], env)


def context(cafile=None):
    """TLS 1.3 only; the key-exchange group list comes from the OpenSSL policy."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def status(code, reason):
    """A minimal HTTP response with status `code`."""
    return ("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % (code, reason)).encode()


def fetch(raw_request, limit, allow_local=False, cafile=None):
    """Fetch the absolute-URI request in `raw_request`; returns raw HTTP response bytes.
    `allow_local` and `cafile` exist for the tests' loopback servers only."""
    try:
        head = raw_request.split(b"\r\n", 1)[0].decode("ascii")
        method, url, _ = head.split(" ", 2)
        parts = urlsplit(url)
        if method not in ("GET", "HEAD") or parts.scheme != "https" or not parts.hostname:
            return status(400, "Bad Request")
        host, port = parts.hostname, parts.port or 443
        addr = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        ip = ipaddress.ip_address(addr[0])
        if not ip.is_global and not allow_local:
            return status(403, "Forbidden")
    except (ValueError, OSError, UnicodeDecodeError):
        return status(502, "Bad Gateway")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    request = (
        "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        % (method, path, host)
    ).encode()
    try:
        with socket.create_connection(addr, FETCH_TIMEOUT) as raw:
            try:
                tls = context(cafile).wrap_socket(raw, server_hostname=host)
            except ssl.SSLError as e:
                text = str(e).lower()
                if "protocol" in text and "version" in text:
                    return status(525, "TLS 1.3 Unavailable")
                return status(526, "Post-Quantum Key Exchange Unavailable")
            with tls:
                tls.settimeout(FETCH_TIMEOUT)
                tls.sendall(request)
                out = b""
                while len(out) < limit:
                    try:
                        chunk = tls.recv(16384)
                    except (OSError, ssl.SSLError):
                        break  # many servers close without close_notify
                    if not chunk:
                        break
                    out += chunk
    except OSError:
        return status(502, "Bad Gateway")
    if not out.startswith(b"HTTP/"):
        return status(502, "Bad Gateway")
    if len(out) > limit:
        # Headers only, if the body does not fit one reply.
        head, _, _ = out.partition(b"\r\n\r\n")
        out = head[: limit - 4] + b"\r\n\r\n"
    return out


def reply_payload(raw_response, limit):
    """The reply in Katzenpost's proxy format: CBOR {"Payload": raw response}, within `limit`."""
    import cbor2

    payload = cbor2.dumps({"Payload": raw_response})
    while len(payload) > limit and raw_response:
        raw_response = raw_response[: len(raw_response) * 3 // 4]
        payload = cbor2.dumps({"Payload": raw_response})
    return payload


def serve(path, limit):
    """Listen on the host's socket; answer each request on its own thread."""
    import cbor2

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    print(path, flush=True)
    conn, _ = srv.accept()
    rfile = conn.makefile("rb")
    lock = threading.Lock()

    def answer(req):
        if req.get("IsParametersRequest"):
            resp = {"IsParametersResponse": True, "Params": {"pq_tls_group": PQ_GROUP}}
        else:
            raw = fetch(req.get("Payload") or b"", max(256, limit - 64))
            resp = {
                "RequestAt": req.get("RequestAt"),
                "Delay": req.get("Delay", 0),
                "ID": req.get("ID", 0),
                "Payload": reply_payload(raw, limit),
                "SURB": req.get("SURB"),
            }
        data = cbor2.dumps(resp)
        with lock:
            conn.sendall(data)

    while True:
        try:
            req = cbor2.load(rfile)
        except (EOFError, cbor2.CBORDecodeError, OSError):
            return
        threading.Thread(target=answer, args=(req,), daemon=True).start()


def main():
    """Entry point: the host hands us a socket path (protocol 2) and the payload length."""
    policy_env()
    if os.environ.get("KATZENPOST_PLUGIN_PROTOCOL") != "2" or not os.environ.get("KATZENPOST_PLUGIN_SOCKET"):
        raise SystemExit("kp_pq_fetch.py runs as a Katzenpost service-node plugin (protocol 2)")
    limit = int(os.environ.get("KATZENPOST_PLUGIN_USER_FORWARD_PAYLOAD_LENGTH") or "2000")
    serve(os.environ["KATZENPOST_PLUGIN_SOCKET"], limit)


if __name__ == "__main__":
    main()
