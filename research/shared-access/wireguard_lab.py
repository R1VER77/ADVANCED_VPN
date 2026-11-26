"""Nested WireGuard forwarding fixture confined to disposable Linux namespaces."""

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
from threading import Thread

from cryptography.hazmat.primitives.asymmetric import x25519


CLIENT, ENTRY, EXIT = "shared-client", "shared-entry", "shared-exit"
SCRIPT = str(Path(__file__).resolve())
DNS_QUERY = bytes.fromhex("010001000001000000000000056c6f63616c04746573740000010001")
DNS_REPLY = (
    DNS_QUERY[:2]
    + b"\x81\x80"
    + DNS_QUERY[4:6]
    + b"\x00\x01"
    + DNS_QUERY[8:]
    + bytes.fromhex("c00c00010001000000000004cb007102")
)


def command(*args, check=True, input=None):
    """Run an isolated namespace command and surface its failure."""
    return subprocess.run(args, check=check, input=input, text=True, capture_output=True, timeout=10)  # noqa: S603


def execute(namespace, *args, **kwargs):
    """Execute only inside one fixture namespace."""
    return command("ip", "netns", "exec", namespace, *args, **kwargs)


def b64(key):
    """Encode a 32-byte key for the reference WireGuard configuration tool."""
    return base64.b64encode(key).decode()


def interface(namespace, name, address, private_key, path, listen=None):
    """Create a fixture WireGuard device with no remote peers yet."""
    command("ip", "-n", namespace, "link", "add", name, "type", "wireguard")
    with path.open("x") as out:
        out.write(b64(private_key.private_bytes_raw()) + "\n")
    settings = ("listen-port", str(listen)) if listen is not None else ()
    execute(namespace, "wg", "set", name, "private-key", str(path), *settings)
    path.unlink()
    command("ip", "-n", namespace, "addr", "add", address, "dev", name)
    command("ip", "-n", namespace, "link", "set", name, "mtu", "1100" if name == "inner" else "1360", "up")


def configure(directory, keys):
    """Build isolated underlays and nested client routes using synthetic addresses."""
    for namespace in (CLIENT, ENTRY, EXIT):
        command("ip", "netns", "add", namespace)
        command("ip", "-n", namespace, "link", "set", "lo", "up")
    for left, a, right, b, subnet in (
        (CLIENT, "wan0", ENTRY, "lan0", "192.0.2"),
        (ENTRY, "wan0", EXIT, "lan0", "198.51.100"),
    ):
        command("ip", "link", "add", a, "netns", left, "type", "veth", "peer", "name", b, "netns", right)
        command("ip", "-n", left, "addr", "add", f"{subnet}.1/30", "dev", a)
        command("ip", "-n", right, "addr", "add", f"{subnet}.2/30", "dev", b)
        command("ip", "-n", left, "link", "set", a, "up")
        command("ip", "-n", right, "link", "set", b, "up")
    execute(ENTRY, "/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=1")
    execute(
        ENTRY,
        "/usr/sbin/nft",
        "-f",
        "-",
        input="""table inet shared_fixture {
 chain forward { type filter hook forward priority 0; policy drop;
  iifname "outer" oifname "wan0" ip daddr 198.51.100.2 udp dport 51831 accept
  iifname "wan0" oifname "outer" ip saddr 198.51.100.2 udp sport 51831 accept
 }
}
""",
    )
    for index, (server, role, port) in enumerate(((ENTRY, "outer", 51830), (EXIT, "inner", 51831)), start=1):
        interface(CLIENT, role, f"10.249.{index}.2/30", keys[role][0], directory / f"{role}-client")
        interface(server, role, f"10.249.{index}.1/30", keys[role][1], directory / f"{role}-server", port)
    command("ip", "-n", CLIENT, "route", "add", "198.51.100.2/32", "via", "10.249.1.1", "dev", "outer")
    command("ip", "-n", EXIT, "route", "add", "10.249.1.2/32", "via", "198.51.100.1", "dev", "lan0")


def peer_key(key):
    """Return the public key recorded by WireGuard for this peer."""
    return b64(key.public_key().public_bytes_raw())


def remove(keys, role):
    """Remove both ends of a role and leave the encounter closed."""
    client, server = keys[role]
    namespace = ENTRY if role == "outer" else EXIT
    execute(namespace, "wg", "set", role, "peer", peer_key(client), "remove")
    execute(CLIENT, "wg", "set", role, "peer", peer_key(server), "remove")


def install(keys, role, *, fail=False):
    """Install one admitted carrier with rollback after a partial update."""
    client, server = keys[role]
    namespace, subnet, endpoint, allowed = (
        (ENTRY, 1, "192.0.2.2:51830", "10.249.1.1/32,198.51.100.2/32")
        if role == "outer"
        else (EXIT, 2, "198.51.100.2:51831", "10.249.2.1/32")
    )
    try:
        execute(namespace, "wg", "set", role, "peer", peer_key(client), "allowed-ips", f"10.249.{subnet}.2/32")
        if fail:
            raise RuntimeError("fixture rejected the second install step")
        execute(CLIENT, "wg", "set", role, "peer", peer_key(server), "allowed-ips", allowed, "endpoint", endpoint)
    except BaseException:
        remove(keys, role)
        raise


def install_path(keys, expiries, now, *, fail=False):
    """Apply both role grants or remove every peer already installed."""
    if any(expiry <= now for expiry in expiries):
        raise RuntimeError("carrier authorization expired")
    install(keys, "outer")
    try:
        install(keys, "inner", fail=fail)
    except BaseException:
        remove(keys, "outer")
        raise


class Handler(BaseHTTPRequestHandler):
    """A synthetic HTTPS destination with no request logs."""

    def log_message(self, *_):
        """Keep the fixture output aggregate-only."""

    def do_GET(self):  # noqa: N802 - HTTP handler method
        """Answer the lab's application probe."""
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"shared fixture\n")


def serve(cert, key):
    """Serve only the private inner exit interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, HTTPServer(("10.249.2.1", 8443), Handler) as https:
        dns.bind(("10.249.2.1", 5300))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        Thread(target=https.serve_forever, daemon=True).start()
        print("ready", flush=True)
        while True:
            request, client = dns.recvfrom(1024)
            if request == DNS_QUERY:
                dns.sendto(DNS_REPLY, client)


def probe(cert, expectation):
    """Return successful DNS and authenticated HTTPS delivery separately."""
    results = dict(dns=False, https=False)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns:
            dns.settimeout(1)
            dns.sendto(DNS_QUERY, ("10.249.2.1", 5300))
            results["dns"] = dns.recvfrom(1024)[0] == DNS_REPLY
    except OSError:
        if expectation == "success":
            raise
    try:
        context = ssl.create_default_context(cafile=cert)
        with socket.create_connection(("10.249.2.1", 8443), timeout=1) as tcp:
            with context.wrap_socket(tcp, server_hostname="exit.vpn.test") as https:
                https.sendall(b"GET / HTTP/1.0\r\nHost: exit.vpn.test\r\n\r\n")
                response = https.makefile("rb").read()
                results["https"] = response.endswith(b"shared fixture\n")
    except OSError:
        if expectation == "success":
            raise
    print(json.dumps(results))


def run_wireguard(carrier_keys, expiries, now, tls):
    """Verify admission-gated nested forwarding and the kernel's response to peer removal."""
    mapping = Path("/proc/self/uid_map").read_text().split()
    if os.geteuid() != 0 or len(mapping) != 3 or mapping[1] == "0" or mapping[2] != "1":
        raise RuntimeError("fresh unprivileged user namespace required")
    if {link["ifname"] for link in json.loads(command("ip", "-j", "link").stdout)} != {"lo"}:
        raise RuntimeError("fresh network namespace required")
    os.umask(0o077)
    command("mount", "--make-rprivate", "/")
    command("mount", "-t", "tmpfs", "tmpfs", "/run")
    keys = {
        role: (client, x25519.X25519PrivateKey.generate())
        for role, client in zip(("outer", "inner"), carrier_keys, strict=True)
    }
    phases = {}
    with tempfile.TemporaryDirectory(prefix="cpvpn-wg-pilot-") as temp:
        directory = Path(temp)
        cert, key = directory / "cert.pem", directory / "key.pem"
        cert.write_text(tls["cert"])
        key.write_text(tls["key"])
        server = None
        try:
            configure(directory, keys)
            server = subprocess.Popen(  # noqa: S603 - fixture isolated above
                ["/usr/sbin/ip", "netns", "exec", EXIT, sys.executable, SCRIPT, "serve", str(cert), str(key)],
                stdout=subprocess.PIPE,
                text=True,
            )
            import select

            ready, _, _ = select.select([server.stdout], [], [], 5)
            if not ready or server.stdout.readline().strip() != "ready":
                raise RuntimeError("fixture exit failed to start")

            def check_phase(name, expected):
                attempt = execute(
                    CLIENT,
                    sys.executable,
                    SCRIPT,
                    "probe",
                    str(cert),
                    "success" if expected else "blocked",
                    check=False,
                )
                if attempt.returncode:
                    raise RuntimeError(attempt.stderr)
                outcome = json.loads(attempt.stdout)
                phases[name] = outcome
                if outcome != dict(dns=expected, https=expected):
                    raise RuntimeError(f"unexpected forwarding result in {name}: {outcome}")

            check_phase("before_install", False)
            try:
                install_path(keys, expiries, now, fail=True)
            except RuntimeError as error:
                if str(error) != "fixture rejected the second install step":
                    raise
            if any(
                execute(ns, "wg", "show", role, "peers").stdout.strip()
                for ns, role in (
                    (ENTRY, "outer"),
                    (EXIT, "inner"),
                    (CLIENT, "outer"),
                    (CLIENT, "inner"),
                )
            ):
                raise RuntimeError("partial peer installation was not rolled back")
            check_phase("after_rollback", False)
            install_path(keys, expiries, now)
            check_phase("both_peers", True)
            # Advance the fixture clock to the earliest grant expiry. A chain
            # cannot stay live after either hop's authorization has ended.
            stopped_at = min(expiries)
            remove(keys, "inner")
            remove(keys, "outer")
            check_phase("after_grant_expiry", False)
            try:
                install_path(keys, expiries, stopped_at)
            except RuntimeError as error:
                if str(error) != "carrier authorization expired":
                    raise
            else:
                raise RuntimeError("expired carrier was installed")
            phases["rolled_back_partial_peer"] = True
            return phases
        finally:
            if server is not None:
                server.terminate()
                server.wait(timeout=5)
                server.stdout.close()
            for namespace in (CLIENT, ENTRY, EXIT):
                command("ip", "netns", "delete", namespace, check=False)


if __name__ == "__main__":
    if sys.argv[1] == "serve":
        serve(*sys.argv[2:])
    elif sys.argv[1] == "probe":
        probe(*sys.argv[2:])
