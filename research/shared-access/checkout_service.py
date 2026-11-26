"""Onion-only shielded Zcash testnet checkout service and client (public sales disabled)."""

from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
from threading import Lock, Thread
import time

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

from checkout_policy import BATCH_SIZE, CheckoutError, CheckoutLedger, Order, REQUIRED_CONFIRMATIONS  # noqa: E402
from shared_admission import Cohort, EPOCH_SECONDS, ROLES, verify_token  # noqa: E402
from zcash_watchers import http_json_request  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_signer(script: Path, payload: dict, *, timeout: float = 30.0) -> dict:
    """Invoke the local Node Privacy Pass blind-RSA helper."""
    node = shutil.which("node")
    if node is None:
        raise CheckoutError("Node.js is required for RFC 9578 blind signing")
    out = subprocess.check_output(  # noqa: S603 - local blind-RSA helper
        [node, str(script)],
        input=json.dumps(payload).encode("utf-8"),
        timeout=timeout,
    )
    return json.loads(out)


class TorOnionBridge:
    """Run an isolated Tor v3 Hidden Service forwarding port 80 to a loopback checkout server."""

    def __init__(self, target_port: int, root: Path):
        self.tor_bin = shutil.which("tor")
        if self.tor_bin is None:
            raise CheckoutError("tor binary not installed")
        self.target_port = target_port
        self.root = root
        self.socks_port = _free_port()
        self.hs_dir = root / "hs"
        self.data_dir = root / "tor-data"
        self.hs_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.hs_dir, 0o700)
        os.chmod(self.data_dir, 0o700)
        self.torrc = root / "torrc"
        self.torrc.write_text(
            "\n".join(
                [
                    f"DataDirectory {self.data_dir}",
                    f"SocksPort 127.0.0.1:{self.socks_port}",
                    f"HiddenServiceDir {self.hs_dir}",
                    "HiddenServiceVersion 3",
                    f"HiddenServicePort 80 127.0.0.1:{self.target_port}",
                    "Log notice stdout",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(self.torrc, 0o600)
        self.proc = None
        self.onion_host: str | None = None

    def start(self, *, wait_bootstrap: bool = False, timeout: float = 60.0) -> str:
        """Launch Tor, wait for the v3 `.onion` hostname (and optionally full bootstrap)."""
        self.proc = subprocess.Popen(  # noqa: S603 - isolated local tor
            [self.tor_bin, "-f", str(self.torrc)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        hostname_file = self.hs_dir / "hostname"
        deadline = time.monotonic() + timeout
        bootstrapped = not wait_bootstrap
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out = self.proc.stdout.read() if self.proc.stdout else ""
                raise CheckoutError(f"tor exited early: {out[-300:]}")
            if self.onion_host is None and hostname_file.exists():
                value = hostname_file.read_text(encoding="utf-8").strip()
                if value.endswith(".onion"):
                    self.onion_host = value
            if not bootstrapped and self.proc.stdout is not None:
                import select

                ready, _, _ = select.select([self.proc.stdout], [], [], 0.2)
                if ready:
                    line = self.proc.stdout.readline()
                    if "Bootstrapped 100%" in line:
                        bootstrapped = True
            else:
                time.sleep(0.1)
            if self.onion_host is not None and bootstrapped:
                return self.onion_host
        raise CheckoutError("timed out waiting for Tor v3 onion service")

    def stop(self):
        """Stop the isolated Tor process cleanly."""
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            if self.proc.stdout:
                self.proc.stdout.close()
            self.proc = None


class CheckoutService:
    """Loopback-only shielded testnet checkout server (disabled unless explicitly opted in)."""

    def __init__(
        self,
        *,
        ledger_path: Path,
        issuer_name: str,
        pool_name: str,
        issuer_keys: dict,
        signer_script: Path,
        watchers,
        price_zat: int = 100_000,
        order_ttl: int = 3600,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        enable_testnet_pilot: bool = False,
        now_fn=time.time,
    ):
        if not enable_testnet_pilot:
            raise CheckoutError("public sales are disabled; explicit testnet pilot opt-in is required")
        if bind_host != "127.0.0.1":
            raise CheckoutError("checkout service must bind strictly to 127.0.0.1 behind Tor")
        self.issuer_name = issuer_name
        self.pool_name = pool_name
        self.issuer_keys = issuer_keys
        self.issuer_spki = bytes.fromhex(issuer_keys["issuerSpki"])
        self.issuer_key_id = hashlib.sha256(self.issuer_spki).digest()
        self.signer_script = signer_script
        self.watchers = tuple(watchers)
        self.price_zat = price_zat
        self.order_ttl = order_ttl
        self.now_fn = now_fn
        self.ledger = CheckoutLedger(ledger_path, self.issuer_key_id)
        if not ledger_path.exists():
            self.ledger.initialize()
        self._lock = Lock()
        self._orders: dict[bytes, Order] = {}
        self._server = ThreadingHTTPServer((bind_host, bind_port), self._make_handler())
        self.port = self._server.server_address[1]
        self._thread = Thread(target=self._server.serve_forever, daemon=True)

    def _mint(self, requests: tuple[bytes, ...]) -> tuple[bytes, ...]:
        reply = run_signer(
            self.signer_script,
            {
                "op": "blind-sign",
                "issuerName": self.issuer_name,
                "privateKeyPkcs8": self.issuer_keys["privateKeyPkcs8"],
                "publicKeySpki": self.issuer_keys["publicKeySpki"],
                "requests": [r.hex() for r in requests],
            },
        )
        return tuple(bytes.fromhex(item) for item in reply["responses"])

    def _make_handler(self):
        service = self

        class CheckoutHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                """Suppress access logging so no order/client metadata is logged."""

            def _send(self, code: int, payload: dict):
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> dict:
                length = int(self.headers.get("Content-Length", "0"))
                if not 2 <= length <= 65536:
                    raise CheckoutError("invalid request size")
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(data, dict):
                    raise CheckoutError("invalid JSON body")
                return data

            def do_GET(self):  # noqa: N802
                if self.path != "/v1/health":
                    self._send(404, {"ok": False, "error": "not found"})
                    return
                now = int(service.now_fn())
                self._send(
                    200,
                    {
                        "ok": True,
                        "public_sales_enabled": False,
                        "network": "testnet",
                        "pool": "orchard",
                        "required_confirmations": REQUIRED_CONFIRMATIONS,
                        "batch_size": BATCH_SIZE,
                        "issuer_name": service.issuer_name,
                        "pool_name": service.pool_name,
                        "issuer_spki": service.issuer_spki.hex(),
                        "next_epoch": now // EPOCH_SECONDS + 1,
                    },
                )

            def do_POST(self):  # noqa: N802
                try:
                    if self.path == "/v1/order":
                        now = int(service.now_fn())
                        order = Order(
                            id=os.urandom(16),
                            receiver=os.urandom(43),
                            price=service.price_zat,
                            expires_at=now + service.order_ttl,
                        )
                        with service._lock:
                            service._orders[order.id] = order
                        self._send(
                            200,
                            {
                                "ok": True,
                                "order_id": order.id.hex(),
                                "receiver": order.receiver.hex(),
                                "price_zat": order.price,
                                "expires_at": order.expires_at,
                                "network": "testnet",
                                "pool": "orchard",
                            },
                        )
                    elif self.path == "/v1/issue":
                        body = self._read_json()
                        order_id = bytes.fromhex(body["order_id"])
                        txid = bytes.fromhex(body["txid"])
                        requests = tuple(bytes.fromhex(item) for item in body["requests"])
                        with service._lock:
                            order = service._orders.get(order_id)
                        if order is None:
                            raise CheckoutError("unknown order")
                        responses = service.ledger.issue(
                            order,
                            txid,
                            requests,
                            service.watchers,
                            service._mint,
                            now=int(service.now_fn()),
                        )
                        self._send(200, {"ok": True, "responses": [r.hex() for r in responses]})
                    else:
                        self._send(404, {"ok": False, "error": "not found"})
                except (CheckoutError, KeyError, ValueError) as err:
                    self._send(400, {"ok": False, "error": str(err)})

        return CheckoutHandler

    def start(self):
        """Start serving loopback checkout requests behind the Tor onion bridge."""
        self._thread.start()

    def stop(self):
        """Shut down the loopback checkout HTTP server."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3)


def purchase_blind_batch(
    *,
    host: str,
    port: int,
    signer_script: Path,
    pay_fn,
    socks_proxy: tuple[str, int] | None = None,
    allow_loopback_test: bool = False,
) -> dict:
    """Execute a blind testnet checkout and return a verified batch with zero order/payment metadata."""
    if not host.endswith(".onion") and not (allow_loopback_test and host == "127.0.0.1"):
        raise CheckoutError("checkout client requires a Tor .onion address")
    if host.endswith(".onion") and socks_proxy is None:
        raise CheckoutError("Tor SOCKS5 proxy is required for .onion checkout")

    status, health = http_json_request(
        host=host, port=port, method="GET", path="/v1/health", socks_proxy=socks_proxy
    )
    if status != 200 or not health.get("ok") or health.get("public_sales_enabled") is not False:
        raise CheckoutError("checkout health check failed")
    if (health.get("network"), health.get("pool")) != ("testnet", "orchard"):
        raise CheckoutError("checkout is not configured for shielded testnet")

    status, order_resp = http_json_request(
        host=host, port=port, method="POST", path="/v1/order", body={}, socks_proxy=socks_proxy
    )
    if status != 200 or not order_resp.get("ok"):
        raise CheckoutError("checkout order creation failed")

    # Caller executes shielded testnet payment to order_resp["receiver"] and returns 32-byte txid.
    txid: bytes = pay_fn(order_resp)
    if not isinstance(txid, bytes) or len(txid) != 32:
        raise CheckoutError("invalid payment txid")

    node = shutil.which("node")
    if node is None:
        raise CheckoutError("Node.js is required for RFC 9578 client unblinding")

    # Line-delimited stdin/stdout handoff keeps client unblinding state strictly in-process.
    proc = subprocess.Popen(  # noqa: S603 - local blind-RSA client
        [node, str(signer_script), "client-checkout"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        init_msg = {
            "issuerName": health["issuer_name"],
            "poolName": health["pool_name"],
            "epoch": int(health["next_epoch"]),
            "issuerSpki": health["issuer_spki"],
        }
        proc.stdin.write(json.dumps(init_msg) + "\n")
        proc.stdin.flush()
        req_line = proc.stdout.readline()
        if not req_line:
            err = proc.stderr.read()
            raise CheckoutError(f"blind client failed: {err}")
        requests_hex = json.loads(req_line)["requests"]
        status, issue_resp = http_json_request(
            host=host,
            port=port,
            method="POST",
            path="/v1/issue",
            body={
                "order_id": order_resp["order_id"],
                "txid": txid.hex(),
                "requests": requests_hex,
            },
            socks_proxy=socks_proxy,
        )
        if status != 200 or not issue_resp.get("ok"):
            raise CheckoutError(issue_resp.get("error", "blind issuance failed"))
        proc.stdin.write(json.dumps({"responses": issue_resp["responses"]}) + "\n")
        proc.stdin.close()
        pairs_line = proc.stdout.readline()
        proc.wait(timeout=15)
        if proc.returncode != 0 or not pairs_line:
            raise CheckoutError(f"blind unblinding failed: {proc.stderr.read()}")
        pairs_hex = json.loads(pairs_line)["pairs"]
    finally:
        if proc.poll() is None:
            with suppress(Exception):
                proc.kill()
            with suppress(Exception):
                proc.wait(timeout=5)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                with suppress(Exception):
                    stream.close()

    # Verify every unblinded token locally against the pinned issuer SPKI and next-epoch cohort.
    spki = bytes.fromhex(health["issuer_spki"])
    epoch = int(health["next_epoch"])
    cohorts = tuple(Cohort(health["issuer_name"], health["pool_name"], role, epoch, spki) for role in ROLES)
    for pair in pairs_hex:
        for tok_hex, cohort in zip(pair, cohorts, strict=True):
            verify_token(bytes.fromhex(tok_hex), cohort.challenge, spki)

    # Return ONLY the verified blind batch; keep order_id and txid out of client credit storage.
    return {
        "issuer_name": health["issuer_name"],
        "pool_name": health["pool_name"],
        "epoch": epoch,
        "issuer_spki": health["issuer_spki"],
        "pairs": pairs_hex,
    }


def prepare_signer_dir(target: Path) -> Path:
    """Install the pinned npm dependencies into a disposable directory and return checkout_signer.mjs."""
    src = Path(__file__).resolve().parent
    for name in ("package.json", "package-lock.json", "checkout_signer.mjs"):
        shutil.copy2(src / name, target / name)
    npm = shutil.which("npm")
    if npm is None:
        raise CheckoutError("npm is required to stage the blind-RSA signer")
    subprocess.run(  # noqa: S603 - local pinned npm install
        [npm, "--prefix", str(target), "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return target / "checkout_signer.mjs"
