"""The mix lane's fetch plugin speaks only post-quantum TLS: hybrid TLS 1.3 servers are
fetched; classical-only TLS 1.3 and TLS 1.2-only servers are refused (526 / 525).

Each server is a Python TLS server under its own OpenSSL policy; the client goes through
the plugin's own re-execution into its policy (`policy_env`), as on a service node."""

import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parent
SERVER = r"""
import socket,ssl,sys
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[1],sys.argv[2])
s=socket.socket();s.bind(('127.0.0.1',0));s.listen(4);print(s.getsockname()[1],flush=True)
while True:
    c,_=s.accept()
    try:
        t=ctx.wrap_socket(c,server_side=True);req=t.recv(4096)
        t.sendall(b'HTTP/1.0 200 ok\r\n\r\n'+req.lower());t.close()
    except (ssl.SSLError,OSError):
        c.close()
"""
PROBE = r"""
import os,sys
sys.path.insert(0, sys.argv[1])
import kp_pq_fetch
kp_pq_fetch.policy_env()  # re-executes this probe under the plugin's OpenSSL policy
raw = kp_pq_fetch.fetch(b"GET https://localhost:%s/ HTTP/1.1\r\n%s\r\n" % (sys.argv[2].encode(), sys.argv[4].encode()),
                        4000, allow_local=True, cafile=sys.argv[3])
head, _, body = raw.partition(b"\r\n\r\n")
print(head.split(b"\r\n", 1)[0].decode())
print(body.decode(errors="replace"))
"""


def server_policy(groups, max_protocol=None):
    text = (
        "openssl_conf = openssl_init\n[openssl_init]\nssl_conf = ssl_sect\n[ssl_sect]\n"
        "system_default = sd\n[sd]\nGroups = %s\n" % groups
    )
    return text + ("MaxProtocol = %s\n" % max_protocol if max_protocol else "")


@unittest.skipUnless(ssl.OPENSSL_VERSION_INFO >= (3, 5), "needs Python linked with OpenSSL 3.5+ (ML-KEM)")
@unittest.skipUnless(shutil.which("openssl"), "needs the openssl tool to make a test certificate")
class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days",
             "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout",
             cls.dir / "key.pem", "-out", cls.dir / "cert.pem"],
            check=True, capture_output=True,
        )  # fmt: skip

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def first_line(self, groups, max_protocol=None, headers=""):
        conf = self.dir / ("server-%s-%s.cnf" % (groups, max_protocol))
        conf.write_text(server_policy(groups, max_protocol))
        env = {k: v for k, v in os.environ.items() if k not in ("OPENSSL_CONF", "AVPN_PQ_FETCH_POLICY")}
        srv = subprocess.Popen(
            [sys.executable, "-c", SERVER, self.dir / "cert.pem", self.dir / "key.pem"],
            stdout=subprocess.PIPE, text=True, env=dict(env, OPENSSL_CONF=str(conf)),
        )  # fmt: skip
        try:
            port = srv.stdout.readline().strip()
            r = subprocess.run(
                [sys.executable, "-c", PROBE, TOOLS, port, self.dir / "cert.pem", headers],
                capture_output=True, text=True, env=env, timeout=30,
            )  # fmt: skip
            self.echo = r.stdout.split("\n", 1)[1] if "\n" in r.stdout else ""
            return r.stdout.split("\n", 1)[0].strip() or r.stderr.strip()[-300:]
        finally:
            srv.kill()
            srv.wait(timeout=5)
            srv.stdout.close()

    def test_hybrid_tls13_is_fetched(self):
        self.assertEqual(self.first_line("X25519MLKEM768"), "HTTP/1.0 200 ok")

    def test_hybrid_among_classical_groups_is_fetched(self):
        # A server that also offers classical groups (as most do) still gets the hybrid one.
        self.assertEqual(self.first_line("X25519:X25519MLKEM768:P-256"), "HTTP/1.0 200 ok")

    def test_classical_tls13_is_refused(self):
        self.assertEqual(self.first_line("X25519:P-256").split()[1], "526")

    def test_the_site_sees_http_1_0_and_only_the_known_codings_the_client_accepts(self):
        self.assertEqual(self.first_line("X25519MLKEM768", headers="Accept-Encoding: deflate, gzip;q=0.5, x-evil\r\n"),
                         "HTTP/1.0 200 ok")  # fmt: skip
        self.assertTrue(self.echo.startswith("get / http/1.0\n"), self.echo[:80])  # text mode: \r\n read as \n
        self.assertIn("accept-encoding: gzip\n", self.echo)
        self.assertNotIn("x-evil", self.echo)
        self.first_line("X25519MLKEM768")
        self.assertNotIn("accept-encoding", self.echo)

    def test_tls12_only_is_refused(self):
        self.assertEqual(self.first_line("X25519:P-256", "TLSv1.2").split()[1], "525")


class OpenSSLTests(unittest.TestCase):
    def test_an_openssl_without_ml_kem_is_refused_at_start(self):
        sys.path.insert(0, str(TOOLS))
        import kp_pq_fetch

        with self.assertRaises(SystemExit):
            kp_pq_fetch.require_pq_openssl((3, 0, 13, 0, 15), "OpenSSL 3.0.13")
        kp_pq_fetch.require_pq_openssl((3, 5, 6, 0, 15), "OpenSSL 3.5.6")  # accepted


class EncodingTests(unittest.TestCase):
    def test_only_known_codings_the_client_accepts(self):
        sys.path.insert(0, str(TOOLS))
        import kp_pq_fetch

        def codings(value):
            return kp_pq_fetch.accepted_encodings(
                b"GET https://a.test/ HTTP/1.1\r\nAccept-Encoding: %s\r\n\r\n" % value
            )

        self.assertEqual(codings(b"gzip, deflate, br"), ["br", "gzip"])
        self.assertEqual(codings(b"br;q=1.0, GZIP ;q=0"), ["br"])  # q=0 means "not acceptable"
        self.assertEqual(codings(b"identity, compress, x-evil"), [])
        self.assertEqual(kp_pq_fetch.accepted_encodings(b"GET https://a.test/ HTTP/1.1\r\n\r\n"), [])


if __name__ == "__main__":
    unittest.main()
