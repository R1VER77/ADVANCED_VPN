"""Guard and immutable-FD tests against the actual compiled executable."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from provision import provision
from keyguard import memory_fd

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target/release/advanced-vpn"


class CliGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.exists():
            raise RuntimeError("build the release binary before CLI tests")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "state"
        self.configs = provision(self.root, "127.0.0.1:4433", "127.0.0.1:4444", adversarial=True)

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, c, ok):
        path = self.root / "check.json"
        path.write_text(json.dumps(c))
        path.chmod(0o600)
        r = subprocess.run([BINARY, "--config", path, "--check"], capture_output=True, text=True, timeout=5)
        self.assertEqual(r.returncode == 0, ok, r.stdout + r.stderr)

    def test_relay_cannot_receive_an_inner_identity(self):
        c = self.configs["relay"]
        c["inner"] = self.configs["client"]["inner"]
        self.check(c, False)

    def test_unknown_security_claim_is_rejected(self):
        c = self.configs["client"]
        c["attestation_verified"] = True
        self.check(c, False)

    def test_permission_and_symlink_guards(self):
        c = self.configs["client"]
        key = Path(c["inner"]["key"])
        key.chmod(0o644)
        self.check(c, False)
        key.chmod(0o600)
        alias = key.with_name("alias.der")
        alias.symlink_to(key)
        c["inner"]["key"] = str(alias)
        self.check(c, False)

    def test_pinned_profile_and_rates_are_required(self):
        c = self.configs["client"]
        c["mtu"] = 1400
        self.check(c, False)
        c["mtu"] = 1280
        c["packets_per_second"] = 0
        self.check(c, False)

    def test_sealed_key_fds_can_be_reused_without_disk_keys(self):
        c = self.configs["client"]
        fds = []
        args = []
        try:
            for role in ["outer", "inner"]:
                path = Path(c[role]["key"])
                fd = memory_fd(path.read_bytes())
                fds.append(fd)
                path.unlink()
                args += ["--key-fd", role + "=" + str(fd)]
            path = self.root / "check.json"
            path.write_text(json.dumps(c))
            path.chmod(0o600)
            for _ in range(2):
                r = subprocess.run(
                    [BINARY, "--config", path, "--check", *args],
                    pass_fds=fds,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            for fd in fds:
                os.close(fd)

    def test_unsealed_key_descriptor_is_rejected(self):
        c = self.configs["client"]
        fd = os.open(c["inner"]["key"], os.O_RDONLY)
        try:
            path = self.root / "check.json"
            path.write_text(json.dumps(c))
            path.chmod(0o600)
            r = subprocess.run(
                [BINARY, "--config", path, "--check", "--key-fd", "inner=" + str(fd)],
                pass_fds=[fd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertNotEqual(r.returncode, 0)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
