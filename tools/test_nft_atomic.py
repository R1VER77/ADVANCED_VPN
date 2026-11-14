"""Kill-switch tables are replaced atomically, even by concurrent writers.

The supervisor and every app launch both rebuild the app namespace's kill switch. With
"list, then delete if present", two writers could both see the table absent and both
add it; nft appends, so every rule was doubled, the drift watchdog remembered the
doubled table and then fought the correct one (seen in CI as "the kill switch was not
restored"). This runs real nft in a throwaway user+network namespace."""

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent

RACE = r"""
import multiprocessing as mp, subprocess, sys
sys.path.insert(0, sys.argv[1])
import avpnctl

BODY = '''table inet advanced_vpn {
 chain output { type filter hook output priority -100; policy drop;
  oifname "lo" accept
 }
}
'''

def writer(barrier):
    barrier.wait()
    avpnctl.replace_table(BODY)

doubled = 0
for _ in range(int(sys.argv[2])):
    subprocess.run(["/usr/sbin/nft", "delete", "table", "inet", "advanced_vpn"], capture_output=True)
    b = mp.Barrier(2)
    ps = [mp.Process(target=writer, args=(b,)) for _ in range(2)]
    [p.start() for p in ps]
    [p.join() for p in ps]
    assert all(p.exitcode == 0 for p in ps)
    out = subprocess.run(["/usr/sbin/nft", "list", "table", "inet", "advanced_vpn"],
                         capture_output=True, text=True, check=True).stdout
    doubled += out.count('oifname "lo" accept') != 1
print(doubled)
"""


def can_unshare():
    if not (os.path.exists("/usr/sbin/nft") and shutil.which("unshare")):
        return False
    return subprocess.run(["unshare", "-Urn", "true"], capture_output=True).returncode == 0


@unittest.skipUnless(can_unshare(), "needs nft and unprivileged user namespaces")
class ConcurrentReplaceTests(unittest.TestCase):
    def test_two_writers_at_once_leave_exactly_one_copy(self):
        r = subprocess.run(
            ["unshare", "-Urn", sys.executable, "-c", RACE, str(TOOLS), "60"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        self.assertEqual(r.stdout.strip(), "0", "concurrent replaces doubled the kill switch")


if __name__ == "__main__":
    unittest.main()
