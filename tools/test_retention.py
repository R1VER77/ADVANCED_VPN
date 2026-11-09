"""The server no-retained-data checks, against fake hosts (the VM proof runs the real ones)."""

from pathlib import Path
import tempfile
import unittest

import retention

HARDENED_MOUNTS = "/dev/vda1 / ext4 rw 0 0\ntmpfs /var/log tmpfs rw,nosuid,nodev,noexec 0 0\n"
STOCK_MOUNTS = "/dev/vda1 / ext4 rw 0 0\n"
NO_SWAP = "Filename\tType\tSize\tUsed\tPriority\n"
SWAP = NO_SWAP + "/swapfile file 1048572 0 -2\n"


class Host:
    """A fake host tree with chosen mounts, swaps and running services."""

    def __init__(
        self, journal="volatile", journal_dir=False, mounts=HARDENED_MOUNTS, swaps=NO_SWAP, running=(), dbs=()
    ):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        d = self.root / "etc/systemd/journald.conf.d"
        d.mkdir(parents=True)
        (self.root / "etc/systemd/journald.conf").write_text("[Journal]\n#Storage=auto\n")
        if journal:
            (d / "50-advanced-vpn.conf").write_text("[Journal]\nStorage=%s\n" % journal)
        if journal_dir:
            (self.root / "var/log/journal").mkdir(parents=True)
        for db in dbs:
            f = self.root / db.lstrip("/")
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("x")
        (self.root / "mounts").write_text(mounts)
        (self.root / "swaps").write_text(swaps)
        self.running = set(running)

    def checks(self):
        return {
            name: ok
            for name, ok, _ in retention.checks(
                root=self.root,
                mounts=self.root / "mounts",
                swaps=self.root / "swaps",
                active=lambda unit: unit in self.running,
            )
        }


class RetentionChecks(unittest.TestCase):
    def host(self, **kw):
        h = Host(**kw)
        self.addCleanup(h.tmp.cleanup)
        return h

    def test_a_hardened_host_passes_every_check(self):
        checks = self.host().checks()
        self.assertTrue(all(checks.values()), checks)

    def test_each_way_of_keeping_logs_is_caught(self):
        cases = {
            "journal in RAM only": [dict(journal=None), dict(journal="persistent"), dict(journal_dir=True)],
            "/var/log in RAM": [dict(mounts=STOCK_MOUNTS)],
            "no disk logger running": [dict(running=["rsyslog.service"]), dict(running=["auditd.service"])],
            "no login database on disk": [dict(dbs=["/var/lib/lastlog/lastlog2.db"])],
            "no swap": [dict(swaps=SWAP)],
        }
        for name, variants in cases.items():
            for kw in variants:
                got = self.host(**kw).checks()
                self.assertFalse(got[name], (name, kw))
                # Only the broken property fails.
                self.assertEqual([k for k, ok in got.items() if not ok], [name], (name, kw))

    def test_the_last_journal_setting_wins(self):
        h = self.host(journal=None)
        conf = h.root / "etc/systemd/journald.conf.d"
        (conf / "10-early.conf").write_text("[Journal]\nStorage=persistent\n")
        (conf / "90-late.conf").write_text("[Journal]\nStorage=volatile\n")
        self.assertTrue(h.checks()["journal in RAM only"])

    def test_cloud_init_carries_exactly_the_hardening_before_sshd(self):
        ud = retention.cloud_init()
        self.assertTrue(ud.startswith("#cloud-config\nbootcmd:\n"))
        body = "\n".join(line[6:] for line in ud.splitlines()[5:])
        self.assertEqual(body.strip(), retention.HARDEN.strip())
        for unit in retention.LOGGERS:
            self.assertIn(unit, retention.HARDEN)
        for must in ("Storage=volatile", "tmpfs /var/log", "rm -rf /var/log/journal", "swapoff -a"):
            self.assertIn(must, retention.HARDEN)


if __name__ == "__main__":
    unittest.main()
