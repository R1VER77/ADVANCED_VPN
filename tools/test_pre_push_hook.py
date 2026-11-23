#!/usr/bin/env python3
"""The pre-push hook refuses commits not signed by a key in docs/allowed_signers.

Two commits were made with signing bypassed on 22 November 2026; the hook is the stop
before GitHub. Each test builds a scratch repository with its own throwaway signing key
and pushes to a local bare remote through the real hook.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "tools/hooks/pre-push"


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "needs git and ssh-keygen")
class PrePushHook(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = self.dir / "key"
        self.other = self.dir / "other"
        for k in (self.key, self.other):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(k)], check=True)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=str(self.dir / "gitconfig"), GIT_CONFIG_NOSYSTEM="1",
                        HOME=str(self.dir))  # fmt: skip
        self.env.pop("SSH_AUTH_SOCK", None)
        self.remote = self.dir / "remote.git"
        self.git("init", "-q", "--bare", str(self.remote), cwd=self.dir)
        self.repo = self.dir / "repo"
        self.git("init", "-q", "-b", "main", str(self.repo), cwd=self.dir)
        for k, v in (("user.name", "t"), ("user.email", "t@example.invalid"), ("gpg.format", "ssh"),
                     ("user.signingkey", str(self.key)), ("commit.gpgsign", "false"),
                     ("core.hooksPath", str(HOOK.parent))):  # fmt: skip
            self.git("config", k, v)
        self.git("remote", "add", "origin", str(self.remote))
        (self.repo / "docs").mkdir()
        pub = (self.key.with_suffix(".pub")).read_text().split()
        (self.repo / "docs/allowed_signers").write_text("t@example.invalid %s %s\n" % (pub[0], pub[1]))

    def git(self, *args, cwd=None, check=True):
        return subprocess.run(["git", *args], cwd=cwd or self.repo, env=self.env, capture_output=True, text=True,
                              check=check)  # fmt: skip

    def commit(self, name, *flags):
        (self.repo / name).write_text(name)
        self.git("add", name)
        self.git("commit", "-q", "-m", name, *flags)

    def push(self):
        return self.git("push", "-q", "origin", "main", check=False)

    def test_signed_commits_push(self):
        self.commit("a", "-S")
        self.commit("b", "-S")
        r = self.push()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_an_unsigned_commit_is_refused_and_named(self):
        self.commit("a", "-S")
        self.commit("b", "--no-gpg-sign")
        r = self.push()
        self.assertNotEqual(r.returncode, 0)
        unsigned = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertIn(unsigned, r.stderr)
        self.assertEqual(self.git("ls-remote", "origin", "main").stdout, "")  # nothing reached the remote

    def test_a_signature_by_a_key_not_listed_is_refused(self):
        self.git("config", "user.signingkey", str(self.other))
        self.commit("a", "-S")
        self.assertNotEqual(self.push().returncode, 0)

    def test_only_new_commits_are_checked_on_a_later_push(self):
        self.commit("a", "-S")
        self.assertEqual(self.push().returncode, 0)
        self.commit("b", "--no-gpg-sign")
        r = self.push()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stderr.count("is not signed"), 1)

    def test_a_missing_signer_list_refuses_everything(self):
        self.commit("a", "-S")
        (self.repo / "docs/allowed_signers").unlink()
        self.assertNotEqual(self.push().returncode, 0)


if __name__ == "__main__":
    unittest.main()
