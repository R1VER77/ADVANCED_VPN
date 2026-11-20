"""The pinned OpenTofu fetcher (tools/tofu.py): nothing but the pinned archive's `tofu`."""

import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tofu  # noqa: E402


def archive(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Fetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.dict(os.environ, XDG_DATA_HOME=self.tmp.name)
        patch.start()
        self.addCleanup(patch.stop)

    def pinned(self, data):
        return mock.patch.dict(tofu.PINS, {"x86_64": ("linux_amd64", hashlib.sha256(data).hexdigest())})

    def test_only_the_pinned_archive_is_accepted_and_only_tofu_is_kept(self):
        good = archive({"tofu": b"\x7fELF binary", "LICENSE": b"MPL", "../evil": b"x"})
        urls = []
        with self.pinned(good):
            path = tofu.ensure(fetch=lambda url: urls.append(url) or good, machine="x86_64")
            self.assertEqual(path.read_bytes(), b"\x7fELF binary")
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o700")
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["ARCHIVE_SHA256", "tofu"])
            self.assertFalse((Path(self.tmp.name) / "evil").exists())
            self.assertIn("v%s/tofu_%s_linux_amd64.tar.gz" % (tofu.VERSION, tofu.VERSION), urls[0])
            # Fetched once: the next call uses the verified copy.
            tofu.ensure(fetch=lambda url: self.fail("fetched again"), machine="x86_64")

    def test_a_tampered_archive_or_one_without_tofu_is_refused(self):
        good = archive({"tofu": b"bin"})
        with self.pinned(good):
            with self.assertRaisesRegex(tofu.TofuError, "does not match the pin"):
                tofu.ensure(fetch=lambda url: archive({"tofu": b"evil"}), machine="x86_64")
            self.assertFalse(tofu.home().joinpath("tofu").exists())
        no_tofu = archive({"tofu-other": b"bin"})
        with self.pinned(no_tofu), self.assertRaisesRegex(tofu.TofuError, "no regular"):
            tofu.ensure(fetch=lambda url: no_tofu, machine="x86_64")

    def test_the_pins_cover_both_processors_and_name_the_signing_key(self):
        self.assertEqual(set(tofu.PINS), {"x86_64", "aarch64"})
        for _arch, sha in tofu.PINS.values():
            self.assertRegex(sha, "^[0-9a-f]{64}$")
        self.assertEqual(len(tofu.SIGNING_KEY), 40)
        with self.assertRaisesRegex(tofu.TofuError, "no pinned"):
            tofu.pin("riscv64")


if __name__ == "__main__":
    unittest.main()
