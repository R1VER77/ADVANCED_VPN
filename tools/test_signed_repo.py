"""Signed repository tooling: build, signature and checksum-chain verification.

A disposable no-passphrase OpenPGP key stands in for the hardware-backed
production key; production procedure and its hardware gates are documented in
docs/SIGNED_REPOSITORY.md and are deliberately not exercised here.
"""

import json
import gzip
import os
from pathlib import Path
import subprocess
import tempfile
import time
from unittest import mock
import unittest

import native_package as package
import signed_repo as repository
from sysexec import trusted_exe
import test_bundled_runtime as runtime_tests

KEY_COMMENT = "cypherpunk signed repository test <test@example.invalid>"


def fingerprints(gnupghome):
    """All full fingerprints currently in the disposable test keyring."""
    environment = dict(os.environ, GNUPGHOME=gnupghome)
    listing = subprocess.run(
        [trusted_exe("gpg"), "--batch", "--with-colons", "--list-keys"],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    ).stdout
    return {line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")}


def generate_key(gnupghome, comment=KEY_COMMENT):
    """Create a disposable ed25519 signing key and return its full fingerprint."""
    environment = dict(os.environ, GNUPGHOME=gnupghome)
    before = fingerprints(gnupghome)
    subprocess.run(
        [
            trusted_exe("gpg"),
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            comment,
            "ed25519",
            "sign",
            "never",
        ],
        check=True,
        env=environment,
        capture_output=True,
        text=True,
    )
    created = fingerprints(gnupghome) - before
    if len(created) != 1:
        raise AssertionError("expected exactly one new key")
    return created.pop()


class SignedRepository(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gnupghome = tempfile.TemporaryDirectory(prefix="cypherpunk-gnupg-")
        cls.addClassCleanup(cls.gnupghome.cleanup)
        os.chmod(cls.gnupghome.name, 0o700)
        cls.fingerprint = generate_key(cls.gnupghome.name)
        fixture = runtime_tests.RuntimeManifest()
        fixture.setUp()
        cls.addClassCleanup(fixture.doCleanups)
        root = fixture.root / "source"
        (root / "tools").mkdir(parents=True)
        (root / "tools/hardware-requirements.txt").write_bytes(fixture.lock.read_bytes())
        (root / "tools/install-offline.sh").write_text("#!/bin/sh\nexit 99\n")
        (root / "tools/install-offline.sh").chmod(0o755)
        (root / "target/release").mkdir(parents=True)
        (root / "target/release/avpn").write_bytes(b"\x7fELF test ABI marker, never run GLIBC_2.35\x00")
        (root / "target/release/avpn").chmod(0o755)
        (root / "Cargo.toml").write_text('[package]\nversion = "1.2.3"\n')
        (root / "LICENSE").write_text("fixture license")
        output = fixture.root / "candidate-output"
        output.mkdir(mode=0o755)
        with (
            mock.patch.object(package.install, "SOURCES", ["tools", "LICENSE"]),
            mock.patch.object(package.install, "BINARIES", ["avpn"]),
        ):
            cls.package = package.debian(root, fixture.bundle, output, epoch=1_700_000_000)
        cls.addClassCleanup(os.chdir, os.getcwd())

    def setUp(self):
        environment = mock.patch.dict(os.environ, {"GNUPGHOME": self.gnupghome.name})
        environment.start()
        self.addCleanup(environment.stop)
        self.work = tempfile.TemporaryDirectory(prefix="cypherpunk-repo-")
        self.addCleanup(self.work.cleanup)
        self.base = Path(self.work.name)

    def build(self, name, **kwargs):
        """Build a repository from the fixture candidate into a fresh directory."""
        out = self.base / name
        arguments = dict(
            packages=[self.package],
            out=out,
            suite="stable",
            fingerprint=self.fingerprint,
            testing=False,
        )
        arguments.update(kwargs)
        return repository.build(**arguments), out

    def test_built_repository_verifies_and_lists_its_packages(self):
        manifest, out = self.build("first")
        suite = out / "dists/stable"
        for name in ("Release", "Release.gpg", "InRelease"):
            self.assertTrue((suite / name).is_file(), name)
        self.assertTrue((out / "pool/main" / self.package.name).is_file())
        self.assertEqual(manifest["status"], "signed_candidate")
        self.assertEqual(manifest["key_fingerprint"], self.fingerprint)
        result = repository.verify(out, self.fingerprint)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["packages"], [self.package.name])
        self.assertIn("Signed-By: " + self.fingerprint, (suite / "Release").read_text())
        entry = (suite / "main/binary-amd64/Packages").read_text()
        self.assertIn("Filename: pool/main/" + self.package.name, entry)
        self.assertIn("SHA256: ", entry)

    def test_verification_requires_the_expected_full_fingerprint(self):
        _, out = self.build("fpr")
        other = "AB" * 20
        with self.assertRaises(ValueError):
            repository.verify(out, other)
        for short in (self.fingerprint[-16:], self.fingerprint[-8:]):
            with self.assertRaises(ValueError):
                repository.verify(out, short)
        manifest = json.loads((out / repository.MANIFEST).read_text())
        with self.assertRaises(ValueError):
            tampered = dict(manifest, key_fingerprint=other)
            (out / repository.MANIFEST).write_text(json.dumps(tampered))
            repository.verify(out, self.fingerprint)

    def test_tampered_pool_package_fails_verification(self):
        _, out = self.build("pool")
        victim = out / "pool/main" / self.package.name
        original = victim.read_bytes()
        victim.write_bytes(original + b"tampered")
        with self.assertRaises(ValueError) as refused:
            repository.verify(out, self.fingerprint)
        self.assertIn("checksum mismatch", str(refused.exception))

    def test_tampered_release_metadata_fails_signature_verification(self):
        _, out = self.build("release")
        release = out / "dists/stable/Release"
        release.write_text(release.read_text() + "# tampered\n")
        with self.assertRaises(ValueError) as refused:
            repository.verify(out, self.fingerprint)
        self.assertIn("Release.gpg does not verify", str(refused.exception))

    def test_tampered_inrelease_fails_signature_verification(self):
        _, out = self.build("inrelease")
        victim = out / "dists/stable/InRelease"
        victim.write_text(victim.read_text().replace("Suite: stable", "Suite: unstable"))
        with self.assertRaises(ValueError) as refused:
            repository.verify(out, self.fingerprint)
        self.assertIn("InRelease does not verify", str(refused.exception))

    def test_tampered_index_fails_checksum_verification(self):
        _, out = self.build("index")
        index = out / "dists/stable/main/binary-amd64/Packages"
        index.write_text(index.read_text() + "# tampered\n")
        with self.assertRaises(ValueError) as refused:
            repository.verify(out, self.fingerprint)
        self.assertIn("index checksum mismatch", str(refused.exception))

    def test_build_refuses_existing_output_non_deb_and_unreadable_inputs(self):
        _, out = self.build("existing")
        with self.assertRaises(FileExistsError):
            repository.build([self.package], out, "stable", self.fingerprint, False)
        plain = self.base / "not-a-package.txt"
        plain.write_text("not a package")
        with self.assertRaises(ValueError):
            repository.build([plain], self.base / "suffix", "stable", self.fingerprint, False)
        with self.assertRaises(OSError):
            repository.build([self.base / "missing.deb"], self.base / "missing", "stable", self.fingerprint, False)
        with self.assertRaises(FileExistsError):
            repository.build([self.package, self.package], self.base / "dupe", "stable", self.fingerprint, False)
        self.assertFalse((self.base / "dupe").exists())

    def test_build_refuses_root_and_unavailable_keys(self):
        with mock.patch.object(repository.os, "geteuid", return_value=0):
            with self.assertRaises(PermissionError):
                repository.build([self.package], self.base / "root", "stable", self.fingerprint, False)
        with self.assertRaises(ValueError) as unavailable:
            repository.build([self.package], self.base / "nokey", "stable", "00" * 20, False)
        self.assertIn("not available", str(unavailable.exception))
        self.assertFalse((self.base / "nokey").exists())

    def test_testing_key_class_is_recorded_and_marked(self):
        manifest, out = self.build("testing", testing=True)
        self.assertEqual(manifest["status"], "testing_signed_candidate")
        self.assertEqual(manifest["key_class"], "testing")
        self.assertEqual(manifest["packages"][0]["name"], self.package.name)
        result = repository.verify(out, self.fingerprint)
        self.assertEqual(result["key_class"], "testing")

    def test_reproducible_date_and_index_for_equal_epoch(self):
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            _, first = self.build("repro-a")
            _, second = self.build("repro-b")
        one = first / "dists/stable"
        two = second / "dists/stable"
        self.assertEqual((one / "Release").read_text(), (two / "Release").read_text())
        self.assertEqual(
            (one / "main/binary-amd64/Packages").read_bytes(), (two / "main/binary-amd64/Packages").read_bytes()
        )
        self.assertEqual(
            (one / "main/binary-amd64/Packages.gz").read_bytes(), (two / "main/binary-amd64/Packages.gz").read_bytes()
        )
        self.assertIn("Date: Tue, 14 Nov 2023 22:13:20", (one / "Release").read_text())

    def test_repository_files_are_not_signed_by_any_ambient_key(self):
        # An unrelated second key exists in the same gnupghome; builds must keep
        # selecting the explicit fingerprint rather than gpg's default choice.
        second = generate_key(self.gnupghome.name, "cypherpunk ambient key <ambient@example.invalid>")
        self.assertNotEqual(second, self.fingerprint)
        _, out = self.build("explicit")
        status = subprocess.run(
            [
                trusted_exe("gpg"),
                "--batch",
                "--status-fd",
                "2",
                "--verify",
                str(out / "dists/stable/InRelease"),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=dict(os.environ),
        )
        self.assertIn("[GNUPG:] VALIDSIG " + self.fingerprint, status.stderr)

    def test_valid_signature_without_required_index_coverage_is_refused(self):
        _, out = self.build("unsigned-index")
        release = out / "dists/stable/Release"
        release.write_text(release.read_text().split("SHA256:", 1)[0])
        repository.sign(self.fingerprint, release, release.parent)
        with self.assertRaisesRegex(ValueError, "both required indexes"):
            repository.verify(out, self.fingerprint)

    def test_unsigned_manifest_cannot_promote_a_testing_repository(self):
        _, out = self.build("promoted", testing=True)
        path = out / repository.MANIFEST
        record = json.loads(path.read_text())
        record.update(key_class="declared-production", status="signed_candidate")
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "signed key class"):
            repository.verify(out, self.fingerprint)

    def test_signed_metadata_freshness_is_required(self):
        _, out = self.build("freshness")
        for clock in (time.time() - 86400, time.time() + repository.VALID_SECONDS + 86400):
            with self.assertRaisesRegex(ValueError, "stale, future-dated"):
                repository.verify(out, self.fingerprint, now=clock)

    def test_signed_paths_cannot_escape_and_symlinked_package_is_refused(self):
        _, out = self.build("traversal")
        suite = out / "dists/stable"
        release = suite / "Release"
        release.write_text(release.read_text().replace(" main/binary-amd64/Packages\n", " ../../outside\n"))
        repository.sign(self.fingerprint, release, suite)
        with self.assertRaisesRegex(ValueError, "signed index checksum"):
            repository.verify(out, self.fingerprint)
        _, out = self.build("linked-package")
        victim = out / "pool/main" / self.package.name
        victim.unlink()
        victim.symlink_to(self.package)
        with self.assertRaises((OSError, ValueError)):
            repository.verify(out, self.fingerprint)

    def test_signed_package_path_cannot_escape_even_with_matching_checksums(self):
        _, out = self.build("indexed-escape")
        suite = out / "dists/stable"
        path = suite / repository.INDEX
        changed = path.read_bytes().replace(b"Filename: pool/main/", b"Filename: ../../")
        path.write_bytes(changed)
        compressed = gzip.compress(changed, mtime=0)
        (suite / (repository.INDEX + ".gz")).write_bytes(compressed)
        (suite / "Release").write_text(
            repository.release(
                "stable",
                self.fingerprint,
                {repository.INDEX: changed, repository.INDEX + ".gz": compressed},
                repository.date(),
            )
        )
        repository.sign(self.fingerprint, suite / "Release", suite)
        with self.assertRaisesRegex(ValueError, "package path"):
            repository.verify(out, self.fingerprint)

    def test_manifest_digest_and_duplicate_fields_cannot_override_signed_data(self):
        _, out = self.build("manifest-hash")
        manifest = out / repository.MANIFEST
        record = json.loads(manifest.read_text())
        record["packages"][0]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "signed package index"):
            repository.verify(out, self.fingerprint)
        with self.assertRaisesRegex(ValueError, "duplicate metadata"):
            repository.parse_packages("Filename: pool/a.deb\nFilename: ../../a.deb\n")
        with self.assertRaisesRegex(ValueError, "at least one"):
            repository.build([], self.base / "empty-repository", "stable", self.fingerprint, True)
        self.assertFalse((self.base / "empty-repository").exists())

    def test_bound_signing_subkey_uses_the_expected_primary_pin(self):
        primary = generate_key(self.gnupghome.name, "cypherpunk subkey fixture <subkey@example.invalid>")
        subprocess.run(
            [
                trusted_exe("gpg"),
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                primary,
                "ed25519",
                "sign",
                "never",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        _, out = self.build("subkey", fingerprint=primary)
        self.assertEqual(repository.verify(out, primary)["fingerprint"], primary)

    def test_expired_or_revoked_status_does_not_pass_despite_validsig(self):
        valid = "[GNUPG:] VALIDSIG " + self.fingerprint + " 2026-11-18 1 0 4 0 22 10 00 " + self.fingerprint
        for rejected in ("EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "BADSIG"):
            with self.assertRaisesRegex(ValueError, "expired, revoked or invalid"):
                repository.signer(valid + "\n[GNUPG:] " + rejected + " bad\n")


if __name__ == "__main__":
    unittest.main()
