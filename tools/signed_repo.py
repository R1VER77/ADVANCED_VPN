#!/usr/bin/env python3
"""Build and verify a signed flat apt repository from reviewed package candidates.

The signature authenticates repository metadata and package checksums; it is a
classical supply-chain assumption, not a substitute for release provenance. Keys
are selected only by an explicit fingerprint: production procedure uses a
dedicated hardware-backed OpenPGP key (see docs/SIGNED_REPOSITORY.md); --testing
marks a repository signed by an ordinary software key for smoke verification.
"""

import argparse
from email.utils import formatdate, parsedate_to_datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import stat
from pathlib import PurePosixPath

from sysexec import trusted_exe

ORIGIN = "cypherpunk-vpn"
ARCHITECTURE = "amd64"
SUITE_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
FINGERPRINT = re.compile(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}")
MANIFEST = "REPOSITORY.json"
INDEX = "main/binary-amd64/Packages"
INDEX_PATHS = {INDEX, INDEX + ".gz"}
ARCHIVE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~\-]*\.deb")
MAX_METADATA = 16 << 20
VALID_SECONDS = 7 * 24 * 3600


def repository_file(root, relative):
    """Open a regular repository file beneath anchored, no-follow directory FDs."""
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(p in (".", "..") for p in path.parts) or str(path) != relative:
        raise ValueError("unsafe repository path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("repository entry is not a regular file")
        return os.fdopen(descriptor, "rb")
    finally:
        os.close(directory)


def metadata(root, relative):
    """Bound metadata bytes before parsing or signature verification."""
    with repository_file(root, relative) as stream:
        value = stream.read(MAX_METADATA + 1)
    if len(value) > MAX_METADATA:
        raise ValueError("repository metadata exceeds the verification bound")
    return value


def digest(path, algorithm):
    """Hash a regular file without reading a whole package into memory."""
    h = hashlib.new(algorithm)
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def date(epoch=None):
    """RFC 2822 repository date; SOURCE_DATE_EPOCH makes builds reproducible."""
    if epoch is None:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    return formatdate(epoch, usegmt=True)


def check_fingerprint(fingerprint):
    """Accept only a full v4/v6 OpenPGP fingerprint, normalised to upper case."""
    if not FINGERPRINT.fullmatch(fingerprint or ""):
        raise ValueError("a full 40/64-hex OpenPGP fingerprint is required, not a key id")
    return fingerprint.upper()


def gpg(args, check=True):
    """Run the system gpg; GNUPGHOME and the agent decide where keys live."""
    return subprocess.run(
        [trusted_exe("gpg"), "--no-options", "--batch", "--no-auto-key-retrieve", "--no-auto-key-import"] + args,
        check=check,
        capture_output=True,
        text=True,
        env=dict(os.environ),
        timeout=120,
    )


def packages_entry(package, relative):
    """One Packages stanza: the archive's own control fields plus repository fields."""
    if package.suffix != ".deb":
        raise ValueError("only .deb candidates are indexed: " + package.name)
    fields = subprocess.run(
        [trusted_exe("dpkg-deb"), "--field", str(package)], check=True, capture_output=True, text=True, timeout=20
    ).stdout
    if len(fields.encode()) > MAX_METADATA or any(
        line.startswith(("Filename:", "Size:", "SHA256:", "SHA512:")) for line in fields.splitlines()
    ):
        raise ValueError("package control contains reserved repository fields")
    architectures = [line.split(": ", 1)[1] for line in fields.splitlines() if line.startswith("Architecture: ")]
    if architectures != [ARCHITECTURE]:
        raise ValueError("unsupported architecture in " + package.name + "; only " + ARCHITECTURE + " is published")
    return (
        fields.rstrip("\n")
        + "\nFilename: "
        + relative
        + "\nSize: "
        + str(package.stat().st_size)
        + "\nSHA256: "
        + digest(package, "sha256")
        + "\nSHA512: "
        + digest(package, "sha512")
        + "\n"
    )


def release(suite, fingerprint, indexes, created, testing=False):
    """Release metadata: the signed index checksums apt verifies against."""
    sections = []
    for algorithm in ("sha256", "sha512"):
        lines = [algorithm.upper() + ":"]
        for path, blob in sorted(indexes.items()):
            h = hashlib.new(algorithm, blob).hexdigest()
            lines.append(" " + h + " " + str(len(blob)) + " " + path)
        sections.append("\n".join(lines))
    return (
        "Origin: "
        + ORIGIN
        + "\nLabel: "
        + ORIGIN
        + "\nSuite: "
        + suite
        + "\nCodename: "
        + suite
        + "\nComponents: main\nArchitectures: "
        + ARCHITECTURE
        + "\nSigned-By: "
        + fingerprint
        + "\nDate: "
        + created
        + "\nValid-Until: "
        + formatdate(parsedate_to_datetime(created).timestamp() + VALID_SECONDS, usegmt=True)
        + "\nX-Cypherpunk-Key-Class: "
        + ("testing" if testing else "declared-production")
        + "\n"
        + "\n".join(sections)
        + "\n"
    )


def require_key(fingerprint):
    """Fail before creating any output when gpg cannot use the requested key."""
    available = gpg(["--with-colons", "--list-secret-keys", fingerprint], check=False)
    fingerprints = {line.split(":")[9] for line in available.stdout.splitlines() if line.startswith("fpr:")}
    if available.returncode or fingerprint not in fingerprints:
        raise ValueError("signing key is not available to gpg: " + fingerprint)


def sign(fingerprint, release_path, output_dir):
    """Detach-sign and clearsign Release with the explicitly selected key only."""
    require_key(fingerprint)
    gpg(
        [
            "--yes",
            "--local-user",
            fingerprint,
            "--detach-sign",
            "--digest-algo",
            "SHA512",
            "--output",
            str(output_dir / "Release.gpg"),
            str(release_path),
        ]
    )
    gpg(
        [
            "--yes",
            "--local-user",
            fingerprint,
            "--clearsign",
            "--digest-algo",
            "SHA512",
            "--output",
            str(output_dir / "InRelease"),
            str(release_path),
        ]
    )


def build(packages, out, suite, fingerprint, testing):
    """Build a flat signed repository; never overwrite an existing output."""
    if os.geteuid() == 0:
        raise PermissionError("build the repository as an ordinary user")
    if not packages:
        raise ValueError("a repository needs at least one package")
    if not SUITE_NAME.fullmatch(suite):
        raise ValueError("invalid suite name")
    fingerprint = check_fingerprint(fingerprint)
    require_key(fingerprint)
    created = date()
    stanzas = []
    records = []
    staged = []
    indexes = {}
    for candidate in packages:
        package = Path(candidate).resolve(strict=True)
        if not ARCHIVE_NAME.fullmatch(package.name):
            raise ValueError("only .deb candidates are indexed: " + package.name)
        if package.name in {row["name"] for row in records}:
            raise FileExistsError("duplicate package archive name: " + package.name)
        packages_entry(package, "pool/main/" + package.name)  # Validate before creating output.
        records.append(dict(name=package.name, sha256=digest(package, "sha256"), size=package.stat().st_size))
        staged.append((package, out / "pool/main" / package.name))
    out.mkdir(mode=0o755, parents=True, exist_ok=False)
    for package, destination in staged:
        if destination.exists():
            raise FileExistsError("refusing to overwrite: " + str(destination))
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copy2(package, destination)
        if digest(destination, "sha256") != next(row["sha256"] for row in records if row["name"] == package.name):
            raise ValueError("package changed while building: " + package.name)
        stanzas.append(packages_entry(destination, "pool/main/" + package.name))
    if not stanzas:
        raise ValueError("a repository needs at least one package")
    index = "main/binary-" + ARCHITECTURE + "/Packages"
    text = "".join(stanzas)
    dists = out / "dists" / suite
    (dists / "main" / ("binary-" + ARCHITECTURE)).mkdir(mode=0o755, parents=True)
    (dists / index).write_text(text)
    indexes[index] = text.encode()
    indexes[index + ".gz"] = gzip.compress(text.encode(), compresslevel=9, mtime=0)
    (dists / (index + ".gz")).write_bytes(indexes[index + ".gz"])
    document = release(suite, fingerprint, indexes, created, testing)
    (dists / "Release").write_text(document)
    sign(fingerprint, dists / "Release", dists)
    manifest = dict(
        schema=1,
        status="testing_signed_candidate" if testing else "signed_candidate",
        suite=suite,
        origin=ORIGIN,
        key_fingerprint=fingerprint,
        key_class="testing" if testing else "declared-production",
        created=created,
        packages=records,
        note="Hardware key backing and publication are procedure gates; this tool "
        "verifies neither. OpenPGP here is a classical supply-chain assumption.",
    )
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def signer(status_text):
    """Extract the full fingerprint gpg verified a signature with."""
    verified = []
    for line in status_text.splitlines():
        fields = line.split()
        if (
            len(fields) > 1
            and fields[0] == "[GNUPG:]"
            and fields[1]
            in {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED"}
        ):
            raise ValueError("expired, revoked or invalid OpenPGP signature")
        if len(fields) > 2 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            # GnuPG authenticates the signing subkey's primary-key binding. Pin
            # the primary fingerprint when provided, not an ambient default key.
            verified.append(check_fingerprint(fields[11] if len(fields) > 11 else fields[2]))
    if len(verified) != 1:
        raise ValueError("expected exactly one valid OpenPGP signature")
    return verified[0]


def parse_release(document):
    """Checksum lines of a Release document: path -> (algorithm, hex, size)."""
    checks = {"sha256": {}, "sha512": {}}
    algorithm = None
    for line in document.splitlines():
        if line.endswith(":") and re.fullmatch(r"(SHA256|SHA512):", line):
            algorithm = line[:-1].lower()
        elif algorithm and line.startswith(" "):
            hexdigest, size, path = line.split()
            if (
                path not in INDEX_PATHS
                or path in checks[algorithm]
                or not size.isdecimal()
                or not re.fullmatch(r"[a-f0-9]{" + str(hashlib.new(algorithm).digest_size * 2) + "}", hexdigest)
            ):
                raise ValueError("invalid or duplicate signed index checksum")
            checks[algorithm][path] = (hexdigest, int(size))
        else:
            algorithm = None
    if any(set(rows) != INDEX_PATHS for rows in checks.values()):
        raise ValueError("Release must authenticate both required indexes with SHA256 and SHA512")
    return checks


def parse_packages(text):
    """Packages stanzas as dictionaries (continuation lines fold into their field)."""
    stanzas = []
    fields = {}
    key = None
    for line in text.splitlines() + [""]:
        if not line:
            if fields:
                stanzas.append(fields)
            fields, key = {}, None
        elif line.startswith((" ", "\t")) and key:
            fields[key] += "\n" + line
        else:
            key, separator, value = line.partition(":")
            if not separator or key in fields:
                raise ValueError("invalid or duplicate metadata field")
            fields[key] = value.strip()
    return stanzas


def verify(repo, fingerprint, now=None):
    """Verify pinned signatures, required signed indexes and every indexed package.

    Signature tools see private bounded snapshots, not attacker-replaceable paths.
    The manifest is cross-checked bookkeeping; it cannot supply unsigned trust data.
    """
    import io

    repo = Path(repo).resolve(strict=True)
    fingerprint = check_fingerprint(fingerprint)
    dists = repo / "dists"
    if dists.is_symlink() or not dists.is_dir():
        raise ValueError("invalid repository distribution directory")
    suites = [p.name for p in dists.iterdir() if p.is_dir() and not p.is_symlink()]
    if len(suites) != 1 or not SUITE_NAME.fullmatch(suites[0]):
        raise ValueError("expected exactly one safe suite directory")
    suite = "dists/" + suites[0] + "/"
    manifest = json.loads(metadata(repo, MANIFEST))
    if manifest.get("schema") != 1 or manifest.get("key_fingerprint") != fingerprint:
        raise ValueError("manifest fingerprint/schema does not match the expected one")
    blobs = {name: metadata(repo, suite + name) for name in ("Release", "Release.gpg", "InRelease")}
    if not blobs["InRelease"].startswith(b"-----BEGIN PGP SIGNED MESSAGE-----"):
        raise ValueError("InRelease is not a clearsigned message")
    with tempfile.TemporaryDirectory(prefix="cypherpunk-repository-verify-") as temporary:
        private = Path(temporary)
        for name, blob in blobs.items():
            (private / name).write_bytes(blob)
        detached = gpg(
            ["--status-fd", "2", "--verify", str(private / "Release.gpg"), str(private / "Release")], check=False
        )
        if detached.returncode:
            raise ValueError("Release.gpg does not verify")
        if signer(detached.stderr) != fingerprint:
            raise ValueError("Release.gpg was signed by a different key")
        clear = gpg(["--status-fd", "2", "--verify", str(private / "InRelease")], check=False)
        if clear.returncode:
            raise ValueError("InRelease does not verify")
        if signer(clear.stderr) != fingerprint:
            raise ValueError("InRelease was signed by a different key")
        extracted = private / "InRelease.payload"
        gpg(["--output", str(extracted), "--decrypt", str(private / "InRelease")])
        if extracted.read_bytes() != blobs["Release"]:
            raise ValueError("InRelease and Release describe different metadata")
    document = blobs["Release"].decode("utf-8")
    rows = parse_packages(document)
    if len(rows) != 1:
        raise ValueError("invalid Release fields")
    fields = rows[0]
    expected = dict(
        Origin=ORIGIN,
        Label=ORIGIN,
        Suite=suites[0],
        Codename=suites[0],
        Components="main",
        Architectures=ARCHITECTURE,
        **{"Signed-By": fingerprint},
    )
    if any(fields.get(key) != value for key, value in expected.items()):
        raise ValueError("Release identity or fingerprint does not match")
    try:
        created = parsedate_to_datetime(fields["Date"])
        expires = parsedate_to_datetime(fields["Valid-Until"])
        if created.tzinfo is None or expires.tzinfo is None:
            raise ValueError("repository dates must include a timezone")
        clock = time.time() if now is None else now
        if (
            not created.timestamp() - 300 <= clock <= expires.timestamp()
            or not 0 < (expires.timestamp() - created.timestamp()) <= VALID_SECONDS
        ):
            raise ValueError("repository metadata is stale, future-dated or overlong")
    except (KeyError, TypeError, OverflowError) as error:
        raise ValueError("missing/invalid repository freshness fields") from error
    key_class = fields.get("X-Cypherpunk-Key-Class")
    if key_class not in ("testing", "declared-production") or manifest.get("key_class") != key_class:
        raise ValueError("unsigned manifest cannot change the signed key class")
    checks = parse_release(document)
    indexes = {path: metadata(repo, suite + path) for path in INDEX_PATHS}
    for algorithm, entries in checks.items():
        for path, (hexdigest, size) in entries.items():
            blob = indexes[path]
            if hashlib.new(algorithm, blob).hexdigest() != hexdigest or len(blob) != size:
                raise ValueError("index checksum mismatch: " + path)
    with gzip.GzipFile(fileobj=io.BytesIO(indexes[INDEX + ".gz"])) as compressed:
        if compressed.read(MAX_METADATA + 1) != indexes[INDEX]:
            raise ValueError("compressed and plain indexes disagree")
    stanzas = parse_packages(indexes[INDEX].decode("utf-8"))
    records = manifest.get("packages")
    if not isinstance(records, list) or not stanzas or len(stanzas) != len(records) or len(records) > 1000:
        raise ValueError("Packages count does not match the manifest")
    declared = {}
    for record in records:
        name = record.get("name")
        if not isinstance(name, str) or not ARCHIVE_NAME.fullmatch(name) or name in declared:
            raise ValueError("invalid or duplicate manifest package")
        declared[name] = record
    seen = set()
    for stanza in stanzas:
        filename = stanza.get("Filename", "")
        name = filename.removeprefix("pool/main/")
        if filename != "pool/main/" + name or not ARCHIVE_NAME.fullmatch(name) or name in seen:
            raise ValueError("unsafe or duplicate indexed package path")
        if stanza.get("Architecture") != ARCHITECTURE or name not in declared:
            raise ValueError("unexpected indexed package")
        try:
            size = int(stanza["Size"])
            if not 0 < size <= 1 << 30:
                raise ValueError("package exceeds verification bound")
            hashes = {algorithm: hashlib.new(algorithm) for algorithm in ("sha256", "sha512")}
            actual = 0
            with repository_file(repo, filename) as stream:
                for block in iter(lambda: stream.read(1 << 20), b""):
                    actual += len(block)
                    if actual > size:
                        raise ValueError("package checksum mismatch: " + filename)
                    for value in hashes.values():
                        value.update(block)
            if actual != size or any(
                value.hexdigest() != stanza.get(algorithm.upper()) for algorithm, value in hashes.items()
            ):
                raise ValueError("package checksum mismatch: " + filename)
            if declared[name].get("sha256") != stanza["SHA256"] or declared[name].get("size") != size:
                raise ValueError("manifest differs from the signed package index")
        except (KeyError, TypeError) as error:
            raise ValueError("missing package metadata") from error
        seen.add(name)
    if seen != set(declared):
        raise ValueError("indexed packages do not match the manifest")
    return dict(status="verified", suite=suites[0], fingerprint=fingerprint, key_class=key_class, packages=sorted(seen))


def main():
    """Build or verify a signed repository from reviewed artifacts only."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    making = commands.add_parser("build", help="sign a set of .deb candidates")
    making.add_argument("--packages", nargs="+", type=Path, required=True)
    making.add_argument("--out", type=Path, required=True)
    making.add_argument("--suite", default="stable")
    making.add_argument("--fingerprint", required=True)
    making.add_argument("--testing", action="store_true")
    checking = commands.add_parser("verify", help="verify a built repository")
    checking.add_argument("--repo", type=Path, required=True)
    checking.add_argument("--fingerprint", required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(args.packages, args.out, args.suite, args.fingerprint, args.testing)
        else:
            result = verify(args.repo, args.fingerprint)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit("signed repository: " + str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
