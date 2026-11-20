#!/usr/bin/env python3
"""Build and verify the pinned offline Linux Python runtime (never during installation).

The archive hash authenticates the selected upstream artifact against the reviewed
source pin. The content manifest detects damage; release provenance/signatures must
authenticate the whole package, including this manifest, before executing its code.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile

VERSION = "3.13.18"
_RELEASE = "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/"
# One reviewed pin per processor, each the SHA-256 the release's SHA256SUMS publishes.
PINS = {
    "x86_64": (
        "x86_64-linux-gnu",
        _RELEASE + "cpython-3.13.18%2B20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "f2d2199eb25880e07863b391cf7124e7ffa1338b0d65600dfcec117c4223a7fb",
    ),
    "aarch64": (
        "aarch64-linux-gnu",
        _RELEASE + "cpython-3.13.18%2B20261110-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "55c00325f7c1fddf325dfc621aabdfbbac4dc54adda224af88ec411dc12db239",
    ),
}
# The x86-64 pin under its historical names (release and CI jobs download it).
_, ARCHIVE_URL, ARCHIVE_SHA256 = PINS["x86_64"]


def pin(machine=None):
    """(platform, archive URL, archive SHA-256) reviewed for this host's processor."""
    machine = machine or platform.machine()
    if platform.system() != "Linux" or machine not in PINS:
        raise RuntimeError("no reviewed runtime pin for %s %s" % (platform.system(), machine))
    return PINS[machine]


MANIFEST = "CYPHERPUNK_RUNTIME.json"
ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    """Hash a regular file without loading an entire runtime into memory."""
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(root):
    """List every runtime entry; refuse escaping links and unsafe special files/modes."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("runtime must be a real directory")
    if root.stat().st_mode & (0o022 | 0o7000):
        raise ValueError("unsafe runtime directory permissions")
    resolved = root.resolve()
    entries = {}
    for p in sorted(root.rglob("*")):
        name = p.relative_to(root).as_posix()
        if name == MANIFEST:
            continue
        mode = p.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(p)
            if Path(target).is_absolute() or not p.resolve().is_relative_to(resolved) or not p.exists():
                raise ValueError("runtime symlink escapes, is cyclic or is broken: " + name)
            entries[name] = dict(kind="link", target=target)
        elif stat.S_ISREG(mode) or stat.S_ISDIR(mode):
            if mode & (0o022 | 0o7000):
                raise ValueError("unsafe runtime file permissions: " + name)
            entry = dict(kind="directory" if p.is_dir() else "file", mode=stat.S_IMODE(mode))
            if p.is_file():
                entry["sha256"] = sha256(p)
            entries[name] = entry
        else:
            raise ValueError("special file in runtime: " + name)
    return entries


def verify(root, requirements):
    """Verify content and lock pin; authenticate the package before its bootstrap runs."""
    root = Path(root)
    marker = root / MANIFEST
    if (
        marker.is_symlink()
        or not marker.is_file()
        or marker.stat().st_size > 4 << 20
        or marker.stat().st_mode & (0o022 | 0o7000)
    ):
        raise ValueError("missing or unsafe bundled runtime manifest")
    m = json.loads(marker.read_text())
    platform_name, _, archive_sha256 = pin()
    expected = dict(schema=1, python=VERSION, platform=platform_name, archive_sha256=archive_sha256)
    if any(m.get(k) != value for k, value in expected.items()):
        raise ValueError("bundled runtime provenance does not match the reviewed pin")
    if m.get("requirements_sha256") != sha256(requirements):
        raise ValueError("bundled runtime dependency lock does not match this package")
    if not (root / "bin/python3").is_file() or inventory(root) != m.get("entries"):
        raise ValueError("bundled runtime files differ from the manifest")
    return m


def build(archive, output, requirements):
    """Build offline dependencies with the pinned interpreter, then publish atomically."""
    archive, output, requirements = Path(archive), Path(output), Path(requirements)
    if os.geteuid() == 0:
        raise RuntimeError("build runtime as an ordinary user, never root")
    platform_name, archive_url, archive_sha256 = pin()
    if output.exists() or output.is_symlink():
        raise FileExistsError("runtime output must not exist")
    if sha256(archive) != archive_sha256:
        raise ValueError("Python archive SHA256 does not match the reviewed pin")
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("runtime build requires Python with tarfile.data_filter")
    # Build under the destination parent, so the completed directory can be renamed.
    with tempfile.TemporaryDirectory(prefix=".cypherpunk-runtime-", dir=output.parent) as temp:
        temp = Path(temp)
        with tarfile.open(archive) as tar:
            if any(not (m.name == "python" or m.name.startswith("python/")) for m in tar.getmembers()):
                raise ValueError("unexpected archive layout")
            tar.extractall(temp, filter="data")
        runtime = temp / "python"
        python = runtime / "bin/python3"
        env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "PIP_"))}
        env.update(PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE=os.devnull)
        subprocess.run([str(python), "-E", "-s", "-c", "import sys; assert sys.version.split()[0] == '" + VERSION + "'"],
                       env=env, check=True)  # fmt: skip
        # Hash checking and binary-only wheels prevent building arbitrary dependency
        # source here. Downloads happen as this ordinary user, before installation.
        wheels = temp / "wheels"
        subprocess.run([str(python), "-E", "-s", "-m", "pip", "download", "--isolated", "--require-hashes",
                        "--only-binary=:all:", "--dest", str(wheels), "-r", str(requirements)],
                       env=env, check=True)  # fmt: skip
        subprocess.run([str(python), "-E", "-s", "-m", "pip", "install", "--isolated", "--no-index",
                        "--find-links", str(wheels), "--require-hashes", "--no-compile", "-r", str(requirements)],
                       env=env, check=True)  # fmt: skip
        subprocess.run([str(python), "-E", "-s", "-c",
                        "from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa; import fido2; "
                        "import ssl; v = tuple(map(int, ssl.OPENSSL_VERSION.split()[1].split('.'))); "
                        "assert v[:2] == (3, 5) and v >= (3, 5, 9), ssl.OPENSSL_VERSION; "
                        "mlkem.MLKEM768PrivateKey.generate(); mldsa.MLDSA65PrivateKey.generate()"],
                       env=env, check=True)  # fmt: skip
        for cache in runtime.rglob("__pycache__"):
            shutil.rmtree(cache)
        # Upstream archives can carry group-writable build-directory modes. The
        # distributed runtime must not; keep executable bits, remove special bits.
        for path in [runtime, *runtime.rglob("*")]:
            if not path.is_symlink():
                path.chmod(stat.S_IMODE(path.stat().st_mode) & ~(0o022 | 0o7000))
        m = dict(schema=1, python=VERSION, platform=platform_name, archive_url=archive_url,
                 archive_sha256=archive_sha256, requirements_sha256=sha256(requirements),
                 entries=inventory(runtime))  # fmt: skip
        (runtime / MANIFEST).write_text(json.dumps(m, sort_keys=True, indent=2) + "\n")
        (runtime / MANIFEST).chmod(0o644)
        verify(runtime, requirements)
        runtime.rename(output)
    return output


def main():
    """Build from an explicitly downloaded archive or verify an existing bundle."""
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--archive", type=Path, help="build using this hash-verified upstream archive")
    mode.add_argument("--verify", type=Path, help="verify this complete runtime without executing it")
    p.add_argument("--out", type=Path, help="new runtime output directory")
    p.add_argument("--requirements", type=Path, default=ROOT / "tools/hardware-requirements.txt")
    a = p.parse_args()
    if a.verify:
        verify(a.verify, a.requirements)
        print("Bundled runtime content and dependency lock verified.")
    else:
        if not a.out:
            p.error("--archive needs --out")
        print(build(a.archive, a.out, a.requirements))


if __name__ == "__main__":
    main()
