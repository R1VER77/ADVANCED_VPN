"""The pinned OpenTofu binary for cloud provisioning (docs/INSTALL_AND_SETUP_PLAN.md phase 3).

Standard library only: `avpn cloud` runs under the system Python.

The pin was made once, by hand: the release's SHA256SUMS verified against its GPG
signature by OpenTofu's signing key, whose fingerprint was cross-checked in OpenTofu's own
installer scripts and tofudl sources. At run time nothing is trusted from the network: the
archive is fetched once, refused unless it matches the pinned SHA-256, and only its `tofu`
binary is kept, in the user's data directory.
"""

import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

VERSION = "1.13.9"
SIGNING_KEY = "E3E6E43D84CB852EADB0051D0C0AF313E5FD9F80"  # OpenTofu, core@opentofu.org
PINS = {
    "x86_64": ("linux_amd64", "b34b327cc1ef07178207b6f2cd1f5276537d3e5b7be316500f6dac50d4c0a857"),
    "aarch64": ("linux_arm64", "5dc196dde75b667e4806d358310ec96742774cd0993c54c1237efee5644b69b8"),
}
URL = "https://github.com/opentofu/opentofu/releases/download/v{v}/tofu_{v}_{arch}.tar.gz"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 192 * 1024 * 1024


class TofuError(RuntimeError):
    """The pinned OpenTofu could not be provided."""


def pin(machine=None):
    """(archive arch, sha256) for this processor."""
    machine = machine or platform.machine()
    if machine not in PINS:
        raise TofuError("no pinned OpenTofu for %s" % machine)
    return PINS[machine]


def home():
    """Where the pinned binary lives (user data, outside ~/.cache, which cleaners empty)."""
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "advanced-vpn" / "tofu" / VERSION


def extract_binary(archive, sha256):
    """The `tofu` binary from a release archive, after checking the archive's hash."""
    if len(archive) > MAX_ARCHIVE:
        raise TofuError("archive too large")
    got = hashlib.sha256(archive).hexdigest()
    if got != sha256:
        raise TofuError("OpenTofu archive does not match the pin (got %s)" % got)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        member = next((m for m in tf.getmembers() if m.name == "tofu"), None)
        if member is None or not member.isfile() or member.size > MAX_BINARY:
            raise TofuError("the archive has no regular `tofu` file")
        return tf.extractfile(member).read()


def ensure(fetch=None, machine=None):
    """Path to the pinned `tofu`, fetched and verified on first use."""
    arch, sha256 = pin(machine)
    target = home() / "tofu"
    stamp = home() / "ARCHIVE_SHA256"
    if target.is_file() and stamp.is_file() and stamp.read_text().strip() == sha256:
        return target
    fetch = fetch or _download
    binary = extract_binary(fetch(URL.format(v=VERSION, arch=arch)), sha256)
    home().mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=home(), prefix=".tofu-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(binary)
        os.chmod(tmp, 0o700)  # this user's tool only
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    stamp.write_text(sha256 + "\n")
    return target


def _download(url):
    with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310 (a fixed https:// URL, hash-pinned)
        data = r.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise TofuError("archive too large")
    return data
