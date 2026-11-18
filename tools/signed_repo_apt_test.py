#!/usr/bin/env python3
"""Exercise real apt authentication/download in disposable, networkless containers.

Uses a supplied public key and locally cached digest-pinned image. No installation,
host keyring changes, hardware access, repository publication or private-key export.
Positive and two broken variants must behave as specified; original inputs stay intact.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import secrets

import signed_repo
from sysexec import trusted_exe

SCRIPT = r"""mkdir -p /tmp/apt/state/lists/partial /tmp/apt/cache/archives/partial /tmp/apt/log /tmp/download
cd /tmp/download
apt_case() {
 apt-get -o Dir::Etc::sourcelist=/fixture/source.list -o Dir::Etc::sourceparts=- \
  -o Dir::State=/tmp/apt/state -o Dir::Cache=/tmp/apt/cache -o Dir::Log=/tmp/apt/log \
  -o APT::Sandbox::User=root -o Acquire::Languages=none -o Acquire::PDiffs=false \
  -o Acquire::Retries=0 "$@"
}
apt_case update
printf '%s\n' CYPHERPUNK_APT_UPDATE_PASSED
apt_case download "$CYPHERPUNK_PACKAGE"
printf '%s\n' CYPHERPUNK_APT_DOWNLOAD_PASSED
sha256sum ./*.deb
"""


def container_run(docker, arguments):
    """Stop only this trial's labelled container if the client times out or exits."""
    token = secrets.token_hex(16)
    name = "cypherpunk-apt-trial-" + token
    label = "org.cypherpunk-vpn.apt-trial"
    try:
        return subprocess.run(
            [docker, "run", "--rm", "--name", name, "--label", label + "=" + token, *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    finally:
        inspected = subprocess.run(
            [docker, "inspect", "--format", '{{index .Config.Labels "' + label + '"}}', name],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if inspected.returncode == 0 and inspected.stdout.strip() == token:
            subprocess.run([docker, "rm", "--force", name], check=True, capture_output=True, timeout=30)


def run(repo, public_key, fingerprint, package, image, work):
    """Preserve scoped evidence; reject unexpected success or unrelated failure."""
    if os.geteuid() == 0:
        raise PermissionError("run the container trial as an ordinary host user")
    fingerprint = signed_repo.check_fingerprint(fingerprint)
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
        raise ValueError("a cached digest-pinned image is required")
    if not re.fullmatch(r"cypherpunk-vpn=[0-9]+\.[0-9]+\.[0-9]+(?:~[A-Za-z0-9.]+)?-1", package):
        raise ValueError("specify the exact native Debian package version")
    if any(character in str(work) for character in ",\n\r"):
        raise ValueError("work path cannot contain Docker mount separators")
    docker, gpg = trusted_exe("docker"), trusted_exe("gpg")
    subprocess.run([docker, "image", "inspect", image], check=True, stdout=subprocess.DEVNULL, timeout=30)
    work.mkdir(mode=0o755, parents=True, exist_ok=False)
    record = dict(schema=1, status="running", scope="apt_metadata_and_download_only", image=image, phases={})
    try:
        with tempfile.TemporaryDirectory(prefix="cypherpunk-apt-public-") as temporary:
            keyhome = Path(temporary)
            environment = dict(os.environ, GNUPGHOME=str(keyhome))
            subprocess.run(
                [gpg, "--no-options", "--batch", "--import", str(public_key)],
                env=environment,
                check=True,
                capture_output=True,
                timeout=30,
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(signed_repo.__file__)),
                    "verify",
                    "--repo",
                    str(repo),
                    "--fingerprint",
                    fingerprint,
                ],
                env=environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
            verified = json.loads(result.stdout)
            record["repository"] = verified
            if len(verified["packages"]) != 1:
                raise ValueError("this trial requires a single-package repository")
            name = verified["packages"][0]
            expected = signed_repo.digest(repo / "pool/main" / name, "sha256")
            source = "deb [signed-by=/fixture/keyring.gpg] file:/repo " + verified["suite"] + " main\n"
            for case in ("positive", "wrong_key", "damaged_package"):
                trial = work / case
                fixture, copied = trial / "fixture", trial / "repo"
                fixture.mkdir(mode=0o755, parents=True)
                suite = "dists/" + verified["suite"] + "/"
                for relative in (
                    "REPOSITORY.json",
                    suite + "Release",
                    suite + "Release.gpg",
                    suite + "InRelease",
                    suite + signed_repo.INDEX,
                    suite + signed_repo.INDEX + ".gz",
                    "pool/main/" + name,
                ):
                    target = copied / relative
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    with signed_repo.repository_file(repo, relative) as incoming, target.open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    target.chmod(0o644)
                (fixture / "source.list").write_text(source)
                keyring = fixture / "keyring.gpg"
                if case == "wrong_key":
                    keyring.write_bytes(b"")
                else:
                    exported = subprocess.run(
                        [gpg, "--no-options", "--batch", "--export", fingerprint],
                        env=environment,
                        check=True,
                        capture_output=True,
                        timeout=30,
                    ).stdout
                    if not exported:
                        raise ValueError("public key export was empty")
                    keyring.write_bytes(exported)
                keyring.chmod(0o644)
                if case == "damaged_package":
                    with (copied / "pool/main" / name).open("r+b") as archive:
                        first = archive.read(1)
                        archive.seek(0)
                        archive.write(bytes([first[0] ^ 1]))
                result = container_run(
                    docker,
                    [
                        "--network",
                        "none",
                        "--read-only",
                        "--cap-drop",
                        "ALL",
                        "--security-opt",
                        "no-new-privileges",
                        "--pids-limit",
                        "128",
                        "--memory",
                        "512m",
                        "--cpus",
                        "1",
                        "--tmpfs",
                        "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
                        "--mount",
                        "type=bind,source=" + str(copied) + ",target=/repo,readonly",
                        "--mount",
                        "type=bind,source=" + str(fixture) + ",target=/fixture,readonly",
                        "--env",
                        "CYPHERPUNK_PACKAGE=" + package,
                        image,
                        "/bin/sh",
                        "-ec",
                        SCRIPT,
                    ],
                )
                output = result.stdout + result.stderr
                (trial / "apt.log").write_text(output)
                updated = "CYPHERPUNK_APT_UPDATE_PASSED" in output
                downloaded = "CYPHERPUNK_APT_DOWNLOAD_PASSED" in output
                if case == "positive":
                    if result.returncode or not updated or not downloaded or expected + "  ./" not in output:
                        raise RuntimeError("real apt positive authentication/download failed")
                elif case == "wrong_key":
                    if (
                        not result.returncode
                        or updated
                        or not any(marker in output for marker in ("NO_PUBKEY", "not signed", "not be verified"))
                    ):
                        raise RuntimeError("wrong-key variant did not fail specifically at authentication")
                elif not result.returncode or not updated or downloaded or "Hash Sum mismatch" not in output:
                    raise RuntimeError("damaged package did not fail specifically at the apt checksum boundary")
                record["phases"][case] = dict(exit_code=result.returncode, update=updated, download=downloaded)
                shutil.rmtree(copied)  # Owned copies only; preserve the log and source hash.
            record.update(status="passed_real_apt_metadata_and_download", package_sha256=expected)
    except BaseException as error:
        record.update(status="failed", error=type(error).__name__ + ": " + str(error)[-1000:])
        raise
    finally:
        (work / "RESULT.json").write_text(json.dumps(record, indent=2) + "\n")


def main():
    """Select a pinned image and public inputs, without modifying any host service."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--package", required=True, help="cypherpunk-vpn=VERSION-1")
    parser.add_argument("--image", required=True, help="cached IMAGE@sha256:DIGEST")
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    run(
        args.repo.resolve(strict=True),
        args.public_key.resolve(strict=True),
        args.fingerprint,
        args.package,
        args.image,
        args.work.absolute(),
    )


if __name__ == "__main__":
    main()
