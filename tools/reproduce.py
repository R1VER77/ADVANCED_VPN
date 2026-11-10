#!/usr/bin/env python3
"""Compare two fresh release builds from different source/output directories.

Same host/toolchain/dependency cache, independent Cargo build trees. This is not
cross-machine reproducibility or a signed supply-chain attestation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work", type=Path, required=True)
    a = p.parse_args()
    a.work.mkdir(mode=0o700, parents=False, exist_ok=False)
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    hashes = []
    for name in ["a", "b"]:
        dest = a.work / name
        dest.mkdir(mode=0o700)
        for f in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]:
            shutil.copy2(root / f, dest / f)
        for d in ["src", ".cargo"]:
            shutil.copytree(root / d, dest / d)
        env = dict(os.environ)
        env.pop("RUSTFLAGS", None)
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
            [
                "--remap-path-prefix=" + str(dest.resolve()) + "=/src/advanced-vpn",
                "--remap-path-prefix=" + str(cargo_home) + "=/cargo",
            ]
        )
        env["CARGO_INCREMENTAL"] = "0"
        env["CARGO_BUILD_JOBS"] = "1"
        subprocess.run(["cargo", "build", "--release", "--locked", "--offline"], cwd=dest, env=env, check=True)
        hashes.append(
            {
                binary: hashlib.sha256((dest / "target/release" / binary).read_bytes()).hexdigest()
                for binary in ["advanced-vpn", "advanced-vpn-wireguard", "advanced-vpn-dns", "advanced-vpn-cloak"]
            }
        )
    result = dict(
        schema=2,
        same_host=True,
        independent_source_and_build_directories=True,
        source_prefix_remapped=True,
        binary_sha256=hashes,
        match=hashes[0] == hashes[1],
    )
    (a.work / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    if not result["match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
