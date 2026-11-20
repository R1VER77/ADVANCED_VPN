#!/bin/sh
# Shared verification/release build, outside sensitive traffic collection.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
# The host's architecture: x86_64 or aarch64 (tools/elf_static.py checks it matches).
target="$(uname -m)-unknown-linux-musl"
rustup target add --toolchain 1.95.0 "$target"
cargo +1.95.0 build --locked --release --target "$target" \
    -p cypherpunk-preflight -p cypherpunk-bootguard -p cypherpunk-controller
mkdir -p target/release
for name in cypherpunk-preflight cypherpunk-bootguard cypherpunk-controller; do
    python3 tools/elf_static.py "target/$target/release/$name"
    install -m 0755 "target/$target/release/$name" "target/release/$name"
done
