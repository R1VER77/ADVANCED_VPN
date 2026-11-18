#!/bin/sh
# Shared verification/release build, outside sensitive traffic collection.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
rustup target add --toolchain 1.95.0 x86_64-unknown-linux-musl
cargo +1.95.0 build --locked --release --target x86_64-unknown-linux-musl \
    -p cypherpunk-preflight -p cypherpunk-bootguard -p cypherpunk-controller
mkdir -p target/release
for name in cypherpunk-preflight cypherpunk-bootguard cypherpunk-controller; do
    python3 tools/elf_static.py "target/x86_64-unknown-linux-musl/release/$name"
    install -m 0755 "target/x86_64-unknown-linux-musl/release/$name" "target/release/$name"
done
