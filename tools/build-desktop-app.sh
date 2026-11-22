#!/bin/sh
# Build the desktop app that the native package ships (tools/native_package.py --gui):
# locked Node and Cargo dependencies, the production web build embedded in the binary
# (tauri/custom-protocol), release mode. Needs Node 22.23.5 and the WebKitGTK 4.1
# development packages (apps/cypherpunk-vpn/README.md). Build it on the release baseline
# (Ubuntu 22.04): the package refuses an app that needs a newer C library.
# Prints the built binary's path.
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../apps/cypherpunk-vpn" && pwd)
cd "$app_dir"
npm ci --ignore-scripts >&2
npm run build >&2
cargo +1.95.0 build --manifest-path src-tauri/Cargo.toml --release --locked --features tauri/custom-protocol >&2
target_dir=${CARGO_TARGET_DIR:-$app_dir/src-tauri/target}
echo "$target_dir/release/cypherpunk-vpn-gui"
