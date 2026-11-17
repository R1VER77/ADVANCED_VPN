#!/bin/sh
# Verify the release's attestation/signature before executing any bundled code.
# This launcher uses the pinned package interpreter; the host needs no Python.
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x "$package_dir/runtime/bin/python3" ]; then
    printf '%s\n' 'The pinned runtime is missing; unpack and verify the complete offline release.' >&2
    exit 1
fi
exec "$package_dir/runtime/bin/python3" -B -E -s "$package_dir/tools/install.py" "$@"
