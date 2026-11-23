#!/bin/sh
# Verify the release's attestation/signature before executing any bundled code.
# This launcher uses the pinned package interpreter; the host needs no Python.
set -eu
package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_mode=0
operator_only=0
removal=0
package_managed=0
protection=none
previous=
for argument do
    case "$previous" in
        --protect) protection=$argument ;;
    esac
    case "$argument" in
        --apply) install_mode=1 ;;
        --user) install_mode=1; operator_only=1 ;;
        --uninstall) removal=1 ;;
        --package-managed) package_managed=1 ;;
    esac
    previous=$argument
done
if [ "$install_mode" = 1 ] && [ "$removal" = 0 ]; then
    preflight=$package_dir/target/release/cypherpunk-preflight
    if [ ! -x "$preflight" ]; then
        printf '%s\n' 'The static preflight is missing; obtain the complete verified release.' >&2
        exit 1
    fi
    if [ "$operator_only" = 1 ]; then
        "$preflight" --package "$package_dir" --target "${XDG_DATA_HOME:-$HOME/.local/share}/cypherpunk-vpn" --operator-only
    elif [ "$package_managed" = 1 ]; then
        # Inside apt: one line when the checks pass, the full report only when they do not.
        if report=$("$preflight" --package "$package_dir" --target /opt --protect "$protection"); then
            printf '%s\n' 'cypherpunk-vpn: host checks passed.'
        else
            printf '%s\n' "$report" >&2
            exit 1
        fi
    else
        "$preflight" --package "$package_dir" --target /opt --protect "$protection"
    fi
fi
if [ ! -x "$package_dir/runtime/bin/python3" ]; then
    printf '%s\n' 'The pinned runtime is missing; unpack and verify the complete offline release.' >&2
    exit 1
fi
exec "$package_dir/runtime/bin/python3" -B -E -s "$package_dir/tools/install.py" "$@"
