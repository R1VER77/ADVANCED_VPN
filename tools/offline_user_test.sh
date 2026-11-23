#!/bin/sh
# Run as an ordinary user inside a disposable container with --network none.
# The read-only release is at /package; HOME is an empty writable location.
set -eu
test "$(id -u)" != 0
if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'This test requires a base image with no host Python.' >&2
    exit 1
fi
mkdir -p "$HOME/.config/cypherpunk-vpn"
printf '{"schema":1,"resources":{}}\n' > "$HOME/.config/cypherpunk-vpn/cloud.json"
/package/install.sh --user
cypherpunk="$HOME/.local/bin/cypherpunk"
"$cypherpunk" --version
"$cypherpunk" --json --state "$HOME/no-state" hops > "$HOME/hops.json"
"$cypherpunk" --json cloud status > "$HOME/cloud.json"
/package/runtime/bin/python3 -B -E -s -c 'import json,sys; assert all(json.load(open(p))["ok"] for p in sys.argv[1:])' "$HOME/hops.json" "$HOME/cloud.json"
/package/install.sh --user
"$cypherpunk" --version
/package/runtime/bin/python3 -B -E -s /package/tools/bundled_runtime.py --verify "$HOME/.local/share/cypherpunk-vpn/app/venv"
/package/install.sh --user --uninstall
test ! -e "$cypherpunk"
test -f "$HOME/.config/cypherpunk-vpn/cloud.json"
printf '%s\n' OFFLINE_USER_PASS
