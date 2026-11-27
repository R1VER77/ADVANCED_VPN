#!/usr/bin/env bash
# Reproducible offline verification script for independent third-party auditors.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
if [ ! -x "$PYTHON" ]; then
  PYTHON="$(command -v python3)"
fi
export PATH="$(dirname "$PYTHON"):$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

echo "=== 1. Rust formatting, lint (-D warnings), and locked offline tests ==="
cargo fmt --check
cargo clippy --locked --offline \
  --lib --bin cypherpunk-vpn --bin cypherpunk-vpn-cloak \
  --bin cypherpunk-vpn-wireguard --bin cypherpunk-vpn-dns \
  --bin cypherpunk --test cypherpunk_cli -- -D warnings
cargo test --locked --offline --lib
cargo test --locked --offline --bin cypherpunk-vpn-dns
cargo test --locked --offline --test cypherpunk_cli

echo "=== 2. Python unit & integration suites ==="
PYTHONPATH="$ROOT/tools" "$PYTHON" -m unittest \
  tools/test_i2p.py \
  tools/test_roadmap_scaffolds.py \
  tools/test_shared_admission.py \
  tools/test_shared_session.py \
  tools/test_docs.py \
  tools/test_controller_json.py \
  tools/test_server_fees.py
"$PYTHON" -m unittest discover -s research/shared-access -p 'test_*.py'

echo "=== 3. Tamarin formal models & mutant falsification (when installed) ==="
if command -v tamarin-prover >/dev/null 2>&1; then
  "$PYTHON" tools/tamarin_check.py \
    formal/shared/shared_pq_handshake.spthy \
    formal/shared/shared_pq_credits.spthy \
    formal/cloak/cloak.spthy \
    formal/link/link.spthy
else
  echo "SKIP: tamarin-prover not found on PATH"
fi

echo "=== 4. Live Linux namespace leak-direction labs (when unshare available) ==="
if command -v unshare >/dev/null 2>&1; then
  unshare --user --map-root-user --net -- "$PYTHON" tools/tor_lab.py
  if [ -x "$ROOT/target/release/cypherpunk-vpn-wireguard" ]; then
    unshare --user --map-root-user --net --mount -- "$PYTHON" \
      research/shared-access/gotatun_shared_lab.py \
      --bin "$ROOT/target/release/cypherpunk-vpn-wireguard"
  fi
fi

echo "=== AUDIT VERIFICATION COMPLETE ==="
