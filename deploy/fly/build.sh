#!/bin/sh
# Build the Fly.io exit image from this tree: deploy/fly/build.sh TAG
# Stages only what the image needs (the package and the release binaries), never the
# repository, the build tree or any key.
set -eu
TAG=${1:?usage: build.sh TAG}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTX=$(mktemp -d)
trap 'rm -rf "$CTX"' EXIT
P=$CTX/package
mkdir -p "$P/bin"
for d in tools deploy third_party; do cp -r "$ROOT/$d" "$P/$d"; done
find "$P" -name __pycache__ -prune -exec rm -rf {} + 
rm -rf "$P/deploy/fly"
for b in cypherpunk-vpn cypherpunk-vpn-dns cypherpunk-vpn-cloak cypherpunk-vpn-wireguard; do
  install -m 0755 "$ROOT/target/release/$b" "$P/bin/$b"
done
cat > "$P/bin/cypherpunkctl" <<'L'
#!/bin/sh
exec /opt/cypherpunk-vpn/venv/bin/python3 -B -E -s /opt/cypherpunk-vpn/tools/cypherpunkctl.py --bin-dir /opt/cypherpunk-vpn/bin "$@"
L
chmod 0755 "$P/bin/cypherpunkctl"
cp "$ROOT/deploy/fly/Dockerfile" "$ROOT/deploy/fly/init.sh" "$ROOT/deploy/fly/systemctl" "$ROOT/deploy/fly/sudo" "$CTX/"
docker build --pull=false -q -t "$TAG" "$CTX"
