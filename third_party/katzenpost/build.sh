#!/bin/sh
# Build the Katzenpost programs the mix lane runs, unmodified, from the pinned release.
# They are separate AGPL-3.0 processes: nothing of ours links them or is linked by them.
#
# usage: third_party/katzenpost/build.sh OUT_DIR
# Needs git and Docker (the official golang image). The source is checked out at the
# pinned commit and verified; the binaries' SHA-256 are printed for SOURCES.json.
set -eu
TAG=v0.0.110
COMMIT=bd15cab2f568167667478f7ac225576e4a993a94
IMAGE=golang:1.26-bookworm
PROGRAMS="dirauth server genconfig kpclientd http-proxy-client http-proxy-server"
OUT=$(realpath "${1:?usage: build.sh OUT_DIR}")
mkdir -p "$OUT"
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT
git clone -q --depth 1 --branch "$TAG" https://github.com/katzenpost/katzenpost "$SRC/katzenpost"
test "$(git -C "$SRC/katzenpost" rev-parse HEAD)" = "$COMMIT" || { echo "tag $TAG is not $COMMIT" >&2; exit 1; }
docker run --rm -v "$SRC/katzenpost:/src:ro" -v "$OUT:/out" -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false \
    -e GOCACHE=/tmp/build -e GOMODCACHE=/tmp/mod -w /src "$IMAGE" sh -c "
    set -e
    for c in $PROGRAMS; do
        (cd cmd/\$c && go build -trimpath -ldflags '-extldflags=-Wl,-z,stack-size=0x1F40000 -buildid=' -o /out/\$c .)
    done
    chown -R $(id -u):$(id -g) /out"
cd "$OUT" && sha256sum $PROGRAMS
