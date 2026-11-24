#!/bin/sh
# Build llama-server for the cypherpunk-vpn-assistant package on the release baseline.
#
#   docker run --rm --network none -v LLAMA_SRC:/llama:ro -v OUT:/out -v REPO/deploy/assistant:/llama-deploy:ro \
#       -e HOST_UID=$(id -u) \
#       cypherpunk-vpn-build:jammy-20261118 sh /llama-build/build-assistant.sh
#
# On a Jammy host: sh tools/build-assistant.sh SOURCE OUTPUT deploy/assistant
# SOURCE is an export of ggml-org/llama.cpp with its commit in .revision.
# CPU only, no remote downloads or HTTPS, static ggml, x86-64 with AVX2/FMA/F16C: a
# CPU without AVX2 cannot start it, and the app then falls back to the rules' own text.
set -eu
LLAMA_REVISION=54315813269112dd0baed7112ec87ad93a8218ca
if [ "${1:-}" = --revision ]; then
  printf '%s\n' "$LLAMA_REVISION"
  exit 0
fi
source_dir=${1:-/llama}
output_dir=${2:-/out}
deploy_dir=${3:-/llama-deploy}
[ -f "$source_dir/.revision" ] && [ "$(cat "$source_dir/.revision")" = "$LLAMA_REVISION" ] || {
  echo "llama.cpp is not at $LLAMA_REVISION" >&2
  exit 1
}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$output_dir"
cp -a "$source_dir" "$work_dir/llama"
# No web UI: the assistant is reached only over a Unix socket. This also keeps the build
# from downloading prebuilt UI assets.
rm -rf "$work_dir/llama/tools/ui/dist"
cmake -S "$work_dir/llama" -B "$work_dir/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DLLAMA_CURL=OFF -DLLAMA_OPENSSL=OFF \
  -DGGML_NATIVE=OFF -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON -DGGML_OPENMP=OFF \
  -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON >/dev/null
cmake --build "$work_dir/build" --target llama-server --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-$(nproc)}" >/dev/null
install -m 0755 "$work_dir/build/bin/llama-server" "$output_dir/llama-server"
strip "$output_dir/llama-server"
# The launcher that gives llama-server its network-less namespace (deploy/assistant).
gcc -O2 -Wall -Wextra -Werror -o "$output_dir/isolate" "$deploy_dir/isolate.c"
strip "$output_dir/isolate"
ldd "$output_dir/llama-server" | sed 's/ (0x[0-9a-f]*)//' > "$output_dir/llama-server.ldd"
ldd --version | head -1 > "$output_dir/llama-server.glibc"
printf '%s\n' "$LLAMA_REVISION" > "$output_dir/llama-server.revision"
# The server binary does not carry the notices embedded by llama.cpp's CLI app.
{
  printf '%s\n\n' 'llama.cpp and ggml'
  cat "$source_dir/LICENSE"
  printf '\n%s\n\n' cpp-httplib
  cat "$source_dir/vendor/cpp-httplib/LICENSE"
  printf '\n%s\n\n' 'JSON for Modern C++'
  cat "$source_dir/licenses/LICENSE-jsonhpp"
} > "$output_dir/llama-server.licenses"
if [ -n "${HOST_UID:-}" ]; then
  chown "$HOST_UID:$HOST_UID" "$output_dir/llama-server" "$output_dir/isolate" \
    "$output_dir/llama-server.ldd" "$output_dir/llama-server.glibc" "$output_dir/llama-server.revision" \
    "$output_dir/llama-server.licenses"
fi
