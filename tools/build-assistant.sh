#!/bin/sh
# Build llama-server for the cypherpunk-vpn-assistant package on the release baseline.
#
#   docker run --rm -v LLAMA_SRC:/llama:ro -v OUT:/out -e HOST_UID=$(id -u) \
#       cypherpunk-vpn-build:jammy-20261118 sh /llama-build/build-assistant.sh
#
# LLAMA_SRC is a checkout of ggml-org/llama.cpp at LLAMA_REVISION (refused otherwise).
# CPU only, no network code (LLAMA_CURL off), static ggml, x86-64 with AVX2/FMA/F16C: a
# CPU without AVX2 cannot start it, and the app then falls back to the rules' own text.
set -eu
LLAMA_REVISION=54315813269112dd0baed7112ec87ad93a8218ca
[ "$(cat /llama/.revision)" = "$LLAMA_REVISION" ] || { echo "llama.cpp is not at $LLAMA_REVISION" >&2; exit 1; }
cp -a /llama /tmp/llama && cd /tmp/llama
# No web UI: the assistant is reached only over a Unix socket. This also keeps the build
# from downloading prebuilt UI assets.
rm -rf tools/ui/dist
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLAMA_CURL=OFF \
  -DGGML_NATIVE=OFF -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_F16C=ON -DGGML_OPENMP=OFF \
  -DLLAMA_BUILD_UI=OFF -DLLAMA_USE_PREBUILT_UI=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON >/dev/null
cmake --build build --target llama-server -j "$(nproc)" >/dev/null
install -m 0755 build/bin/llama-server /out/llama-server
strip /out/llama-server
ldd /out/llama-server | sed 's/ (0x[0-9a-f]*)//' > /out/llama-server.ldd
ldd --version | head -1 > /out/llama-server.glibc
printf '%s\n' "$LLAMA_REVISION" > /out/llama-server.revision
chown -R "$HOST_UID:$HOST_UID" /out
