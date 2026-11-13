# The mix lane lab's container: namespaces, NAT and packet capture with real internet,
# and the post-quantum fetch plugin's needs (python3-cbor2; OpenSSL 3.5 from trixie).
# build: docker build -t avpn-mixlab:2 -f tools/mix_lab.Dockerfile tools
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-cbor2 openssl iproute2 nftables ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
