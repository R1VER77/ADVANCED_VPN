# The mix lane lab's container: namespaces, NAT and packet capture with real internet.
# build: docker build -t avpn-mixlab:1 -f tools/mix_lab.Dockerfile tools
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 iproute2 nftables ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
