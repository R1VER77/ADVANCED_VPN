# The exit as a Fly.io Machine image (docs/FLY_EXIT.md). Built by deploy/fly/build.sh from a
# staged context: the package (tools, deploy, third_party), the release binaries and this
# directory's shims. No systemd: deploy/fly/init.sh is the service manager.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends python3 python3-venv nftables iproute2 procps unbound ca-certificates \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /var/log/* /usr/share/doc /usr/share/man \
 && systemctl disable unbound 2>/dev/null; rm -f /etc/systemd/system/multi-user.target.wants/unbound.service; true
COPY package/ /opt/advanced-vpn/
RUN python3 -m venv /opt/advanced-vpn/venv \
 && /opt/advanced-vpn/venv/bin/python -m pip install -q --no-cache-dir --require-hashes \
      -r /opt/advanced-vpn/tools/hardware-requirements.txt \
 && rm -rf /root/.cache \
 && mkdir -p /etc/systemd/journald.conf.d \
 && printf '[Journal]\nStorage=volatile\n' > /etc/systemd/journald.conf.d/50-advanced-vpn.conf \
 && useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin advanced-vpn \
 && touch /opt/advanced-vpn/IMAGE
COPY init.sh /usr/local/sbin/avpn-fly-init
COPY systemctl /usr/local/bin/systemctl
COPY sudo /usr/local/bin/sudo
RUN chmod 0755 /usr/local/sbin/avpn-fly-init /usr/local/bin/systemctl /usr/local/bin/sudo
ENTRYPOINT ["/usr/local/sbin/avpn-fly-init"]
