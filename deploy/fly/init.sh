#!/bin/sh
# The exit's service manager on a Fly.io Machine (no systemd). Prints nothing: a Machine's
# output goes to Fly's log store, and a server keeps no logs.
exec >/dev/null 2>&1
umask 077
# RAM only: everything written while running (status, the operator's unlock key) and every
# log. The volume at /data keeps only the enrolled state and the month's metering.
mount -t tmpfs -o mode=0755,size=16m tmpfs /run
mount -t tmpfs -o nosuid,nodev,noexec,mode=0755,size=16m tmpfs /var/log
mount -t tmpfs -o mode=1777,size=16m tmpfs /tmp
swapoff -a 2>/dev/null || true
mkdir -p /data/advanced-vpn
chmod 0700 /data/advanced-vpn
ln -sfn /data/advanced-vpn /etc/advanced-vpn
# The supervisor, restarted whenever it ends (a locked server waits for `avpn cloud unlock`;
# `systemctl stop` here holds it until `start`). Same command as advanced-vpn.service.
while :; do
  if [ -f /etc/advanced-vpn/enrolled/profile.json ] && [ ! -e /run/avpn-stopped ]; then
    /opt/advanced-vpn/bin/avpnctl connect &
    echo $! > /run/avpn-supervisor.pid
    wait $!
    rm -f /run/avpn-supervisor.pid
  fi
  sleep 3
done
