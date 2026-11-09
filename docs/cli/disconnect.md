# avpn disconnect

Stop the VPN service. The kill switch stays in place, so nothing leaks in cleartext
afterwards. To remove the kill switch, see `avpn help reset`.

## Usage

    sudo avpn disconnect

## What it changes

Stops `advanced-vpn.service`. The supervisor gets SIGTERM and shuts the data plane
down. Firewall rules stay in place.
