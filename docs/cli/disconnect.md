# avpn disconnect

Stop the VPN service. The kill switch stays in place, so nothing leaks in cleartext
afterwards. To remove the kill switch, see `avpn help reset`.

## Usage

    sudo avpn disconnect

## What it changes

Stops `advanced-vpn.service`, then also stops any supervisor running in the
foreground (`avpn connect --foreground`) for this device: stopping the service alone
reports success even when the service is inactive, which used to leave a foreground
supervisor running. Each supervisor gets SIGTERM and must exit; one that ignores it
is an error, not a success. When nothing is running, disconnect reports that and
changes nothing. Firewall rules stay in place.
