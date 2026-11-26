# cypherpunk reset

Remove the kill switch and restore cleartext networking. Disconnect first.

## Usage

    sudo cypherpunk reset --allow-cleartext
    sudo cypherpunk killswitch-disarm --allow-cleartext

In the interactive view, press `k` or enter `/killswitch-disarm`. After
confirmation, the view stops the VPN and disarms the guard. Close any
protected apps before disarming.

## Options

- `--allow-cleartext`: required. It confirms that traffic may leave unprotected afterwards.

## What it changes

- Deletes the protected namespace, if no protected programs are still running.
- Removes the nftables tables.
- Restores the routes saved at connect time.
