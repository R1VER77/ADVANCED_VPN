# avpn reset

Remove the kill switch and restore cleartext networking. Disconnect first.

## Usage

    sudo avpn reset --allow-cleartext

## Options

- `--allow-cleartext`: required. It confirms that traffic may leave unprotected afterwards.

## What it changes

- Deletes the protected namespace, if no protected programs are still running.
- Removes the nftables tables.
- Restores the routes saved at connect time.
