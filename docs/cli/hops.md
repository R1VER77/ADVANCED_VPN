# avpn hops

Show the enrolled chain, hop by hop, as the client reaches it.

## Usage

    sudo avpn hops

## Example

    client → relay 198.51.100.80:443 → exit 203.0.113.80:4444

## Meaning of each hop

- relay (entry): sees your address (or your upstream's, see `avpn help privacy`). It never sees your destinations.
- middle (3 hops only): sees only the relay and the exit.
- exit: sees the destinations, but only the previous hop's address.

To change the chain, see `avpn enroll --replace` and `avpn help chains`.

## What it changes

Nothing.
