# Chains

A chain is the ordered list of servers your traffic crosses.

- **1 hop:** client → exit. The exit terminates WireGuard and sees your address and your destinations.
- **2 hops:** client → relay → exit. The relay sees your address but only ciphertext; the exit sees destinations but only the relay's address.
- **3 hops:** client → relay → middle → exit. The middle sees neither end.

Each hop is a separate QUIC layer (X25519MLKEM768 key exchange, ML-DSA-65
certificates). Layers are nested inside-out, so each server can unwrap only its own
layer. The WireGuard + DAITA carrier runs innermost, and travels to the first hop as
QUIC datagrams on UDP 443, so that link looks like HTTP/3. Inner packets are 1100
bytes, and each outer layer adds 56 bytes of budget.

Switch chains with `cypherpunk init` (new bundles), then `cypherpunk enroll BUNDLE --replace` on
each device.

## Saved client chains

Press `l` in the interactive view to list signed chains, import bundles, or
filter by the country or city of a hop.

    sudo cypherpunk chains list
    sudo cypherpunk chains import NAME BUNDLE
    sudo cypherpunk chains select NAME
    sudo cypherpunk chains location set exit --country DE --city Frankfurt
    sudo cypherpunk chains location set entry --chain NAME --country AE --city Dubai

Use a bundle for this device signed by its enrolled operator. Import the
original bundle if you want to switch back to a route that predates saved
chains. If you intend to leave the current route unsaved, explicitly pass
`--allow-unsaved-current` to `chains select`. Disconnect before selecting,
then connect when ready. The kill switch stays in place.

An expiry in the signed set is enforced. Older bundles may have no signed
expiry. Live servers still validate their own peer authorization.

Locations come from endpoint labels you set or a matching local operator
inventory record with a known region. Missing values appear as Unknown.
The country and city are display labels. A listed primary exit may have
a standby.
