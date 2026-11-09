# Chains

A chain is the ordered list of servers your traffic crosses.

- **1 hop:** client → exit. The exit terminates WireGuard and sees your address and your destinations.
- **2 hops:** client → relay → exit. The relay sees your address but only ciphertext; the exit sees destinations but only the relay's address.
- **3 hops:** client → relay → middle → exit. The middle sees neither end.

Each hop is a separate QUIC layer (X25519MLKEM768 key exchange, ML-DSA-65
certificates). Layers are nested inside-out, so each server can unwrap only its own
layer. The WireGuard + DAITA carrier runs innermost. Inner packets are 1100 bytes,
and each outer layer adds 56 bytes of budget.

Switch chains with `avpn init` (new bundles), then `avpn enroll BUNDLE --replace` on
each device.
