# Privacy and your source address

## What each hop can know

- The first hop's network stack always sees the address its packets come from. Encryption cannot change that, and neither can zero-knowledge proofs: Bulletproofs are range proofs and have nothing to say about packet headers.
- Later hops see only the previous hop's address.
- The exit sees destinations, but not you.

## Hiding your address from the first hop

Reach the first hop through something that already hides it: an existing VPN, or
another anonymising network.

    sudo avpn preferences --upstream-interface vpn0

With an upstream interface set, the kill switch lets traffic to the first hop leave
only through that interface. If the upstream drops, the first hop becomes unreachable;
your real address is never used as a fallback. `avpn doctor --check-egress` shows the
address the first hop sees.

## Identity

This is a single-owner system, so every relay already knows the traffic is yours.
Anonymous credentials (blind tokens) would hide which of your devices connects, not
your address. They are not needed for one user.
