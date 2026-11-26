# Privacy and your source address

## What each hop can know

- The first hop's network stack always sees the address its packets come from. Encryption cannot change that, and neither can zero-knowledge proofs: Bulletproofs are range proofs and have nothing to say about packet headers.
- Later hops see only the previous hop's address.
- The exit sees destinations and connection timing. A managed-profile exit can also recognize the client credential pinned at enrollment.

## Hiding your address from the first hop

Reach the first hop through something that already hides it: an existing VPN, or
another anonymising network.

    sudo cypherpunk preferences --upstream-interface vpn0

With an upstream interface set, the kill switch lets traffic to the first hop leave
only through that interface. If the upstream drops, the first hop becomes unreachable;
your real address is never used as a fallback. `cypherpunk doctor --check-egress` shows the
address the first hop sees.

## What the cloud providers can still see

Nothing on a server keeps logs (`cypherpunk help retention`), but each provider runs the
machine, the network and the control plane under it. These were checked on the live
AWS project on 2026-11-09; OCI's are from its documentation.

| What | Who keeps it | For how long | What reduces it |
|---|---|---|---|
| Your address as the caller of every API command (create, firewall change, teardown) | AWS CloudTrail event history, OCI Audit | 90 days (AWS), 365 days (OCI); cannot be turned off | Run `cypherpunk cloud` while connected through a chain: the caller is then the exit. Every plan shows a `caller` row. |
| Addresses written into firewall rules | the provider's configuration, and the audit log of each change | while the rule exists, then as above | The first hop is open to any address and later hops admit only servers, so no rule names you after `cypherpunk cloud chain`. `cypherpunk cloud audit` reports any rule that names an address other than your servers. |
| The account owner: name, email, payment card | the provider | the account's life | Nothing technical: providers require it. Split the hops across providers so no one account sees both ends. |
| Packet metadata on its own hop: addresses, sizes, timing | the provider's network (flow logs, if enabled, or its own monitoring) | unknown | The entry sees your address but only ciphertext; the exit sees destinations but only the relay. DAITA padding and decoys blur sizes and timing. |
| The server's memory and disk | the hypervisor; disks are encrypted with provider-managed keys | while it runs | Keys and runtime state are in RAM only and nothing about traffic is written to disk. No confidential-computing (SEV-SNP) instance type exists in the project's AWS Region, so memory is not hidden from the provider. |
| Legal requests | the provider, under its jurisdiction | — | Use providers under different jurisdictions for the entry and the exit. |

Providers can observe metadata at each hop they host. A provider with visibility at both
ends can attempt to correlate the traffic. The exit's provider knows who rents the exit
and can see exit traffic, so a single-owner deployment can link that activity to the
operator. Shared access needs independent operators, unlinkable admission, and a stated
collusion model. The [shared-access lab](../../research/shared-access/README.md) tests
admission components locally. The shipped client still uses managed enrollment.

## Identity

In the single-owner setup, the relays know their peer configuration. Blind credits could
remove the persistent device identifier in shared access. The first network operator
would still see the connection's source address. Websites and applications can also link
sessions through logins, cookies, and browser fingerprints.
