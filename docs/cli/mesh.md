# cypherpunk mesh — the community mesh

Browse the mesh, contribute nodes, build chains across members' servers.
Full design: docs/MESH_DESIGN.md. Membership is your hardware device — there
is no account.

## Commands

    cypherpunk mesh identity
        Show your member ID (!xxxxxxxx), derived from your device key.

    cypherpunk mesh nodes [--fetch]
        The directory: role, provider, country, latency, uptime, cover
        budget, operator. --fetch pulls fresh descriptors from beacons.

    cypherpunk mesh offer --guided
        Ranked always-free providers (OCI Always Free first, ~10 TiB/mo
        egress), what each can contribute, and the cover budget math.

    cypherpunk mesh offer --apply [--provider oci|aws|host] [--role relay|entry|exit]
                    [--country CC] [--name NAME] [--private]
        Provision and contribute a node. --private keeps it out of the mesh
        directory, usable only by you. Role exit additionally requires
        --i-understand-exit-risk and shows ToS/abuse guidance.

    cypherpunk mesh chain [--hops 1..3] [--group public|GROUP] [--exit-country CC]
                    [--prefer !xxxxxxxx] [--allow-same-jurisdiction] [--apply]
        Plan (or build) a chain. Every hop is a distinct operator, provider
        and country; an operator never appears twice. Your own node is your
        entry when it offers one, so no stranger learns your address. The
        exit answers to another legal sphere than the entry (US clouds are
        one sphere under the CLOUD Act; a self-hosted node answers to its
        country): one legal order never reaches both ends. The middle does
        not count. --allow-same-jurisdiction lifts that rule.

    cypherpunk mesh publish [--dry-run] [--gateway-key PATH]
        Sign this node's descriptor with your hardware key and gossip it.
        A beacon that answers oblivious requests adds --gateway-key (the
        file it serves with): the public key is signed into the descriptor,
        so every member can check they were given the same one.

    Oblivious routes (beacons.json entries with a relay and a gateway key)
    are checked for key consistency: --fetch compares the configured key
    with the gateway operator's own signed descriptor as at least two other
    beacons show it. Until then the route only fetches the directory;
    a different key, or two signed keys from one operator, refuses it.

    cypherpunk credits
    cypherpunk mesh quota
        Show credits held, credits pending for the next epoch, today's earned
        and spent counts, the UTC rollover, and public-pool redemption status.
        Run as your regular user. Use --json for wallet counts and protocol details.

Changing operations show a --dry-run plan and ask before acting. The tool
runs as you (your cloud sign-ins, your hardware token), never as root.
