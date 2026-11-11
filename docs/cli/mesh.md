# avpn mesh — the community mesh

Browse the mesh, contribute nodes, build chains across members' servers.
Full design: docs/MESH_DESIGN.md. Membership is your hardware device — there
is no account.

## Commands

    avpn mesh identity
        Show your member ID (!xxxxxxxx), derived from your device key.

    avpn mesh nodes [--fetch]
        The directory: role, provider, country, latency, uptime, cover
        budget, operator. --fetch pulls fresh descriptors from beacons.

    avpn mesh offer --guided
        Ranked always-free providers (OCI Always Free first, ~10 TiB/mo
        egress), what each can contribute, and the cover budget math.

    avpn mesh offer --apply [--provider oci|aws|host] [--role relay|entry|exit]
                    [--country CC] [--name NAME] [--private]
        Provision and contribute a node. --private keeps it out of the mesh
        directory, usable only by you. Role exit additionally requires
        --i-understand-exit-risk and shows ToS/abuse guidance.

    avpn mesh chain [--hops 1..3] [--group public|GROUP] [--exit-country CC]
                    [--prefer !xxxxxxxx] [--apply]
        Plan (or build) a chain. Every hop is a distinct operator, provider
        and country; an operator never appears twice.

    avpn mesh quota
        Contribution credits: earned relaying, spent on chains, today's
        balance. Private-group credits only until the public pool's VOPRF
        verifier lands.

Changing operations show a --dry-run plan and ask before acting. The tool
runs as you (your cloud sign-ins, your hardware token), never as root.
