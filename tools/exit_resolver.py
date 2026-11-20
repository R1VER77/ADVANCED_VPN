"""The exit's own recursive resolver (`avpn init --dns-recursive`).

By default the exit forwards every lookup over hybrid post-quantum DNS over TLS to one
public resolver, which therefore sees every name a member resolves. In recursive mode the
exit runs Unbound itself and asks the authoritative servers directly, so no single
resolver operator sees them all:

- QNAME minimisation (RFC 9156): each authoritative server learns only the next label;
- DNSSEC validation against the root trust anchor (Debian's dns-root-data);
- 0x20 query-name randomisation, hardened referrals, no identity or version answers;
- listening on loopback only, for the exit's own forwarder (advanced-vpn-dns), which keeps
  doing the filtering, the .invalid probe and the tunnel-side access control.

The cost, named in docs/PQ_INVENTORY.md: queries from the exit to authoritative servers
are plain DNS, neither encrypted nor post-quantum, as all authoritative DNS is today. They
leave from the exit's address, which the member's own traffic leaves from anyway. Inside
the chain nothing changes.
"""

from pathlib import Path

LISTEN = "127.0.0.1:5335"
UNBOUND_PATHS = ("/usr/sbin/unbound", "/usr/bin/unbound")
TRUST_ANCHOR = "/usr/share/dns/root.key"  # Debian's dns-root-data


def unbound_path():
    """The installed Unbound, or a RuntimeError naming the packages to install."""
    for p in UNBOUND_PATHS:
        if Path(p).is_file():
            return p
    raise RuntimeError("the exit's recursive resolver needs Unbound: apt install unbound dns-root-data")


def config(listen=LISTEN, trust_anchor=TRUST_ANCHOR):
    """unbound.conf for the exit: loopback only, validating, minimising, no logs, no files."""
    host, port = listen.rsplit(":", 1)
    if host != "127.0.0.1":
        raise ValueError("the exit's resolver listens on loopback only")
    return f"""server:
    interface: {host}
    port: {int(port)}
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    username: ""
    chroot: ""
    directory: "/"
    pidfile: ""
    use-syslog: no
    logfile: ""
    verbosity: 0
    log-queries: no
    log-replies: no
    num-threads: 1
    so-sndbuf: 0
    so-rcvbuf: 0
    trust-anchor-file: "{trust_anchor}"
    qname-minimisation: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-algo-downgrade: yes
    # Not harden-referral-path: Unbound calls it experimental, and on 20 November 2026 it
    # made www.debian.org fail (SERVFAIL) while every other setting here resolved it.
    use-caps-for-id: yes
    aggressive-nsec: yes
    hide-identity: yes
    hide-version: yes
    deny-any: yes
    minimal-responses: yes
    prefetch: yes
remote-control:
    control-enable: no
"""
