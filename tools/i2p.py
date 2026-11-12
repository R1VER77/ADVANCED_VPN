"""The one-hop I2P front: the client reaches the chain's entry through I2P, so the entry
(and its cloud provider) sees I2P routers, never the client's address, and the client's
network sees I2P, never a VPN server.

    client cloak --TCP--> 127.0.0.1:41197  i2pd client tunnel (`hops` hops each way)
        ... I2P ...
    entry i2pd server tunnel (0 hops: the entry is already known to the client)
        --TCP--> 127.0.0.1:8443  the entry's cloak (TLS 1.3 + proof, as on TCP 443)

The entry's I2P destination is generated with its other keys (`avpn request`) and its
b32 address is signed into the client's profile, so the client reaches exactly that
entry. i2pd is a separate, unmodified process (BSD-3-Clause) under its own user; the
client's firewall lets only that user leave, and never towards the entry's own address,
so the entry never exchanges a packet with the client directly (it is never one of the
client's tunnel hops either).
"""

import base64
import hashlib
import ipaddress
import os
from pathlib import Path
import re

# The client's local end of its I2P tunnel; the cloak connects here instead of the entry.
CLIENT_TUNNEL = "127.0.0.1:41197"
# The entry's server tunnel hands streams to the cloak's TCP listener on loopback.
SERVER_TARGET = ("127.0.0.1", 8443)
# Hops of the client's tunnels, each way. 1: one I2P router sits between the client and
# the entry (it sees both addresses, never the content). 2: no single router sees both.
FRONT_HOPS = (1, 2, 3)
DEFAULT_HOPS = 2
# Rate classes an I2P stream carries (measured in docs/evidence/I2P_FRONT.json).
FRONT_RATES = ("metered", "standard")
# Debian's i2pd package keeps the reseed signers' certificates here.
CERTS_DIR = "/usr/share/i2pd/certificates"
# I2P router ports: a random one in the range i2pd itself picks from.
PORT_RANGE = (9111, 30777)
B32 = re.compile(r"[a-z2-7]{52}\.b32\.i2p")
SIG_EDDSA = 7  # Ed25519
CRYPTO_ECIES_X25519 = 4
IDENTITY_LEN = 256 + 128 + 3 + 4  # keys, then a key certificate naming both key types
PRIVATE_LEN = IDENTITY_LEN + 32 + 32  # + X25519 private key + Ed25519 seed


def destination_keys():
    """A new I2P destination (X25519 encryption, Ed25519 signing), as i2pd's private keys
    file and the public destination (its identity)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

    raw = serialization.Encoding.Raw
    enc = x25519.X25519PrivateKey.generate()
    sig = ed25519.Ed25519PrivateKey.generate()
    enc_pub = enc.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    sig_pub = sig.public_key().public_bytes(raw, serialization.PublicFormat.Raw)
    # A short encryption key sits at the start of its 256-byte field and a short signing
    # key at the end of its 128-byte field; the rest is padding (random, as i2pd's own).
    pad = os.urandom(32) * 10
    identity = (
        enc_pub
        + pad[: 256 - 32]
        + pad[: 128 - 32]
        + sig_pub
        + bytes([5, 0, 4])
        + SIG_EDDSA.to_bytes(2, "big")
        + CRYPTO_ECIES_X25519.to_bytes(2, "big")
    )
    private = (
        identity
        + enc.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        + sig.private_bytes(raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    )
    return private, identity


def check_identity(identity):
    """Refuse anything but an Ed25519 + X25519 destination identity."""
    if (
        type(identity) is not bytes
        or len(identity) != IDENTITY_LEN
        or identity[384:387] != bytes([5, 0, 4])
        or int.from_bytes(identity[387:389], "big") != SIG_EDDSA
        or int.from_bytes(identity[389:391], "big") != CRYPTO_ECIES_X25519
    ):
        raise ValueError("not an Ed25519/X25519 I2P destination")
    return identity


def b32(identity):
    """The destination's b32 address: base32 of the SHA-256 of its identity."""
    return base64.b32encode(hashlib.sha256(check_identity(identity)).digest()).decode().lower().rstrip("=") + ".b32.i2p"


def private_identity(private):
    """The public identity inside i2pd's private keys file (checked)."""
    if type(private) is not bytes or len(private) != PRIVATE_LEN:
        raise ValueError("bad I2P destination key")
    return check_identity(private[:IDENTITY_LEN])


def valid_front(front, role):
    """Validate a profile's `front` section for `role` ("client" or a first-hop server)."""
    if front is None:
        return None
    if type(front) is not dict or front.get("kind") != "i2p":
        raise ValueError("unknown front")
    if role == "client":
        if (
            set(front) != {"kind", "destination", "hops"}
            or not B32.fullmatch(str(front["destination"]))
            or front["hops"] not in FRONT_HOPS
        ):
            raise ValueError("bad I2P front")
    elif (
        set(front) != {"kind", "router_port"}
        or type(front["router_port"]) is not int
        or not PORT_RANGE[0] <= front["router_port"] <= PORT_RANGE[1]
    ):
        raise ValueError("bad I2P front")
    return front


def router_conf(datadir, host=None, port=None, verbose=False, testnet=None):
    """i2pd's configuration: only the router and the tunnels file; every proxy, console and
    control port off; no transit (the entry's quota and the client's link carry only this
    chain); no log unless `verbose` (lab: to stdout). `host` is the router's public address
    (the entry's), `testnet` a private network for the lab: netid, reseed zip, this
    node's address, and for the lab's own routers floodfill and transit."""
    del datadir  # i2pd gets it on its command line
    lines = [
        "ipv4 = true",
        "ipv6 = false",
        "notransit = %s" % ("false" if testnet and testnet.get("transit") else "true"),
        "bandwidth = X" if testnet else "bandwidth = L",
        "log = stdout",
        "loglevel = %s" % ("info" if verbose else "none"),
    ]
    if not testnet:
        lines.append("certsdir = %s" % CERTS_DIR)
    if testnet and testnet.get("address"):
        lines.append("address4 = %s" % ipaddress.IPv4Address(testnet["address"]))
        if testnet.get("transit") and host is None:
            host = testnet["address"]  # the lab's own I2P routers publish their address
    if host is not None:
        lines += ["host = %s" % ipaddress.IPv4Address(host), "nat = false"]
    if port is not None:
        lines.append("port = %d" % int(port))
    if testnet:
        lines += [
            "netid = %d" % int(testnet["netid"]),
            "reservedrange = false",
            "floodfill = %s" % ("true" if testnet.get("floodfill") else "false"),
        ]
    # The client's router is hidden: it publishes no address, so nobody (the entry
    # included) learns from the network database that the client's address runs I2P.
    hidden = host is None and not (testnet and testnet.get("transit"))
    published = "false" if hidden else "true"
    # It also speaks only NTCP2: SSU2's peer test asks a third router to send a probe
    # straight to the tester's address, and that router could be the entry.
    lines += ["[ntcp2]", "enabled = true", "published = " + published]
    lines += ["[ssu2]", "enabled = %s" % ("false" if hidden else "true"), "published = " + published]
    lines += ["[trust]", "hidden = %s" % ("true" if hidden else "false")]
    for section in ["upnp", "http", "httpproxy", "socksproxy", "sam", "bob", "i2cp", "i2pcontrol", "addressbook"]:
        lines += ["[%s]" % section, "enabled = false"]
    if testnet:
        lines += ["[reseed]", "verify = false", "threshold = 3"]
        if testnet.get("reseed"):
            lines.append("zipfile = %s" % Path(testnet["reseed"]))
    else:
        # The public network: reseed bundles are signed; refuse unsigned ones.
        lines += ["[reseed]", "verify = true"]
    return "\n".join(lines) + "\n"


def tunnels_conf(front, keys=None, datadir=None):
    """i2pd's tunnels file: the client's tunnel to the entry, or the entry's server tunnel
    (its destination's private keys at `keys`; i2pd reads that path relative to `datadir`)."""
    common = "i2cp.leaseSetType = 3\ni2cp.leaseSetEncType = 4\ninbound.quantity = 2\noutbound.quantity = 2\n"
    if "destination" in front:
        h = int(front["hops"])
        host, port = CLIENT_TUNNEL.rsplit(":", 1)
        return (
            "[avpn-front]\ntype = client\naddress = %s\nport = %s\ndestination = %s\nkeys = transient\n"
            "inbound.length = %d\noutbound.length = %d\ninbound.lengthVariance = 0\noutbound.lengthVariance = 0\n"
            % (host, port, front["destination"], h, h)
        ) + common
    # The entry is already known to its client: zero hops on its side costs no anonymity.
    return (
        "[avpn-front]\ntype = server\nhost = %s\nport = %d\nkeys = %s\ninbound.length = 0\noutbound.length = 0\n"
        % (SERVER_TARGET[0], SERVER_TARGET[1], os.path.relpath(Path(keys), Path(datadir)))
    ) + common


def front_firewall(entry_ip):
    """nftables table for a client with an I2P front: nothing on this host exchanges a
    packet with the entry's own address, so the entry never sees the client, nor serves as
    one of its tunnel hops. A separate table, so its drop is final whatever others accept."""
    ip = ipaddress.IPv4Address(entry_ip)
    return (
        "table inet advanced_vpn_front {\n"
        " chain output { type filter hook output priority -120; policy accept;\n  ip daddr %s drop\n }\n"
        " chain input { type filter hook input priority -120; policy accept;\n  ip saddr %s drop\n }\n"
        "}\n"
    ) % (ip, ip)
