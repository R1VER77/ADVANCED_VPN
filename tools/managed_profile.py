"""Signed, relocatable, role-separated enrollment bundles. Never put bundles in Git."""

import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import zipfile
from cryptography import x509

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519, mldsa

# operator.pub (JSON): a classical half (the Nitrokey FIDO2 credential, or a lab-only
# Ed25519 key) and an ML-DSA-65 public key. Enrollment requires BOTH signatures.
MLDSA65_PUBLIC = 1952

from provision import put, RATE_BYTES, RATE_PACKETS
from keyguard import read_private


def canonical(v):
    """Canonical JSON bytes (sorted keys, no spaces): what gets signed and hashed."""
    return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()


# Server order per chain length, and the layer each server role terminates.
CHAINS = {1: ["exit"], 2: ["relay", "exit"], 3: ["relay", "middle", "exit"]}
CHAIN_LANES = {1: ["inner"], 2: ["outer", "inner"], 3: ["outer", "middle", "inner"]}
SERVER_LANE = {"relay": "outer", "middle": "middle", "exit": "inner"}
ALL_LANES = ["outer", "middle", "inner"]


# Inner IP MTU is 1100 for every chain; the layer count is explicit (QUIC needs >=1200-byte payloads).
MANAGED_MTU = 1100
# Constant-cell padding on every hop. Always on: no command, flag or preference turns it
# off. (A constant only so tests can build a chain the way it was signed before padding
# existed, to prove such a chain is refused.)
CELLS = True
PADDING_REQUIRED = "this chain was signed without constant-cell padding, which is now required; re-sign it (avpn cloud chain --apply, or avpn init) and enroll the new bundle with --replace"
# HTTP/3 camouflage (advanced-vpn-cloak) in front of the WireGuard carrier. Always on:
# WireGuard is reached only through it. (A constant only so tests can build a chain the
# way it was signed before the cloak existed, to prove such a chain is refused.)
CLOAK = True
CLOAK_REQUIRED = "this chain was signed before the HTTP/3 camouflage, which is now required; re-sign it (avpn cloud chain --apply, or avpn init) and enroll the new bundles with --replace"
# Fixed cloak and carrier addresses: the client's carrier sends to its local cloak; the
# first hop's cloak listens on 8443 (its firewall redirects the public port there) and
# hands datagrams to WireGuard on loopback.
CLOAK_CLIENT = dict(listen="127.0.0.1:41196", wireguard="127.0.0.1:41195")
CLOAK_SERVER = dict(listen="0.0.0.0:8443", wireguard="127.0.0.1:41194")
CLOAK_FIELDS = {
    "schema",
    "role",
    "listen",
    "wireguard",
    "remote",
    "cover_name",
    "server_spki_sha256",
    "cert",
    "statistics",
}
FIRST_HOP_ROLES = ("relay", "exit")  # either may be a chain's first hop and run the cloak server


def require_padding(p):
    """Refuse a profile that does not pad every hop (connect and enroll call this)."""
    if p["core"].get("cells") is not True:
        raise ValueError(PADDING_REQUIRED)
    return p


def require_current(p):
    """Refuse a profile signed before padding or before the HTTP/3 camouflage (connect and
    enroll call this; reset, guard and info still load such a profile)."""
    require_padding(p)
    if p["carrier"] and not p.get("cloak"):
        raise ValueError(CLOAK_REQUIRED)
    return p


def valid_cover_name(name):
    """A cover name is a plain DNS name, or None (then no server name is sent)."""
    if name is not None and (
        not isinstance(name, str) or not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", name)
    ):
        raise ValueError("bad cover name")
    return name


def profile_validate(p):
    """Validate a profile's exact schema and every value that reaches rules or commands."""
    base = {"schema", "role", "hops", "core", "carrier", "dns", "network", "daily_budget_bytes"}
    # Without "cloak": signed before the camouflage; well-formed, but require_current refuses it.
    if (
        set(p) not in (base, base | {"cloak"})
        or p["schema"] != 3
        or p["role"] not in ["client", "relay", "middle", "exit"]
    ):
        raise ValueError("unknown managed profile")
    h = p["hops"]
    if h not in CHAINS or (p["role"] != "client" and p["role"] not in CHAINS[h]):
        raise ValueError("role not in this chain")
    # None = no daily cap (default). A configured cap is fail-closed.
    if p["daily_budget_bytes"] is not None and (
        type(p["daily_budget_bytes"]) is not int or not 65536 <= p["daily_budget_bytes"] <= 10_737_418_240
    ):
        raise ValueError("budget out of bounds")
    core_role = "relay" if p["role"] in ("relay", "middle") else p["role"]
    if p["core"]["role"] != core_role or p["core"]["mtu"] != MANAGED_MTU or p["core"].get("layers") != h:
        raise ValueError("wrong inner profile")
    # Absent means signed before padding existed: still a well-formed profile, so the
    # kill switch, reset and info keep working; connecting and enrolling refuse it
    # (require_padding). Anything other than true or absent is malformed.
    if "cells" in p["core"] and p["core"]["cells"] is not True:
        raise ValueError("malformed padding flag")
    lanes = {l for l in ALL_LANES if p["core"].get(l)}
    if lanes != (set(CHAIN_LANES[h]) if p["role"] == "client" else {SERVER_LANE[p["role"]]}):
        raise ValueError("identity role separation failed")
    for lane in lanes:
        i = p["core"][lane]
        for field in ["ca", "cert", "key"]:
            expected = lane + "-" + ("key.der" if field == "key" else "cert.der" if field == "cert" else "ca.der")
            if i[field] != expected:
                raise ValueError("unsafe identity path")
        if i.get("pin_kind") != "spki":
            raise ValueError("managed profiles require public-key identity pins")
    n = p["network"]
    network = {
        "relay_endpoint",
        "middle_endpoint",
        "exit_endpoint",
        "dns_ip",
        "dns_port",
        "protected_destinations",
        "peer_overlay",
        "local_overlay",
    }
    if set(n) not in (network, network | {"cover_name"}) or ("cover_name" in n) != ("cloak" in p):
        raise ValueError("network schema mismatch")
    valid_cover_name(n.get("cover_name"))
    for endpoint in [n["relay_endpoint"], n["exit_endpoint"]] + ([n["middle_endpoint"]] if h == 3 else []):
        host, port = endpoint.rsplit(":", 1)
        ip = ipaddress.IPv4Address(host)
        if ip.is_multicast or ip.is_unspecified or not 1 <= int(port) <= 65535:
            raise ValueError("bad endpoint")
    if (n["middle_endpoint"] is None) != (h != 3):
        raise ValueError("middle endpoint only in three-hop chains")
    if n["dns_ip"] != "10.77.0.1" or n["dns_port"] != 53:
        raise ValueError("managed DNS required")
    if n["local_overlay"] not in ["10.78.0.1", "10.78.0.2"] or n["peer_overlay"] not in ["10.78.0.1", "10.78.0.2"]:
        raise ValueError("fixed carrier subnet required")
    for route in n["protected_destinations"]:
        ipaddress.IPv4Network(route)
    # The carrier (WireGuard+DAITA) runs on the client and on the chain's first hop.
    first_hop = CHAINS[h][0]
    if (p["carrier"] is not None) != (p["role"] in ("client", first_hop)):
        raise ValueError("carrier role separation failed")
    if (p["dns"] is not None) != (p["role"] == "exit"):
        raise ValueError("DNS role separation failed")
    if p["core"]["tun"] != ("avpn0" if p["role"] in ("client", "exit") else None):
        raise ValueError("fixed managed TUN required")
    if p["carrier"]:
        w = p["carrier"]
        if w["tun"] != "avwg0" or w["role"] != "wireguard" or w["defense"] not in ["balanced", "strong"]:
            raise ValueError("managed DAITA required")
        if type(w["listen_port"]) is not int or not 1024 <= w["listen_port"] <= 65535:
            raise ValueError("unprivileged carrier port required")
        if (
            w["identity"] != {"key": "wireguard-key.bin", "cert": "wireguard-binding.json"}
            or w["statistics"] != "carrier-status.json"
        ):
            raise ValueError("carrier path rejected")
        if not re.fullmatch("[0-9a-f]{64}", w["peer_public_hex"]) or w["allowed_ip"] != n["peer_overlay"] + "/32":
            raise ValueError("carrier peer rejected")
        if "cloak" in p:
            # Schema 2: WireGuard only behind the cloak, on fixed loopback addresses.
            client = p["role"] == "client"
            if w["schema"] != 2 or (w["listen_port"], w["endpoint"]) != (
                (41195, CLOAK_CLIENT["listen"]) if client else (41194, None)
            ):
                raise ValueError("the carrier must run behind the cloak")
        elif w["schema"] != 1:
            raise ValueError("carrier schema mismatch")
    if "cloak" in p:
        c = p["cloak"]
        if (c is not None) != (p["carrier"] is not None):
            raise ValueError("cloak role separation failed")
        if c is not None:
            client = p["role"] == "client"
            fixed = CLOAK_CLIENT if client else CLOAK_SERVER
            if (
                set(c) != CLOAK_FIELDS
                or c["schema"] != 1
                or c["role"] != ("client" if client else "server")
                or (c["listen"], c["wireguard"]) != (fixed["listen"], fixed["wireguard"])
                or c["cover_name"] != n["cover_name"]
                or c["statistics"] != "cloak-status.json"
            ):
                raise ValueError("cloak binding rejected")
            if client:
                if (
                    c["remote"] != n["relay_endpoint"]
                    or c["cert"] is not None
                    or not re.fullmatch("[0-9a-f]{64}", c["server_spki_sha256"] or "")
                ):
                    raise ValueError("cloak peer rejected")
            elif c["remote"] is not None or c["server_spki_sha256"] is not None or c["cert"] != "cloak-cert.der":
                raise ValueError("cloak server rejected")
    if p["dns"]:
        d = p["dns"]
        if d["listen"] != "10.77.0.1:1053" or d["client_ip"] != "10.77.0.2" or d["test_ca"] not in [None, "dns-ca.der"]:
            raise ValueError("DNS binding rejected")
        host, port = d["upstream"].rsplit(":", 1)
        ipaddress.IPv4Address(host)
        if not 1 <= int(port) <= 65535 or not re.fullmatch("[A-Za-z0-9.-]{1,253}", d["server_name"]):
            raise ValueError("DNS upstream rejected")
    return p


# The client generates all three layer identities once, so it can join any chain.
LANES = {"client": ["outer", "middle", "inner"], "relay": ["outer"], "middle": ["middle"], "exit": ["inner"]}
NAMES = {
    ("client", "outer"): "client-outer",
    ("client", "middle"): "client-middle",
    ("client", "inner"): "client-inner",
    ("relay", "outer"): "relay",
    ("middle", "middle"): "middle",
    ("exit", "inner"): "exit",
}
PEER = {
    ("client", "outer"): ("relay", "outer"),
    ("relay", "outer"): ("client", "outer"),
    ("client", "middle"): ("middle", "middle"),
    ("middle", "middle"): ("client", "middle"),
    ("client", "inner"): ("exit", "inner"),
    ("exit", "inner"): ("client", "inner"),
}
CARRIER_ROLES = ("client", "relay", "exit")  # any of these may terminate WireGuard
PROTECTIONS = ("nitrokey", "systemd-creds", "none")
PLAINTEXT = {
    "outer": "outer-key.der",
    "middle": "middle-key.der",
    "inner": "inner-key.der",
    "wireguard": "wireguard-key.bin",
    "kem": "kem-key.bin",
    "cloak": "cloak-key.der",
}
MLDSA65_OID = "2.16.840.1.101.3.4.3.18"


def spki_sha256(cert_der):
    """SHA-256 of a certificate's SubjectPublicKeyInfo, the pinned identity."""
    cert = x509.load_der_x509_certificate(cert_der)
    return hashlib.sha256(
        cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()


def device_certificate(name, key):
    """Self-issued identity certificate. Peers pin its SPKI and use it as their
    trust anchor; TLS presents fresh 12-hour leaves under the same key."""
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=12))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .sign(key, None)
        .public_bytes(serialization.Encoding.DER)
    )


def binding(state, name):
    """Public value each protected private key is bound to (envelope AAD)."""
    if name in ("outer", "middle", "inner"):
        return read_private(state / (name + "-cert.der"))
    request = json.loads(read_private(state / "request.json"))
    if name == "wireguard":
        return b"wireguard:" + bytes.fromhex(request["wireguard_public_hex"])
    if name == "kem":
        return b"kem:" + base64.b64decode(request["kem_public"])
    raise ValueError("unknown key")


def store_keys(state, keys, secret=None, meta=None):
    """Protect private keys at rest according to state/protection.json. Plaintext
    is written only in the explicit 'none' mode."""
    from keyguard import seal_bytes, creds_encrypt, atomic

    mode = json.loads(read_private(state / "protection.json"))["mode"]
    for name, value in keys.items():
        if mode == "nitrokey":
            atomic(
                state / (name + "-key.sealed.json"),
                canonical(seal_bytes(secret, meta, name, binding(state, name), value)),
            )
        elif mode == "systemd-creds":
            target = state / (name + "-key.cred")
            if target.exists():
                target.unlink()
            creds_encrypt(
                "advanced-vpn-" + name,
                value,
                target,
                json.loads(read_private(state / "protection.json")).get("creds_key", "host"),
            )
        else:
            atomic(state / PLAINTEXT[name], value)


def load_keys(state, names, secret=None, meta=None):
    """Recover named private keys into memory (one hardware unlock covers all)."""
    from keyguard import open_bytes, creds_decrypt, hardware_secret

    protection = json.loads(read_private(state / "protection.json"))
    mode = protection["mode"]
    if mode == "nitrokey":
        if secret is None:
            secret, meta = hardware_secret(Path(protection["vault"]))
        return {
            n: open_bytes(
                secret, meta, n, binding(state, n), json.loads(read_private(state / (n + "-key.sealed.json")))
            )
            for n in names
        }
    if mode == "systemd-creds":
        return {n: creds_decrypt("advanced-vpn-" + n, state / (n + "-key.cred")) for n in names}
    return {n: read_private(state / PLAINTEXT[n]) for n in names}


def forget_key(state, name):
    """Delete every stored form of private key `name` (sealed, credential, plaintext)."""
    for f in [state / (name + "-key.sealed.json"), state / (name + "-key.cred"), state / PLAINTEXT[name]]:
        if f.exists():
            f.unlink()


def request(role, state, protect, vault=None):
    """Generate this device's private keys locally and protect them immediately.
    Returns the public enrollment request; no private key leaves the device."""
    from keyguard import kem_keypair, hardware_secret, b64

    if role not in LANES or protect not in PROTECTIONS:
        raise ValueError("unknown role or protection")
    if (protect == "nitrokey") != (vault is not None):
        raise ValueError("a hardware vault is required exactly for nitrokey protection")
    if state.exists():
        raise ValueError("this device already has keys in %s; reset it before generating new ones" % state)
    # Unlock the vault first (one PIN + touch): a refused or wrong vault leaves no
    # half-created device state behind.
    secret = meta = None
    if protect == "nitrokey":
        secret, meta = hardware_secret(vault)
    state.mkdir(mode=0o700, parents=False, exist_ok=False)
    keys = {}
    certs = {}
    for lane in LANES[role]:
        k = mldsa.MLDSA65PrivateKey.generate()
        certs[lane] = device_certificate(NAMES[(role, lane)] + ".advanced-vpn.internal", k)
        put(state / (lane + "-cert.der"), certs[lane])
        keys[lane] = k.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    req = dict(
        schema=1,
        role=role,
        certificates={l: b64(c) for l, c in certs.items()},
        issued=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        protection=protect,
    )
    # (protection.json, written below, records whether systemd-creds is TPM-bound.)
    if role in CARRIER_ROLES:
        w = x25519.X25519PrivateKey.generate()
        keys["wireguard"] = w.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        req["wireguard_public_hex"] = (
            w.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        )
        keys["kem"], kem_public = kem_keypair()
        req["kem_public"] = b64(kem_public)
    if role in FIRST_HOP_ROLES:
        # The HTTP/3 cloak's server key (ECDSA P-256, as a web server's would be). Clients
        # pin its public key; the certificate is self-signed at each start.
        c = ec.generate_private_key(ec.SECP256R1())
        keys["cloak"] = c.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        req["cloak_spki_sha256"] = hashlib.sha256(
            c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ).hexdigest()
    put(state / "request.json", canonical(req))
    protection = dict(schema=1, mode=protect, vault=str(vault.resolve()) if vault else None)
    if protect == "systemd-creds":
        from keyguard import tpm2_usable

        protection["creds_key"] = "host+tpm2" if tpm2_usable() else "host"
    put(state / "protection.json", canonical(protection))
    store_keys(state, keys, secret, meta)
    return req


def load_request(raw, role):
    """Parse and check one device's public enrollment request for `role`."""
    r = json.loads(raw)
    if r.get("schema") != 1 or r.get("role") != role:
        raise ValueError("wrong enrollment request for " + role)
    certs = {l: base64.b64decode(c, validate=True) for l, c in r["certificates"].items()}
    if set(certs) != set(LANES[role]):
        raise ValueError("request lanes mismatch")
    for c in certs.values():
        cert = x509.load_der_x509_certificate(c)
        if cert.signature_algorithm_oid.dotted_string != MLDSA65_OID or not isinstance(
            cert.public_key(), mldsa.MLDSA65PublicKey
        ):
            raise ValueError("ML-DSA-65 identity required")
        cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes)  # proof of possession
    if role in CARRIER_ROLES:
        if not re.fullmatch("[0-9a-f]{64}", r["wireguard_public_hex"]):
            raise ValueError("bad WireGuard key")
        from keyguard import KEM_PUBLIC

        if len(base64.b64decode(r["kem_public"], validate=True)) != KEM_PUBLIC:
            raise ValueError("bad hybrid KEM key")
    if "cloak_spki_sha256" in r and (
        role not in FIRST_HOP_ROLES or not re.fullmatch("[0-9a-f]{64}", r["cloak_spki_sha256"])
    ):
        raise ValueError("bad cloak key")
    return r, certs


class SoftwareOperator:
    """TEST/LAB ONLY: operator keys as plaintext files. Production uses the Nitrokey."""

    def __init__(self, directory):
        self.directory = directory
        off = directory / "offline"
        if not off.exists():
            off.mkdir(mode=0o700, parents=True)
            put(
                off / "operator-ed25519.key",
                ed25519.Ed25519PrivateKey.generate().private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
                ),
            )
            put(
                off / "operator-mldsa65.key",
                mldsa.MLDSA65PrivateKey.generate().private_bytes(
                    serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                ),
            )
        self.classical = ed25519.Ed25519PrivateKey.from_private_bytes(read_private(off / "operator-ed25519.key"))
        self.pq = serialization.load_der_private_key(read_private(off / "operator-mldsa65.key"), password=None)

    def public(self):
        """The operator's public keys (Ed25519 and ML-DSA-65)."""
        raw = serialization.Encoding.Raw
        fmt = serialization.PublicFormat.Raw
        return dict(
            schema=2,
            classical=dict(
                kind="ed25519", public=base64.b64encode(self.classical.public_key().public_bytes(raw, fmt)).decode()
            ),
            mldsa65=base64.b64encode(self.pq.public_key().public_bytes(raw, fmt)).decode(),
        )

    def sign(self, message):
        """Sign `message` with both halves of the hybrid operator key."""
        return dict(kind="ed25519", signature=base64.b64encode(self.classical.sign(message)).decode()), self.pq.sign(
            message
        )


class HardwareOperator:
    """Classical half: the non-exportable FIDO2 credential signs (PIN + touch).
    PQ half: an ML-DSA-65 key sealed under that credential's hmac-secret; one
    assertion yields both, so the ML-DSA key is plaintext only in memory."""

    def __init__(self, vault):
        self.vault = vault.resolve()

    def public(self):
        """The hardware operator's public keys: the FIDO2 credential and the ML-DSA-65 key."""
        from keyguard import credential_public

        pq = self.vault / "operator-mldsa65.pub"
        if not pq.exists():
            raise ValueError("operator ML-DSA key not created yet; run init once")
        return dict(
            schema=2,
            classical=dict(kind="fido2", credential=credential_public(self.vault)),
            mldsa65=base64.b64encode(read_private(pq)).decode(),
        )

    def sign(self, message):
        """Sign `message`: a FIDO2 assertion plus ML-DSA-65, the key unsealed for this one use (created and sealed on first use)."""
        from keyguard import hardware_assertion, seal_bytes, open_bytes, atomic

        secret, meta, assertion = hardware_assertion(self.vault, message)
        sealed = self.vault / "operator-mldsa65.sealed.json"
        pub = self.vault / "operator-mldsa65.pub"
        if sealed.exists():
            key = serialization.load_der_private_key(
                open_bytes(secret, meta, "operator-mldsa65", read_private(pub), json.loads(read_private(sealed))),
                password=None,
            )
        else:
            key = mldsa.MLDSA65PrivateKey.generate()
            public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            atomic(pub, public)
            der = key.private_bytes(
                serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            atomic(sealed, canonical(seal_bytes(secret, meta, "operator-mldsa65", public, der)))
        return dict(kind="fido2", **assertion), key.sign(message)


def verify_operator(operator, message, classical, pq_signature):
    """Both halves must verify (hybrid)."""
    c = operator["classical"]
    if c["kind"] == "fido2" and classical.get("kind") == "fido2":
        from keyguard import verify_assertion

        verify_assertion(c["credential"], message, classical)
    elif c["kind"] == "ed25519" and classical.get("kind") == "ed25519":
        ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(c["public"])).verify(
            base64.b64decode(classical["signature"]), message
        )
    else:
        raise ValueError("operator signature kind mismatch")
    mldsa.MLDSA65PublicKey.from_public_bytes(base64.b64decode(operator["mldsa65"])).verify(pq_signature, message)


def create(
    root,
    requests,
    relay,
    exit_address,
    signer,
    defense="balanced",
    destinations=None,
    daily_mib=None,
    dns=None,
    rates=None,
    hops=2,
    middle=None,
    cover_name=None,
):
    """Operator: build signed bundles for a 1-, 2- or 3-hop chain from public device
    requests. Bundles carry no private key; the WireGuard PSK is hybrid-KEM encrypted
    to the client and the chain's first hop.

    relay  = entry relay's public WireGuard endpoint (2-3 hops)
    middle = middle relay's public QUIC endpoint (3 hops)
    exit_address = exit's public QUIC endpoint (2-3 hops) or WireGuard endpoint (1 hop)"""
    from keyguard import kem_seal

    if hops not in CHAINS:
        raise ValueError("hops must be 1, 2 or 3")
    servers = CHAINS[hops]
    first = servers[0]
    if (relay is None) != (hops == 1) or (middle is None) != (hops != 3):
        raise ValueError("endpoints do not match the chain")
    for a in [x for x in [relay, middle, exit_address] if x]:
        ipaddress.IPv4Address(a.rsplit(":", 1)[0])
    carrier_endpoint = relay if hops > 1 else exit_address
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    roles = ["client"] + servers
    if set(requests) != set(roles):
        raise ValueError("requests needed exactly for: " + ", ".join(roles))
    reqs = {role: load_request(requests[role], role) for role in roles}
    valid_cover_name(cover_name)
    if CLOAK and "cloak_spki_sha256" not in reqs[first][0]:
        raise ValueError(
            "the %s's keys predate the HTTP/3 camouflage; create them again with this release (avpn reset, then avpn request)"
            % first
        )
    allowed = destinations if destinations is not None else ["0.0.0.0/0"]

    # Cloud hosts are 1:1 NATed: the public address is not on the interface. Public
    # listeners bind every local address on the enrolled port; peers still send to
    # the public endpoint, and QUIC authentication pins who may connect.
    def any_address(endpoint):
        return "0.0.0.0:" + endpoint.rsplit(":", 1)[1] if endpoint else None

    listen = {
        "relay": "10.78.0.1:4433",
        "middle": any_address(middle),
        "exit": "10.78.0.1:4433" if hops == 1 else any_address(exit_address),
    }
    nxt = {"relay": middle if hops == 3 else exit_address, "middle": exit_address}
    psk = os.urandom(32)
    payloads = {}
    for role in roles:
        req, certs = reqs[role]
        files = {}
        lanes = CHAIN_LANES[hops] if role == "client" else [SERVER_LANE[role]]
        core = dict(
            schema=1,
            role="relay" if role in ("relay", "middle") else role,
            listen="10.78.0.2:0" if role == "client" else listen[role],
            relay="10.78.0.1:4433" if role == "client" else None,
            exit=nxt.get(role),
            outer=None,
            middle=None,
            inner=None,
            tun="avpn0" if role in ("client", "exit") else None,
            local_ip={"client": "10.77.0.2", "exit": "10.77.0.1"}.get(role),
            peer_ip={"client": "10.77.0.1", "exit": "10.77.0.2"}.get(role),
            destinations=allowed if role in ("client", "exit") else [],
            session_seconds=300,
            packets_per_second=RATE_PACKETS,
            bytes_per_second=RATE_BYTES,
            mtu=MANAGED_MTU,
            layers=hops,
        )
        if CELLS:
            # Constant-cell padding is always on; there is no unpadded chain.
            core["cells"] = True
        if rates:
            core.update(rates)
        for lane in lanes:
            peer_role, peer_lane = PEER[(role, lane)]
            peer_cert = reqs[peer_role][1][peer_lane]
            files[lane + "-ca.der"] = peer_cert
            files[lane + "-cert.der"] = certs[lane]
            core[lane] = dict(
                ca=lane + "-ca.der",
                cert=lane + "-cert.der",
                key=lane + "-key.der",
                peer_sha256=spki_sha256(peer_cert),
                server_name=NAMES[(peer_role, peer_lane)] + ".advanced-vpn.internal",
                pin_kind="spki",
            )
        carrier = None
        dns_cfg = None
        local = "10.78.0.2" if role == "client" else "10.78.0.1"
        peer = "10.78.0.1" if role == "client" else "10.78.0.2"
        if role in ("client", first):
            other = first if role == "client" else "client"
            peer_public = reqs[other][0]["wireguard_public_hex"]
            files["wireguard-binding.json"] = canonical(
                dict(schema=2, role=role, own_public_hex=req["wireguard_public_hex"], peer_public_hex=peer_public)
            )
            files["psk.kem.json"] = canonical(
                kem_seal(base64.b64decode(req["kem_public"]), psk, b"advanced-vpn/wireguard-psk/" + role.encode())
            )
            carrier = dict(
                schema=2 if CLOAK else 1,
                role="wireguard",
                tun="avwg0",
                listen_port=(41195 if role == "client" else 41194)
                if CLOAK
                else (41195 if role == "client" else int(carrier_endpoint.rsplit(":", 1)[1])),
                endpoint=(CLOAK_CLIENT["listen"] if CLOAK else carrier_endpoint) if role == "client" else None,
                peer_public_hex=peer_public,
                allowed_ip=peer + "/32",
                identity=dict(key="wireguard-key.bin", cert="wireguard-binding.json"),
                defense=defense,
                statistics="carrier-status.json",
                byte_budget=67_108_864,
            )
            client = role == "client"
            cloak = dict(
                schema=1,
                role="client" if client else "server",
                remote=carrier_endpoint if client else None,
                cover_name=cover_name,
                server_spki_sha256=reqs[first][0]["cloak_spki_sha256"] if client else None,
                cert=None if client else "cloak-cert.der",
                statistics="cloak-status.json",
                **(CLOAK_CLIENT if client else CLOAK_SERVER),
            )
        else:
            cloak = None
        if role == "exit":
            d = dict(upstream="9.9.9.9:853", server_name="dns.quad9.net", test_ca=None)
            if dns:
                d.update(upstream=dns["upstream"], server_name=dns["server_name"])
                if dns.get("test_ca"):
                    files["dns-ca.der"] = dns["test_ca"]
                    d["test_ca"] = "dns-ca.der"
            dns_cfg = dict(schema=1, listen="10.77.0.1:1053", client_ip="10.77.0.2", **d)
        profile = dict(
            schema=3,
            role=role,
            hops=hops,
            core=core,
            carrier=carrier,
            dns=dns_cfg,
            daily_budget_bytes=None if daily_mib is None else daily_mib * 1048576,
            network=dict(
                relay_endpoint=carrier_endpoint,
                middle_endpoint=middle,
                exit_endpoint=exit_address,
                dns_ip="10.77.0.1",
                dns_port=53,
                protected_destinations=allowed,
                peer_overlay=peer,
                local_overlay=local,
            ),
        )
        if CLOAK:
            profile["cloak"] = cloak
            profile["network"]["cover_name"] = cover_name
        profile_validate(profile)
        files["profile.json"] = canonical(profile)
        payloads[role] = files
    del psk
    manifests = {
        role: canonical(dict(schema=2, role=role, files={n: hashlib.sha256(b).hexdigest() for n, b in files.items()}))
        for role, files in payloads.items()
    }
    enrollment_set = canonical(
        dict(
            schema=2,
            hops=hops,
            issued=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            bundles={role: hashlib.sha256(m).hexdigest() for role, m in manifests.items()},
        )
    )
    # One signing operation (one PIN + touch) covers every bundle in the chain.
    classical, pq_signature = signer.sign(enrollment_set)
    operator = signer.public()
    verify_operator(operator, enrollment_set, classical, pq_signature)
    put(root / "operator.pub", canonical(operator))
    for role, files in payloads.items():
        path = root / (role + ".avpn")
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as z:
            z.writestr("manifest.json", manifests[role])
            z.writestr("set.json", enrollment_set)
            z.writestr("set.classical.json", canonical(classical))
            z.writestr("set.mldsa65.sig", pq_signature)
            for name, b in files.items():
                z.writestr(name, b)
        os.chmod(path, 0o600)
    return hashlib.sha256(canonical(operator)).hexdigest()


def read_operator(path):
    """Read and validate the operator public key file (not writable by group or others)."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_size > 16384 or m.st_mode & 0o022:
            raise ValueError("untrusted operator key file")
        raw = f.read(16385)
    operator = json.loads(raw)
    if operator.get("schema") != 2 or set(operator) != {"schema", "classical", "mldsa65"}:
        raise ValueError("wrong enrollment operator key")
    if len(base64.b64decode(operator["mldsa65"], validate=True)) != MLDSA65_PUBLIC:
        raise ValueError("wrong operator ML-DSA key")
    return raw, operator


ENROLLMENT_FILES = ["profile.json", "ENROLLMENT.json", "operator.pub", "wireguard-binding.json", "dns-ca.der"] + [
    l + "-ca.der" for l in ["outer", "middle", "inner"]
]


def enroll(bundle, operator_public, state, replace=False):
    """Device: verify the hybrid operator signature and that the bundle names this
    device's own keys, then decrypt the PSK and re-protect the WireGuard key.
    replace=True swaps in a new chain (e.g. another hop count) keeping device keys;
    the caller must have stopped the controller."""
    raw_operator, operator = read_operator(operator_public)
    request_doc = json.loads(read_private(state / "request.json"))
    if (state / "profile.json").exists() and not replace:
        raise ValueError("already enrolled; use replace to switch chains")
    if bundle.stat().st_size > 1_048_576:
        raise ValueError("oversized bundle")
    signed = {"manifest.json", "set.json", "set.classical.json", "set.mldsa65.sig"}
    with zipfile.ZipFile(bundle) as z:
        entries = z.infolist()
        names = [v.filename for v in entries]
        if (
            len(names) > 32
            or len(names) != len(set(names))
            or any(not re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", name) for name in names)
        ):
            raise ValueError("unsafe bundle member")
        if any(v.file_size > 65536 for v in entries) or sum(v.file_size for v in entries) > 262144:
            raise ValueError("bundle expansion bound")
        enrollment_set = z.read("set.json")
        verify_operator(operator, enrollment_set, json.loads(z.read("set.classical.json")), z.read("set.mldsa65.sig"))
        raw = z.read("manifest.json")
        manifest = json.loads(raw)
        role = manifest["role"]
        if json.loads(enrollment_set)["bundles"].get(role) != hashlib.sha256(raw).hexdigest():
            raise ValueError("manifest not covered by signature")
        if manifest["schema"] != 2 or set(names) != set(manifest["files"]) | signed:
            raise ValueError("unsigned bundle content")
        contents = {name: z.read(name) for name in manifest["files"]}
        for name, b in contents.items():
            if hashlib.sha256(b).hexdigest() != manifest["files"][name]:
                raise ValueError("bundle integrity failure")
    profile = require_current(profile_validate(json.loads(contents["profile.json"])))
    if profile["role"] != role or role != request_doc["role"]:
        raise ValueError("role substitution")
    allowed = {"profile.json"}
    for lane in ALL_LANES:
        if profile["core"].get(lane):
            allowed.update([lane + "-ca.der", lane + "-cert.der"])
    if profile["carrier"]:
        allowed.update(["wireguard-binding.json", "psk.kem.json"])
    if profile["dns"] and profile["dns"]["test_ca"]:
        allowed.add("dns-ca.der")
    if set(contents) != allowed:
        raise ValueError("reserved or unreferenced enrollment member")
    # The bundle must name exactly the keys this device generated.
    for lane in ALL_LANES:
        if profile["core"].get(lane) and contents[lane + "-cert.der"] != read_private(state / (lane + "-cert.der")):
            raise ValueError("bundle is for another device")
    if profile["carrier"]:
        b = json.loads(contents["wireguard-binding.json"])
        if (
            b["own_public_hex"] != request_doc["wireguard_public_hex"]
            or b["peer_public_hex"] != profile["carrier"]["peer_public_hex"]
        ):
            raise ValueError("bundle is for another device")
    secret = meta = None
    protection = json.loads(read_private(state / "protection.json"))
    if profile["carrier"]:
        from keyguard import kem_open, hardware_secret

        if protection["mode"] == "nitrokey":
            secret, meta = hardware_secret(Path(protection["vault"]))
        keys = load_keys(state, ["wireguard", "kem"], secret, meta)
        psk = kem_open(
            keys["kem"], json.loads(contents["psk.kem.json"]), b"advanced-vpn/wireguard-psk/" + role.encode()
        )
        if len(psk) != 32:
            raise ValueError("bad PSK")
    if replace:
        for name in ENROLLMENT_FILES:
            if (state / name).exists():
                (state / name).unlink()
    for name, b in contents.items():
        if name.endswith("-cert.der") or name == "psk.kem.json":
            continue
        put(state / name, b)
    if profile["carrier"]:
        # Private key (first 32 bytes) is the device's own; the PSK belongs to this chain.
        # The KEM key stays protected at rest so later chains can deliver a new PSK.
        store_keys(state, {"wireguard": keys["wireguard"][:32] + psk}, secret, meta)
    put(state / "operator.pub", raw_operator)
    put(
        state / "ENROLLMENT.json",
        canonical(
            dict(
                schema=2,
                signer_sha256=hashlib.sha256(raw_operator).hexdigest(),
                manifest_sha256=hashlib.sha256(raw).hexdigest(),
            )
        ),
    )
    return profile


def runtime(profile, root):
    """Resolve only approved relative names; operator bundle contains no executable code."""
    c = json.loads(json.dumps(profile["core"]))
    for i in [c.get("outer"), c.get("middle"), c.get("inner")]:
        if i:
            for field in ["ca", "cert", "key"]:
                i[field] = str(root / i[field])
    out = {"core": c}
    # The cloak starts before the carrier, so WireGuard's first handshake finds it ready.
    if profile.get("cloak"):
        k = dict(profile["cloak"])
        k["statistics"] = str(root / "cloak-status.json")
        if k["cert"]:
            k["cert"] = str(root / k["cert"])
        out["cloak"] = k
    if profile["carrier"]:
        w = json.loads(json.dumps(profile["carrier"]))
        for field in ["cert", "key"]:
            w["identity"][field] = str(root / w["identity"][field])
        w["statistics"] = str(root / "carrier-status.json")
        out["carrier"] = w
    if profile["dns"]:
        out["dns"] = dict(profile["dns"])
        if out["dns"].get("test_ca"):
            out["dns"]["test_ca"] = str(root / Path(out["dns"]["test_ca"]).name)
    return out


def cloak_certificate(key_der, cover_name):
    """A fresh self-signed certificate (DER) for the cloak's ECDSA key, naming the cover
    name (or localhost). Clients pin the key, not the certificate, so it can change."""
    key = serialization.load_der_private_key(key_der, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("the cloak key must be ECDSA")
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cover_name or "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cover_name or "localhost")]), critical=False)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def refresh_leaves(config, root, keys=None, out_dir=None):
    """Stable pinned identity; fresh TLS leaves. No CA signing key is used online."""
    now = dt.datetime.now(dt.timezone.utc)
    for role in ["outer", "middle", "inner"]:
        i = config.get(role)
        if not i:
            continue
        if i.get("pin_kind") != "spki":
            raise ValueError("managed rotation requires a public-key pin")
        original = x509.load_der_x509_certificate(read_private(root / (role + "-cert.der")))
        private = keys[role] if keys else read_private(Path(i["key"]))
        key = serialization.load_der_private_key(private, password=None)
        if key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != original.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ):
            raise ValueError("identity key mismatch")
        b = (
            x509.CertificateBuilder()
            .subject_name(original.subject)
            .issuer_name(original.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=12))
        )
        for extension in original.extensions:
            b = b.add_extension(extension.value, extension.critical)
        from provision import digest_for

        fresh = b.sign(key, digest_for(key)).public_bytes(serialization.Encoding.DER)
        path = (out_dir or root) / (role + "-active-cert.der")  # supervisor: RAM-only runtime dir
        from keyguard import atomic

        atomic(path, fresh)
        i["cert"] = str(path)


def lab_setup(
    root,
    relay,
    exit_address,
    protect=None,
    vault=None,
    dns=None,
    daily_mib=None,
    destinations=None,
    operator=None,
    rates=None,
    defense="balanced",
    hops=2,
    middle=None,
    cover_name=None,
):
    """TEST/LAB: run the real request -> init -> enroll flow for every role in the
    chain. `protect` maps role -> protection (default 'none'); the operator is
    software unless a HardwareOperator is passed."""
    protect = protect or {}
    roles = ["client"] + CHAINS[hops]
    for role in roles:
        mode = protect.get(role, "none")
        request(role, root / role, mode, vault if mode == "nitrokey" else None)
    ops = root / "operator"
    signer = operator or SoftwareOperator(root / "operator-keys")
    create(
        ops,
        {r: read_private(root / r / "request.json") for r in roles},
        relay if hops > 1 else None,
        exit_address,
        signer,
        destinations=destinations,
        daily_mib=daily_mib,
        dns=dns,
        rates=rates,
        defense=defense,
        hops=hops,
        middle=middle,
        cover_name=cover_name,
    )
    for role in roles:
        enroll(ops / (role + ".avpn"), ops / "operator.pub", root / role)
    return ops
