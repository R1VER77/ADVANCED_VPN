"""Pinned pilot directories and shared entry selection."""

import base64
from dataclasses import dataclass
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

import mesh
from shared_admission import AdmissionError, Cohort, EPOCH_SECONDS, ROLES


DIRECTORY_DOMAIN = b"cpvpn/shared-pool/v1\0"
DIRECTORY_FIELDS = {"schema", "pool", "issuer", "issuer_spki", "epoch", "nodes", "signature"}


@dataclass(frozen=True)
class SharedPool:
    """A single issuer configuration and node set signed by the pinned pilot operator."""

    cohorts: tuple[Cohort, Cohort]
    _nodes: bytes

    @classmethod
    def verify(cls, manifest, pinned_key: mldsa.MLDSA65PublicKey, now: int):
        """Authenticate the pool and its individual operator-signed descriptors."""
        if set(manifest) != DIRECTORY_FIELDS or manifest["schema"] != 1:
            raise AdmissionError("invalid pool directory format")
        try:
            nodes = manifest["nodes"]
            if not isinstance(nodes, list) or not 2 <= len(nodes) <= 256:
                raise AdmissionError("invalid pool size")
            pinned_key.verify(
                base64.b64decode(manifest["signature"], validate=True), DIRECTORY_DOMAIN + mesh.canonical(manifest)
            )
            spki = base64.b64decode(manifest["issuer_spki"], validate=True)
            cohorts = tuple(
                Cohort(manifest["issuer"], manifest["pool"], role, manifest["epoch"], spki) for role in ROLES
            )
            if cohorts[0].epoch not in (now // EPOCH_SECONDS, now // EPOCH_SECONDS + 1):
                raise AdmissionError("inactive directory epoch")
            seen = set()
            for node in nodes:
                if (
                    not isinstance(node["operator"], str)
                    or not isinstance(node["provider"], str)
                    or not isinstance(node["roles"], list)
                    or mesh.validate(node, now)
                    or not mesh.verify_descriptor(node)
                    or node["node_id"] in seen
                ):
                    raise AdmissionError("invalid pool node")
                seen.add(node["node_id"])
        except AdmissionError:
            raise
        except (AttributeError, InvalidSignature, KeyError, TypeError, ValueError):
            raise AdmissionError("pool directory verification failed") from None
        return cls(cohorts, json.dumps(nodes).encode())

    def route(self, now: int, *, excluded_nodes=(), excluded_operators=()):
        """Choose a shared chain without preferring or admitting the client's own nodes."""
        if now // EPOCH_SECONDS != self.cohorts[0].epoch:
            raise AdmissionError("shared pool epoch is inactive")
        excluded_nodes, excluded_operators = frozenset(excluded_nodes), frozenset(excluded_operators)
        nodes = [
            node
            for node in json.loads(self._nodes)
            if node["expires"] > now
            and node["node_id"] not in excluded_nodes
            and node["operator"] not in excluded_operators
        ]
        pairs = [
            (entry, exit)
            for entry in nodes
            if "entry" in entry["roles"]
            for exit in nodes
            if "exit" in exit["roles"]
            if entry["node_id"] != exit["node_id"]
            and entry["operator"] != exit["operator"]
            and entry["provider"] != exit["provider"]
            and entry["country"] != exit["country"]
            and mesh.legal_parent(entry["provider"], entry["country"])
            != mesh.legal_parent(exit["provider"], exit["country"])
        ]
        if not pairs:
            raise AdmissionError("no independent shared route is available")
        return secrets.choice(pairs)
