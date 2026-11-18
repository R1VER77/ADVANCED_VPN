"""Project only validated public enrollment material into the desktop response."""

import hashlib

from controller_bridge import canonical
from keyguard import read_private
import managed_profile


def public_request(state):
    """Read the fixed public request record; never open a private key or output path."""
    path = state / "request.json"
    if not path.exists() and not path.is_symlink():
        return None
    raw = read_private(path, limit=65536)
    value, _ = managed_profile.load_request(raw, "client")
    if type(value.get("schema")) is not int or value.get("protection") not in managed_profile.PROTECTIONS:
        raise ValueError("invalid public request metadata")
    # An unknown future field must not accidentally export private material.
    projected = {
        name: value[name]
        for name in (
            "schema",
            "role",
            "certificates",
            "wireguard_public_hex",
            "kem_public",
            "protection",
        )
    }
    issued = value.get("issued")
    if not isinstance(issued, str) or len(issued) > 64 or not issued.isascii() or not issued.isprintable():
        raise ValueError("invalid public request issuance metadata")
    projected["issued"] = issued
    result = canonical(projected)
    if len(result) > 65536:
        raise ValueError("public request exceeds desktop bound")
    return dict(text=result.decode("ascii"), sha256=hashlib.sha256(result).hexdigest())
