#!/usr/bin/env python3
"""Copy the provider logos the desktop app shows out of two pinned CC0 icon packages.

    python3 tools/provider_logos.py SIMPLE_ICONS.tgz LOGOS.tgz

The app never fetches a logo: each release carries these files, so the provider list
makes no request to a provider or an icon site. The packages are checked against the
digests below before anything is read; a different file is refused. Hosts without a
logo in either package get a lettered tile drawn by the app instead.
"""

import io
import json
import hashlib
from pathlib import Path
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "apps/cypherpunk-vpn/src/assets/providers"
PACKAGES = {
    "simple-icons": ("16.36.0", "2069d8e682dda3aa05fa71de36c0ab17984e62d2bd34d7082c4a85e0691b4235"),
    "@iconify-json/logos": ("1.2.19", "1e8907c088bbf02eab8ee1b28f37e68ef22c380f2fb579ff99736b8ce5abf13a"),
}
# provider key -> (package, icon name). Full-colour marks where the logos set has them,
# otherwise Simple Icons' one-colour mark in the brand's own colour.
CHOSEN = {
    "oci": ("@iconify-json/logos", "oracle"),
    "aws": ("@iconify-json/logos", "aws"),
    "azure": ("@iconify-json/logos", "microsoft-azure"),
    "gcp": ("@iconify-json/logos", "google-cloud"),
    "digitalocean": ("@iconify-json/logos", "digital-ocean-icon"),
    "vultr": ("@iconify-json/logos", "vultr-icon"),
    "fly": ("simple-icons", "flydotio"),
    "akamai": ("simple-icons", "akamai"),
    "hetzner": ("simple-icons", "hetzner"),
    "ovh": ("simple-icons", "ovh"),
    "netcup": ("simple-icons", "netcup"),
    "ionos": ("simple-icons", "ionos"),
    "scaleway": ("simple-icons", "scaleway"),
    "infomaniak": ("simple-icons", "infomaniak"),
    "exoscale": ("simple-icons", "exoscale"),
}

# Wordmarks too wide to read in a small tile: show the brand's own symbol part instead.
CROP = {"oci": "-2 -2 112 71"}  # Oracle's red "O"


def member(archive, name):
    """One file from a package tarball, as bytes."""
    with archive.extractfile("package/" + name) as stream:
        return stream.read()


def extract(simple_icons, logos):
    """{key: svg text} for every chosen provider, from the verified packages."""
    archives = {}
    for package, path in (("simple-icons", simple_icons), ("@iconify-json/logos", logos)):
        raw = Path(path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != PACKAGES[package][1]:
            raise SystemExit("%s is not the pinned %s %s" % (path, package, PACKAGES[package][0]))
        archives[package] = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
    colours = {i["slug"]: i["hex"] for i in json.loads(member(archives["simple-icons"], "data/simple-icons.json"))}
    logo_set = json.loads(member(archives["@iconify-json/logos"], "icons.json"))
    out = {}
    for key, (package, icon) in CHOSEN.items():
        if package == "simple-icons":
            svg = member(archives[package], "icons/%s.svg" % icon).decode()
            svg = svg.replace("<svg ", '<svg fill="#%s" ' % colours[icon], 1)
        else:
            entry = logo_set["icons"][icon]
            width, height = entry.get("width", logo_set["width"]), entry.get("height", logo_set["height"])
            box = CROP.get(key, "0 0 %d %d" % (width, height))
            svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="%s">%s</svg>' % (box, entry["body"])
        # Static marks only: nothing that runs, loads or links.
        if re.search(r"<script|on[a-z]+=|href=\"(?!#)|url\((?!#)|<foreignObject|<image", svg, re.I):
            raise SystemExit("%s/%s is not a plain static mark" % (package, icon))
        out[key] = svg
    return out


def main():
    """Write the logos and their source record."""
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    logos = extract(*sys.argv[1:])
    OUT.mkdir(parents=True, exist_ok=True)
    for key, svg in logos.items():
        (OUT / (key + ".svg")).write_text(svg + ("" if svg.endswith("\n") else "\n"))
    manifest = dict(
        license="CC0-1.0",
        packages={
            p: dict(version=v, tarball_sha256=d, source="https://www.npmjs.com/package/%s/v/%s" % (p, v))
            for p, (v, d) in PACKAGES.items()
        },  # fmt: skip
        icons={k: dict(package=p, icon=i, **({"crop": CROP[k]} if k in CROP else {})) for k, (p, i) in CHOSEN.items()},
        note="Trademarks belong to their owners; the marks only identify each provider in the provider list.",
    )
    (OUT / "SOURCES.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("wrote %d logos to %s" % (len(logos), OUT.relative_to(ROOT)))


if __name__ == "__main__":
    main()
