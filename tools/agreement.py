#!/usr/bin/env python3
"""The user agreement the desktop app shows on first launch, made from the documents.

    agreement.py --generate     write apps/cypherpunk-vpn/src/controller/agreement.json
    agreement.py --check        fail when that file no longer matches the documents

The documents stay the source of truth (docs/TERMS_OF_SERVICE.md and
docs/PRIVACY_NOTICE.md); the app ships them as plain text, so it renders no Markdown and
fetches nothing. `version` is the SHA-256 of the sources, so any change to them asks for
acceptance again.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ("docs/TERMS_OF_SERVICE.md", "docs/PRIVACY_NOTICE.md")
OUT = ROOT / "apps/cypherpunk-vpn/src/controller/agreement.json"
SCHEMA = 1

LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
CODE = re.compile(r"`([^`]*)`")
STRONG = re.compile(r"\*\*([^*]+)\*\*|__([^_]+)__")
EMPH = re.compile(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])")


def plain(text):
    """Markdown inline markup to plain text: links keep their words, markers go."""
    text = LINK.sub(r"\1", text)
    text = CODE.sub(r"\1", text)
    text = STRONG.sub(lambda m: m.group(1) or m.group(2), text)
    text = EMPH.sub(r"\1", text)
    return " ".join(text.split())


def table_rows(lines):
    """A Markdown table as one line per row: 'First cell. Header: cell. Header: cell.'"""
    cells = [[plain(c) for c in row.strip().strip("|").split("|")] for row in lines]
    header, rows = cells[0], [r for r in cells[1:] if not all(set(c) <= set("-: ") for c in r)]
    return ["%s. %s" % (r[0].rstrip("."), " ".join("%s: %s." % (h, c.rstrip(".")) for h, c in zip(header[1:], r[1:], strict=True)))
            for r in rows]  # fmt: skip


def blocks(lines):
    """Paragraphs, list items and table rows, in order."""
    out, para, i = [], [], 0

    def flush():
        if para:
            out.append(dict(k="p", t=plain(" ".join(para))))
            para.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            flush()
        elif stripped.startswith("|"):
            flush()
            table = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table.append(lines[i])
                i += 1
            out += [dict(k="li", t=row) for row in table_rows(table)]
            continue
        elif re.match(r"[-*] ", stripped) and not line.startswith("    "):
            flush()
            para.append(stripped[2:])
            out.append(None)  # placeholder: the item's text is gathered below
        elif re.match(r"\d+\. ", stripped) and not line.startswith("    "):
            flush()
            para.append(stripped)
            out.append(None)
        else:
            para.append(stripped)
        # an item runs until a blank line or the next item
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if out and out[-1] is None and (not nxt or re.match(r"([-*]|\d+\.) ", nxt) or nxt.startswith("|")):
            out[-1] = dict(k="li", t=plain(" ".join(para)))
            para.clear()
        i += 1
    flush()
    return out


def document(path):
    """One document: its title and its sections."""
    lines = path.read_text(encoding="utf-8").splitlines()
    title, sections, current = None, [], None
    for line in lines:
        if line.startswith("# ") and title is None:
            title = plain(line[2:])
            current = dict(heading="", lines=[])
            sections.append(current)
        elif line.startswith("## ") or line.startswith("### "):
            current = dict(heading=plain(line.lstrip("#")), lines=[])
            sections.append(current)
        elif current is not None:
            current["lines"].append(line)
    out = [dict(heading=s["heading"], blocks=blocks(s["lines"])) for s in sections]
    return dict(title=title, sections=[s for s in out if s["heading"] or s["blocks"]])


def version():
    """SHA-256 over every source, by name and content."""
    digest = hashlib.sha256()
    for name in SOURCES:
        data = (ROOT / name).read_bytes()
        digest.update(b"%s\0%d\0" % (name.encode(), len(data)) + data)
    return digest.hexdigest()


def build():
    """The JSON the app ships."""
    return dict(schema=SCHEMA, version=version(), documents=[document(ROOT / name) for name in SOURCES])


def render():
    """The file's exact text."""
    return json.dumps(build(), indent=1, ensure_ascii=False) + "\n"


def main(argv=None):
    """Generate or check the app's copy."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true")
    mode.add_argument("--check", action="store_true")
    a = parser.parse_args(argv)
    text = render()
    if a.generate:
        OUT.write_text(text, encoding="utf-8")
        print("wrote %s (version %s)" % (OUT.relative_to(ROOT), json.loads(text)["version"][:12]))
        return 0
    if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
        print("%s is stale: run tools/agreement.py --generate" % OUT.name, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
