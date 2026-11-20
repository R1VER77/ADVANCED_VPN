#!/usr/bin/env python3
"""Require reviewed Linux bootstrap artifacts (x86-64 or AArch64, the host's own) to have no
dynamic loader/dependencies."""

import argparse
from pathlib import Path
import platform
import struct

# ELF e_machine of each supported host.
MACHINES = {"x86_64": 62, "aarch64": 183}


def verify(path, machine=None):
    """Validate bounded ELF program headers, including static PIE's dynamic entries. The
    binary must be for `machine` (an ELF e_machine), by default this host's architecture."""
    if machine is None:
        machine = MACHINES.get(platform.machine())
        if machine is None:
            raise ValueError("no reviewed bootstrap architecture for %s" % platform.machine())
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
            raise ValueError("bootstrap must be a little-endian 64-bit ELF")
        kind, found = struct.unpack_from("<HH", header, 16)
        offset = struct.unpack_from("<Q", header, 32)[0]
        entry = struct.unpack_from("<Q", header, 24)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if found != machine or kind not in (2, 3) or size != 56 or not 1 <= count <= 128:
            raise ValueError("unexpected bootstrap architecture or program-header layout")
        length = stream.seek(0, 2)
        if offset + size * count > length:
            raise ValueError("truncated ELF program headers")
        executable_entry = False
        for i in range(count):
            stream.seek(offset + i * size)
            fields = struct.unpack("<IIQQQQQQ", stream.read(56))
            segment, flags, start, virtual, _, files, _, _ = fields
            if start + files > length:
                raise ValueError("truncated ELF program segment")
            if segment == 3:
                raise ValueError("bootstrap contains a dynamic interpreter")
            if segment == 1 and flags & 3 == 3:
                raise ValueError("bootstrap contains writable executable memory")
            if segment == 1 and flags & 1 and virtual <= entry < virtual + files:
                executable_entry = True
            if segment == 2:
                if files > 65536 or files % 16:
                    raise ValueError("invalid static PIE dynamic segment")
                stream.seek(start)
                terminated = False
                for _ in range(files // 16):
                    tag, _ = struct.unpack("<QQ", stream.read(16))
                    if tag == 1:
                        raise ValueError("bootstrap contains a dynamic library dependency")
                    if tag == 0:
                        terminated = True
                        break
                if not terminated:
                    raise ValueError("unterminated static PIE dynamic segment")
        if not executable_entry:
            raise ValueError("bootstrap has no executable entry in a loadable file segment")
    return dict(architecture="x86_64", interpreter=False, needed_libraries=False)


def main():
    """Check all supplied artifacts before release staging."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    for path in parser.parse_args().files:
        verify(path)
        print(path.name + ": static ELF verified")


if __name__ == "__main__":
    main()
