"""Corrupt, non-loadable and dynamic artifacts must fail the static-bootstrap gate."""

from pathlib import Path
import struct
import tempfile
import unittest

import elf_static


class ArtifactGate(unittest.TestCase):
    def test_rejects_a_loader_a_needed_library_writable_code_and_non_loadable_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HH", header, 16, 3, 62)
            struct.pack_into("<Q", header, 24, 0x1000)
            struct.pack_into("<Q", header, 32, 64)
            struct.pack_into("<HH", header, 54, 56, 2)
            load = struct.pack("<IIQQQQQQ", 1, 5, 176, 0x1000, 0, 16, 16, 0x1000)
            dynamic = struct.pack("<IIQQQQQQ", 2, 4, 192, 0x2000, 0, 16, 16, 8)
            clean = bytes(header) + load + dynamic + bytes(16) + struct.pack("<QQ", 0, 0)
            path.write_bytes(clean)
            self.assertFalse(elf_static.verify(path, 62)["interpreter"])
            # The architecture must be the one expected: an x86-64 artifact is not AArch64's,
            # and an AArch64 one passes only where AArch64 is expected.
            with self.assertRaisesRegex(ValueError, "architecture"):
                elf_static.verify(path, elf_static.MACHINES["aarch64"])
            arm = bytearray(clean)
            struct.pack_into("<H", arm, 18, elf_static.MACHINES["aarch64"])
            path.write_bytes(arm)
            self.assertFalse(elf_static.verify(path, elf_static.MACHINES["aarch64"])["interpreter"])
            with self.assertRaisesRegex(ValueError, "architecture"):
                elf_static.verify(path, 62)
            path.write_bytes(clean)
            broken = [b"not an ELF", clean[:80], clean[:-1]]
            loader = bytearray(clean)
            struct.pack_into("<I", loader, 120, 3)
            broken.append(loader)
            needed = bytearray(clean)
            struct.pack_into("<Q", needed, 192, 1)
            broken.append(needed)
            writable = bytearray(clean)
            struct.pack_into("<I", writable, 68, 7)
            broken.append(writable)
            no_code = bytearray(clean)
            struct.pack_into("<I", no_code, 64, 0)
            broken.append(no_code)
            for number, value in enumerate(broken):
                with self.subTest(case=number):
                    path.write_bytes(value)
                    with self.assertRaises(ValueError):
                        elf_static.verify(path, 62)
