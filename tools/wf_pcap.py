"""Small Linux libpcap adapter: bounded header snapshots and explicit kernel direction."""

import ctypes as c
import os
from pathlib import Path
import platform
import select


class Header(c.Structure):
    """Native 64-bit libpcap header; nanosecond precision is requested explicitly."""

    _fields_ = [("seconds", c.c_long), ("nanoseconds", c.c_long), ("captured", c.c_uint32), ("length", c.c_uint32)]


class Stats(c.Structure):
    """Linux pcap_stat counters; cumulative for each active handle."""

    _fields_ = [("received", c.c_uint32), ("dropped", c.c_uint32), ("interface_dropped", c.c_uint32)]


def timestamp(seconds, nanoseconds):
    """Reject an absent or malformed timestamp rather than using Python's receive time."""
    if seconds <= 0 or not 0 <= nanoseconds < 1_000_000_000:
        raise ValueError("invalid kernel-derived packet timestamp")
    return seconds + nanoseconds / 1_000_000_000


def library_path():
    """Use a root-owned system library, not a user-provided loader search path."""
    machine = platform.machine()
    triplet = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}.get(machine)
    if not triplet or c.sizeof(c.c_long) != 8:
        raise RuntimeError("the capture adapter requires a qualified 64-bit Linux libpcap ABI")
    mapping = Path("/proc/self/uid_map").read_text().splitlines()[0].split()
    lab = os.geteuid() == 0 and mapping[0] == "0" and mapping[1] != "0"
    # Host root is unmapped inside the lab. The ordinary-user experiment runner
    # verifies root ownership and hashes this same fixed system path before each arm.
    owner = int(Path("/proc/sys/kernel/overflowuid").read_text()) if lab else 0
    for directory in (Path("/usr/lib") / triplet, Path("/lib") / triplet, Path("/usr/lib64"), Path("/lib64")):
        for name in ("libpcap.so.0.8", "libpcap.so.1"):
            path = directory / name
            if path.is_file():
                real = path.resolve(strict=True)
                meta = real.stat()
                if meta.st_uid == owner and not meta.st_mode & 0o022:
                    return real
    raise RuntimeError("install the distribution's libpcap runtime before running collection")


class Capture:
    """Two direction-filtered rings avoid inferring direction from potentially spoofed headers."""

    def __init__(self, interface):
        self.path = library_path()
        self.lib = c.CDLL(str(self.path))
        self.handles = []
        lib = self.lib
        for name, arguments, result in (
            ("pcap_create", [c.c_char_p, c.c_void_p], c.c_void_p),
            ("pcap_activate", [c.c_void_p], c.c_int),
            ("pcap_get_tstamp_precision", [c.c_void_p], c.c_int),
            ("pcap_datalink", [c.c_void_p], c.c_int),
            ("pcap_get_selectable_fd", [c.c_void_p], c.c_int),
            ("pcap_geterr", [c.c_void_p], c.c_char_p),
            ("pcap_close", [c.c_void_p], None),
            ("pcap_lib_version", [], c.c_char_p),
            ("pcap_setnonblock", [c.c_void_p, c.c_int, c.c_void_p], c.c_int),
            ("pcap_stats", [c.c_void_p, c.POINTER(Stats)], c.c_int),
            ("pcap_next_ex", [c.c_void_p, c.POINTER(c.POINTER(Header)), c.POINTER(c.POINTER(c.c_ubyte))], c.c_int),
        ):
            function = getattr(lib, name)
            function.argtypes, function.restype = arguments, result
        for name in (
            "pcap_set_snaplen",
            "pcap_set_buffer_size",
            "pcap_set_timeout",
            "pcap_set_tstamp_precision",
            "pcap_set_tstamp_type",
            "pcap_setdirection",
        ):
            function = getattr(lib, name)
            function.argtypes, function.restype = [c.c_void_p, c.c_int], c.c_int
        self.version = lib.pcap_lib_version().decode("ascii", errors="replace")
        try:
            for direction in (1, 2):  # PCAP_D_IN, PCAP_D_OUT: kernel packet type, not MAC inference.
                error = c.create_string_buffer(256)
                handle = lib.pcap_create(os.fsencode(interface), error)
                if not handle:
                    raise RuntimeError("pcap_create: " + error.value.decode(errors="replace"))
                self.handles.append((handle, direction))
                for name, value in (
                    ("pcap_set_snaplen", 96),
                    ("pcap_set_buffer_size", 64 * 1024**2),
                    ("pcap_set_timeout", 10),
                    ("pcap_set_tstamp_precision", 1),
                    ("pcap_set_tstamp_type", 0),
                ):
                    if getattr(lib, name)(handle, value) != 0:
                        raise RuntimeError(name + ": " + self.error(handle))
                if lib.pcap_activate(handle) != 0:
                    raise RuntimeError("pcap_activate: " + self.error(handle))
                if lib.pcap_get_tstamp_precision(handle) != 1 or lib.pcap_datalink(handle) != 1:
                    raise RuntimeError("capture requires nanosecond timestamps and Ethernet link headers")
                if lib.pcap_setdirection(handle, direction) != 0 or lib.pcap_setnonblock(handle, 1, error) != 0:
                    raise RuntimeError("cannot set capture direction/nonblocking mode")
        except BaseException:
            self.close()
            raise
        self.fds = [lib.pcap_get_selectable_fd(handle) for handle, _ in self.handles]
        if any(fd < 0 for fd in self.fds):
            self.close()
            raise RuntimeError("capture backend has no selectable descriptors")

    def error(self, handle):
        """A bounded library error, never packet data."""
        return (self.lib.pcap_geterr(handle) or b"unknown capture error").decode(errors="replace")[:300]

    def next_batch(self):
        """One packet per direction, retaining fairness between the rings."""
        packets = []
        for handle, direction in self.handles:
            header, data = c.POINTER(Header)(), c.POINTER(c.c_ubyte)()
            result = self.lib.pcap_next_ex(handle, c.byref(header), c.byref(data))
            if result < 0:
                raise RuntimeError("pcap read failed: " + self.error(handle))
            if result == 1:
                info = header.contents
                if not 0 < info.captured <= 96 or info.length < info.captured:
                    raise RuntimeError("invalid libpcap header bounds")
                packets.append(
                    (
                        timestamp(info.seconds, info.nanoseconds),
                        c.string_at(data, info.captured),
                        int(info.length),
                        direction == 2,
                    )
                )
        if not packets:
            select.select(self.fds, [], [], 0.05)
        return packets

    def stats(self):
        """Sum both handles; receive counts may count a packet twice, drops must still be zero."""
        values = []
        for handle, _ in self.handles:
            value = Stats()
            if self.lib.pcap_stats(handle, c.byref(value)) != 0:
                raise RuntimeError("cannot read capture loss counters")
            values.append(value)
        return sum(v.received for v in values), sum(v.dropped + v.interface_dropped for v in values)

    def close(self):
        """Release only handles owned by this capture."""
        for handle, _ in self.handles:
            self.lib.pcap_close(handle)
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
