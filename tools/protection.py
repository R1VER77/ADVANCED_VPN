"""The controller's verdict on whether traffic is protected (the GUI's "Connected").

The supervisor's own state says its processes are alive, which is not the same thing. This
module turns three pieces of fresh evidence into the verdict the GUI shows:

- the cloak is connected: under cloak protocol v2 that means both ends proved the member's
  key over the hybrid exchange (its status file is rewritten every second);
- the carrier (WireGuard) has a handshake (likewise fresh);
- a path probe through the whole chain was answered recently: a DNS query from inside the
  application namespace to the exit's resolver (10.77.0.1), for a name under `.invalid`
  (RFC 6761: never resolves), which the exit answers itself and never forwards.

"protected" needs all three, fresh, with the kill switch in force. Anything less is
"blocked": "connecting" before the first verdict, "reconnecting" after one lapses.
"""

import os
import socket
import struct
import threading
import time

PROBE_NAME = "probe.cpvpn.invalid"
PROBE_SERVER = ("10.77.0.1", 53)
PROBE_EVERY = 5.0  # seconds between probes
PROBE_TIMEOUT = 2.0
PROBE_RETRY = 1.0  # seconds before retrying a probe that got no answer
# How old each piece of evidence may be. The status files are rewritten every second; the
# probe runs every 5 s, so 15 s tolerates two lost probes.
MAX_AGE = dict(cloak=3.0, carrier=3.0, probe=15.0)


def dns_query(qid, name=PROBE_NAME):
    """A DNS query (A record, recursion desired) for `name` with id `qid`."""
    if not 0 <= qid < 65536:
        raise ValueError("DNS id is 16 bits")
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def is_answer(packet, qid):
    """Whether `packet` is a DNS response to our query `qid` (any rcode: NXDOMAIN is the
    expected answer for a `.invalid` name and proves the exit's resolver replied)."""
    return len(packet) >= 12 and struct.unpack("!H", packet[:2])[0] == qid and bool(packet[2] & 0x80)


class PathProbe(threading.Thread):
    """Probes the chain from inside a network namespace. The namespace switch applies to
    this thread only (setns with CLONE_NEWNET is per thread), so the supervisor's own
    threads stay where they are."""

    def __init__(self, namespace_path, server=PROBE_SERVER, every=PROBE_EVERY, timeout=PROBE_TIMEOUT, clock=time.time):
        super().__init__(daemon=True, name="cpvpn-path-probe")
        self.namespace_path, self.server, self.every, self.timeout, self.clock = (
            namespace_path,
            server,
            every,
            timeout,
            clock,
        )
        self.ok_at = None
        self.stop = threading.Event()

    def once(self, sock):
        """One probe; returns True if the exit's resolver answered."""
        qid = int.from_bytes(os.urandom(2), "big")
        try:
            sock.sendto(dns_query(qid), self.server)
            deadline = time.monotonic() + self.timeout
            while (left := deadline - time.monotonic()) > 0:
                sock.settimeout(left)
                packet, addr = sock.recvfrom(512)
                if addr == self.server and is_answer(packet, qid):
                    self.ok_at = self.clock()
                    return True
        except OSError:
            pass
        return False

    def run(self):
        """Enter the namespace (this thread only), then probe every `every` seconds."""
        if self.namespace_path:
            fd = os.open(self.namespace_path, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.setns(fd, os.CLONE_NEWNET)
            finally:
                os.close(fd)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while not self.stop.is_set():
                # After a lost probe, try again soon: one lost packet during a busy page
                # load should not age the evidence towards a false "reconnecting".
                self.stop.wait(self.every if self.once(sock) else PROBE_RETRY)


class Evidence:
    """Tracks when each piece of evidence was last seen good, and gives the verdict."""

    def __init__(self):
        self.cloak_at = self.carrier_at = self.probe_at = None
        self.ever_protected = False
        self.since = None
        self.last = None

    def observe(self, now, cloak=None, cloak_mtime=None, carrier=None, carrier_mtime=None, probe_at=None):
        """Record what the status files and the probe show at `now`. A status file counts
        only while it is fresh (its writer is alive)."""
        if (
            cloak
            and cloak.get("connected") is True
            and cloak_mtime is not None
            and now - cloak_mtime <= MAX_AGE["cloak"]
        ):
            self.cloak_at = now
        if (
            carrier
            and carrier.get("handshake") is True
            and carrier_mtime is not None
            and now - carrier_mtime <= MAX_AGE["carrier"]
        ):
            self.carrier_at = now
        if probe_at is not None:
            self.probe_at = probe_at

    def fresh(self, now):
        """Whether every piece of evidence is within its maximum age at `now`."""
        ages = dict(cloak=self.cloak_at, carrier=self.carrier_at, probe=self.probe_at)
        return all(at is not None and now - at <= MAX_AGE[k] for k, at in ages.items())

    def verdict(self, now, supervising, kill_switch):
        """{lifecycle, protection, since, evidence}: "protected" only with all evidence
        fresh, the supervisor running and the kill switch in force."""
        if not (supervising and kill_switch):
            lifecycle, protection = "blocked", "blocked"
        elif self.fresh(now):
            lifecycle, protection = "connected", "protected"
            self.ever_protected = True
        else:
            lifecycle, protection = ("reconnecting" if self.ever_protected else "connecting"), "blocked"
        if lifecycle != self.last:
            self.since, self.last = now, lifecycle
        ages = dict(cloak=self.cloak_at, carrier=self.carrier_at, probe=self.probe_at)
        # Which evidence is missing or stale, and how old: what the GUI can say is wrong.
        stale = {
            k: (None if at is None else round(now - at, 1))
            for k, at in ages.items()
            if at is None or now - at > MAX_AGE[k]
        }
        evidence = None
        if protection == "protected":
            evidence = dict(
                cloak_confirmed_at=round(self.cloak_at, 3),
                carrier_handshake_at=round(self.carrier_at, 3),
                path_probe_at=round(self.probe_at, 3),
            )
        return dict(
            lifecycle=lifecycle, protection=protection, since=round(self.since, 3), evidence=evidence, stale=stale
        )
