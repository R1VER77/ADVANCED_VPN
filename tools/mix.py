"""The mix lane: a Katzenpost mixnet client inside the protected namespace.

    avpn mix setup --config DIR     install a mixnet's client configuration
    avpn mix start                  run the mixnet client (and its cover traffic)
    avpn mix fetch URL              one request through the mixnet
    avpn mix status | stop

The VPN carries low-latency traffic; the mix lane carries what can wait seconds (mail,
chat, small fetches) and needs more than a VPN can give: every packet is held a random
time at every hop, and the client sends real-or-decoy packets and loops at a constant
Poisson rate whether or not it has anything to say, so even an adversary watching every
link cannot tell when, or whether, it sent (docs/evidence/MIX_LANE.json).

The client runs inside the protected namespace (`avpn run`), so the mixnet's gateway sees
the chain's exit, never this device. Its programs are Katzenpost's own, unmodified and
separate (AGPL-3.0; third_party/katzenpost/build.sh): kpclientd and its HTTP proxy, which
listens on 127.0.0.1:41199 inside the namespace for any application started with `avpn run`.
"""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

PROXY = ("127.0.0.1", 41199)
THIN = "127.0.0.1:41198"
BINARIES = ("kpclientd", "http-proxy-client")
INSTALLED = Path("/usr/lib/advanced-vpn/katzenpost")
CONFIG_FILES = ("client.toml", "thinclient.toml")


def binaries():
    """kpclientd and http-proxy-client: $AVPN_KATZENPOST (lab) or the installed copies."""
    base = Path(os.environ.get("AVPN_KATZENPOST", INSTALLED))
    found = {b: base / b for b in BINARIES}
    missing = [b for b, p in found.items() if not os.access(p, os.X_OK)]
    if missing:
        raise RuntimeError(
            "the mix lane needs Katzenpost's %s (third_party/katzenpost/build.sh, then install them in %s)"
            % (" and ".join(missing), base)
        )
    return found


def check_config(client):
    """A mixnet client configuration we can run: pinned gateways and voting authorities,
    decoy traffic on, no upstream proxy, and our fixed thin-client address. Returns the
    rewritten pair (the listen and dial addresses are ours, not the operator's)."""
    for need in ["[PinnedGateways]", "[VotingAuthority]", "[SphinxGeometry]"]:
        if need not in client:
            raise ValueError("not a Katzenpost client configuration: no " + need)
    if re.search(r"(?m)^\s*DisableDecoyTraffic\s*=\s*true", client):
        raise ValueError("this configuration turns decoy traffic off; the mix lane requires it")
    if re.search(r'(?m)^\s*Type\s*=\s*"(?!none")', client):
        raise ValueError("this configuration sends through an upstream proxy; the mix lane does not")
    host, port = THIN.split(":")
    client = re.sub(r'(?ms)(\[Listen\.Tcp\]\s*\n\s*Address\s*=\s*)"[^"]*"', r'\1"%s"' % THIN, client)
    client = re.sub(r'(?m)^(\s*File\s*=\s*)"[^"]*"', r'\1""', client)  # log to stderr, never a file
    if '"%s"' % THIN not in client:
        raise ValueError("the configuration has no [Listen.Tcp] address to set")
    thin = '[Dial]\n  [Dial.Tcp]\n    Address = "%s:%s"\n    Network = "tcp"\n' % (host, port)
    return client, thin


def setup(source, target):
    """Install a mixnet's client configuration (client.toml) into `target`."""
    client = (Path(source) / "client.toml").read_text()
    client, thin = check_config(client)
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    (target / "client.toml").write_text(client)
    (target / "thinclient.toml").write_text(thin)
    return target


def proxy_ready(timeout=0.5):
    """True when the mix lane's HTTP proxy accepts connections."""
    try:
        socket.create_connection(PROXY, timeout).close()
        return True
    except OSError:
        return False


def serve(config):
    """Run kpclientd and the HTTP proxy until either stops (inside the protected namespace)."""
    bins = binaries()
    work = Path(config)  # the private copy avpnctl made for this user
    procs = [subprocess.Popen([str(bins["kpclientd"]), "-c", str(work / "client.toml")], cwd=work,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]  # fmt: skip
    time.sleep(2)
    procs.append(
        subprocess.Popen(
            [str(bins["http-proxy-client"]), "--cfg", str(work / "thinclient.toml"), "--listen", "%s:%d" % PROXY,
             "--retry", "-1", "--delay", "5"],
            cwd=work, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    )  # fmt: skip

    def stop(*_):
        for p in procs:
            if p.poll() is None:
                p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while all(p.poll() is None for p in procs):
        time.sleep(1)
    stop()


def request(url, method="GET", timeout=180):
    """One request through the mix lane's proxy; returns (status, headers, body).
    The proxy answers 502 until the client has the mixnet's directory: retried."""
    if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d+)?(/[^\s]*)?", url):
        raise ValueError("an absolute http(s) URL is required")
    if method not in ("GET", "HEAD"):
        raise ValueError("GET or HEAD")
    host = url.split("/")[2]
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            c = socket.create_connection(PROXY, 10)
            c.settimeout(max(5, end - time.monotonic()))
            c.sendall(
                (
                    "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    % (method, url, host)
                ).encode()
            )
            raw = b""
            while True:
                b = c.recv(65536)
                if not b:
                    break
                raw += b
            c.close()
            head, _, body = raw.partition(b"\r\n\r\n")
            lines = head.decode(errors="replace").split("\r\n")
            status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else None
            last = (status, lines[1:], body)
            if status not in (None, 502):
                return last
        except OSError:
            pass
        time.sleep(5)
    if last:
        return last
    raise RuntimeError("the mix lane did not answer (is `avpn mix start` running?)")


def main(argv=None):
    """Entry point inside the protected namespace (avpnctl runs it via `avpn run`)."""
    p = argparse.ArgumentParser(description="mix lane (inside the protected namespace)")
    s = p.add_subparsers(dest="action", required=True)
    sv = s.add_parser("serve")
    sv.add_argument("--config", type=Path, required=True)
    f = s.add_parser("fetch")
    f.add_argument("url")
    f.add_argument("--method", choices=["GET", "HEAD"], default="GET")
    f.add_argument("--timeout", type=float, default=180)
    s.add_parser("ready")
    a = p.parse_args(argv)
    if a.action == "serve":
        serve(a.config)
    elif a.action == "ready":
        sys.exit(0 if proxy_ready() else 1)
    else:
        t = time.monotonic()
        status, headers, body = request(a.url, a.method, a.timeout)
        print(
            json.dumps(
                dict(status=status, seconds=round(time.monotonic() - t, 1), bytes=len(body), headers=headers[:20])
            )
        )
        if a.method == "GET" and body:
            sys.stdout.buffer.write(body)


if __name__ == "__main__":
    main()
