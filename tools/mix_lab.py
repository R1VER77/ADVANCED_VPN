#!/usr/bin/env python3
"""Mix lane lab: a Katzenpost mixnet carrying live web requests, against a global passive
adversary, compared with a low-latency proxy on the same workload.

    clients c0..c9 (each its own namespace: kpclientd + http-proxy-client + a workload)
        |  one link each
    mixnet namespace: 3 directory authorities, 3 mix layers, a gateway, a service node
        running Katzenpost's HTTP proxy (and, for the baseline, a low-latency proxy)
        |  NAT
    the internet: live public websites

Every client sends HEAD requests at Poisson times to its own live websites. Phase 1 sends
them through the mixnet (Poisson delays at every hop; every client sends real-or-decoy
packets at the same Poisson rate and loops; nothing distinguishes a real request on the
wire). Phase 2 sends the same workload through a plain proxy with no mixing and no cover,
as a multi-hop VPN's shared exit carries it.

The adversary captures every client's link (when each client sends) and the service's
internet link (when each website is looked up, the first thing a fetch does), and is given
the delay distribution. tools/gpa.py scores each request against every client. The
result: its accuracy on each lane against chance (1/N), the posterior's entropy, whether a
client's link rate changes when it sends, latency percentiles and how many live fetches
succeeded.

Runs inside a disposable privileged container (it builds namespaces, NAT and raw
captures, and reaches the internet through Docker's bridge):

    docker build -t avpn-mixlab:2 -f tools/mix_lab.Dockerfile tools
    docker run --rm --privileged -v KATZENPOST_BIN:/kp/bin:ro -v $PWD/tools:/lab/tools:ro \\
        -v OUT:/out avpn-mixlab:2 python3 /lab/tools/mix_lab.py --bin /kp/bin --out /out

KATZENPOST_BIN holds unmodified Katzenpost binaries (dirauth, server, genconfig,
kpclientd, http-proxy-client, http-proxy-server; see third_party/katzenpost/build.sh).
Not run in CI (it takes about 40 minutes and the internet); its result is
docs/evidence/MIX_LANE.json.
"""

import argparse
import json
import math
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gpa  # noqa: E402
import mix  # noqa: E402

N_CLIENTS = 10
# Live public websites, three per client (disjoint, so the experimenter's ground truth
# for each lookup is exact; the attacker uses only timing). Every one negotiates hybrid
# post-quantum TLS 1.3 (X25519MLKEM768; checked 12 Nov 2026), which the lane's fetch
# plugin requires.
SITES = [
    "www.gnome.org", "www.kernel.org", "www.mozilla.org", "www.python.org", "www.rust-lang.org",
    "www.libreoffice.org", "www.privacyguides.org", "www.torproject.org", "tails.net", "www.apache.org",
    "www.qubes-os.org", "www.w3.org", "www.ietf.org", "www.iana.org", "pypi.org",
    "gitlab.com", "www.cloudflare.com", "crates.io", "www.bbc.co.uk", "www.theguardian.com",
    "www.npr.org", "archive.org", "signal.org", "mullvad.net", "www.ivpn.net",
    "proton.me", "duckduckgo.com", "www.openstreetmap.org", "www.postgresql.org", "www.fedoraproject.org",
]  # fmt: skip
# Cover clients (--cover-clients): ordinary mixnet clients with the same workload, on
# their own sites (hybrid-TLS too, none shared with the measured clients). They are never
# scored; the question is how much they hide the measured clients.
COVER_SITES = [
    "developer.mozilla.org", "www.chromium.org", "go.dev", "www.php.net", "www.ruby-lang.org",
    "www.haskell.org", "www.npmjs.com", "www.docker.com", "www.kali.org", "www.sqlite.org",
]  # fmt: skip
MIX_IP = "10.200.0.1"
BASELINE_PORT = 8888
# The low-latency baseline: an HTTP proxy that fetches absolute-URI requests at once.
DIRECT_PROXY = r"""
import socket,threading,urllib.request,sys
def serve(c):
    try:
        c.settimeout(60);buf=b''
        while b'\r\n\r\n' not in buf:
            b=c.recv(4096)
            if not b:return
            buf+=b
        method,url,_=buf.split(b'\r\n',1)[0].decode().split(' ',2)
        req=urllib.request.Request(url,method=method,headers={'User-Agent':'Mozilla/5.0','Connection':'close'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*a,**k):return None
        try:
            r=urllib.request.build_opener(NoRedirect).open(req,timeout=30);code=r.status
        except urllib.error.HTTPError as e:code=e.code
        c.sendall(('HTTP/1.1 %d X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'%code).encode())
    except Exception:
        try:c.sendall(b'HTTP/1.1 502 X\r\nContent-Length: 0\r\n\r\n')
        except Exception:pass
    finally:c.close()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])));s.listen(64)
while True:
    c,_=s.accept();threading.Thread(target=serve,args=(c,),daemon=True).start()
"""
# A client's workload: HEAD requests at Poisson times through a proxy, one JSON line each.
WORK = r"""
import json,random,socket,sys,threading,time
proxy_host,proxy_port,mean,duration,out=sys.argv[1],int(sys.argv[2]),float(sys.argv[3]),float(sys.argv[4]),sys.argv[5]
sites=sys.argv[6].split(',');rng=random.Random();lock=threading.Lock();f=open(out,'a')
def one(site):
    t=time.time();status=None
    try:
        c=socket.create_connection((proxy_host,proxy_port),10);c.settimeout(120)
        c.sendall(('HEAD https://%s/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n'%(site,site)).encode())
        line=c.makefile('rb').readline().decode(errors='replace').split()
        status=int(line[1]) if len(line)>1 and line[1].isdigit() else None;c.close()
    except Exception:pass
    with lock:f.write(json.dumps(dict(site=site,sent=t,done=time.time(),status=status))+'\n');f.flush()
end=time.time()+duration;threads=[]
while True:
    time.sleep(rng.expovariate(1/mean))
    if time.time()>=end:break
    th=threading.Thread(target=one,args=(rng.choice(sites),));th.start();threads.append(th)
for th in threads:th.join(150)
"""
# One GET through a client's proxy, with or without gzip (HTTP/1.0 to the proxy, so its
# answer is never chunked): what arrives, and whether a compressed page decodes whole.
GETZ = r"""
import json,socket,sys,zlib
c=socket.create_connection((sys.argv[1],int(sys.argv[2])),10);c.settimeout(150)
ae='Accept-Encoding: gzip\r\n' if sys.argv[4]=='gzip' else ''
c.sendall(('GET https://%s/ HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n%s\r\n'%(sys.argv[3],sys.argv[3],ae)).encode())
raw=b''
while True:
    b=c.recv(65536)
    if not b:break
    raw+=b
head,_,body=raw.partition(b'\r\n\r\n');h=head.decode('latin-1').lower().split('\r\n')
enc=[x.split(':',1)[1].strip() for x in h[1:] if x.startswith('content-encoding:')]
page,whole=body,None
if enc==['gzip'] and body:
    try:
        d=zlib.decompressobj(16+zlib.MAX_WBITS);page=d.decompress(body);whole=d.eof
    except zlib.error:whole=False
low=page[:4096].lower()
print(json.dumps(dict(site=sys.argv[3],asked=sys.argv[4],status=h[0],content_encoding=enc,wire_body_bytes=len(body),
                      page_bytes=len(page),gzip_whole=whole,html=b'<html' in low or b'<!doctype html' in low)))
"""
# The adversary's capture in the mixnet namespace: every packet a client sends towards the
# gateway or the baseline proxy (time, client), and every DNS lookup leaving for the
# internet (time, name). Contents are never read beyond the DNS question.
SNIFF = r"""
import socket,struct,sys,time
ports={int(p) for p in sys.argv[2].split(',')};out=open(sys.argv[1],'a',buffering=1)
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
def qname(b):
    labels=[];i=0
    while i<len(b) and b[i]:
        labels.append(b[i+1:i+1+b[i]].decode(errors='replace'));i+=1+b[i]
    return '.'.join(labels).lower()
while True:
    b,a=s.recvfrom(65535);t=time.time();ifn=a[0]
    if len(b)<34 or b[12:14]!=b'\x08\x00':continue
    ihl=(b[14]&15)*4;proto=b[23];p=14+ihl
    if ifn.startswith('m') and a[2]!=socket.PACKET_OUTGOING and proto==6:
        dport=struct.unpack('!H',b[p+2:p+4])[0];doff=(b[p+12]>>4)*4
        tot=struct.unpack('!H',b[16:18])[0];payload=tot-ihl-doff
        if dport in ports and payload>0:out.write('c %s %.6f %d %d\n'%(ifn[1:],t,dport,payload))
    elif ifn.startswith('m') and a[2]!=socket.PACKET_OUTGOING and proto==17:
        # Option E cells (4100-byte frames); mailbox pulls are tiny and told apart by size.
        dport=struct.unpack('!H',b[p+2:p+4])[0];payload=struct.unpack('!H',b[p+4:p+6])[0]-8
        if dport in ports and payload>1000:out.write('c %s %.6f %d %d\n'%(ifn[1:],t,dport,payload))
    elif ifn=='eg' and a[2]==socket.PACKET_OUTGOING and proto==17:
        dport=struct.unpack('!H',b[p+2:p+4])[0]
        if dport==53 and len(b)>p+8+12:out.write('d %.6f %s\n'%(t,qname(b[p+8+12:])))
"""


def sh(*args, check=True, timeout=120):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True, check=check, timeout=timeout)


def percentiles(values):
    if not values:
        return None
    v = sorted(values)
    pick = lambda q: round(v[min(len(v) - 1, int(q * len(v)))], 2)  # noqa: E731
    return dict(p50=pick(0.5), p90=pick(0.9), p99=pick(0.99), max=round(v[-1], 2), n=len(v))


def events(times, gap=0.02):
    """Group a client's packets into send events: one Sphinx packet is several segments."""
    out = []
    for t in sorted(times):
        if not out or t - out[-1][1] > gap:
            out.append([t, t])
        else:
            out[-1][1] = t
    return [a for a, _ in out]


def gamma_model(hops, mu_per_s, offset, n=200000, seed=7):
    """The network's own delay law: `hops` Poisson mix delays plus a fixed offset."""
    rng = random.Random(seed)
    return gpa.DelayModel([offset + sum(rng.expovariate(mu_per_s) for _ in range(hops)) for _ in range(n)])


def main():
    """Run both phases and the attack."""
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--bin", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--mix-seconds", type=float, default=900)
    p.add_argument("--baseline-seconds", type=float, default=420)
    p.add_argument("--mean-interval", type=float, default=30)
    p.add_argument(
        "--lane", choices=["katzenpost", "option_e"], default="katzenpost", help="which mixnet carries phase 1"
    )
    p.add_argument("--mixnode", type=Path, help="option_e: the advanced-vpn-mixnode binary")
    # X-Wing (Katzenpost) tuning: the speed/bandwidth/anonymity frontier.
    p.add_argument("--cover-clients", type=int, default=0, help="extra unscored clients (cover generators)")
    p.add_argument("--pki-scheme", default="Ed25519 Sphincs+", help="katzenpost: directory signature scheme")
    p.add_argument("--payload", type=int, default=8000, help="katzenpost: UserForwardPayloadLength (bytes)")
    p.add_argument("--lambda-p", type=float, default=1.0, help="katzenpost: real-or-drop cells per second")
    p.add_argument("--lambda-l", type=float, default=0.5, help="katzenpost: loops per second")
    p.add_argument("--mean-delay-ms", type=float, default=200, help="katzenpost: mean delay per hop (ms)")
    p.add_argument(
        "--stock-proxy",
        action="store_true",
        help="katzenpost: Katzenpost's own HTTP proxy instead of the post-quantum-only fetch plugin",
    )
    a = p.parse_args()
    out = a.out
    out.mkdir(parents=True, exist_ok=True)
    lab = Path("/run/mixlab")
    shutil.rmtree(lab, ignore_errors=True)
    lab.mkdir(parents=True)
    procs = []

    def spawn(ns, args, log, cwd=None):
        f = open(out / log, "a")  # noqa: SIM115
        x = subprocess.Popen(["ip", "netns", "exec", ns, *map(str, args)], stdout=f, stderr=subprocess.STDOUT, cwd=cwd)
        procs.append(x)
        return x

    n_all = N_CLIENTS + a.cover_clients  # measured clients first (0..9), then cover
    result = dict(
        lane=a.lane,
        clients=N_CLIENTS,
        cover_clients=a.cover_clients,
        live_sites=len(SITES),
        started=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    try:
        if a.lane == "katzenpost":
            # The mixnet's configuration, generated by Katzenpost's own tool.
            sh(a.bin / "genconfig", "-v", "--nrVoting", 3, "--nodes", 3, "--layers", 3, "--gateways", 1,
               "--serviceNodes", 1, "--storageNodes", 0, "--addr", MIX_IP, "--port", 30000, "-o", lab, "-b", lab,
               "--noMetrics", "--epochDuration", "2m", "--wirekem", "xwing", "--nike", "", "--kem", "xwing",
               "--pkiScheme", a.pki_scheme, "--UserForwardPayloadLength", a.payload, "--logLevel", "NOTICE",
               "--lambdaP", a.lambda_p / 1000, "--lambdaL", a.lambda_l / 1000,
               "--mu", 1 / a.mean_delay_ms)  # fmt: skip
            # The network must be one the product accepts: post-quantum Sphinx, hybrid
            # directory signatures and hybrid link KEMs (tools/mix.py check_config).
            mix.check_config((lab / "client" / "client.toml").read_text())
            result["pki_scheme"], result["wire_kem"], result["sphinx_kem"] = a.pki_scheme, "xwing", "xwing"
            params = dict(
                re.findall(
                    r"^\s*(Mu|LambdaP|LambdaL|LambdaM|LambdaR) = ([0-9.e-]+)",
                    (lab / "auth1/authority.toml").read_text(),
                    re.M,
                )
            )
            result["katzenpost_parameters"] = {k: float(v) for k, v in params.items()}
            geometry = dict(
                re.findall(
                    r'^\s*(PacketLength|HeaderLength|KEMName|NIKEName) = "?([^"\n]*)"?',
                    (lab / "client/client.toml").read_text(),
                    re.M,
                )
            )
            result["sphinx"] = geometry
            # The service node runs only the HTTP proxy (open to any global address).
            sn = lab / "servicenode1/katzenpost.toml"
            text = sn.read_text()
            blocks = text.split("  [[ServiceNode.CBORPluginKaetzchen]]")
            kept = [b for b in blocks[1:] if 'Capability = "http"' in b]
            tail = blocks[-1][blocks[-1].index("[PKI]") :] if "[PKI]" in blocks[-1] else ""
            kept = [b[: b.index("[PKI]")] if "[PKI]" in b else b for b in kept]
            text = blocks[0] + "".join("  [[ServiceNode.CBORPluginKaetzchen]]" + b for b in kept) + tail
            text = text.replace('host = "localhost:4242"', 'host = "*"')
            if not a.stock_proxy:
                # Our post-quantum-only fetch plugin replaces Katzenpost's Go proxy (TLS 1.3,
                # X25519MLKEM768 only); the clients' http-proxy-client is unchanged.
                text = text.replace(
                    'Command = "%s"' % (lab / "proxy_server"),
                    'Command = "%s"' % (Path(__file__).resolve().parent / "kp_pq_fetch.py"),
                )
            sn.write_text(text)
            result["fetch_plugin"] = (
                "katzenpost http-proxy-server" if a.stock_proxy else "tools/kp_pq_fetch.py (PQ-only)"
            )
            shutil.copy(a.bin / "http-proxy-server", lab / "proxy_server")
            gateway_port = int(
                re.search(
                    r'Addresses = \["tcp://gateway1:(\d+)"\]', (lab / "gateway1/katzenpost.toml").read_text()
                ).group(1)
            )
            names = ["auth1", "auth2", "auth3", "mix1", "mix2", "mix3", "gateway1", "servicenode1"]
            node_ports = {gateway_port}

        else:
            # Option E: three mixes and two providers (one runs the fetch service and its
            # reply-block pool), keys from the daemon's own keygen; same address, own ports.
            if not a.mixnode:
                raise SystemExit("--lane option_e needs --mixnode")
            names = []
            nodes = [("mix", 31001), ("mix", 31002), ("mix", 31003), ("provider", 31004), ("provider", 31005)]
            for i, (role, port) in enumerate(nodes):
                sh(a.mixnode, "--experimental", "keygen", "--dir", lab / ("node%d" % i), "--addr",
                   "%s:%d" % (MIX_IP, port), "--role", role)  # fmt: skip
            publics = [json.loads((lab / ("node%d" % i) / "public.json").read_text()) for i in range(len(nodes))]
            (lab / "directory.json").write_text(json.dumps(dict(mixes=publics)))
            client_provider = publics[4]["id"]
            gateway_port = None
            node_ports = {port for _, port in nodes}
            result["option_e"] = dict(mean_delay_ms=200, lambda_p=1.0, lambda_l=0.5, hops=3, pool_size=4000)
            result["sphinx"] = dict(
                scheme="PQ-Sphinx option E (entry ML-KEM-768, inner X25519)", header_bytes=1396, cell_bytes=4096
            )
        # Namespaces: the mixnet with its NAT link out; one namespace per client.
        sh("sysctl", "-qw", "net.ipv4.ip_forward=1")
        sh("ip", "netns", "add", "mix")
        sh("ip", "-n", "mix", "link", "set", "lo", "up")
        sh("ip", "-n", "mix", "address", "add", MIX_IP + "/32", "dev", "lo")
        sh("ip", "link", "add", "egh", "type", "veth", "peer", "name", "eg")
        sh("ip", "link", "set", "eg", "netns", "mix")
        sh("ip", "address", "add", "10.199.0.1/30", "dev", "egh")
        sh("ip", "link", "set", "egh", "up")
        sh("ip", "-n", "mix", "address", "add", "10.199.0.2/30", "dev", "eg")
        sh("ip", "-n", "mix", "link", "set", "eg", "up")
        sh("ip", "-n", "mix", "route", "add", "default", "via", "10.199.0.1")
        nat = "table ip mixlab {\n chain post {\n  type nat hook postrouting priority 100;\n  ip saddr 10.199.0.0/30 masquerade\n }\n}\n"
        subprocess.run(["nft", "-f", "-"], input=nat, text=True, check=True)
        Path("/etc/netns/mix").mkdir(parents=True, exist_ok=True)
        Path("/etc/netns/mix/hosts").write_text(
            "127.0.0.1 localhost\n" + "".join("%s %s\n" % (MIX_IP, n) for n in names)
        )
        Path("/etc/netns/mix/resolv.conf").write_text("nameserver 9.9.9.9\n")
        for k in range(n_all):
            ns = "c%d" % k
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
            sh("ip", "link", "add", "m%d" % k, "type", "veth", "peer", "name", "v%d" % k)
            sh("ip", "link", "set", "m%d" % k, "netns", "mix")
            sh("ip", "link", "set", "v%d" % k, "netns", ns)
            sh("ip", "-n", "mix", "address", "add", "10.201.%d.1/30" % k, "dev", "m%d" % k)
            sh("ip", "-n", ns, "address", "add", "10.201.%d.2/30" % k, "dev", "v%d" % k)
            sh("ip", "-n", "mix", "link", "set", "m%d" % k, "up")
            sh("ip", "-n", ns, "link", "set", "v%d" % k, "up")
            sh("ip", "-n", ns, "route", "add", "default", "via", "10.201.%d.1" % k)
            if a.lane == "option_e":
                # One 4100-byte cell per packet, as on the paced links it will ride.
                sh("ip", "-n", "mix", "link", "set", "m%d" % k, "mtu", 9000)
                sh("ip", "-n", ns, "link", "set", "v%d" % k, "mtu", 9000)
            Path("/etc/netns/" + ns).mkdir(parents=True, exist_ok=True)
            Path("/etc/netns/%s/hosts" % ns).write_text(
                "127.0.0.1 localhost kpclientd\n" + "".join("%s %s\n" % (MIX_IP, n) for n in names)
            )
            Path("/etc/netns/%s/resolv.conf" % ns).write_text("nameserver 127.0.0.1\n")  # clients resolve nothing
        capture = out / "capture.txt"
        spawn("mix", [sys.executable, "-c", SNIFF, capture, ",".join(map(str, sorted(node_ports | {BASELINE_PORT})))],
              "sniff.log")  # fmt: skip

        if a.lane == "katzenpost":
            # The mixnet: authorities first, then the nodes.
            for n in names[:3]:
                spawn("mix", [a.bin / "dirauth", "-f", lab / n / "authority.toml"], n + ".log", cwd=lab / n)
            time.sleep(3)
            for n in names[3:]:
                spawn("mix", [a.bin / "server", "-f", lab / n / "katzenpost.toml"], n + ".log", cwd=lab / n)
            spawn("mix", [sys.executable, "-c", DIRECT_PROXY, MIX_IP, BASELINE_PORT], "direct-proxy.log")
            # The clients: one kpclientd and one HTTP proxy client each.
            for k in range(n_all):
                d = lab / ("client%d" % k)
                d.mkdir()
                shutil.copy(lab / "client/client.toml", d / "client.toml")
                shutil.copy(lab / "client/thinclient.toml", d / "thinclient.toml")
                spawn("c%d" % k, [a.bin / "kpclientd", "-c", d / "client.toml"], "kpclientd%d.log" % k, cwd=d)
            time.sleep(5)
            for k in range(n_all):
                d = lab / ("client%d" % k)
                spawn("c%d" % k, [a.bin / "http-proxy-client", "--cfg", d / "thinclient.toml", "--listen",
                                  "127.0.0.1:8080", "--retry", 60, "--delay", 10], "proxyclient%d.log" % k, cwd=d)  # fmt: skip
        else:
            for i in range(5):
                args = [a.mixnode, "--experimental", "mix", "--dir", lab / ("node%d" % i), "--directory",
                        lab / "directory.json", "--mean-delay-ms", 200]  # fmt: skip
                if i == 3:
                    args += ["--service-pool", lab / "pool.json", "--pool-size", 4000]
                spawn("mix", args, "node%d.log" % i)
            spawn("mix", [sys.executable, "-c", DIRECT_PROXY, MIX_IP, BASELINE_PORT], "direct-proxy.log")
            time.sleep(3)
            for k in range(n_all):
                spawn("c%d" % k, [a.mixnode, "--experimental", "client", "--directory", lab / "directory.json",
                                  "--provider", client_provider, "--pool", lab / "pool.json", "--listen",
                                  "127.0.0.1:8080"], "optione-client%d.log" % k)  # fmt: skip
        sites = {k: SITES[3 * k : 3 * k + 3] for k in range(N_CLIENTS)}
        sites.update({k: COVER_SITES for k in range(N_CLIENTS, n_all)})

        # Wait until every client fetches a live site through the mixnet.
        t0 = time.time()
        ready = set()
        attempt = 0
        while len(ready) < n_all and time.time() - t0 < 1500:
            attempt += 1
            for k in sorted(set(range(n_all)) - ready):
                probe = out / ("ready%d.jsonl" % k)
                sh("ip", "netns", "exec", "c%d" % k, sys.executable, "-c", WORK, "127.0.0.1", 8080, 0.01, 0.02,
                   probe, sites[k][attempt % len(sites[k])], check=False, timeout=200)  # fmt: skip
                rows = [json.loads(x) for x in probe.read_text().splitlines()] if probe.exists() else []
                if any(r["status"] and r["status"] < 500 for r in rows):
                    ready.add(k)
            time.sleep(5)
        result["mixnet_ready_seconds"] = round(time.time() - t0, 1)
        result["clients_ready"] = len(ready)
        if len(ready) < n_all:
            raise RuntimeError("only %d clients reached the mixnet" % len(ready))

        # Phase 1: the mix lane. Phase 2: the same workload through the low-latency proxy.
        phases = {}
        for phase, (host, port, seconds) in {
            "mix": ("127.0.0.1", 8080, a.mix_seconds),
            "baseline": (MIX_IP, BASELINE_PORT, a.baseline_seconds),
        }.items():
            start = time.time()
            work = [spawn("c%d" % k, [sys.executable, "-c", WORK, host, port, a.mean_interval, seconds,
                                      out / ("%s%d.jsonl" % (phase, k)), ",".join(sites[k])], "work.log")
                    for k in range(n_all)]  # fmt: skip
            for w in work:
                w.wait(timeout=seconds + 400)
            phases[phase] = (start, time.time(), port)
            time.sleep(10)

        # After the measured phases: a compressed page through the real mixnet, end to end
        # (client proxy -> mixnet -> fetch plugin -> site and back), against the same page plain.
        if a.lane == "katzenpost":
            checks = []
            for site in ("www.kernel.org", "www.iana.org"):
                for mode in ("gzip", "plain"):
                    r = sh("ip", "netns", "exec", "c0", sys.executable, "-c", GETZ, "127.0.0.1", 8080, site, mode,
                           check=False, timeout=200)  # fmt: skip
                    try:
                        checks.append(json.loads(r.stdout.strip().splitlines()[-1]))
                    except (ValueError, IndexError):
                        checks.append(dict(site=site, asked=mode, error=r.stderr.strip()[-200:]))
            result["compressed_fetch"] = checks

        # The adversary's view.
        sends = {ph: {k: [] for k in range(n_all)} for ph in phases}
        up_bytes = {ph: {k: 0 for k in range(n_all)} for ph in phases}
        lookups = []
        for line in capture.read_text().splitlines():
            f = line.split()
            if f[0] == "c":
                k, t, port = int(f[1]), float(f[2]), int(f[3])
                for ph, (s, e, pport) in phases.items():
                    if (port in node_ports if ph == "mix" else port == pport) and s <= t <= e + 200:
                        sends[ph][k].append(t)
                        if t <= e:
                            up_bytes[ph][k] += int(f[4])
            elif f[0] == "d":
                lookups.append((float(f[1]), f[2]))
        owner = {site: k for k, ss in sites.items() if k < N_CLIENTS for site in ss}
        sends = {ph: {k: events(v) for k, v in by.items()} for ph, by in sends.items()}
        for ph, (s, e, _) in phases.items():
            requests = []
            for k in range(N_CLIENTS):
                f = out / ("%s%d.jsonl" % (ph, k))
                requests += [dict(json.loads(x), client=k) for x in f.read_text().splitlines()] if f.exists() else []
            # Ground truth: each lookup belongs to the earliest unmatched request for that
            # site sent before it (one lookup per fetch; repeats within 3 s are one).
            arrivals, delays, last = [], [], {}
            pending = sorted(requests, key=lambda r: r["sent"])
            for t, name in sorted(lookups):
                if not s <= t <= e + 200 or name not in owner or t - last.get(name, -1e9) < 3:
                    continue
                last[name] = t
                match = next((r for r in pending if r["site"] == name and r["sent"] <= t and not r.get("m")), None)
                if match:
                    match["m"] = True
                    arrivals.append((t, owner[name]))
                    delays.append(t - match["sent"])
            ok = [r for r in requests if r["status"] and r["status"] < 500]
            row = dict(
                requests=len(requests),
                live_fetches_answered=len(ok),
                statuses=sorted({r["status"] for r in requests if r["status"]}),
                latency_seconds=percentiles([r["done"] - r["sent"] for r in ok]),
                lookups_matched=len(arrivals),
                wire_send_events=sum(len(v) for v in sends[ph].values()),
                client_up_kbit_per_s=round(sum(up_bytes[ph].values()) * 8 / 1000 / max(1, e - s) / n_all, 1),
            )
            if arrivals:
                models = {"empirical": gpa.DelayModel(delays)}
                if ph == "mix" and a.lane == "katzenpost":
                    mu = result["katzenpost_parameters"]["Mu"] * 1000  # per ms -> per s
                    models["network_law"] = gamma_model(5, mu, max(min(delays), 0.0) * 0.5)
                elif ph == "mix":
                    models["network_law"] = gamma_model(3, 1000 / 200, max(min(delays), 0.0) * 0.5)
                # Every client is a candidate sender: the attacker cannot tell cover from users.
                attacks = {name: gpa.summary(gpa.attack(sends[ph], arrivals, m), n_all) for name, m in models.items()}
                best = max(attacks.values(), key=lambda r: r["top1_accuracy"])
                row.update(attack_models=attacks, attacker=best)
                if a.cover_clients:
                    # The attacker knows which clients are cover and ranks only the users.
                    users = {k: v for k, v in sends[ph].items() if k < N_CLIENTS}
                    known = {name: gpa.summary(gpa.attack(users, arrivals, m), N_CLIENTS) for name, m in models.items()}
                    row["attacker_knowing_cover"] = max(known.values(), key=lambda r: r["top1_accuracy"])
            # Does a client's link rate change while it has a request in flight?
            busy, idle = [0, 0.0], [0, 0.0]
            for k in range(N_CLIENTS):
                spans = [(r["sent"], r["done"]) for r in requests if r["client"] == k]
                ev = sends[ph][k]
                grid = s
                while grid + 1 <= e:
                    n = sum(1 for t in ev if grid <= t < grid + 1)
                    target = busy if any(x <= grid + 0.5 <= y for x, y in spans) else idle
                    target[0] += n
                    target[1] += 1
                    grid += 1
            row["sends_per_second"] = dict(
                busy=round(busy[0] / busy[1], 3) if busy[1] else None,
                idle=round(idle[0] / idle[1], 3) if idle[1] else None,
            )
            result[ph] = row
        result["chance"] = round(1 / n_all, 4)
        if a.cover_clients:
            result["chance_knowing_cover"] = round(1 / N_CLIENTS, 4)
        result["max_entropy_bits"] = round(math.log2(n_all), 3)
        print(json.dumps(result, indent=1))
        (out / "MIX_LANE.json").write_text(json.dumps(result, indent=1) + "\n")
    finally:
        for x in reversed(procs):
            if x.poll() is None:
                x.kill()
        for x in procs:
            try:
                x.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


if __name__ == "__main__":
    main()
