use crate::{
    config::{Config, Identity},
    tls,
    tun::{Tun, allowed_packet, network},
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use quinn::{Connection, Endpoint};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};

#[derive(Default, serde::Serialize)]
/// Packet counters for one session, reported in status.
pub struct Counts {
    /// Datagrams forwarded.
    pub sent: u64,
    /// Datagrams received.
    pub received: u64,
    /// Datagrams refused as malformed or not allowed.
    pub dropped: u64,
    /// Datagrams refused by the per-second budget.
    pub rate_dropped: u64,
    /// Relays: the session ended because the next hop went silent (failover follows).
    pub next_hop_lost: bool,
}

// No per-peer maps or unbounded queues. Each direction has its own fixed budget.
/// A fixed per-second packet and byte budget for one direction of one session.
pub struct Budget {
    since: Instant,
    packets: u64,
    bytes: u64,
    max_packets: u64,
    max_bytes: u64,
}
impl Budget {
    /// A budget of `p` packets and `b` bytes per second.
    pub fn new(p: u64, b: u64) -> Self {
        Self {
            since: Instant::now(),
            packets: 0,
            bytes: 0,
            max_packets: p,
            max_bytes: b,
        }
    }
    /// Whether an `n`-byte datagram fits this second's budget (and count it if so).
    pub fn admit(&mut self, n: usize) -> bool {
        if self.since.elapsed() >= Duration::from_secs(1) {
            self.since = Instant::now();
            self.packets = 0;
            self.bytes = 0;
        }
        if self.packets >= self.max_packets || self.bytes.saturating_add(n as u64) > self.max_bytes
        {
            return false;
        }
        self.packets += 1;
        self.bytes += n as u64;
        true
    }
}
/// Constant-cell padding (`avpn help threat-model`), always on. Every datagram on every
/// hop is framed `[len: u16 big-endian][payload][zero padding]` up to the layer's `cell`
/// size, so the real packet size never shows on the wire — not just on the first hop,
/// the way DAITA alone would leave it. The receiver reads `len` and ignores the padding.
/// There is no unpadded mode: the signed profile must say `cells: true`
/// (`Config::validate`), so both ends of every layer always frame the same way.
fn frame(payload: &[u8], cell: usize) -> Bytes {
    // Callers bound `payload` below `cell - 2`; never truncate if that ever fails.
    let target = cell.max(payload.len() + 2);
    let mut b = vec![0u8; target];
    b[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    b[2..2 + payload.len()].copy_from_slice(payload);
    Bytes::from(b)
}

/// Recover the real payload from a received cell: read the length prefix and return
/// that many bytes, rejecting a frame that claims more than it carries.
fn unframe(d: &[u8]) -> Option<&[u8]> {
    let len = u16::from_be_bytes([*d.first()?, *d.get(1)?]) as usize;
    d.get(2..2 + len)
}

/// Room left below a layer's QUIC payload for the DATAGRAM frame's own header, so the
/// padded cell always fits what `max_datagram_size()` will allow. Generous (quinn's
/// real overhead is ~20 bytes) so the cell never has to shrink at runtime.
const CELL_RESERVE: usize = 48;

/// The cell size on a layer whose configured QUIC payload is `layer_payload`. It is a
/// fixed function of the signed profile, not of runtime timing, so every datagram on
/// the layer is one size from the very first packet and both peers agree without
/// negotiation.
fn cell_size(layer_payload: usize) -> usize {
    layer_payload - CELL_RESERVE
}

/// Test-only: when `AVPN_CELL_AUDIT` names a path, every process records the distinct
/// datagram payload sizes it sends to `<path>.<role>.<pid>`. The namespace lab asserts that
/// under constant-cell padding each hop's set collapses to one size — which catches any
/// send path that forgot to pad, not just the padding helper in isolation. No file, no
/// cost in production.
fn audit(role: &str, len: usize) {
    // Keyed by the sending layer's label: one client process runs several layers (its
    // inner tunnel and an outer bridge), so each has its own cell and its own file.
    static SEEN: std::sync::Mutex<
        Option<std::collections::BTreeMap<String, std::collections::BTreeSet<usize>>>,
    > = std::sync::Mutex::new(None);
    if let Some(path) = std::env::var_os("AVPN_CELL_AUDIT") {
        let mut guard = SEEN.lock().unwrap();
        let seen = guard.get_or_insert_with(Default::default);
        if seen.entry(role.to_string()).or_default().insert(len) {
            let sizes: Vec<_> = seen[role].iter().copied().collect();
            // One file per process and layer, so every process the lab starts is checked.
            let mut p = path.clone();
            p.push(format!(".{role}.{}", std::process::id()));
            let _ = std::fs::write(p, format!("{sizes:?}"));
        }
    }
}

fn endpoint_server(bind: SocketAddr, i: &Identity, fd: Option<i32>, mtu: u16) -> Result<Endpoint> {
    let s = tls::server(i, fd, mtu)?;
    let sock = std::net::UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let mut e = quinn::EndpointConfig::default();
    e.max_udp_payload_size(mtu)?;
    Ok(Endpoint::new(
        e,
        Some(s),
        sock,
        Arc::new(quinn::TokioRuntime),
    )?)
}
fn endpoint_client(bind: SocketAddr, i: &Identity, fd: Option<i32>, mtu: u16) -> Result<Endpoint> {
    let sock = std::net::UdpSocket::bind(bind)?;
    sock.set_nonblocking(true)?;
    let mut e = quinn::EndpointConfig::default();
    e.max_udp_payload_size(mtu)?;
    let mut out = Endpoint::new(e, None, sock, Arc::new(quinn::TokioRuntime))?;
    out.set_default_client_config(tls::client(i, fd, mtu)?);
    Ok(out)
}
async fn connect(e: &Endpoint, addr: SocketAddr, i: &Identity) -> Result<(Connection, Duration)> {
    let c = timeout(Duration::from_secs(5), e.connect(addr, &i.server_name)?).await??;
    let life = match tls::authenticated(&c, i) {
        Ok((life, _pin)) => life,
        Err(e) => {
            c.close(1u32.into(), b"policy rejected");
            return Err(e);
        }
    };
    Ok((c, life))
}
fn fd(fds: &BTreeMap<String, i32>, role: &str) -> Option<i32> {
    fds.get(role).copied()
}

/// A server's link keys: outbound (in `link_out` order), then inbound.
pub type LinkKeys = (Vec<[u8; 32]>, Vec<[u8; 32]>);
/// This server's link keys from the sealed `link` descriptor: one 32-byte key per
/// outbound link (`link_out` order), then one per inbound link.
pub fn link_keys(c: &Config, fds: &BTreeMap<String, i32>) -> Result<LinkKeys> {
    let want = c.link_out.len() + c.link_in;
    if want == 0 {
        return Ok((vec![], vec![]));
    }
    let raw = crate::config::sealed_fd(
        fd(fds, "link").context("link keys required (per-hop shaping)")?,
        32 * want as u64,
    )?;
    ensure!(raw.len() == 32 * want, "one 32-byte key per link");
    let keys: Vec<[u8; 32]> = raw
        .chunks_exact(32)
        .map(|k| k.try_into().expect("chunk length"))
        .collect();
    ensure!(
        keys.iter().all(|k| k.iter().any(|&b| b != 0)),
        "nonzero link keys required"
    );
    let (out, inbound) = keys.split_at(c.link_out.len());
    Ok((out.to_vec(), inbound.to_vec()))
}

/// The bytes a paced link cell holds for a layer whose QUIC payload is `payload`.
fn link_cell(payload: usize) -> usize {
    payload + 2
}

/// A paced link answers every tick; this long without an authenticated cell means the
/// next hop is gone, and the session ends so the client reconnects through a live one.
const LINK_DEAD: Duration = Duration::from_secs(3);
/// How long a new session waits for a next hop's first cell before trying the next.
const LINK_LIVE_WAIT: Duration = Duration::from_secs(2);
/// A next hop found dead is skipped for this long.
const DEAD_FOR: Duration = Duration::from_secs(30);

fn random_u64() -> u64 {
    use aws_lc_rs::rand::SecureRandom;
    let mut b = [0u8; 8];
    // The OS generator; if it ever fails, rotation simply waits the window's minimum.
    let _ = aws_lc_rs::rand::SystemRandom::new().fill(&mut b);
    u64::from_be_bytes(b)
}

/// The next hops of the server before the exit: the exit, then standby exits. New
/// sessions go to the current one if it is live, else the next live one (failover);
/// with a rotation window, the current one changes at a random time within it, always
/// at a session boundary. The entry (the client's guard) is not this server's choice.
pub struct NextHops {
    order: Vec<SocketAddr>,
    current: usize,
    dead: BTreeMap<SocketAddr, Instant>,
    window: Option<[u64; 2]>,
    rotate_at: Option<Instant>,
}

impl NextHops {
    /// The next hops of a relay: its exit (or middle relay) first, then standby exits.
    pub fn new(c: &Config) -> Self {
        let order: Vec<SocketAddr> = c
            .exit
            .into_iter()
            .chain(c.alternates.iter().copied())
            .collect();
        let mut h = NextHops {
            order,
            current: 0,
            dead: BTreeMap::new(),
            window: c.rotate_seconds,
            rotate_at: None,
        };
        h.rotate_at = h.window.map(|_| Instant::now() + h.draw());
        h
    }
    fn draw(&self) -> Duration {
        let [lo, hi] = self.window.unwrap_or([0, 0]);
        Duration::from_secs(lo + random_u64() % (hi - lo + 1))
    }
    fn is_dead(&self, a: &SocketAddr) -> bool {
        self.dead
            .get(a)
            .is_some_and(|until| Instant::now() < *until)
    }
    /// The next hops to try for a new session, in order.
    pub fn candidates(&mut self) -> Vec<SocketAddr> {
        let n = self.order.len();
        if n > 1 && self.rotate_at.is_some_and(|at| Instant::now() >= at) {
            let others: Vec<usize> = (0..n)
                .filter(|&k| k != self.current && !self.is_dead(&self.order[k]))
                .collect();
            if !others.is_empty() {
                self.current = others[(random_u64() % others.len() as u64) as usize];
            }
            self.rotate_at = Some(Instant::now() + self.draw());
        }
        let ring: Vec<SocketAddr> = (0..n).map(|k| self.order[(self.current + k) % n]).collect();
        let live: Vec<SocketAddr> = ring.iter().copied().filter(|a| !self.is_dead(a)).collect();
        if live.is_empty() { ring } else { live }
    }
    /// Record that `a` carries the current sessions.
    pub fn using(&mut self, a: SocketAddr) {
        if let Some(k) = self.order.iter().position(|x| *x == a) {
            self.current = k;
        }
        self.dead.remove(&a);
    }
    /// Record that `a` did not answer: skip it for a while.
    pub fn lost(&mut self, a: SocketAddr) {
        self.dead.insert(a, Instant::now() + DEAD_FOR);
    }
    /// Test-only: force the rotation deadline.
    #[cfg(test)]
    fn rotate_now(&mut self) {
        self.rotate_at = Some(Instant::now());
    }
}

/// Open the paced link from this relay to `next_hop`.
async fn open_link(
    c: &Config,
    layer: usize,
    next_hop: SocketAddr,
    psk: [u8; 32],
) -> Result<crate::link::Egress> {
    let next = tls::layer_payload(c.mtu, c.layers, layer + 1) as usize;
    let pace = crate::link::Pace::of(c.link_class().context("link rate required")?);
    crate::link::egress(next_hop, psk, pace, link_cell(next)).await
}

async fn relay_session(
    c: &Config,
    conn: &Connection,
    life: Duration,
    layer: usize,
    mut link: crate::link::Egress,
) -> Result<Counts> {
    let next = tls::layer_payload(c.mtu, c.layers, layer + 1) as usize;
    let mut counts = Counts::default();
    let mut health = tokio::time::interval(Duration::from_millis(250));
    let started = Instant::now();
    let mut up = Budget::new(c.packets_per_second, c.bytes_per_second);
    let mut down = Budget::new(c.packets_per_second, c.bytes_per_second);
    // Datagrams carry the next layer's packets, bounded by that layer's payload size.
    let cell = cell_size(tls::layer_payload(c.mtu, c.layers, layer) as usize);
    let deadline = sleep(life.min(Duration::from_secs(c.session_seconds)));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _=&mut deadline=>break,
            _=health.tick()=>{
                // Never heard, or silent since: the next hop is gone; end the session.
                let gone=match link.silent_for(){Some(s)=>s>LINK_DEAD,None=>started.elapsed()>LINK_DEAD};
                if gone {counts.next_hop_lost=true;break;}
            }
            r=conn.read_datagram()=>{
                let d=r?;
                if !up.admit(d.len()) {counts.rate_dropped+=1;continue;}
                let Some(p)=unframe(&d) else {counts.dropped+=1;continue;};
                if p.len()>next || p.is_empty() {counts.dropped+=1;continue;}
                // Into the paced link: a full queue drops, it never bursts.
                if link.send(p) {counts.sent+=1;} else {counts.dropped+=1;}
            }
            r=link.rx.recv()=>{
                let Some(b)=r else {break};
                let n=b.len();
                if n==0 || n>next {counts.dropped+=1;continue;}
                if !down.admit(cell) {counts.rate_dropped+=1;continue;}
                let f=frame(&b[..n],cell);audit(&c.role,f.len());if conn.send_datagram(f).is_err() {counts.dropped+=1;}else{counts.received+=1;}
            }
        }
    }
    Ok(counts)
}

/// Legacy relay session (MTU 1280, no per-hop shaping): plain UDP forwarding to the
/// next hop without paced links. Managed chains (MTU 1100) always use paced links.
async fn legacy_relay_session(
    c: &Config,
    conn: &Connection,
    life: Duration,
    layer: usize,
    next_hop: SocketAddr,
) -> Result<Counts> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(next_hop).await?;
    let mut b = vec![0; 65536];
    let mut counts = Counts::default();
    let mut up = Budget::new(c.packets_per_second, c.bytes_per_second);
    let mut down = Budget::new(c.packets_per_second, c.bytes_per_second);
    // Datagrams carry the next layer's packets, bounded by that layer's payload size.
    let next = tls::layer_payload(c.mtu, c.layers, layer + 1) as usize;
    let cell = cell_size(tls::layer_payload(c.mtu, c.layers, layer) as usize);
    let deadline = sleep(life.min(Duration::from_secs(c.session_seconds)));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _=&mut deadline=>break,
            r=conn.read_datagram()=>{
                let d=r?;
                if !up.admit(d.len()) {counts.rate_dropped+=1;continue;}
                let Some(p)=unframe(&d) else {counts.dropped+=1;continue;};
                if p.len()>next || p.is_empty() {counts.dropped+=1;continue;}
                udp.send(p).await?;counts.sent+=1;
            }
            r=udp.recv(&mut b)=>{
                let n=r?;
                if n==0 || n>next {counts.dropped+=1;continue;}
                if !down.admit(cell) {counts.rate_dropped+=1;continue;}
                let f=frame(&b[..n],cell);audit(&c.role,f.len());if conn.send_datagram(f).is_err() {counts.dropped+=1;}else{counts.received+=1;}
            }
        }
    }
    Ok(counts)
}

async fn tunnel(
    c: &Config,
    conn: &Connection,
    life: Duration,
    tun_fd: Option<i32>,
) -> Result<Counts> {
    let name = c.tun.as_deref().context("TUN missing")?;
    let tun = if let Some(fd) = tun_fd {
        Tun::inherited(fd, name)?
    } else {
        Tun::open(name)?
    };
    let a: Ipv4Addr = c.local_ip.as_deref().unwrap().parse()?;
    let b: Ipv4Addr = c.peer_ip.as_deref().unwrap().parse()?;
    let mut routes = c
        .destinations
        .iter()
        .map(|s| network(s))
        .collect::<Result<Vec<_>>>()?;
    let (fixed, out_source) = if c.role == "client" {
        (a, true)
    } else {
        (b, false)
    };
    // The tunnel peer itself is always reachable, in addition to explicit destination CIDRs.
    routes.push((u32::from(if c.role == "client" { b } else { a }), u32::MAX));
    let mut buf = vec![0; 65536];
    let mut counts = Counts::default();
    let mut up = Budget::new(c.packets_per_second, c.bytes_per_second);
    let mut down = Budget::new(c.packets_per_second, c.bytes_per_second);
    let cell = cell_size(tls::layer_payload(c.mtu, c.layers, c.layers - 1) as usize);
    let deadline = sleep(life.min(Duration::from_secs(c.session_seconds)));
    tokio::pin!(deadline);
    println!("{{\"event\":\"tunnel_ready\",\"kx\":\"X25519MLKEM768\",\"cipher\":\"AES_256_GCM\"}}");
    loop {
        tokio::select! {
            _=&mut deadline=>break,
            r=tun.read(&mut buf)=>{
                let n=r?;
                if !allowed_packet(&buf[..n],fixed,&routes,out_source,c.mtu) {counts.dropped+=1;continue;}
                if !up.admit(cell) {counts.rate_dropped+=1;continue;}
                let f=frame(&buf[..n],cell);audit(&c.role,f.len());if conn.send_datagram(f).is_err(){counts.dropped+=1;}else{counts.sent+=1;}
            }
            r=conn.read_datagram()=>{
                let d=r?;
                if !down.admit(d.len()){counts.rate_dropped+=1;continue;}
                let Some(p)=unframe(&d) else {counts.dropped+=1;continue;};
                if !allowed_packet(p,fixed,&routes,!out_source,c.mtu){counts.dropped+=1;continue;}
                tun.write(p).await?;counts.received+=1;
            }
        }
    }
    Ok(counts)
}

/// Sessions of one mesh exit, keyed by member tunnel address: the shared TUN reader
/// hands each downlink packet to the owning session over a bounded channel.
type Demux = Arc<std::sync::Mutex<BTreeMap<Ipv4Addr, tokio::sync::mpsc::Sender<Bytes>>>>;

/// Read the exit's shared TUN and route every packet to the session that owns its
/// destination address. Packets for an unknown address are dropped, never misdelivered.
async fn demux_tun(tun: Arc<Tun>, demux: Demux, mtu: usize) -> Result<()> {
    let mut buf = vec![0; 65536];
    loop {
        let n = tun.read(&mut buf).await?;
        if !(20..=mtu).contains(&n) {
            continue;
        }
        let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
        let sender = demux.lock().unwrap().get(&dst).cloned();
        if let Some(tx) = sender {
            let _ = tx.try_send(Bytes::copy_from_slice(&buf[..n]));
        }
    }
}

/// One mesh exit session: the member's uplink goes to the shared TUN; its downlink
/// arrives from the demux. The member's own tunnel address is the only source its
/// packets may carry and the only destination it receives.
async fn mesh_tunnel(
    c: Arc<Config>,
    conn: Connection,
    life: Duration,
    member: crate::config::Member,
    tun: Arc<Tun>,
    demux: Demux,
) -> Result<Counts> {
    let member_ip: Ipv4Addr = member
        .peer_ip
        .as_deref()
        .context("member tunnel address missing")?
        .parse()?;
    let local: Ipv4Addr = c
        .local_ip
        .as_deref()
        .context("local_ip required")?
        .parse()?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(256);
    demux.lock().unwrap().insert(member_ip, tx);
    let mut routes = c
        .destinations
        .iter()
        .map(|s| network(s))
        .collect::<Result<Vec<_>>>()?;
    // The exit itself (its DNS forwarder) stays reachable for every member.
    routes.push((u32::from(local), u32::MAX));
    let mut counts = Counts::default();
    let mut up = Budget::new(c.packets_per_second, c.bytes_per_second);
    let mut down = Budget::new(c.packets_per_second, c.bytes_per_second);
    let cell = cell_size(tls::layer_payload(c.mtu, c.layers, c.layers - 1) as usize);
    let deadline = sleep(life.min(Duration::from_secs(c.session_seconds)));
    tokio::pin!(deadline);
    println!("{{\"event\":\"tunnel_ready\",\"kx\":\"X25519MLKEM768\",\"cipher\":\"AES_256_GCM\"}}");
    let result = loop {
        tokio::select! {
            _=&mut deadline=>break Ok(()),
            r=conn.read_datagram()=>{
                let d=match r { Ok(d)=>d, Err(e)=>break Err(e.into()) };
                if !up.admit(d.len()){counts.rate_dropped+=1;continue;}
                let Some(p)=unframe(&d) else {counts.dropped+=1;continue;};
                if !allowed_packet(p,member_ip,&routes,true,c.mtu){counts.dropped+=1;continue;}
                tun.write(p).await?;counts.sent+=1;
            }
            r=rx.recv()=>{
                let Some(p)=r else {break Ok(())};
                if !allowed_packet(&p,member_ip,&routes,false,c.mtu){counts.dropped+=1;continue;}
                if !down.admit(cell){counts.rate_dropped+=1;continue;}
                let f=frame(&p,cell);audit(&c.role,f.len());
                if conn.send_datagram(f).is_err(){counts.dropped+=1;}else{counts.received+=1;}
            }
        }
    };
    // Deregister before reporting: no downlink is routed to a closing session.
    demux.lock().unwrap().remove(&member_ip);
    result.map(|_| counts)
}

/// Run a relay or exit: accept authenticated sessions and terminate this server's layer.
pub async fn serve(c: &Config, fds: &BTreeMap<String, i32>, tun_fd: Option<i32>) -> Result<()> {
    let relay = c.role == "relay";
    // Each server terminates exactly one layer: entry/middle relays forward the
    // next layer's ciphertext; the exit owns the innermost layer and the TUN.
    let (role, i, layer) = c.server_layer()?;
    let (link_out, link_in) = link_keys(c, fds)?;
    // Behind a relay, the public port belongs to the paced link; QUIC listens on
    // loopback and sees each relay as one local peer.
    let bind = if c.paced_ingress() {
        "127.0.0.1:0".parse()?
    } else {
        c.listen
    };
    let endpoint = endpoint_server(
        bind,
        i,
        fd(fds, role),
        tls::layer_payload(c.mtu, c.layers, layer),
    )?;
    let _ingress = if c.paced_ingress() {
        let pace = crate::link::Pace::of(c.link_class().context("link rate required")?);
        let cell = link_cell(tls::layer_payload(c.mtu, c.layers, layer) as usize);
        let quic = endpoint.local_addr()?;
        let task = tokio::spawn(crate::link::ingress(
            c.listen,
            quic,
            link_in,
            pace,
            cell,
            2 * c.members.len().max(1) + 8,
        ));
        Some(crate::link::Guard::new(task))
    } else {
        None
    };
    let mut hops = NextHops::new(c);
    let link_for = |next: SocketAddr| -> Result<[u8; 32]> {
        let k = c
            .link_out
            .iter()
            .position(|n| *n == next)
            .context("no paced link to this next hop")?;
        Ok(link_out[k])
    };
    println!("{{\"event\":\"listening\"}}");
    if c.members.is_empty() {
        // Single-chain server: one session at a time.
        while let Some(incoming) = endpoint.accept().await {
            // QUIC Retry verifies return routability before expensive handshake allocation.
            if !incoming.remote_address_validated() {
                let _ = incoming.retry();
                continue;
            }
            let conn = match timeout(Duration::from_secs(5), incoming).await {
                Ok(Ok(c)) => c,
                _ => continue,
            };
            let (life, _pin) = match tls::authenticated(&conn, i) {
                Ok(v) => v,
                Err(_) => {
                    conn.close(1u32.into(), b"policy rejected");
                    continue;
                }
            };
            println!(
                "{{\"event\":\"authenticated\",\"kx\":\"X25519MLKEM768\",\"cipher\":\"AES_256_GCM\"}}"
            );
            let result = if relay {
                let next = c.exit.context("relay exit required")?;
                // Legacy standalone mode (MTU 1280) has no paced links; forward directly.
                if c.link_out.is_empty() {
                    legacy_relay_session(c, &conn, life, layer, next).await
                } else {
                    // Managed chains use paced links with failover to standby exits.
                    let mut chosen = None;
                    for candidate in hops.candidates() {
                        let link = open_link(c, layer, candidate, link_for(candidate)?).await?;
                        if link.alive_within(LINK_LIVE_WAIT).await {
                            chosen = Some((candidate, link));
                            break;
                        }
                        hops.lost(candidate);
                    }
                    match chosen {
                        None => Err(anyhow::anyhow!("no live next hop")),
                        Some((candidate, link)) => {
                            hops.using(candidate);
                            let index = c
                                .exit
                                .into_iter()
                                .chain(c.alternates.iter().copied())
                                .position(|a| a == candidate);
                            println!("{}", serde_json::json!({"event":"next_hop","index":index}));
                            let r = relay_session(c, &conn, life, layer, link).await;
                            if r.as_ref().is_ok_and(|k| k.next_hop_lost) {
                                hops.lost(candidate);
                            }
                            r
                        }
                    }
                }
            } else {
                tunnel(c, &conn, life, tun_fd).await
            };
            conn.close(0u32.into(), b"session ended");
            if let Ok(counts) = result {
                println!(
                    "{}",
                    serde_json::json!({"event":"session_ended","counts":counts})
                );
            } else {
                println!("{{\"event\":\"session_closed\"}}");
            }
        }
        return Ok(());
    }
    // Mesh server: admitted members share this process, one task per session, bounded
    // by the member count. A member is identified by the pin its certificate proved.
    let c = Arc::new(c.clone());
    let (tun, demux) = if relay {
        (None, None)
    } else {
        let name = c.tun.as_deref().context("TUN missing")?;
        let tun = Arc::new(if let Some(fd) = tun_fd {
            Tun::inherited(fd, name)?
        } else {
            Tun::open(name)?
        });
        let demux: Demux = Arc::default();
        tokio::spawn(demux_tun(tun.clone(), demux.clone(), c.mtu));
        (Some(tun), Some(demux))
    };
    let slots = Arc::new(tokio::sync::Semaphore::new(2 * c.members.len() + 8));
    while let Some(incoming) = endpoint.accept().await {
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
        let conn = match timeout(Duration::from_secs(5), incoming).await {
            Ok(Ok(c)) => c,
            _ => continue,
        };
        let (life, pin) = match tls::authenticated(&conn, i) {
            Ok(v) => v,
            Err(_) => {
                conn.close(1u32.into(), b"policy rejected");
                continue;
            }
        };
        let Some(member) = c.member(&pin).cloned() else {
            conn.close(1u32.into(), b"unknown member");
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            conn.close(1u32.into(), b"server busy");
            continue;
        };
        println!(
            "{{\"event\":\"authenticated\",\"kx\":\"X25519MLKEM768\",\"cipher\":\"AES_256_GCM\"}}"
        );
        let psk = match member.exit {
            Some(next) => link_for(next).ok(),
            None => None,
        };
        let link_out_empty = c.link_out.is_empty();
        let (c, tun, demux) = (c.clone(), tun.clone(), demux.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let result = if relay {
                // Legacy standalone mode (MTU 1280) has no paced links.
                if link_out_empty {
                    match member.exit {
                        Some(next) => legacy_relay_session(&c, &conn, life, layer, next).await,
                        None => Err(anyhow::anyhow!("member without a next hop")),
                    }
                } else {
                    match (member.exit, psk) {
                        (Some(next), Some(psk)) => match open_link(&c, layer, next, psk).await {
                            Ok(link) => relay_session(&c, &conn, life, layer, link).await,
                            Err(e) => Err(e),
                        },
                        _ => Err(anyhow::anyhow!("member without a paced next hop")),
                    }
                }
            } else {
                mesh_tunnel(
                    c,
                    conn.clone(),
                    life,
                    member,
                    tun.expect("exit TUN"),
                    demux.expect("exit demux"),
                )
                .await
            };
            conn.close(0u32.into(), b"session ended");
            if let Ok(counts) = result {
                println!(
                    "{}",
                    serde_json::json!({"event":"session_ended","counts":counts})
                );
            } else {
                println!("{{\"event\":\"session_closed\"}}");
            }
        });
    }
    Ok(())
}

/// Carry one layer's UDP packets as DATAGRAMs of its parent connection.
fn bridge(
    socket: Arc<UdpSocket>,
    parent: Connection,
    max_datagram: usize,
    max_packets: u64,
    max_bytes: u64,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        let mut up = Budget::new(max_packets, max_bytes);
        let mut down = Budget::new(max_packets, max_bytes);
        let cell = cell_size(max_datagram + tls::LAYER_STEP as usize);
        loop {
            tokio::select! {
                r=socket.recv(&mut buf)=>{let n=r?;if n>0 && n<=max_datagram && up.admit(cell) {let f=frame(&buf[..n],cell);audit("bridge",f.len());let _=parent.send_datagram(f);}}
                r=parent.read_datagram()=>{let d=r?;if down.admit(d.len()) && let Some(p)=unframe(&d) && !p.is_empty() && p.len()<=max_datagram {socket.send(p).await?;}}
            }
        }
    })
}

/// Build the onion: layer 0 to the first hop over the carrier, then each further
/// layer inside the previous one. Only the first hop's address is known here; each
/// relay knows only its own next hop.
pub async fn client_once(
    c: &Config,
    fds: &BTreeMap<String, i32>,
    tun_fd: Option<i32>,
) -> Result<()> {
    let lanes = c.lanes();
    let (first_lane, first) = lanes[0];
    let endpoint = endpoint_client(
        c.listen,
        first,
        fd(fds, first_lane),
        tls::layer_payload(c.mtu, c.layers, 0),
    )?;
    let (conn0, life0) = connect(&endpoint, c.relay.unwrap(), first).await?;
    println!("{{\"event\":\"layer_authenticated\",\"layer\":0,\"kx\":\"X25519MLKEM768\"}}");
    let mut endpoints = vec![endpoint];
    let mut conns = vec![conn0];
    let mut tasks = Vec::new();
    let mut life = life0;
    let result = async {
        for (k, (lane, identity)) in lanes.iter().enumerate().skip(1) {
            let payload = tls::layer_payload(c.mtu, c.layers, k);
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let inner = endpoint_client("127.0.0.1:0".parse()?, identity, fd(fds, lane), payload)?;
            socket.connect(inner.local_addr()?).await?;
            let parent = conns.last().unwrap().clone();
            tasks.push(bridge(
                socket.clone(),
                parent,
                payload as usize,
                c.packets_per_second,
                c.bytes_per_second,
            ));
            // The parent must be able to carry this layer's packets as single datagrams.
            ensure!(
                conns
                    .last()
                    .unwrap()
                    .max_datagram_size()
                    .is_some_and(|m| m >= payload as usize),
                "layer budget exceeds the parent layer's datagram capacity"
            );
            let (conn, l) = connect(&inner, socket.local_addr()?, identity).await?;
            println!(
                "{}",
                serde_json::json!({"event":"layer_authenticated","layer":k,"kx":"X25519MLKEM768"})
            );
            life = life.min(l);
            endpoints.push(inner);
            conns.push(conn);
        }
        let last = conns.last().unwrap().clone();
        ensure!(
            last.max_datagram_size().is_some_and(|n| n >= c.mtu),
            "path cannot carry configured inner MTU"
        );
        // The session ends as soon as any lower layer closes.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        for lower in &conns[..conns.len() - 1] {
            let (lower, tx) = (lower.clone(), tx.clone());
            tasks.push(tokio::spawn(async move {
                lower.closed().await;
                let _ = tx.send(()).await;
                Ok(())
            }));
        }
        drop(tx);
        let mut work = Box::pin(tunnel(c, &last, life, tun_fd));
        tokio::select! {
            r = &mut work => r.map(|_| ()),
            _ = rx.recv(), if conns.len() > 1 => Err(anyhow::anyhow!("lower layer ended")),
        }
    }
    .await;
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
    for conn in conns.iter().rev() {
        conn.close(0u32.into(), b"session ended");
    }
    for e in endpoints.iter().rev() {
        e.close(0u32.into(), b"session ended");
    }
    // Give queued CONNECTION_CLOSE frames a bounded chance to release the peer's
    // single-session slot before a replacement connection is attempted.
    let _ = timeout(Duration::from_millis(250), endpoints[0].wait_idle()).await;
    result
}

/// Run the client: build every nested layer to the exit, bridge the TUN, reconnect with backoff.
pub async fn client(c: &Config, fds: &BTreeMap<String, i32>, tun_fd: Option<i32>) -> Result<()> {
    let mut backoff = 1;
    loop {
        let start = Instant::now();
        let _ = client_once(c, fds, tun_fd).await;
        println!("{{\"event\":\"reconnecting\"}}");
        if start.elapsed() > Duration::from_secs(10) {
            backoff = 1;
        }
        sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constant_cells_round_trip_and_hide_size() {
        // Two different payloads become the same wire size, and each recovers exactly.
        let cell = 1200;
        let small = frame(b"short", cell);
        let big = frame(&vec![7u8; 900], cell);
        assert_eq!(small.len(), cell);
        assert_eq!(
            big.len(),
            cell,
            "every cell is one size regardless of payload"
        );
        assert_eq!(unframe(&small), Some(&b"short"[..]));
        assert_eq!(unframe(&big), Some(&vec![7u8; 900][..]));
        // The padding really is beyond the real bytes.
        assert_eq!(&small[2..7], b"short");
        assert!(small[7..].iter().all(|&x| x == 0));
        // A receiver that did not strip would see the padded blob, not the packet, so
        // an unpadded peer can never silently accept padded traffic.
        assert_ne!(&small[..], b"short");
        // A frame claiming more than it carries is rejected, not read out of bounds.
        assert_eq!(unframe(&[0x00, 0x40, 1, 2]), None);
        assert_eq!(unframe(&[0x00]), None);
    }
    #[test]
    fn every_layer_cell_fits_what_it_carries() {
        // The cell must hold the largest payload a layer carries plus the 2-byte prefix,
        // and stay below the QUIC payload so it always fits a datagram.
        for (mtu, hops) in [
            (tls::MANAGED_IP_MTU, 1),
            (tls::MANAGED_IP_MTU, 2),
            (tls::MANAGED_IP_MTU, 3),
            (1280, 2),
        ] {
            let p = |k: usize| tls::layer_payload(mtu, hops, k) as usize;
            // Innermost: inner IP packets up to `mtu`.
            assert!(mtu + 2 <= cell_size(p(hops - 1)), "inner cell too small");
            for k in 0..hops - 1 {
                // A relay layer k carries layer k+1's packets.
                assert!(p(k + 1) + 2 <= cell_size(p(k)), "relay cell too small");
            }
            if hops > 1 {
                // A client bridge for layer k rides layer k-1's cell.
                let child = p(hops - 1);
                assert!(child + 2 <= cell_size(child + tls::LAYER_STEP as usize));
            }
            for k in 0..hops {
                assert!(
                    cell_size(p(k)) < p(k),
                    "cell must leave room for QUIC framing"
                );
            }
        }
    }
    #[test]
    fn layer_budget_respects_quic_minimum_and_carrier_mtu() {
        for hops in 1..=tls::MAX_HOPS {
            let p = |k| tls::layer_payload(tls::MANAGED_IP_MTU, hops, k);
            // RFC 9000: every QUIC layer needs at least a 1200-byte UDP payload.
            assert_eq!(p(hops - 1), tls::QUIC_MIN_PAYLOAD);
            for k in 1..hops {
                // Each layer fits inside its parent's datagrams (~32 bytes overhead).
                assert!(p(k) + 32 <= p(k - 1));
            }
            // Layer 0 plus IPv4/UDP headers must fit the 1340-byte WireGuard MTU.
            assert!(p(0) as usize + 28 <= 1340);
            assert!(tls::MANAGED_IP_MTU + 32 <= p(hops - 1) as usize);
        }
        assert_eq!(tls::layer_payload(1280, 2, 0), tls::OUTER_MTU);
    }
    #[test]
    fn rate_budget_bounds_both_bytes_and_packets() {
        let mut b = Budget::new(2, 10);
        assert!(b.admit(6));
        assert!(!b.admit(5));
        assert!(b.admit(4));
        assert!(!b.admit(0));
    }

    fn hops(n: usize, window: Option<[u64; 2]>) -> NextHops {
        let order: Vec<SocketAddr> = (0..n)
            .map(|k| format!("198.51.100.{}:4444", k + 2).parse().unwrap())
            .collect();
        NextHops {
            order,
            current: 0,
            dead: BTreeMap::new(),
            window,
            rotate_at: None,
        }
    }

    #[test]
    fn failover_skips_a_dead_next_hop_and_keeps_order() {
        let mut h = hops(3, None);
        let all = h.candidates();
        assert_eq!(all.len(), 3);
        h.lost(all[0]);
        assert_eq!(h.candidates(), vec![all[1], all[2]]);
        h.using(all[1]);
        assert_eq!(h.candidates()[0], all[1]);
        // Everything dead: still try them all rather than give up.
        h.lost(all[1]);
        h.lost(all[2]);
        assert_eq!(h.candidates().len(), 3);
    }

    #[test]
    fn rotation_moves_to_another_live_exit_only_when_due() {
        let mut h = hops(3, Some([60, 120]));
        h.rotate_at = Some(Instant::now() + Duration::from_secs(60));
        let first = h.candidates()[0];
        assert_eq!(h.candidates()[0], first, "not due: no rotation");
        let mut moved = 0;
        for _ in 0..40 {
            h.rotate_now();
            let before = h.order[h.current];
            let after = h.candidates()[0];
            if after != before {
                moved += 1;
            }
        }
        assert_eq!(moved, 40, "a due rotation always picks another exit");
        // A dead exit is never rotated to.
        let mut h = hops(2, Some([60, 60]));
        let other = h.order[1];
        h.lost(other);
        h.rotate_now();
        assert_eq!(h.candidates(), vec![h.order[0]]);
    }

    #[test]
    fn the_rotation_window_is_respected() {
        let h = hops(2, Some([900, 3600]));
        for _ in 0..200 {
            let d = h.draw().as_secs();
            assert!((900..=3600).contains(&d));
        }
    }
}
