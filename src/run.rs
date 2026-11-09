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
/// Constant-cell padding (`avpn help threat-model`). When the signed profile sets
/// `cells`, every datagram on every hop is framed `[len: u16 big-endian][payload][zero
/// padding]` up to `cell` bytes, so the real packet size never shows on the wire — not
/// just on the first hop, the way DAITA alone would leave it. The receiver reads `len`
/// and ignores the padding. Both ends of a layer share one `cells` setting (it is part
/// of the chain the operator signs), so there is never a padded/unpadded mismatch.
///
/// Framing is driven by `cells` (a chain-wide signed constant, identical on both ends),
/// so the sender and receiver never disagree. `cell` only sets how far to pad: when it
/// is `None` (the connection has not reported a datagram size yet) the frame is just the
/// length prefix and the payload, still parseable by the same receiver.
fn frame(payload: &[u8], cells: bool, cell: Option<usize>) -> Bytes {
    if !cells {
        return Bytes::copy_from_slice(payload);
    }
    let target = cell.unwrap_or(0).max(payload.len() + 2);
    let mut b = vec![0u8; target];
    b[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    b[2..2 + payload.len()].copy_from_slice(payload);
    Bytes::from(b)
}

/// Recover the real payload from a received datagram. With `cells` off the datagram is
/// the payload. With it on, read the length prefix and return that many bytes, rejecting
/// a frame that claims more than it carries.
fn unframe(d: &[u8], cells: bool) -> Option<&[u8]> {
    if !cells {
        return Some(d);
    }
    let len = u16::from_be_bytes([*d.first()?, *d.get(1)?]) as usize;
    d.get(2..2 + len)
}

/// Room left below a layer's QUIC payload for the DATAGRAM frame's own header, so the
/// padded cell always fits what `max_datagram_size()` will allow. Generous (quinn's
/// real overhead is ~20 bytes) so the cell never has to shrink at runtime.
const CELL_RESERVE: usize = 48;

/// The cell size to pad to on a layer whose configured QUIC payload is `layer_payload`,
/// or `None` when padding is off. It is a fixed function of the signed profile, not of
/// runtime timing, so every datagram on the layer is one size from the very first
/// packet and both peers agree without negotiation.
fn cell_size(cells: bool, layer_payload: usize) -> Option<usize> {
    cells.then(|| layer_payload - CELL_RESERVE)
}

/// Test-only: when `AVPN_CELL_AUDIT` names a path, every process records the distinct
/// datagram payload sizes it sends to `<path>.<role>`. The namespace lab asserts that
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
            let p = std::path::Path::new(&path).with_extension(role);
            let _ = std::fs::write(p, format!("{sizes:?}"));
        }
    }
}

fn endpoint_server(c: &Config, i: &Identity, fd: Option<i32>, mtu: u16) -> Result<Endpoint> {
    let s = tls::server(i, fd, mtu)?;
    let sock = std::net::UdpSocket::bind(c.listen)?;
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
        Ok(life) => life,
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

async fn relay_session(
    c: &Config,
    conn: &Connection,
    life: Duration,
    layer: usize,
) -> Result<Counts> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(c.exit.context("exit missing")?).await?;
    let mut b = vec![0; 65536];
    let mut counts = Counts::default();
    let mut up = Budget::new(c.packets_per_second, c.bytes_per_second);
    let mut down = Budget::new(c.packets_per_second, c.bytes_per_second);
    // Datagrams carry the next layer's packets, bounded by that layer's payload size.
    let next = tls::layer_payload(c.mtu, c.layers, layer + 1) as usize;
    let cell = cell_size(c.cells, tls::layer_payload(c.mtu, c.layers, layer) as usize);
    let deadline = sleep(life.min(Duration::from_secs(c.session_seconds)));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _=&mut deadline=>break,
            r=conn.read_datagram()=>{
                let d=r?;
                if !up.admit(d.len()) {counts.rate_dropped+=1;continue;}
                let Some(p)=unframe(&d,c.cells) else {counts.dropped+=1;continue;};
                if p.len()>next || p.is_empty() {counts.dropped+=1;continue;}
                udp.send(p).await?;counts.sent+=1;
            }
            r=udp.recv(&mut b)=>{
                let n=r?;
                if n==0 || n>next {counts.dropped+=1;continue;}
                if !down.admit(cell.unwrap_or(n)) {counts.rate_dropped+=1;continue;}
                let f=frame(&b[..n],c.cells,cell);audit(&c.role,f.len());if conn.send_datagram(f).is_err() {counts.dropped+=1;}else{counts.received+=1;}
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
    let cell = cell_size(c.cells, tls::layer_payload(c.mtu, c.layers, c.layers - 1) as usize);
    let deadline = sleep(life.min(Duration::from_secs(c.session_seconds)));
    tokio::pin!(deadline);
    println!("{{\"event\":\"tunnel_ready\",\"kx\":\"X25519MLKEM768\",\"cipher\":\"AES_256_GCM\"}}");
    loop {
        tokio::select! {
            _=&mut deadline=>break,
            r=tun.read(&mut buf)=>{
                let n=r?;
                if !allowed_packet(&buf[..n],fixed,&routes,out_source,c.mtu) {counts.dropped+=1;continue;}
                if !up.admit(cell.unwrap_or(n)) {counts.rate_dropped+=1;continue;}
                let f=frame(&buf[..n],c.cells,cell);audit(&c.role,f.len());if conn.send_datagram(f).is_err(){counts.dropped+=1;}else{counts.sent+=1;}
            }
            r=conn.read_datagram()=>{
                let d=r?;
                if !down.admit(d.len()){counts.rate_dropped+=1;continue;}
                let Some(p)=unframe(&d,c.cells) else {counts.dropped+=1;continue;};
                if !allowed_packet(p,fixed,&routes,!out_source,c.mtu){counts.dropped+=1;continue;}
                tun.write(p).await?;counts.received+=1;
            }
        }
    }
    Ok(counts)
}

/// Run a relay or exit: accept authenticated sessions and terminate this server's layer.
pub async fn serve(c: &Config, fds: &BTreeMap<String, i32>, tun_fd: Option<i32>) -> Result<()> {
    let relay = c.role == "relay";
    // Each server terminates exactly one layer: entry/middle relays forward the
    // next layer's ciphertext; the exit owns the innermost layer and the TUN.
    let (role, i, layer) = c.server_layer()?;
    let endpoint = endpoint_server(
        c,
        i,
        fd(fds, role),
        tls::layer_payload(c.mtu, c.layers, layer),
    )?;
    println!("{{\"event\":\"listening\"}}");
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
        let life = match tls::authenticated(&conn, i) {
            Ok(l) => l,
            Err(_) => {
                conn.close(1u32.into(), b"policy rejected");
                continue;
            }
        };
        println!(
            "{{\"event\":\"authenticated\",\"kx\":\"X25519MLKEM768\",\"cipher\":\"AES_256_GCM\"}}"
        );
        let result = if relay {
            relay_session(c, &conn, life, layer).await
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
    Ok(())
}

/// Carry one layer's UDP packets as DATAGRAMs of its parent connection.
fn bridge(
    socket: Arc<UdpSocket>,
    parent: Connection,
    max_datagram: usize,
    max_packets: u64,
    max_bytes: u64,
    cells: bool,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        let mut up = Budget::new(max_packets, max_bytes);
        let mut down = Budget::new(max_packets, max_bytes);
        let cell = cell_size(cells, max_datagram + tls::LAYER_STEP as usize);
        loop {
            tokio::select! {
                r=socket.recv(&mut buf)=>{let n=r?;if n>0 && n<=max_datagram && up.admit(cell.unwrap_or(n)) {let f=frame(&buf[..n],cells,cell);audit("bridge",f.len());let _=parent.send_datagram(f);}}
                r=parent.read_datagram()=>{let d=r?;if down.admit(d.len()){if let Some(p)=unframe(&d,cells){if !p.is_empty() && p.len()<=max_datagram {socket.send(p).await?;}}}}
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
                c.cells,
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
        // Padding off: the datagram is the payload, unchanged.
        let p = b"an inner IP packet";
        assert_eq!(&frame(p, false, None)[..], p);
        assert_eq!(unframe(p, false), Some(&p[..]));
        // Padding on: two different payloads become the same wire size, and each
        // recovers exactly.
        let cell = 1200;
        let small = frame(b"short", true, Some(cell));
        let big = frame(&vec![7u8; 900], true, Some(cell));
        assert_eq!(small.len(), cell);
        assert_eq!(big.len(), cell, "every cell is one size regardless of payload");
        assert_eq!(unframe(&small, true), Some(&b"short"[..]));
        assert_eq!(unframe(&big, true), Some(&vec![7u8; 900][..]));
        // The padding really is beyond the real bytes.
        assert_eq!(&small[2..7], b"short");
        assert!(small[7..].iter().all(|&x| x == 0));
        // A receiver that forgets to strip gets the padded blob, not the packet — which
        // is why a mismatched (unpadded) peer cannot silently accept padded traffic.
        assert_ne!(unframe(&small, false), Some(&b"short"[..]));
        // Cells on but the size is not known yet: framed with just the prefix, and the
        // same receiver still recovers it (this is the bug that broke the first lab run).
        let nopad = frame(b"hello", true, None);
        assert_eq!(nopad.len(), 7);
        assert_eq!(unframe(&nopad, true), Some(&b"hello"[..]));
        // A frame claiming more than it carries is rejected, not read out of bounds.
        assert_eq!(unframe(&[0x00, 0x40, 1, 2], true), None);
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
}
