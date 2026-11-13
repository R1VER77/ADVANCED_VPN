//! Bounded owned-exit DNS-over-TLS forwarder with an optional signed domain filter.
//! No DNS query logging or persistent cache.
//!
//! The filter (an anti-tracker, decided at the exit, inside the tunnel): a signed
//! blocklist and allowlist in the common list formats (plain domains, `.domain`,
//! `*.domain`, hosts-file `0.0.0.0 domain`, adblock `||domain^`). The allowlist wins.
//! Answers are checked too: a permitted name whose CNAME chain leads into a blocked
//! domain (CNAME cloaking, how first-party trackers evade query-name filters) is
//! answered `NXDOMAIN` like the blocked name itself.
use advanced_vpn::config::private_read;
use anyhow::{Result, ensure};
use clap::Parser;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};
use tokio_rustls::TlsConnector;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    listen: SocketAddr,
    client_ip: IpAddr,
    /// Mesh exits only: the member tunnel network (CIDR) queries may arrive from.
    /// Absent on a single-chain exit, which serves exactly `client_ip`.
    client_network: Option<String>,
    upstream: SocketAddr,
    server_name: String,
    test_ca: Option<PathBuf>,
    /// Optional signed domain blocklist file (one domain per line; `#` comments ignored).
    #[serde(default)]
    blocklist: Option<PathBuf>,
    /// Optional inline blocked domain suffixes from the profile.
    #[serde(default)]
    blocked_domains: Vec<String>,
    /// Optional signed allowlist file (same formats): its entries are never blocked.
    #[serde(default)]
    allowlist: Option<PathBuf>,
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}

/// One filter rule's reach.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reach {
    /// `domain`, `.domain`, `0.0.0.0 domain`, `||domain^`: the domain and its subdomains.
    WithSubdomains,
    /// `*.domain`: subdomains only, not the domain itself.
    SubdomainsOnly,
}

/// A domain rule set: an entry `ads.example.com` covers `ads.example.com` and
/// `sub.ads.example.com`, never `badads.example.com`.
#[derive(Default, Clone)]
struct Rules {
    domains: BTreeMap<String, Reach>,
}

impl Rules {
    /// Parse list text in the common formats, plus inline entries.
    fn from_lines(text: &str, inline: &[String]) -> Result<Self> {
        let mut domains = BTreeMap::new();
        for raw in text.lines().chain(inline.iter().map(String::as_str)) {
            let mut line = raw.split(['#', '!']).next().unwrap_or("").trim();
            // hosts-file format: "0.0.0.0 domain" or "127.0.0.1 domain"
            if let Some((addr, rest)) = line.split_once(char::is_whitespace)
                && matches!(addr, "0.0.0.0" | "127.0.0.1" | "::" | "::1")
            {
                line = rest.trim();
            }
            // adblock format: "||domain^"
            if let Some(inner) = line.strip_prefix("||") {
                line = inner.strip_suffix('^').unwrap_or(inner);
            }
            let (reach, name) = if let Some(rest) = line.strip_prefix("*.") {
                (Reach::SubdomainsOnly, rest)
            } else if let Some(rest) = line.strip_prefix('.') {
                (Reach::WithSubdomains, rest)
            } else {
                (Reach::WithSubdomains, line)
            };
            let name = name.trim_end_matches('.');
            if name.is_empty() || matches!(name, "localhost" | "local" | "broadcasthost") {
                continue;
            }
            let lower = name.to_ascii_lowercase();
            ensure!(valid_domain(&lower), "invalid domain in filter list");
            // The wider rule wins if both forms appear.
            let entry = domains.entry(lower).or_insert(reach);
            if reach == Reach::WithSubdomains {
                *entry = Reach::WithSubdomains;
            }
        }
        Ok(Self { domains })
    }

    fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    fn matches(&self, qname: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        let clean = qname.trim_end_matches('.').to_ascii_lowercase();
        let mut cursor = clean.as_str();
        let mut is_apex = true;
        loop {
            match self.domains.get(cursor) {
                Some(Reach::WithSubdomains) => return true,
                Some(Reach::SubdomainsOnly) if !is_apex => return true,
                _ => {}
            }
            match cursor.split_once('.') {
                Some((_, rest)) => {
                    cursor = rest;
                    is_apex = false;
                }
                None => return false,
            }
        }
    }
}

/// The exit's filter: blocked unless allowed.
#[derive(Default, Clone)]
struct Blocklist {
    block: Rules,
    allow: Rules,
}

impl Blocklist {
    fn from_lines(text: &str, inline: &[String]) -> Result<Self> {
        Ok(Self {
            block: Rules::from_lines(text, inline)?,
            allow: Rules::default(),
        })
    }

    fn with_allowlist(mut self, text: &str) -> Result<Self> {
        self.allow = Rules::from_lines(text, &[])?;
        Ok(self)
    }

    fn is_blocked(&self, qname: &str) -> bool {
        !self.block.is_empty() && self.block.matches(qname) && !self.allow.matches(qname)
    }

    /// True when an upstream answer's CNAME chain enters a blocked domain.
    fn answer_is_cloaked(&self, answer: &[u8]) -> bool {
        !self.block.is_empty()
            && cname_targets(answer)
                .map(|names| names.iter().any(|n| self.is_blocked(n)))
                .unwrap_or(false)
    }
}

/// Read a (possibly compressed) DNS name at `pos`; returns the name and the offset just
/// past it in the original record. Bounded: at most 32 pointer jumps and 255 bytes.
fn read_name(pkt: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    let mut total = 0usize;
    loop {
        let len = *pkt.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            let target = ((len & 0x3F) << 8) | *pkt.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 32 || target >= pkt.len() {
                return None;
            }
            pos = target;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if len == 0 {
            break;
        }
        let label = pkt.get(pos..pos + len)?;
        total += len + 1;
        if total > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

/// Every name in an answer's CNAME chain (owners and targets of CNAME records), or
/// None if the answer does not parse.
fn cname_targets(pkt: &[u8]) -> Option<Vec<String>> {
    let qd = u16::from_be_bytes([*pkt.get(4)?, *pkt.get(5)?]) as usize;
    let an = u16::from_be_bytes([*pkt.get(6)?, *pkt.get(7)?]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(pkt, pos)?.1 + 4;
    }
    let mut names = Vec::new();
    for _ in 0..an.min(64) {
        let (owner, after) = read_name(pkt, pos)?;
        let rtype = u16::from_be_bytes([*pkt.get(after)?, *pkt.get(after + 1)?]);
        let rdlen = u16::from_be_bytes([*pkt.get(after + 8)?, *pkt.get(after + 9)?]) as usize;
        let rdata = after + 10;
        pkt.get(rdata..rdata + rdlen)?;
        if rtype == 5 {
            names.push(owner);
            names.push(read_name(pkt, rdata)?.0);
        }
        pos = rdata + rdlen;
    }
    Some(names)
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// Parse the first question's QNAME and return `(lowercased_domain, question_end_offset)`.
/// Rejects compression pointers and malformed label lengths.
fn parse_question(pkt: &[u8]) -> Result<(String, usize)> {
    ensure!(pkt.len() >= 17, "DNS packet too short");
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    ensure!(qdcount >= 1, "DNS packet has no question");
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        ensure!(pos < pkt.len(), "truncated DNS QNAME");
        let len = pkt[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        ensure!(len <= 63 && pos + len <= pkt.len(), "bad DNS label length");
        let label = std::str::from_utf8(&pkt[pos..pos + len])?;
        ensure!(
            label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid byte in DNS QNAME"
        );
        labels.push(label.to_ascii_lowercase());
        pos += len;
        ensure!(pos <= 267, "DNS QNAME too long");
    }
    // QTYPE (2 bytes) + QCLASS (2 bytes)
    ensure!(pos + 4 <= pkt.len(), "truncated DNS question");
    Ok((labels.join("."), pos + 4))
}

/// Synthesize an immediate `NXDOMAIN` (`RCODE = 3`) response for a blocked query.
fn nxdomain_response(query: &[u8], q_end: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(q_end);
    // Transaction ID
    out.extend_from_slice(&query[..2]);
    // Flags: QR=1 (0x80), preserve RD (query[2] & 0x01); RA=1 (0x80), RCODE=3 (NXDOMAIN)
    out.push(0x80 | (query[2] & 0x01));
    out.push(0x83);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Copy the first question verbatim
    out.extend_from_slice(&query[12..q_end]);
    out
}

/// TLS to the upstream resolver: TLS 1.3 with the hybrid post-quantum group
/// X25519MLKEM768 as the only key exchange. An upstream that cannot do it gets no query
/// (DNS fails closed), so no lookup ever crosses the exit's last leg under classical
/// key exchange alone.
fn upstream_tls(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.enable_early_data = false;
    crypto.resumption = rustls::client::Resumption::disabled();
    Ok(crypto)
}

/// One upstream DNS-over-TLS connection.
type Upstream = tokio_rustls::client::TlsStream<TcpStream>;
/// Idle upstream connections kept for reuse (RFC 7858 §3.4): a lookup then costs one
/// round trip instead of TCP + a hybrid post-quantum TLS handshake + one.
const POOL: usize = 4;
/// An idle connection older than this is closed rather than reused.
const IDLE: Duration = Duration::from_secs(20);

/// One query and its answer on an upstream connection (2-byte length framing).
async fn exchange(tls: &mut Upstream, b: &[u8]) -> Result<Vec<u8>> {
    let mut msg = u16::try_from(b.len())?.to_be_bytes().to_vec();
    msg.extend_from_slice(b);
    tls.write_all(&msg).await?;
    let n = tls.read_u16().await? as usize;
    ensure!((12..=65535).contains(&n), "bad DNS length");
    let mut answer = vec![0; n];
    tls.read_exact(&mut answer).await?;
    ensure!(
        answer[..2] == b[..2] && answer[2] & 0x80 != 0,
        "bad DNS response"
    );
    Ok(answer)
}

struct Resolver {
    tls: TlsConnector,
    addr: SocketAddr,
    name: ServerName<'static>,
    slots: Arc<Semaphore>,
    blocklist: Blocklist,
    count: AtomicU64,
    blocked: AtomicU64,
    /// Idle connections and when each went idle.
    idle: std::sync::Mutex<Vec<(Upstream, std::time::Instant)>>,
    /// Upstream TLS handshakes made (the pool's effect, for tests and stats).
    connects: AtomicU64,
}
impl Resolver {
    async fn connect(&self) -> Result<Upstream> {
        let stream = timeout(Duration::from_secs(3), TcpStream::connect(self.addr)).await??;
        let tls = timeout(
            Duration::from_secs(3),
            self.tls.connect(self.name.clone(), stream),
        )
        .await??;
        self.connects.fetch_add(1, Ordering::Relaxed);
        Ok(tls)
    }
    fn take_idle(&self) -> Option<Upstream> {
        let mut idle = self.idle.lock().ok()?;
        idle.retain(|(_, since)| since.elapsed() < IDLE);
        idle.pop().map(|(c, _)| c)
    }
    fn put_idle(&self, c: Upstream) {
        if let Ok(mut idle) = self.idle.lock()
            && idle.len() < POOL
        {
            idle.push((c, std::time::Instant::now()));
        }
    }
    /// The answer to `b` from the upstream: on an idle connection when one is left, else
    /// (or when the upstream has closed it meanwhile) on a fresh one. Queries are
    /// idempotent, so one retry on a new connection is safe.
    async fn ask(&self, b: &[u8]) -> Result<Vec<u8>> {
        if let Some(mut c) = self.take_idle()
            && let Ok(Ok(answer)) = timeout(Duration::from_secs(3), exchange(&mut c, b)).await
        {
            self.put_idle(c);
            return Ok(answer);
        }
        let mut c = self.connect().await?;
        let answer = timeout(Duration::from_secs(3), exchange(&mut c, b)).await??;
        self.put_idle(c);
        Ok(answer)
    }
    async fn query(&self, b: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            b.len() >= 12 && b.len() <= 4096 && b[2] & 0x80 == 0,
            "bad DNS request"
        );
        if let Ok((qname, q_end)) = parse_question(b)
            && self.blocklist.is_blocked(&qname)
        {
            self.blocked.fetch_add(1, Ordering::Relaxed);
            return Ok(nxdomain_response(b, q_end));
        }
        let answer = self.ask(b).await?;
        self.count.fetch_add(1, Ordering::Relaxed);
        // CNAME cloaking: a permitted name that resolves through a blocked one.
        if self.blocklist.answer_is_cloaked(&answer)
            && let Ok((_, q_end)) = parse_question(b)
        {
            self.blocked.fetch_add(1, Ordering::Relaxed);
            return Ok(nxdomain_response(b, q_end));
        }
        Ok(answer)
    }
}
async fn work() -> Result<()> {
    let a = Args::parse();
    let c: Config = serde_json::from_slice(&private_read(&a.config, 8192)?)?;
    ensure!(
        c.schema == 1
            && c.listen.is_ipv4()
            && c.client_ip.is_ipv4()
            && c.listen.port() >= 1024
            && c.upstream.port() != 0,
        "invalid DNS profile"
    );
    // Single chain: exactly the client's address. Mesh: the member tunnel network.
    let member_net = match &c.client_network {
        Some(s) => Some(advanced_vpn::tun::network(s)?),
        None => None,
    };
    let from_client = |ip: IpAddr| match (member_net, ip) {
        (Some((net, mask)), IpAddr::V4(a)) => u32::from(a) & mask == net,
        (None, ip) => ip == c.client_ip,
        (Some(_), _) => false,
    };
    let blocklist_text = match &c.blocklist {
        Some(path) => String::from_utf8(private_read(path, 1 << 20)?)?,
        None => String::new(),
    };
    let allowlist_text = match &c.allowlist {
        Some(path) => String::from_utf8(private_read(path, 1 << 20)?)?,
        None => String::new(),
    };
    let blocklist = Blocklist::from_lines(&blocklist_text, &c.blocked_domains)?
        .with_allowlist(&allowlist_text)?;
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = c.test_ca {
        roots.add(CertificateDer::from(private_read(&path, 16384)?))?;
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let resolver = Arc::new(Resolver {
        tls: TlsConnector::from(Arc::new(upstream_tls(roots)?)),
        addr: c.upstream,
        name: ServerName::try_from(c.server_name)?,
        slots: Arc::new(Semaphore::new(16)),
        idle: std::sync::Mutex::new(Vec::new()),
        connects: AtomicU64::new(0),
        blocklist,
        count: AtomicU64::new(0),
        blocked: AtomicU64::new(0),
    });
    if a.check {
        println!("{{\"configuration_valid\":true,\"upstream_tls\":true}}");
        return Ok(());
    }
    let udp = Arc::new(UdpSocket::bind(c.listen).await?);
    let tcp = TcpListener::bind(c.listen).await?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut buffer = vec![0; 65536];
    let mut budget = advanced_vpn::run::Budget::new(100, 409600);
    loop {
        tokio::select! {
            _=term.recv()=>break,
            _=tokio::signal::ctrl_c()=>break,
            received=udp.recv_from(&mut buffer)=>{
                let(n,peer)=received?;
                if !from_client(peer.ip()) || n>4096 || !budget.admit(n){continue;}
                let Ok(permit)=resolver.slots.clone().try_acquire_owned() else {continue};
                let r=resolver.clone();let u=udp.clone();let query=buffer[..n].to_vec();
                tokio::spawn(async move {let _permit=permit;
                    if let Ok(Ok(mut answer))=timeout(Duration::from_secs(5),r.query(&query)).await {
                        if answer.len()>1232 {answer.truncate(12);answer[2]|=2;for v in &mut answer[4..12]{*v=0;}}
                        let _=u.send_to(&answer,peer).await;
                    }
                });
            }
            received=tcp.accept()=>{
                let(mut stream,peer)=received?;
                if !from_client(peer.ip()) || !budget.admit(4096){continue;}
                let Ok(permit)=resolver.slots.clone().try_acquire_owned() else {continue};let r=resolver.clone();
                tokio::spawn(async move {let _permit=permit;
                    let work=async {
                        let n=stream.read_u16().await? as usize;ensure!((12..=4096).contains(&n),"bad request size");
                        let mut b=vec![0;n];stream.read_exact(&mut b).await?;let answer=r.query(&b).await?;
                        stream.write_all(&u16::try_from(answer.len())?.to_be_bytes()).await?;stream.write_all(&answer).await?;
                        Ok::<(),anyhow::Error>(())
                    };
                    let _=timeout(Duration::from_secs(5),work).await;
                });
            }
        }
    }
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // SAFETY: scalar process hardening and valid rlimit pointer.
    unsafe {
        libc::umask(0o077);
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let l = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &l);
    }
    if work().await.is_err() {
        eprintln!("DNS profile or transport rejected");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_query(txid: [u8; 2], domain: &str) -> Vec<u8> {
        let mut pkt = vec![
            txid[0], txid[1], 0x01, 0x00, // RD=1
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in domain.split('.') {
            if !label.is_empty() {
                pkt.push(label.len() as u8);
                pkt.extend_from_slice(label.as_bytes());
            }
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        pkt
    }

    #[test]
    fn blocklist_matches_exact_and_subdomains_never_partial_labels() {
        let bl = Blocklist::from_lines(
            "# comment\nads.example.com\ntracker.example.org.\n",
            &["malware.test".to_string()],
        )
        .unwrap();
        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("ADS.EXAMPLE.COM."));
        assert!(bl.is_blocked("sub.ads.example.com"));
        assert!(bl.is_blocked("deep.sub.tracker.example.org"));
        assert!(bl.is_blocked("malware.test"));
        assert!(!bl.is_blocked("badads.example.com"));
        assert!(!bl.is_blocked("example.com"));
        assert!(!bl.is_blocked("notmalware.test"));
    }

    #[test]
    fn blocked_query_synthesizes_nxdomain_with_matching_txid_and_question() {
        let q = make_query([0xab, 0xcd], "pixel.ads.example.com");
        let (qname, q_end) = parse_question(&q).unwrap();
        assert_eq!(qname, "pixel.ads.example.com");
        assert_eq!(q_end, q.len());
        let resp = nxdomain_response(&q, q_end);
        assert_eq!(&resp[..2], &[0xab, 0xcd]);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0f, 3); // RCODE=3 (NXDOMAIN)
        assert_eq!(&resp[12..], &q[12..]);
    }

    /// An upstream answer for `qname`: optional CNAME chain (compressed names), then an A record.
    fn answer_with_chain(query: &[u8], chain: &[&str]) -> Vec<u8> {
        let (_, q_end) = parse_question(query).unwrap();
        let mut a = query[..2].to_vec();
        a.extend_from_slice(&[0x81, 0x80, 0x00, 0x01]);
        a.extend_from_slice(&((chain.len() + 1) as u16).to_be_bytes());
        a.extend_from_slice(&[0, 0, 0, 0]);
        a.extend_from_slice(&query[12..q_end]);
        let mut owner_ptr = 12u16; // the question's name
        for target in chain {
            a.extend_from_slice(&(0xC000 | owner_ptr).to_be_bytes());
            a.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 30]);
            let mut rdata = Vec::new();
            for label in target.split('.') {
                rdata.push(label.len() as u8);
                rdata.extend_from_slice(label.as_bytes());
            }
            rdata.push(0);
            a.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            owner_ptr = a.len() as u16;
            a.extend_from_slice(&rdata);
        }
        a.extend_from_slice(&(0xC000 | owner_ptr).to_be_bytes());
        a.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 203, 0, 113, 9]);
        a
    }

    #[test]
    fn list_formats_and_reach() {
        let list = "tracker.example\n.ads.example\n*.cdn.example\n0.0.0.0 hosts.example\n||abp.example^\n! adblock comment\n# comment\n";
        let bl = Blocklist::from_lines(list, &[]).unwrap();
        for blocked in [
            "tracker.example",
            "x.tracker.example",
            "ads.example",
            "a.b.ads.example",
            "x.cdn.example",
            "hosts.example",
            "abp.example",
            "sub.abp.example",
        ] {
            assert!(bl.is_blocked(blocked), "{blocked} should be blocked");
        }
        // `*.domain` is subdomains only; partial labels never match.
        for allowed in ["cdn.example", "nottracker.example", "example", "other.test"] {
            assert!(!bl.is_blocked(allowed), "{allowed} should pass");
        }
    }

    #[test]
    fn the_allowlist_overrides_the_blocklist() {
        let bl = Blocklist::from_lines(".ads.example\n", &[])
            .unwrap()
            .with_allowlist("needed.ads.example\n")
            .unwrap();
        assert!(bl.is_blocked("ads.example"));
        assert!(bl.is_blocked("other.ads.example"));
        assert!(!bl.is_blocked("needed.ads.example"));
        assert!(!bl.is_blocked("x.needed.ads.example"));
    }

    #[test]
    fn a_cname_into_a_blocked_domain_is_refused() {
        let bl = Blocklist::from_lines("tracker.example\n", &[]).unwrap();
        let q = make_query([0x12, 0x34], "metrics.news.test");
        // metrics.news.test -> edge.tracker.example -> A: cloaked.
        assert!(bl.answer_is_cloaked(&answer_with_chain(&q, &["edge.tracker.example"])));
        // A two-step chain whose second hop is blocked.
        assert!(bl.answer_is_cloaked(&answer_with_chain(
            &q,
            &["cdn.news.test", "pixel.tracker.example"]
        )));
        // A clean chain and a plain answer pass.
        assert!(!bl.answer_is_cloaked(&answer_with_chain(&q, &["cdn.news.test"])));
        assert!(!bl.answer_is_cloaked(&answer_with_chain(&q, &[])));
        // An allowlisted target passes.
        let allowed = bl.clone().with_allowlist("edge.tracker.example\n").unwrap();
        assert!(!allowed.answer_is_cloaked(&answer_with_chain(&q, &["edge.tracker.example"])));
    }

    /// The test CA that signed the `dns.test` leaf below.
    const TEST_CA: &str = "308201853082012ba00302010202147b7305c0759fb590e5a7ae9d8bb6d7ac097cfbea300a06082a8648ce3d04030230173115301306035504030c0c6176706e2d746573742d63613020170d3236313131333035353433395a180f32313236313032303035353433395a30173115301306035504030c0c6176706e2d746573742d63613059301306072a8648ce3d020106082a8648ce3d03010703420004c710ec326571976fcfd7d98d41efefbc1893c444207bd0e6bfecdbb63f26480bd5a16083e73c0bca5f672f290cb8b032f59b884b9963709c8065d85dc93893b7a3533051301d0603551d0e04160414139907b6deea232678b8088cb0b62ea0edd293a9301f0603551d23041830168014139907b6deea232678b8088cb0b62ea0edd293a9300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100f136aab056185d15cf4182274e9a71d474ae8b67b423df111ced447bbde84a3202200cc81300198159d03f9ef61b3c7d26eb3885d34804f1aa5368db78a395b5a06d";

    /// A one-query DoT upstream on loopback whose TLS offers only `group`.
    async fn upstream(group: &'static dyn rustls::crypto::SupportedKxGroup) -> SocketAddr {
        upstream_serving(group, false).await.0
    }

    /// A DoT upstream on loopback whose TLS offers only `group`: it answers every query on
    /// a connection (or, with `one_per_connection`, one and then hangs up) and counts the
    /// connections it accepted.
    async fn upstream_serving(
        group: &'static dyn rustls::crypto::SupportedKxGroup,
        one_per_connection: bool,
    ) -> (SocketAddr, Arc<AtomicU64>) {
        let leaf = hex::decode("308201a93082014ea003020102021471f551994895b91cd0289bb0042ee254e36de3ba300a06082a8648ce3d04030230173115301306035504030c0c6176706e2d746573742d63613020170d3236313131333035353433395a180f32313236313032303035353433395a30133111300f06035504030c08646e732e746573743059301306072a8648ce3d020106082a8648ce3d03010703420004ba1bf9a7be9b7dd8fbb144a88f4beb11d65be11694a065daefe54ffbc253a6b2df818ad8bee3dfc91597d9da80feec3130d5066a42b2d1b38a69bd771d0a51fea37a307830130603551d11040c300a8208646e732e74657374300c0603551d130101ff0402300030130603551d25040c300a06082b06010505070301301d0603551d0e0416041457a0a83014e8cf81d3d60c53f5647a5b7405ee0b301f0603551d23041830168014139907b6deea232678b8088cb0b62ea0edd293a9300a06082a8648ce3d0403020349003046022100a4bd85e0f7da323809b0122f2fb0f3eb372cc2d77aa0df8bc2422999628f2479022100cbc246742740337ed5ca5c74b54ccf5ed7f65da31d2da771788bc749735c81a4").unwrap();
        let key = hex::decode("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420feab05caade22b54dd100ed6fb00ba235e524a17672e582c7debf928f085c660a14403420004ba1bf9a7be9b7dd8fbb144a88f4beb11d65be11694a065daefe54ffbc253a6b2df818ad8bee3dfc91597d9da80feec3130d5066a42b2d1b38a69bd771d0a51fe").unwrap();
        let mut p = rustls::crypto::aws_lc_rs::default_provider();
        p.kx_groups = vec![group];
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf)],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicU64::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(s).await else {
                        return;
                    };
                    while let Ok(n) = tls.read_u16().await {
                        let mut q = vec![0; n as usize];
                        if tls.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        q[2] |= 0x80; // the query, answered (no records)
                        let _ = tls.write_all(&n.to_be_bytes()).await;
                        let _ = tls.write_all(&q).await;
                        if one_per_connection {
                            let _ = tls.shutdown().await;
                            return;
                        }
                    }
                });
            }
        });
        (addr, accepted)
    }

    fn resolver_to(addr: SocketAddr) -> Resolver {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(hex::decode(TEST_CA).unwrap()))
            .unwrap();
        Resolver {
            tls: TlsConnector::from(Arc::new(upstream_tls(roots).unwrap())),
            addr,
            name: ServerName::try_from("dns.test").unwrap(),
            slots: Arc::new(Semaphore::new(1)),
            blocklist: Blocklist::from_lines("", &[]).unwrap(),
            count: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            idle: std::sync::Mutex::new(Vec::new()),
            connects: AtomicU64::new(0),
        }
    }

    #[tokio::test]
    async fn lookups_reuse_one_upstream_connection() {
        let (addr, accepted) =
            upstream_serving(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768, false).await;
        let r = resolver_to(addr);
        for i in 0..3u8 {
            r.query(&make_query([i, 1], "example.org")).await.unwrap();
        }
        assert_eq!(r.connects.load(Ordering::Relaxed), 1);
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn an_upstream_that_hangs_up_still_gets_every_lookup_answered() {
        let (addr, accepted) =
            upstream_serving(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768, true).await;
        let r = resolver_to(addr);
        for i in 0..3u8 {
            r.query(&make_query([i, 2], "example.org")).await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn the_upstream_must_offer_hybrid_post_quantum_tls() {
        use rustls::crypto::aws_lc_rs::kx_group;
        for (group, answered) in [(kx_group::X25519MLKEM768, true), (kx_group::X25519, false)] {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(hex::decode(TEST_CA).unwrap()))
                .unwrap();
            let resolver = Resolver {
                tls: TlsConnector::from(Arc::new(upstream_tls(roots).unwrap())),
                addr: upstream(group).await,
                name: ServerName::try_from("dns.test").unwrap(),
                slots: Arc::new(Semaphore::new(1)),
                idle: std::sync::Mutex::new(Vec::new()),
                connects: AtomicU64::new(0),
                blocklist: Blocklist::from_lines("", &[]).unwrap(),
                count: AtomicU64::new(0),
                blocked: AtomicU64::new(0),
            };
            let r = resolver.query(&make_query([7, 9], "example.org")).await;
            assert_eq!(r.is_ok(), answered, "{:?}: {r:?}", group.name());
        }
    }

    #[test]
    fn malformed_answers_never_panic() {
        let q = make_query([0, 1], "a.test");
        let good = answer_with_chain(&q, &["b.test"]);
        for cut in 0..good.len() {
            let _ = cname_targets(&good[..cut]);
        }
        // A compression pointer loop is refused, not followed forever.
        let mut looped = good.clone();
        let n = looped.len();
        looped[n - 16] = 0xC0;
        looped[n - 15] = (n - 16) as u8;
        let _ = cname_targets(&looped);
        let mut self_ptr = vec![0u8; 12];
        self_ptr[5] = 1;
        self_ptr.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert!(cname_targets(&self_ptr).is_none());
    }
}
