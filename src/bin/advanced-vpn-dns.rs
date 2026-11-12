//! Bounded owned-exit DNS-over-TLS forwarder with optional signed domain blocklist.
//! No DNS query logging or persistent cache.
use advanced_vpn::config::private_read;
use anyhow::{Result, ensure};
use clap::Parser;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
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
}
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    check: bool,
}

/// Suffix-aware domain blocklist: an entry `ads.example.com` blocks `ads.example.com`
/// and `sub.ads.example.com`, never `badads.example.com`.
#[derive(Default, Clone)]
struct Blocklist {
    domains: BTreeSet<String>,
}

impl Blocklist {
    fn from_lines(text: &str, inline: &[String]) -> Result<Self> {
        let mut domains = BTreeSet::new();
        for raw in text.lines().chain(inline.iter().map(String::as_str)) {
            let line = raw
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('.');
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            ensure!(valid_domain(&lower), "invalid domain in blocklist");
            domains.insert(lower);
        }
        Ok(Self { domains })
    }

    fn is_blocked(&self, qname: &str) -> bool {
        if self.domains.is_empty() {
            return false;
        }
        let clean = qname.trim_end_matches('.').to_ascii_lowercase();
        let mut cursor = clean.as_str();
        loop {
            if self.domains.contains(cursor) {
                return true;
            }
            match cursor.split_once('.') {
                Some((_, rest)) => cursor = rest,
                None => return false,
            }
        }
    }
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

struct Resolver {
    tls: TlsConnector,
    addr: SocketAddr,
    name: ServerName<'static>,
    slots: Arc<Semaphore>,
    blocklist: Blocklist,
    count: AtomicU64,
    blocked: AtomicU64,
}
impl Resolver {
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
        let stream = timeout(Duration::from_secs(3), TcpStream::connect(self.addr)).await??;
        let mut tls = timeout(
            Duration::from_secs(3),
            self.tls.connect(self.name.clone(), stream),
        )
        .await??;
        tls.write_all(&u16::try_from(b.len())?.to_be_bytes())
            .await?;
        tls.write_all(b).await?;
        let n = tls.read_u16().await? as usize;
        ensure!((12..=65535).contains(&n), "bad DNS length");
        let mut answer = vec![0; n];
        tls.read_exact(&mut answer).await?;
        ensure!(
            answer[..2] == b[..2] && answer[2] & 0x80 != 0,
            "bad DNS response"
        );
        self.count.fetch_add(1, Ordering::Relaxed);
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
    let blocklist = Blocklist::from_lines(&blocklist_text, &c.blocked_domains)?;
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = c.test_ca {
        roots.add(CertificateDer::from(private_read(&path, 16384)?))?;
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.enable_early_data = false;
    crypto.resumption = rustls::client::Resumption::disabled();
    let resolver = Arc::new(Resolver {
        tls: TlsConnector::from(Arc::new(crypto)),
        addr: c.upstream,
        name: ServerName::try_from(c.server_name)?,
        slots: Arc::new(Semaphore::new(16)),
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
}
